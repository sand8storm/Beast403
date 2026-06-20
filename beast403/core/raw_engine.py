"""Raw HTTP/1.1 sender -- sends the exact request-target bytes, unmangled.

Why this exists: httpx (like most HTTP clients) normalizes the URL path --
collapsing '..', merging '//', re-encoding, and outright rejecting some mangled
paths. That silently defeats path-based 403 bypasses: you either get a crash or,
worse, a misleading result (e.g. '/./admin/./' quietly rewritten to '/admin/').

This engine talks raw HTTP/1.1 over a socket, so '/admin/..;/', '/%2fadmin',
'/./admin/./' go out on the wire EXACTLY as written. It is a drop-in replacement
for core.engine.Engine: same constructor, same send()/send_many() interface,
returning the same Response objects.
"""
from __future__ import annotations

import asyncio
import ssl
import time
from urllib.parse import urlsplit

from .models import Request, Response, Probe


def _build_raw_request(req: Request, host_header: str) -> bytes:
    lines = [f"{req.method} {req.raw_path} HTTP/1.1", f"Host: {host_header}"]
    for k, v in req.headers.items():
        if k.lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    body = req.body or b""
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Accept: */*")
    lines.append("Connection: close")            # close-delimited: trivial to read
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body


def _dechunk(data: bytes) -> bytes:
    out, i = b"", 0
    while i < len(data):
        j = data.find(b"\r\n", i)
        if j == -1:
            break
        try:
            size = int(data[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        start = j + 2
        out += data[start:start + size]
        i = start + size + 2
    return out


class RawEngine:
    def __init__(
        self,
        *,
        concurrency: int = 20,
        timeout: float = 8.0,
        delay_ms: int = 0,
        max_retries: int = 2,
        follow_redirects: bool = False,   # accepted for interface parity (we never follow)
        verify_tls: bool = False,
    ) -> None:
        self.timeout = timeout
        self.delay = delay_ms / 1000
        self.max_retries = max_retries
        self._sem = asyncio.Semaphore(concurrency)
        self._not_limited = asyncio.Event()
        self._not_limited.set()
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._ssl_ctx = ctx

    async def __aenter__(self) -> "RawEngine":
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def send(self, req: Request) -> Response:
        async with self._sem:
            await self._not_limited.wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            return await self._send_with_retry(req)

    async def _send_with_retry(self, req: Request) -> Response:
        parts = urlsplit(req.url)
        host = parts.hostname or ""
        use_tls = parts.scheme == "https"
        default_port = 443 if use_tls else 80
        port = parts.port or default_port
        host_header = host if port == default_port else f"{host}:{port}"
        raw = _build_raw_request(req, host_header)

        backoff = 0.5
        for attempt in range(self.max_retries + 1):
            writer = None
            try:
                started = time.perf_counter()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port,
                                            ssl=self._ssl_ctx if use_tls else None),
                    timeout=self.timeout,
                )
                writer.write(raw)
                await writer.drain()
                resp = await asyncio.wait_for(self._read_response(reader),
                                              timeout=self.timeout)
                resp.elapsed_ms = (time.perf_counter() - started) * 1000
                resp.final_url = req.full_url
                if resp.status == 429:
                    await self._cooldown()
                    continue
                return resp
            except (asyncio.TimeoutError, OSError, ssl.SSLError) as e:
                if attempt >= self.max_retries:
                    return Response(error=f"{type(e).__name__}: {e}")
                await asyncio.sleep(backoff)
                backoff *= 2
            except Exception as e:
                return Response(error=f"{type(e).__name__}: {e}")
            finally:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception:
                        pass
        return Response(error="exhausted retries")

    async def _read_response(self, reader: asyncio.StreamReader) -> Response:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await reader.read(65536)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        header_lines = head.split(b"\r\n")

        status = 0
        if header_lines:
            sl = header_lines[0].decode("latin-1", "replace").split(" ", 2)
            if len(sl) >= 2 and sl[1].isdigit():
                status = int(sl[1])

        headers: dict[str, str] = {}
        for line in header_lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.decode("latin-1", "replace").strip().lower()] = \
                    v.decode("latin-1", "replace").strip()

        body = rest
        te = headers.get("transfer-encoding", "").lower()
        cl = headers.get("content-length")
        if "chunked" in te:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                body += chunk
            body = _dechunk(body)
        elif cl is not None and cl.isdigit():
            need = int(cl)
            while len(body) < need:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                body += chunk
            body = body[:need]
        else:
            while True:                          # Connection: close -> read to EOF
                chunk = await reader.read(65536)
                if not chunk:
                    break
                body += chunk

        return Response(status=status, headers=headers, body=body)

    async def _cooldown(self) -> None:
        if self._not_limited.is_set():
            self._not_limited.clear()
            await asyncio.sleep(2.0)
            self._not_limited.set()

    async def send_many(self, probes: list[Probe]) -> list[tuple[Probe, Response]]:
        async def one(p: Probe) -> tuple[Probe, Response]:
            return p, await self.send(p.request)
        return await asyncio.gather(*(one(p) for p in probes))
