"""Async HTTP engine for Beast403.

Responsibilities:
  - fire requests concurrently with a bounded semaphore
  - retry transient errors with exponential backoff
  - respect a rate-limit delay and pause globally on HTTP 429
  - preserve raw paths as much as the transport allows

RAW-PATH WARNING (read this): HTTP clients tend to normalize URLs -- collapsing
'..', merging '//', re-encoding characters. That normalization would silently
defeat path-based 403 bypasses, and you would never know why your tool "finds
nothing". httpx preserves most raw paths, but you MUST verify against your lab:
send '/admin/..;/' and confirm via the lab's access log that the bytes on the
wire are unchanged. If httpx normalizes, swap THIS file for a raw h11/socket
sender -- the rest of the pipeline does not change, because everything else
only talks to Request/Response.
"""
from __future__ import annotations

import asyncio
import time

import httpx

from .models import Request, Response, Probe


class Engine:
    def __init__(
        self,
        *,
        concurrency: int = 20,
        timeout: float = 8.0,
        delay_ms: int = 0,
        max_retries: int = 2,
        follow_redirects: bool = False,   # default OFF: a redirect to /login is signal, not success
        verify_tls: bool = False,         # labs use self-signed certs
    ) -> None:
        self.delay = delay_ms / 1000
        self.max_retries = max_retries
        self._sem = asyncio.Semaphore(concurrency)
        self._not_limited = asyncio.Event()
        self._not_limited.set()           # set == we are NOT rate-limited
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify_tls,
            follow_redirects=follow_redirects,
        )

    async def __aenter__(self) -> "Engine":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def send(self, req: Request) -> Response:
        async with self._sem:
            await self._not_limited.wait()       # block all workers while cooling down
            if self.delay:
                await asyncio.sleep(self.delay)
            return await self._send_with_retry(req)

    async def _send_with_retry(self, req: Request) -> Response:
        backoff = 0.5
        for attempt in range(self.max_retries + 1):
            try:
                started = time.perf_counter()
                r = await self._client.request(
                    req.method,
                    req.full_url,
                    headers=req.headers,
                    content=req.body,
                )
                elapsed = (time.perf_counter() - started) * 1000
                if r.status_code == 429:
                    await self._cooldown()
                    continue
                return Response(
                    status=r.status_code,
                    headers=dict(r.headers),
                    body=r.content,
                    elapsed_ms=elapsed,
                    final_url=str(r.url),
                )
            except (httpx.TimeoutException, httpx.TransportError) as e:
                if attempt >= self.max_retries:
                    return Response(error=f"{type(e).__name__}: {e}")
                await asyncio.sleep(backoff)
                backoff *= 2
            except Exception as e:
                # non-transient (e.g. httpx.InvalidURL on a deliberately mangled
                # raw path that the client refuses to send). Retrying won't help,
                # and one bad probe must never abort the whole scan.
                return Response(error=f"{type(e).__name__}: {e}")
        return Response(error="exhausted retries")

    async def _cooldown(self) -> None:
        """Crude global pause on 429. Refine later by parsing Retry-After."""
        if self._not_limited.is_set():
            self._not_limited.clear()
            await asyncio.sleep(2.0)
            self._not_limited.set()

    async def send_many(self, probes: list[Probe]) -> list[tuple[Probe, Response]]:
        async def one(p: Probe) -> tuple[Probe, Response]:
            return p, await self.send(p.request)
        return await asyncio.gather(*(one(p) for p in probes))
