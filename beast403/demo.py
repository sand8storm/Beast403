"""Smoke test: proves the engine + models work and previews the ORACLE idea.

Run against your lab:
    python -m beast403.demo https://localhost:8443 /admin

It fires three reference requests and prints their features side by side:
    O1 blocked   -> the target path with no bypass
    O2 not-found -> a guaranteed-garbage path (random UUID)
    O3 public    -> the site root

This is the raw material the verifier will later classify. Already at this stage
you can SEE the core insight: if O2 (garbage) returns the same 200 + same length
as O3 (root), the target is a SPA/catch-all, and ANY path-based "200 bypass" you
find later is a false positive. That single comparison is worth more than 50
bypass payloads.
"""
from __future__ import annotations

import asyncio
import sys
import uuid

from .core.engine import Engine
from .core.models import Request


async def main(base: str, path: str) -> None:
    refs = {
        "O1 blocked  ": Request(url=base, raw_path=path),
        "O2 not-found": Request(url=base, raw_path="/" + uuid.uuid4().hex),
        "O3 public   ": Request(url=base, raw_path="/"),
    }
    async with Engine() as eng:
        results = {}
        for name, req in refs.items():
            r = await eng.send(req)
            results[name] = r
            if r.error:
                print(f"{name} -> ERROR {r.error}")
            else:
                print(f"{name} -> {r.status}  {r.length:>7} bytes  "
                      f"{r.elapsed_ms:6.1f} ms  {req.raw_path}")

        nf, pub = results["O2 not-found"], results["O3 public   "]
        if nf.error is None and pub.error is None:
            spa = nf.status == pub.status == 200 and abs(nf.length - pub.length) < 64
            print("\n[SPA / catch-all detected]" if spa
                  else "\n[OK] not-found and public differ -> path signals are trustworthy")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python -m beast403.demo <base_url> <path>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
