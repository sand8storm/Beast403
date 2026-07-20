"""Fire ALL techniques against a target and dump raw results.

This is PRE-verifier on purpose: it shows every probe with its status/length so
you can SEE the false-positive problem with your own eyes (lots of '!!' lines
that are not real bypasses) before we build the verifier that filters them.

    python -m beast403.run https://localhost:8443 /admin

Lines marked '!!' are anything that is not 403/404 -- i.e. what a naive tool
would wrongly report as a bypass. The verifier's whole job is to thin this list
down to the real ones.
"""
from __future__ import annotations

import asyncio
import sys

from .core.engine import Engine
from .core.models import Request, TargetProfile
from .techniques.registry import select


async def main(base: str, path: str) -> None:
    target = Request(url=base, raw_path=path)
    profile = TargetProfile(base_url=base)   # empty profile: every technique fires

    probes = select(target, profile)
    print(f"generated {len(probes)} probes against {base}{path}\n")

    async with Engine(concurrency=15) as eng:
        results = await eng.send_many(probes)

    # interesting (non-403/404) first
    results.sort(key=lambda pr: (pr[1].status in (403, 404), pr[1].status))
    for probe, r in results:
        if r.error:
            mark, info = "ERR", r.error
        else:
            mark = "!!" if r.status not in (403, 404) else "  "
            info = f"{r.status}  {r.length:>7}b  {r.elapsed_ms:6.1f}ms"
        print(f"{mark} [{probe.technique:8}] {info:30} {probe.label}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python -m beast403.run <base_url> <path>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1], sys.argv[2]))
