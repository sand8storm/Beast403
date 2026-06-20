"""Full pipeline: calibrate oracles -> fire techniques -> verify -> report.

This is Beast403 doing its actual job end to end:

    python -m beast403.scan https://localhost:8443 /admin

Unlike run.py (which dumps every raw 200), scan.py reports ONLY the responses
the verifier judged as real bypasses, sorted by confidence, each with its
reasons and a ready-to-paste curl PoC.
"""
from __future__ import annotations

import asyncio
import sys

from .core.engine import Engine
from .core.models import Request, TargetProfile, Finding, Verdict
from .techniques.registry import select
from .oracle.calibrator import calibrate
from .analysis.features import extract_features
from .analysis.verifier import verify


async def scan(base: str, path: str) -> list[Finding]:
    target = Request(url=base, raw_path=path)
    async with Engine(concurrency=15) as eng:
        print("[*] calibrating oracles ...")
        oracles = await calibrate(eng, target)
        print(f"    baseline={oracles.blocked.status}  "
              f"public={oracles.public.status}  "
              f"not_found={[f.status for f in oracles.not_found]}  "
              f"SPA={oracles.is_spa}")

        probes = select(target, TargetProfile(base_url=base))
        print(f"[*] firing {len(probes)} probes ...")
        results = await eng.send_many(probes)

        findings: list[Finding] = []
        for probe, r in results:
            if r.error:
                continue
            feat = extract_features(r)
            verdict, conf, reasons = verify(feat, oracles)
            findings.append(Finding(probe=probe, response=r, features=feat,
                                    verdict=verdict, confidence=conf, reasons=reasons))
    return findings


def report(findings: list[Finding]) -> None:
    bypasses = sorted(
        (f for f in findings if f.verdict == Verdict.BYPASS),
        key=lambda f: f.confidence, reverse=True,
    )
    raw_200s = sum(1 for f in findings if 200 <= f.features.status < 300)
    print(f"\n[+] {len(bypasses)} likely bypass(es) "
          f"(filtered from {raw_200s} raw 2xx responses across {len(findings)} probes)\n")
    for f in bypasses:
        print(f"  conf {f.confidence:.0%}  [{f.probe.technique}] {f.probe.label}")
        print(f"        status {f.features.status}  {f.features.length}b  |  {', '.join(f.reasons)}")
        print(f"        {f.curl()}\n")
    if not bypasses:
        print("  none -- the verifier classified every 2xx as a false positive.\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python -m beast403.scan <base_url> <path>")
        sys.exit(1)
    report(asyncio.run(scan(sys.argv[1], sys.argv[2])))
