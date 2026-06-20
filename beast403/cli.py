"""Beast403 command-line interface -- the full pipeline with options.

    python -m beast403.cli https://target.com /admin
    python -m beast403.cli https://target.com /admin -o markdown --out-file poc.md
    python -m beast403.cli https://target.com /admin --auth-header "Cookie: session=..."
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from .core.engine import Engine
from .core.raw_engine import RawEngine
from .core.models import Request, Finding, Verdict
from .recon.fingerprint import fingerprint
from .oracle.calibrator import calibrate
from .techniques.registry import select
from .analysis.features import extract_features
from .analysis.verifier import verify
from .report.json_out import to_json
from .report.poc import to_markdown


def _parse_headers(items) -> dict[str, str]:
    headers: dict[str, str] = {}
    for it in items or []:
        if ":" not in it:
            raise SystemExit(f"bad --auth-header (need 'Name: Value'): {it}")
        k, v = it.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


async def run(args) -> list[Finding]:
    target = Request(url=args.url, raw_path=args.path)
    auth = _parse_headers(args.auth_header)

    engine_cls = RawEngine if args.engine == "raw" else Engine
    async with engine_cls(concurrency=args.concurrency, delay_ms=args.delay_ms,
                          timeout=args.timeout) as eng:
        print("[*] fingerprinting ...", file=sys.stderr)
        profile = await fingerprint(eng, target)
        print(f"    server={profile.server!r}  waf={profile.waf}  tech={profile.tech}",
              file=sys.stderr)

        print("[*] calibrating oracles ...", file=sys.stderr)
        oracles = await calibrate(eng, target, public_path=args.public_path,
                                  authed_headers=auth or None)
        print(f"    baseline={oracles.blocked.status}  public={oracles.public.status}  "
              f"SPA={oracles.is_spa}", file=sys.stderr)

        probes = select(target, profile)
        print(f"[*] firing {len(probes)} probes ...", file=sys.stderr)
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


def render(findings: list[Finding], args) -> str:
    if args.output == "json":
        return to_json(findings, only_bypass=not args.all, min_conf=args.min_confidence)
    if args.output == "markdown":
        return to_markdown(args.url, args.path, findings, min_conf=args.min_confidence)

    shown = sorted(
        (f for f in findings
         if (args.all or f.verdict == Verdict.BYPASS) and f.confidence >= args.min_confidence),
        key=lambda f: f.confidence, reverse=True,
    )
    n_bypass = sum(1 for f in findings if f.verdict == Verdict.BYPASS)
    out = [f"\n[+] {n_bypass} bypass(es) of {len(findings)} probes\n"]
    for f in shown:
        out.append(f"  {f.confidence:4.0%} [{f.verdict.value:12}] [{f.probe.technique}] {f.probe.label}")
        out.append(f"        {', '.join(f.reasons)}")
        out.append(f"        {f.curl()}")
    return "\n".join(out) if shown else "  (nothing to show)"


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="beast403",
                                description="Accuracy-first 403 bypass scanner.")
    p.add_argument("url", help="base URL, e.g. https://target.com")
    p.add_argument("path", help="blocked path, e.g. /admin")
    p.add_argument("-c", "--concurrency", type=int, default=15)
    p.add_argument("--delay-ms", type=int, default=0, help="delay between requests")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--public-path", default="/", help="known-public path for the O3 oracle")
    p.add_argument("--auth-header", action="append",
                   help="'Name: Value' for the optional O4 oracle (repeatable)")
    p.add_argument("--engine", choices=["raw", "httpx"], default="raw",
                   help="raw = exact-byte socket sender (preserves mangled paths); "
                        "httpx = normalizing HTTP client")
    p.add_argument("-o", "--output", choices=["console", "json", "markdown"], default="console")
    p.add_argument("--out-file", help="write the report to a file instead of stdout")
    p.add_argument("--all", action="store_true", help="show all verdicts, not just bypasses")
    p.add_argument("--min-confidence", type=float, default=0.0)
    args = p.parse_args(argv)

    findings = asyncio.run(run(args))
    out = render(findings, args)
    if args.out_file:
        with open(args.out_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[*] wrote {args.out_file}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
