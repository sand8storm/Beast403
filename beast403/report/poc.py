"""Markdown PoC report -- ready to paste into a bug-bounty submission."""
from __future__ import annotations

from datetime import datetime, timezone

from ..core.models import Finding, Verdict


def to_markdown(base: str, path: str, findings: list[Finding], *, min_conf: float = 0.0) -> str:
    bypasses = sorted(
        (f for f in findings if f.verdict == Verdict.BYPASS and f.confidence >= min_conf),
        key=lambda f: f.confidence, reverse=True,
    )
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"# Beast403 report — `{base}{path}`",
        "",
        f"- generated: {now}",
        f"- probes fired: {len(findings)}",
        f"- confirmed bypasses: {len(bypasses)}",
        "",
        "> Authorized testing only. Each finding is verified against live "
        "per-target oracles (block / not-found / public) to suppress false positives.",
        "",
    ]
    if not bypasses:
        lines.append("No candidate passed verification.")
        return "\n".join(lines)

    for i, f in enumerate(bypasses, 1):
        lines += [
            f"## {i}. {f.probe.technique}: {f.probe.label}",
            f"- **confidence:** {f.confidence:.0%}",
            f"- **status:** {f.features.status}  ·  **length:** {f.features.length} bytes",
            f"- **why accepted:** {', '.join(f.reasons)}",
            "",
            "```bash",
            f.curl(),
            "```",
            "",
        ]
    return "\n".join(lines)
