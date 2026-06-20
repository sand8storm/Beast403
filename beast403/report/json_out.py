"""JSON report output."""
from __future__ import annotations

import json

from ..core.models import Finding, Verdict


def findings_to_dicts(findings: list[Finding], *, only_bypass: bool = True,
                      min_conf: float = 0.0) -> list[dict]:
    out = []
    for f in findings:
        if only_bypass and f.verdict != Verdict.BYPASS:
            continue
        if f.confidence < min_conf:
            continue
        out.append({
            "technique": f.probe.technique,
            "label": f.probe.label,
            "method": f.probe.request.method,
            "url": f.probe.request.full_url,
            "headers": f.probe.request.headers,
            "status": f.features.status,
            "length": f.features.length,
            "content_type": f.features.content_type,
            "verdict": f.verdict.value,
            "confidence": round(f.confidence, 3),
            "reasons": f.reasons,
            "curl": f.curl(),
        })
    return out


def to_json(findings: list[Finding], **kwargs) -> str:
    return json.dumps(findings_to_dicts(findings, **kwargs), indent=2, ensure_ascii=False)
