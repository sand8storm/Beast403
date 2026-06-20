"""Core data models for Beast403.

The whole tool is a pipeline. Each stage consumes the previous stage's
dataclass and produces the next one:

    URL -> TargetProfile -> OracleSet -> [Probe] -> [Response] -> [Features] -> [Finding]

Keeping these as plain dataclasses means every stage is independently testable
and the data flow is explicit. Nothing hides state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


@dataclass
class Request:
    """A request template. `raw_path` is the literal path string and MUST NOT
    be normalized by us -- the whole point of path-based bypasses is to send
    bytes like '/admin/..;/' untouched."""
    method: str = "GET"
    url: str = ""              # scheme + host only, e.g. https://target.com
    raw_path: str = "/"        # literal path, e.g. /admin/..;/
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    http_version: str = "1.1"

    @property
    def full_url(self) -> str:
        return self.url.rstrip("/") + self.raw_path


@dataclass
class Response:
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: float = 0.0
    final_url: str = ""        # after redirects (if followed)
    error: Optional[str] = None

    @property
    def length(self) -> int:
        return len(self.body)


@dataclass
class Probe:
    """A single mutated request produced by a technique."""
    technique: str             # e.g. "headers"
    label: str                 # human description, e.g. "X-Original-URL: /admin"
    request: Request


class Verdict(str, Enum):
    BLOCKED = "blocked"          # clusters with O1
    NOT_FOUND = "not_found"      # clusters with O2 (incl. SPA catch-all)
    BYPASS = "bypass"            # distinct, resembles success, no denial markers
    INCONCLUSIVE = "inconclusive"


@dataclass
class ResponseFeatures:
    """The vector the verifier reasons about -- never raw status/length alone."""
    status: int = 0
    length: int = 0
    struct_hash: int = 0         # SimHash of structure-normalized body
    has_denial_markers: bool = False   # "Forbidden", "Login", "captcha"...
    content_type: str = ""
    title: str = ""
    elapsed_ms: float = 0.0


@dataclass
class OracleSet:
    """The reference points, computed ONCE before any technique runs."""
    blocked: ResponseFeatures                  # O1: target path, no bypass
    not_found: list[ResponseFeatures]          # O2: random garbage paths
    public: ResponseFeatures                   # O3: known-public path
    authed: Optional[ResponseFeatures] = None  # O4: authorized request
    is_spa: bool = False                       # all garbage paths returned same 200
    baseline_len_mean: float = 0.0
    baseline_len_std: float = 0.0


@dataclass
class TargetProfile:
    base_url: str = ""
    server: str = ""                  # Server header
    waf: Optional[str] = None         # cloudflare / akamai / aws-alb / ...
    tech: list[str] = field(default_factory=list)   # tomcat, iis, nginx, php...
    http_versions: list[str] = field(default_factory=lambda: ["1.1"])


@dataclass
class Finding:
    probe: Probe
    response: Response
    features: ResponseFeatures
    verdict: Verdict = Verdict.INCONCLUSIVE
    confidence: float = 0.0           # 0..1, calibrated
    reasons: list[str] = field(default_factory=list)   # explainability

    def curl(self) -> str:
        """Reproducible PoC line for a bug-bounty report."""
        parts = [f"curl -sk -X {self.probe.request.method}"]
        for k, v in self.probe.request.headers.items():
            parts.append(f"-H '{k}: {v}'")
        parts.append(f"'{self.probe.request.full_url}'")
        return " ".join(parts)
