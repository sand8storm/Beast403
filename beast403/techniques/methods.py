"""HTTP method techniques.

Root cause: the access rule is written for one verb (often GET) but the backend
also serves others. We switch verbs, vary their case, or use method-override
headers.

Verifier note (for later): HEAD/OPTIONS responses may have no body, so a
body-less 200 must not be auto-scored as a real bypass -- judge it against the
oracles like everything else, but expect length-based signals to be weak here.
"""
from __future__ import annotations

from typing import Iterator

from ..core.models import Request, Probe, TargetProfile

_METHODS = ["POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
_CASE_VARIANTS = ["get", "Get", "gEt"]          # case-sensitive rule vs tolerant parser
_OVERRIDE_HEADERS = ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"]


class MethodTechnique:
    name = "methods"

    def applies_to(self, profile: TargetProfile) -> bool:
        return True

    def generate(self, target: Request, profile: TargetProfile) -> Iterator[Probe]:
        for m in _METHODS:
            yield self._probe(target, m, dict(target.headers), f"method {m}")
        for m in _CASE_VARIANTS:
            yield self._probe(target, m, dict(target.headers), f"method case '{m}'")
        for h in _OVERRIDE_HEADERS:
            yield self._probe(
                target, "POST", {**target.headers, h: "GET"}, f"{h}: GET"
            )

    def _probe(self, target, method, headers, label) -> Probe:
        return Probe(
            technique=self.name,
            label=label,
            request=Request(
                method=method,
                url=target.url,
                raw_path=target.raw_path,
                headers=headers,
                http_version=target.http_version,
            ),
        )
