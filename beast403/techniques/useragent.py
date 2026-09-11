"""User-Agent techniques.

Idea: some access rules whitelist specific clients -- search-engine crawlers,
internal tooling, scripting libraries -- assuming only trusted traffic sets
those User-Agents. We keep the original method and path and only swap the
User-Agent header, then let the verifier judge the response.
"""
from __future__ import annotations

from typing import Iterator

from ..core.models import Request, Probe, TargetProfile

_USER_AGENTS = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.1.0",
    "Mozilla/5.0 (compatible; bingbot/2.0)",
    "python-requests/2.31.0",
    "Wget/1.21",
    "Go-http-client/1.1",
    "axios/1.4.0",
    "libwww-perl/6.72",
]


class UserAgentTechnique:
    name = "useragent"

    def applies_to(self, profile: TargetProfile) -> bool:
        return True

    def generate(self, target: Request, profile: TargetProfile) -> Iterator[Probe]:
        for ua in _USER_AGENTS:
            yield Probe(
                technique=self.name,
                label=f"User-Agent: {ua}",
                request=Request(
                    method=target.method,
                    url=target.url,
                    raw_path=target.raw_path,
                    headers={**target.headers, "User-Agent": ua},
                    http_version=target.http_version,
                ),
            )
