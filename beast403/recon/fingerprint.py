"""Recon: fingerprint the target's stack to guide technique selection.

This does NOT judge success -- that is the verifier's job, via live oracles.
It only answers "which tricks are worth trying", e.g. fire the Tomcat '..;/'
path trick only when the stack looks like Java/Tomcat. Less noise, fewer
requests, cleaner results.
"""
from __future__ import annotations

from ..core.engine import Engine
from ..core.models import Request, TargetProfile

# substrings checked against the lowercased header blob -> (sign, label)
_WAF_SIGNS = [
    ("cf-ray", "cloudflare"), ("cloudflare", "cloudflare"),
    ("akamai", "akamai"), ("x-akamai", "akamai"),
    ("awselb", "aws-alb"), ("aws-alb", "aws-alb"),
    ("x-sucuri", "sucuri"), ("incap_ses", "imperva"), ("incapsula", "imperva"),
    ("barracuda", "barracuda"), ("mod_security", "modsecurity"),
    ("modsecurity", "modsecurity"),
]
_TECH_SIGNS = [
    ("microsoft-iis", "iis"), ("asp.net", "iis"),
    ("apache-coyote", "tomcat"), ("servlet", "tomcat"), ("tomcat", "tomcat"),
    ("jetty", "java"),
    ("nginx", "nginx"), ("apache", "apache"),
    ("php", "php"), ("express", "node"),
]


async def fingerprint(engine: Engine, target: Request) -> TargetProfile:
    r = await engine.send(
        Request(url=target.url, raw_path="/", http_version=target.http_version)
    )
    blob = " ".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
    server = r.headers.get("server", "") or r.headers.get("Server", "")

    waf = next((label for sign, label in _WAF_SIGNS if sign in blob), None)

    tech: list[str] = []
    for sign, label in _TECH_SIGNS:
        if sign in blob and label not in tech:
            tech.append(label)

    return TargetProfile(base_url=target.url, server=server, waf=waf, tech=tech)
