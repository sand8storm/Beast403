"""Common-file techniques.

Idea: the access control is applied to a directory or an endpoint, but a
concrete file living under it may be served without the same check. We append
common default/index filenames to the protected path and let the verifier judge
whether any of them slips past the guard. As always, this only *generates*
candidate requests -- it never decides success.
"""
from __future__ import annotations

from typing import Iterator

from ..core.models import Request, Probe, TargetProfile

_COMMON_FILES = [
    "index.html", "index.php", "index.asp", "default.asp", "default.html",
    "home.html", "main.html", "index.jsp", "index.cfm",
]


class CommonFileTechnique:
    name = "common_files"

    def applies_to(self, profile: TargetProfile) -> bool:
        return True

    def generate(self, target: Request, profile: TargetProfile) -> Iterator[Probe]:
        seg = target.raw_path
        base = seg if seg.endswith("/") else f"{seg}/"
        for filename in _COMMON_FILES:
            new_path = f"{base}{filename}"
            yield Probe(
                technique=self.name,
                label=f"common file {filename} -> {new_path}",
                request=Request(
                    method=target.method,
                    url=target.url,
                    raw_path=new_path,
                    headers=dict(target.headers),
                    http_version=target.http_version,
                ),
            )
