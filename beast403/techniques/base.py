"""Technique plugin interface.

CRITICAL DESIGN RULE: a technique NEVER decides whether a bypass succeeded.
It only generates candidate requests (Probes). All judgment lives in
analysis/verifier.py, against the OracleSet. This separation -- signal
generation decoupled from judgment -- is the architectural reason Beast403
can kill false positives that status/length-based tools cannot.

To add a technique: implement this Protocol and register it in registry.py.
`applies_to` is the fingerprint gate -- return False to skip a technique on a
stack where it cannot work (e.g. '..;/' only matters on Tomcat/Java).
"""
from __future__ import annotations

from typing import Iterator, Protocol

from ..core.models import Request, Probe, TargetProfile


class Technique(Protocol):
    name: str

    def applies_to(self, profile: TargetProfile) -> bool:
        ...

    def generate(self, target: Request, profile: TargetProfile) -> Iterator[Probe]:
        ...
