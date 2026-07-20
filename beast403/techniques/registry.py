"""Technique registry + fingerprint-driven selection.

`select()` returns only the probes from techniques whose `applies_to()` passes
for this target profile. This is where "which tricks to try" lives -- fully
decoupled from "did it work" (the verifier). Add a technique to ALL_TECHNIQUES
and it is picked up automatically.
"""
from __future__ import annotations

from ..core.models import Request, Probe, TargetProfile
from .paths import PathTechnique
from .headers import HeaderTechnique
from .methods import MethodTechnique
from .encoding import EncodingTechnique
from .params import ParamTechnique

ALL_TECHNIQUES = [
    PathTechnique(),
    HeaderTechnique(),
    MethodTechnique(),
    EncodingTechnique(),
]


def select(target: Request, profile: TargetProfile, *, params: bool = False) -> list[Probe]:
    # ParamTechnique is opt-in: added only when -p is set, never in ALL_TECHNIQUES.
    techniques = list(ALL_TECHNIQUES)
    if params:
        techniques.append(ParamTechnique(enabled=True))
    probes: list[Probe] = []
    for tech in techniques:
        if tech.applies_to(profile):
            probes.extend(tech.generate(target, profile))
    return probes
