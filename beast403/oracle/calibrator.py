"""The calibrator: builds the OracleSet before any technique runs.

It establishes the reference points the verifier compares against:
  - baseline : the target path as-is (whatever status -- usually 403)
  - not_found: a few random garbage paths (also powers SPA detection)
  - public   : a known-public path (home/root)
  - authed   : optional, only if credentials are supplied

This is the live, per-target "signature" -- far more robust than any static
database of server error pages.
"""
from __future__ import annotations

import uuid
from typing import Optional

from ..core.engine import Engine
from ..core.models import Request, ResponseFeatures, OracleSet
from ..analysis.features import extract_features
from ..analysis.similarity import similarity

_SPA_SIM = 0.95   # garbage paths this similar to each other AND to public => catch-all


async def calibrate(
    engine: Engine,
    target: Request,
    *,
    samples: int = 3,
    public_path: str = "/",
    authed_headers: Optional[dict[str, str]] = None,
) -> OracleSet:
    # baseline: the target itself
    base_f = extract_features(await engine.send(target))

    # not-found: random garbage paths
    nf_features: list[ResponseFeatures] = []
    for _ in range(samples):
        rnd = Request(url=target.url, raw_path="/" + uuid.uuid4().hex,
                      http_version=target.http_version)
        nf_features.append(extract_features(await engine.send(rnd)))

    # public/home
    pub_f = extract_features(
        await engine.send(Request(url=target.url, raw_path=public_path,
                                  http_version=target.http_version))
    )

    # authorized (optional)
    authed_f: Optional[ResponseFeatures] = None
    if authed_headers:
        authed_f = extract_features(
            await engine.send(Request(url=target.url, raw_path=target.raw_path,
                                      headers=authed_headers,
                                      http_version=target.http_version))
        )

    is_spa = _detect_spa(nf_features, pub_f)

    lengths = [f.length for f in nf_features]
    mean = sum(lengths) / len(lengths) if lengths else 0.0
    var = sum((x - mean) ** 2 for x in lengths) / len(lengths) if lengths else 0.0

    return OracleSet(
        blocked=base_f,
        not_found=nf_features,
        public=pub_f,
        authed=authed_f,
        is_spa=is_spa,
        baseline_len_mean=mean,
        baseline_len_std=var ** 0.5,
    )


def _detect_spa(nf_features: list[ResponseFeatures], pub_f: ResponseFeatures) -> bool:
    """Catch-all if every garbage path returns a 2xx that is structurally the
    same as the others AND as the public page."""
    if not nf_features:
        return False
    if not all(200 <= f.status < 300 for f in nf_features):
        return False
    h0 = nf_features[0].struct_hash
    same_among = all(similarity(h0, f.struct_hash) >= _SPA_SIM for f in nf_features)
    same_public = similarity(h0, pub_f.struct_hash) >= _SPA_SIM
    return same_among and same_public
