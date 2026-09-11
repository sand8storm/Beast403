"""The verifier: the five-question judgment ladder.

Given the features of a candidate response and the OracleSet, decide whether it
is a real bypass -- and, crucially, WHY. Every rejection and every confidence
contribution is recorded in `reasons`, so each finding is self-explaining and
doubles as a PoC justification.

This is the only place in the whole tool that judges success. Techniques only
generate candidates; the verdict lives here, against live per-target oracles.
"""
from __future__ import annotations

from ..core.models import ResponseFeatures, OracleSet, Verdict
from .similarity import similarity

# Structural-similarity threshold to call two pages "the same room".
SAME = 0.90
# Minimum confidence to call something a real bypass.
BYPASS_THRESHOLD = 0.50


def verify(feat: ResponseFeatures, oracles: OracleSet) -> tuple[Verdict, float, list[str]]:
    def s(other: ResponseFeatures) -> float:
        return similarity(feat.struct_hash, other.struct_hash)

    base_sim = s(oracles.blocked)
    nf_sim = max((s(nf) for nf in oracles.not_found), default=0.0)
    pub_sim = s(oracles.public)
    max_ref_sim = max(base_sim, nf_sim, pub_sim)

    # --- the ladder: each rung removes a class of false positive ---

    # 1. looks like the original block page (even if status flipped to 200)
    if base_sim >= SAME:
        return Verdict.BLOCKED, 0.05, [f"matches baseline block page ({base_sim:.0%})"]

    # 2. site is a SPA / catch-all: any path-based 200 is meaningless
    if oracles.is_spa and 200 <= feat.status < 300:
        return Verdict.NOT_FOUND, 0.05, ["site is SPA/catch-all; path-based 200 ignored"]

    # 3. looks like a 'not found' sample
    if nf_sim >= SAME:
        return Verdict.NOT_FOUND, 0.05, [f"matches a not-found sample ({nf_sim:.0%})"]

    # 4. looks like the public/home page -> redirect-home or generic content
    if pub_sim >= SAME:
        return Verdict.NOT_FOUND, 0.10, [f"matches public page ({pub_sim:.0%}); likely redirect/home"]

    # --- candidate bypass: transparent, additive confidence ---
    # It already survived the rejection rungs: not the block page, not a
    # not-found, not the public page. That survival is itself a strong signal,
    # so a 2xx here is weighted heavily. Denial markers are no longer a veto --
    # they are a gated weight applied below (penalized only when the page ALSO
    # structurally resembles a block). We reward DISTANCE from
    # the block and not-found oracles (a real bypass must be unlike both) and do
    # NOT over-penalize partial resemblance to the public page, because a genuine
    # protected page often reuses the site's chrome (nav/footer).
    reasons: list[str] = []
    confidence = 0.0

    d_block = 1.0 - base_sim
    d_nf = 1.0 - nf_sim

    if 200 <= feat.status < 300:
        confidence += 0.45
        reasons.append(f"success status {feat.status} after surviving all reject rules")
    elif 300 <= feat.status < 400:
        reasons.append(f"redirect status {feat.status} (not following)")

    confidence += 0.25 * d_block + 0.15 * d_nf
    reasons.append(f"distinct from block ({d_block:.0%}) and not-found ({d_nf:.0%})")

    # Denial markers matter ONLY when the page also structurally resembles a
    # block. Words + high block-similarity = real soft block (penalize).
    # Words + low block-similarity = a legit page that merely mentions access
    # control in its copy -> structure says it's a different room; don't punish.
    # NOTE: 0.70 is a provisional gate set from only two data points
    # (/local 0.61 vs /admin/-decoy 0.75). It MUST be calibrated on a larger
    # labeled set before being trusted. Tracked as future work, not settled.
    if feat.has_denial_markers and base_sim >= 0.70:
        confidence -= 0.20
        reasons.append(f"denial markers + block-similar ({base_sim:.0%}); likely soft block")

    if 0.80 <= pub_sim < SAME:
        confidence -= 0.10
        reasons.append(f"partially resembles public page ({pub_sim:.0%}); verify manually")

    if oracles.authed is not None:
        authed_sim = s(oracles.authed)
        if authed_sim >= SAME:
            confidence += 0.25
            reasons.append(f"matches authorized-success page ({authed_sim:.0%})")

    if feat.length < 64:
        confidence -= 0.20
        reasons.append("very small body (possibly empty)")

    confidence = max(0.0, min(1.0, confidence))
    verdict = Verdict.BYPASS if confidence >= BYPASS_THRESHOLD else Verdict.INCONCLUSIVE
    return verdict, confidence, reasons
