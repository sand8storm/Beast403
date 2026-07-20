"""Structural similarity via SimHash.

A SimHash maps a bag of tokens to a fixed-width fingerprint such that *similar*
token sets produce *close* fingerprints (small Hamming distance). We feed it the
structural skeleton of a page (see features.py), so two pages built from the
same template hash close together even if their text differs -- which is exactly
what we need to tell "same room" from "different room".

We use blake2b (not Python's built-in hash, which is randomized per process and
would make results non-reproducible across runs).
"""
from __future__ import annotations

import hashlib

_BITS = 64
_MASK = (1 << _BITS) - 1


def _token_hash(token: str) -> int:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") & _MASK


def simhash(tokens: list[str]) -> int:
    """64-bit SimHash of a token list. Empty -> 0."""
    if not tokens:
        return 0
    acc = [0] * _BITS
    for tok in tokens:
        h = _token_hash(tok)
        for i in range(_BITS):
            acc[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(_BITS):
        if acc[i] > 0:
            out |= (1 << i)
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def similarity(a: int, b: int) -> float:
    """0.0 (totally different) .. 1.0 (identical structure)."""
    return 1.0 - hamming(a, b) / _BITS
