"""Query-parameter techniques (opt-in via -p/--params).

Root cause: access rules and backends often disagree on how the query string is
parsed -- which copy of a repeated key wins, whether an extra control parameter
is honored, how a bracketed key binds. None of that is path-based, so it lives
here, gated behind an explicit flag: a parameterized URL is required, and
without -p no probes are produced at all.

Like every technique, this NEVER judges success. It only reshapes the query
into candidate Probes; the existing verifier decides what bypassed.

raw_path stays sacred: we split it on the FIRST '?' only to reach the query, and
rebuild the path byte-for-byte from literal segments -- no decoding, no
re-encoding, no path normalization.
"""
from __future__ import annotations

from typing import Iterator

from ..core.models import Request, Probe, TargetProfile

# control params some backends honor once a request leaks past the access check
_INJECT = ["admin=true", "debug=1", "role=admin", "internal=true"]
# a distinct, traceable value for the second copy in parameter pollution
_POLLUTE_ALT = "beast403"


def _split_query(raw_path: str) -> tuple[str, str]:
    """Path, query -- split on the FIRST '?' only. Path is left untouched."""
    path, _, query = raw_path.partition("?")
    return path, query


def _parse_pairs(query: str) -> list[tuple[str, str, bool]]:
    """(key, value, has_eq) per segment, order + duplicates preserved.
    Segments stay as literal substrings -- never decoded."""
    pairs: list[tuple[str, str, bool]] = []
    for seg in query.split("&"):
        if not seg:
            continue
        if "=" in seg:
            k, _, v = seg.partition("=")
            pairs.append((k, v, True))
        else:
            pairs.append((seg, "", False))
    return pairs


def _seg(key: str, value: str, has_eq: bool = True) -> str:
    return f"{key}={value}" if has_eq else key


def _rebuild(path: str, segs: list[str]) -> str:
    q = "&".join(segs)
    return f"{path}?{q}" if q else path


class ParamTechnique:
    name = "params"

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    def applies_to(self, profile: TargetProfile) -> bool:
        # True only when the user opted in via -p/--params.
        return self.enabled

    def generate(self, target: Request, profile: TargetProfile) -> Iterator[Probe]:
        if not self.enabled:
            return
        path, query = _split_query(target.raw_path)
        pairs = _parse_pairs(query)
        if not pairs:
            raise SystemExit(
                "error: -p requires at least one parameter in the URL "
                "(e.g. /path?key=value)"
            )

        base = [_seg(*p) for p in pairs]

        for i, (k, v, has_eq) in enumerate(pairs):
            orig = _seg(k, v, has_eq)

            # (a) parameter pollution: same key twice, both orderings
            alt = _seg(k, _POLLUTE_ALT)
            yield self._probe(target, path, self._replace(base, i, [orig, alt]),
                              f"pollution {k}: original then {_POLLUTE_ALT}")
            yield self._probe(target, path, self._replace(base, i, [alt, orig]),
                              f"pollution {k}: {_POLLUTE_ALT} then original")

            # (c) key-shape change: key[]=val
            yield self._probe(target, path,
                              self._replace(base, i, [_seg(k + "[]", v, has_eq)]),
                              f"array key {k}[]")

            # (d) value tampering: empty value, and drop the parameter
            yield self._probe(target, path, self._replace(base, i, [_seg(k, "")]),
                              f"empty value {k}=")
            yield self._probe(target, path, self._replace(base, i, []),
                              f"drop parameter {k}")

            # (e) key case: KEY=val
            ku = k.upper()
            if ku != k:
                yield self._probe(target, path,
                                  self._replace(base, i, [_seg(ku, v, has_eq)]),
                                  f"upper key {ku}")

        # (b) control-parameter injection: independent of any single param, so
        # emitted ONCE per URL (not per-param) to avoid structurally-identical
        # duplicate probes -- consistent with the project's anti-inflation goal.
        for inj in _INJECT:
            yield self._probe(target, path, base + [inj], f"inject &{inj}")

    @staticmethod
    def _replace(base: list[str], i: int, repl: list[str]) -> list[str]:
        """`base` with segment i swapped for `repl` (0, 1, or 2 segments)."""
        return base[:i] + repl + base[i + 1:]

    def _probe(self, target: Request, path: str, segs: list[str], label: str) -> Probe:
        return Probe(
            technique=self.name,
            label=label,
            request=Request(
                method=target.method,
                url=target.url,
                raw_path=_rebuild(path, segs),
                headers=dict(target.headers),
                http_version=target.http_version,
            ),
        )
