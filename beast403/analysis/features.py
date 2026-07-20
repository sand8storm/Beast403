"""Feature extraction: Response -> ResponseFeatures.

We deliberately never reason about raw status/length alone. The key feature is
`struct_hash`: a SimHash of the page's STRUCTURE (tag skeleton), not its bytes.
Dynamic noise (text, dates, tokens) is dropped, so the same template always
hashes the same way.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

from ..core.models import Response, ResponseFeatures
from .similarity import simhash

# Denial markers in visible text -> strong "this is a block/login" signal.
# Multilingual on purpose (Arabic + English); extend freely.
_DENIAL_MARKERS = [
    "forbidden", "access denied", "not authorized", "unauthorized",
    "permission denied", "you don't have permission", "sign in", "log in",
    "login", "please authenticate", "authentication required", "captcha",
    "ممنوع", "غير مصرح", "غير مصرّح", "تسجيل الدخول", "ليس لديك صلاحية",
    "الدخول مرفوض", "وصول مرفوض",
]


class _Skeleton(HTMLParser):
    """Collects the tag sequence, visible text, and <title> -- ignoring the
    contents of <script>/<style> so JS noise never leaks into our signals."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.text: list[str] = []
        self.title = ""
        self._in_title = False
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag in ("script", "style"):
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._skip_depth:
            return
        chunk = data.strip()
        if not chunk:
            return
        if self._in_title:
            self.title += chunk
        self.text.append(chunk)


def _parse_html(body_text: str) -> tuple[list[str], str, str]:
    parser = _Skeleton()
    try:
        parser.feed(body_text)
    except Exception:
        pass
    return parser.tags, " ".join(parser.text), parser.title


def _structural_tokens(tags: list[str], body_text: str) -> list[str]:
    """Reduce a page to structure tokens.
    HTML -> shingles of consecutive tags (captures layout shape).
    Non-HTML (JSON/text) -> word shingles with digits normalized to '#'."""
    if tags:
        if len(tags) < 2:
            return tags
        return [f"{tags[i]}>{tags[i + 1]}" for i in range(len(tags) - 1)]
    norm = re.sub(r"\d", "#", body_text.lower())
    words = norm.split()
    if len(words) < 2:
        return words
    return [f"{words[i]} {words[i + 1]}" for i in range(len(words) - 1)]


def extract_features(resp: Response) -> ResponseFeatures:
    body_text = resp.body.decode("utf-8", "ignore")
    tags, text, title = _parse_html(body_text)
    tokens = _structural_tokens(tags, body_text)
    struct = simhash(tokens)

    haystack = (text + " " + title).lower()
    denial = any(marker in haystack for marker in _DENIAL_MARKERS)

    ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()

    return ResponseFeatures(
        status=resp.status,
        length=resp.length,
        struct_hash=struct,
        has_denial_markers=denial,
        content_type=ctype,
        title=title[:120],
        elapsed_ms=resp.elapsed_ms,
    )
