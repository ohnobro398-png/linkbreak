"""HTML inspection for LINKBREAK — meta refresh and canonical detection.

Uses :class:`html.parser.HTMLParser` from the standard library instead
of regular expressions, so attribute order, quote style (double, single,
or none), and tag casing do not matter. Downloaded pages are only
*parsed* — scripts are never executed.

Extracted signals
-----------------
* ``meta_refresh`` — ``(delay_seconds, target_url)`` from the first
  ``<meta http-equiv="refresh" content="N; url=...">`` tag that carries
  a URL. A delay of 0 means an instant redirect; longer delays are
  reported so the chain shows what the page asked for.
* ``canonical_url`` — the ``rel="canonical"`` link href, when present.
* ``og_url`` — the ``og:url`` meta property, used only as a fallback
  when no ``rel="canonical"`` exists.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

_URL_IN_REFRESH = re.compile(r"url\s*=\s*[\"']?([^\"'>\s;]+)", re.IGNORECASE)
_DELAY_IN_REFRESH = re.compile(r"^\s*(\d+)")


class _PageInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta_refresh: tuple[int, str] | None = None
        self.canonical_url: str | None = None
        self.og_url: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            http_equiv = attributes.get("http-equiv", "").strip().lower()
            if http_equiv == "refresh" and self.meta_refresh is None:
                content = attributes.get("content", "")
                url_match = _URL_IN_REFRESH.search(content)
                if url_match:
                    delay_match = _DELAY_IN_REFRESH.search(content)
                    delay = int(delay_match.group(1)) if delay_match else 0
                    target = url_match.group(1).strip().strip("\"'")
                    if target:
                        self.meta_refresh = (delay, target)
            prop = attributes.get("property", "").strip().lower()
            if prop == "og:url" and self.og_url is None:
                content = attributes.get("content", "").strip()
                if content:
                    self.og_url = content
        elif tag == "link":
            rel = attributes.get("rel", "").strip().lower()
            if "canonical" in rel.split() and self.canonical_url is None:
                href = attributes.get("href", "").strip()
                if href:
                    self.canonical_url = href


def inspect_html(html: str) -> dict:
    """Parse ``html`` and return its redirect/canonical signals.

    Returns ``{"meta_refresh": (delay, target) | None,
    "canonical_url": str | None, "canonical_source": str | None}`` where
    ``canonical_source`` is ``"rel=canonical"``, ``"og:url"``, or None.
    Parsing never raises for malformed HTML — on error the signals found
    so far are returned.
    """
    inspector = _PageInspector()
    try:
        inspector.feed(html)
    except Exception:
        pass
    try:
        inspector.close()
    except Exception:
        pass
    if inspector.canonical_url:
        canonical_url = inspector.canonical_url
        canonical_source = "rel=canonical"
    elif inspector.og_url:
        canonical_url = inspector.og_url
        canonical_source = "og:url"
    else:
        canonical_url = None
        canonical_source = None
    return {
        "meta_refresh": inspector.meta_refresh,
        "canonical_url": canonical_url,
        "canonical_source": canonical_source,
    }
