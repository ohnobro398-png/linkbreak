"""Scam-safety analysis for LINKBREAK results.

A short link hides its destination by design — that is the whole point
of a shortener, and also what makes short links a favourite vehicle for
scams. This module never *verdicts* a link (it is not a blocklist and
does not call any reputation service); it surfaces the facts a human
needs before clicking:

* the final domain, prominently;
* whether the final domain differs from the short link's domain;
* whether a *brand* shortlink (e.g. ``amzn.to``) lands somewhere other
  than that brand's real domain — the strongest mismatch signal;
* cheap structural warnings: bare-IP destination, unencrypted (http)
  destination, IDN/punycode domain (homograph risk), credentials in
  the URL (``user@host`` trick).

Everything here is computed from the two URLs alone — no external
lookups, no blocklists, no claims beyond what the URLs themselves show.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

# Brand shortlink host -> domains the brand legitimately lands on.
# A brand shortlink landing anywhere else is worth a loud warning.
BRAND_DOMAINS: dict[str, list[str]] = {
    "youtu.be": ["youtube.com", "youtu.be", "youtube-nocookie.com"],
    "amzn.to": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in",
                "amazon.ca", "amazon.com.au", "amazon.co.jp", "amazon.fr",
                "amazon.it", "amazon.es", "amazon.com.mx", "amazon.com.br"],
    "fb.me": ["facebook.com", "fb.com", "messenger.com"],
    "fb.gg": ["facebook.com", "fb.com"],
    "apple.co": ["apple.com"],
    "msft.it": ["microsoft.com"],
    "go.microsoft.com": ["microsoft.com"],
    "ibm.co": ["ibm.com"],
    "nyti.ms": ["nytimes.com"],
    "wapo.st": ["washingtonpost.com"],
    "bbc.in": ["bbc.com", "bbc.co.uk"],
    "econ.st": ["economist.com"],
    "spoti.fi": ["spotify.com", "open.spotify.com"],
    "t.co": ["twitter.com", "x.com"],
    "goo.gl": ["google.com", "youtube.com"],
}


def _base_domain(host: str) -> str:
    """Registrable-ish domain: last two labels (good enough for display)."""
    host = host.lower().rstrip(".")
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_safety(original_url: str, final_url: str | None) -> dict:
    """Return the safety facts for a resolution result."""
    original_host = (urlparse(original_url or "").hostname or "").lower()
    final_host = (urlparse(final_url or "").hostname or "").lower()
    final_scheme = (urlparse(final_url or "").scheme or "").lower()

    domain_changed = bool(original_host and final_host) and (
        _base_domain(original_host) != _base_domain(final_host)
    )

    # Brand mismatch: a brand shortlink landing off-brand.
    brand_mismatch = False
    brand_note = ""
    expected = BRAND_DOMAINS.get(original_host)
    if expected and final_host:
        final_base = _base_domain(final_host)
        if final_base not in [_base_domain(d) for d in expected]:
            brand_mismatch = True
            brand_note = (
                f"This looks like a {_base_domain(original_host)} short link, "
                f"but it lands on {final_host} — not the brand's real domain. "
                "Treat it with suspicion."
            )

    notes: list[str] = []
    if brand_note:
        notes.append(brand_note)
    if final_host and original_host and domain_changed and not brand_mismatch:
        notes.append(
            f"Final domain ({final_host}) differs from the short link's "
            f"domain ({original_host}). Short links hide the destination by "
            "design — check the domain before clicking."
        )
    if final_host and _is_ip_literal(final_host):
        notes.append(
            "The final destination is a bare IP address, not a named "
            "domain. Legitimate sites almost always use a domain name."
        )
    if final_scheme == "http" and final_host:
        notes.append(
            "The final destination is not encrypted (http, not https). "
            "Do not enter passwords or payment details there."
        )
    if final_host and ("xn--" in final_host or not final_host.isascii()):
        notes.append(
            "The final domain uses international (IDN/punycode) characters, "
            "which can be used to imitate a familiar domain. Look closely."
        )
    if final_url and "@" in urlparse(final_url).netloc:
        notes.append(
            "The final URL contains credentials before the @ sign — a "
            "classic trick to make a link look like it goes somewhere else."
        )
    if final_host and not domain_changed and original_host:
        notes.append(
            f"Final domain matches the short link's domain ({final_host}). "
            "The destination is on the same site the link came from."
        )

    return {
        "original_domain": original_host or None,
        "final_domain": final_host or None,
        "domain_changed": domain_changed,
        "brand_mismatch": brand_mismatch,
        "safety_notes": notes,
    }
