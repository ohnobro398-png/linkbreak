"""Provider registry for LINKBREAK.

The resolver engine never hard-codes provider knowledge: every known
shortlink service lives in the tables below. Adding a new provider is a
one-line change here — no engine code has to be touched.

Two tables exist on purpose:

* ``PROVIDERS`` — ordinary HTTP-redirect shorteners. The engine follows
  their redirects like any other link. This covers the standard
  shorteners plus well-known brand shortlinks (youtu.be, amzn.to, …)
  and other legitimate redirect services. Any host *not* listed here is
  still resolved as ``generic`` — the registry names providers, it does
  not gatekeep which links can be resolved.
* ``UNSUPPORTED_PROVIDERS`` — services that hide the destination behind
  a JavaScript challenge, an interstitial ad page, or a countdown.
  LINKBREAK detects these by hostname and reports them as
  ``Unsupported`` with an honest explanation. It never tries to defeat
  the challenge, run the page's JavaScript, or automate past the gate.

Honest scope: LINKBREAK resolves standard HTTP redirects and
meta-refresh pages automatically. It does NOT resolve CAPTCHA pages,
login walls, paywalls, DRM, JavaScript challenges, or ad-gates — those
need a human in a browser. See README.md for the full breakdown.
"""

from __future__ import annotations

# hostname (lowercase, without port) -> display name
PROVIDERS: dict[str, str] = {
    # --- general-purpose shorteners ---
    "bit.ly": "bit.ly",
    "j.mp": "j.mp (Bitly)",
    "tinyurl.com": "TinyURL",
    "tiny.cc": "tiny.cc",
    "tiny.one": "tiny.one",
    "t.co": "X (t.co)",
    "is.gd": "is.gd",
    "v.gd": "v.gd",
    "cutt.ly": "Cutt.ly",
    "rebrand.ly": "Rebrandly",
    "shorturl.at": "shorturl.at",
    "buff.ly": "Buffer (buff.ly)",
    "ow.ly": "Hootsuite (ow.ly)",
    "rb.gy": "rb.gy",
    "s.id": "s.id",
    "goo.gl": "Google URL Shortener (retired)",
    "bit.do": "bit.do",
    "bl.ink": "Bl.ink",
    "short.io": "Short.io",
    "snip.ly": "Sniply",
    "t.ly": "T.ly",
    "gg.gg": "gg.gg",
    "kutt.it": "Kutt",
    "spoo.me": "Spoo.me",
    "ulvis.net": "Ulvis",
    "cleanuri.com": "CleanURI",
    "chilp.it": "Chilp.it",
    "t2m.io": "T2M",
    "cli.re": "Cli.re",
    "hyperurl.co": "HyperURL",
    "urlz.fr": "Urlz.fr",
    "trib.al": "Trib.al",
    "dlvr.it": "dlvr.it",
    "dld.bz": "dld.bz",
    "yourls.org": "YOURLS (self-hosted instances)",
    # --- brand / publisher shortlinks (plain HTTP redirects) ---
    "youtu.be": "YouTube (youtu.be)",
    "amzn.to": "Amazon (amzn.to)",
    "fb.me": "Facebook (fb.me)",
    "fb.gg": "Facebook Gaming (fb.gg)",
    "lnk.to": "Linkfire (lnk.to)",
    "apple.co": "Apple (apple.co)",
    "msft.it": "Microsoft (msft.it)",
    "go.microsoft.com": "Microsoft (go.microsoft.com)",
    "ibm.co": "IBM (ibm.co)",
    "nyti.ms": "New York Times (nyti.ms)",
    "wapo.st": "Washington Post (wapo.st)",
    "bbc.in": "BBC (bbc.in)",
    "econ.st": "The Economist (econ.st)",
    "for.tn": "Fortune (for.tn)",
    "ti.me": "TIME (ti.me)",
    "spoti.fi": "Spotify (spoti.fi)",
}

# Hostnames that hide the destination behind a JavaScript challenge,
# interstitial ad page, or countdown — LINKBREAK does not try to
# defeat those. Detected by hostname and reported as "Unsupported".
UNSUPPORTED_PROVIDERS: dict[str, str] = {
    "linkvertise.com": (
        "Linkvertise hides the destination behind an interstitial ad page "
        "and a JavaScript challenge that must be completed by a human."
    ),
    "adf.ly": (
        "Adf.ly hides the destination behind an interstitial ad page with "
        "a countdown that must be waited out in a browser."
    ),
    "ouo.io": (
        "ouo.io hides the destination behind an interstitial ad page and "
        "a JavaScript challenge."
    ),
    "ouo.press": (
        "ouo.press hides the destination behind an interstitial ad page and "
        "a JavaScript challenge."
    ),
    "shrinkme.io": (
        "shrinkme.io hides the destination behind an interstitial ad page "
        "and a JavaScript challenge."
    ),
    "shorte.st": (
        "shorte.st hides the destination behind an interstitial ad page "
        "with a countdown and ads."
    ),
    "exe.io": (
        "exe.io hides the destination behind an interstitial ad page and "
        "a JavaScript challenge."
    ),
    "adfoc.us": (
        "adfoc.us hides the destination behind an interstitial ad page "
        "with a countdown."
    ),
    "bc.vc": (
        "bc.vc hides the destination behind an interstitial ad page and "
        "a JavaScript challenge."
    ),
    "clk.sh": (
        "clk.sh hides the destination behind an interstitial ad page and "
        "a JavaScript challenge."
    ),
    "sh.st": (
        "sh.st hides the destination behind an interstitial ad page with "
        "a countdown."
    ),
    "linkbucks.com": (
        "LinkBucks hides the destination behind an interstitial ad page "
        "with a countdown and ads."
    ),
    "ity.im": (
        "ity.im hides the destination behind an interstitial ad page and "
        "a JavaScript challenge."
    ),
    "coinurl.com": (
        "CoinURL hides the destination behind an interstitial ad page."
    ),
}


def _match(hostname: str, table: dict[str, str]) -> str | None:
    """Exact hostname or sub-domain match (e.g. www.linkvertise.com)."""
    host = hostname.lower().rstrip(".")
    if host in table:
        return table[host]
    for key, value in table.items():
        if host.endswith("." + key):
            return value
    return None


def register_provider(hostname: str, display_name: str) -> None:
    """Plugin hook: register a new shortlink provider at runtime.

    Example::

        from app.providers import register_provider
        register_provider("short.example", "Example Shortener")
    """
    PROVIDERS[hostname.lower().rstrip(".")] = display_name


def register_unsupported(hostname: str, reason: str) -> None:
    """Plugin hook: register a new JS/ad-gated provider as unsupported."""
    UNSUPPORTED_PROVIDERS[hostname.lower().rstrip(".")] = reason


def detect_provider(hostname: str) -> tuple[str, bool, str | None]:
    """Return ``(display_name, is_unsupported, unsupported_reason)``.

    Unknown hosts are reported as ``generic`` with their hostname, so
    the resolver still works for any standard HTTP redirect service.
    """
    host = (hostname or "").lower().rstrip(".")
    reason = _match(host, UNSUPPORTED_PROVIDERS)
    if reason is not None:
        return host, True, reason
    name = _match(host, PROVIDERS)
    if name is not None:
        return name, False, None
    return host or "generic", False, None
