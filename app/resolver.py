"""Resolution engine for LINKBREAK.

Follows standard HTTP redirects manually (``follow_redirects=False``)
so every hop is recorded, with:

* HEAD first, GET fallback when a server refuses HEAD;
* ``<meta http-equiv="refresh">`` detection via a real HTML parser
  (attribute order / quote style / casing do not matter) — the refresh
  target counts as a hop, with its delay recorded;
* ``rel="canonical"`` detection (``og:url`` as fallback) — reported,
  never silently substituted;
* SSRF re-validation on *every* hop (DNS-rebinding defense);
* 10-hop limit, 10 s timeout, 2 retries on transient network errors;
* inspected HTML bodies capped at 1 MB;
* downloaded content is only parsed for meta-refresh / canonical tags —
  scripts are never executed;
* every result carries a scam-safety analysis (final domain, brand
  mismatch, structural warnings) so the user can judge the destination
  before clicking.

Statuses
--------
Resolved            final destination reached with a 2xx response.
Partially Resolved  the chain ended somewhere useful but not 2xx
                    (non-2xx final status, hop limit, or a meta-refresh
                    on the last hop) — a destination is still reported.
Blocked             SSRF guard, disallowed protocol, or bad URL.
Unsupported         known JavaScript-challenge / ad-gated provider.
Failed              network / DNS / timeout error, nothing resolved.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from .htmlinspect import inspect_html
from .providers import detect_provider
from .safety import analyze_safety
from .security import BlockedError, assert_public_host, check_url_basics

MAX_HOPS = 10
TIMEOUT_SECONDS = 10.0
MAX_RETRIES = 2
MAX_BODY_BYTES = 1_000_000
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
HEAD_REFUSED_STATUSES = {403, 405, 501}

USER_AGENT = "LINKBREAK/1.0 (universal shortlink resolver)"


def _proxy_from_env() -> str | None:
    """Proxy URL from the environment, validated before use.

    NOTE — sandbox proxy env: this sandbox sets a ``no_proxy`` list
    containing bare IPv6 literals (``fd8b:...::1``) and bracketed ones.
    httpx with ``trust_env=True`` parses every ``no_proxy`` entry as a
    URL pattern and crashes on them
    (``InvalidURL: Invalid port: ':1]'``), which made *every* live
    resolve return HTTP 500. We therefore build the client with
    ``trust_env=False`` and pass only a validated proxy URL
    explicitly. Targets are public hosts, and localhost is already
    blocked by the SSRF guard, so ignoring ``no_proxy`` is safe here.
    """
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        raw = os.environ.get(key)
        if raw:
            try:
                httpx.URL(raw)
                return raw
            except Exception:
                continue
    return None


def _verify_from_env() -> str | bool:
    """TLS trust store for live resolution.

    NOTE — sandbox egress MITM: httpx with ``trust_env=False``
    builds its SSL context from certifi's Mozilla bundle, which does
    NOT contain the sandbox egress proxy's MITM CA ("Hatch Sandbox
    Egress CA") — so every HTTPS fetch failed with
    CERTIFICATE_VERIFY_FAILED even though the CA is in the egress
    bundle and curl verifies fine. Pass the bundle explicitly:
    prefer SSL_CERT_FILE / REQUESTS_CA_BUNDLE when set, then the
    well-known sandbox bundle path when it exists. On a normal
    machine neither exists and this returns True (certifi default).
    """
    for key in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        path = os.environ.get(key)
        if path and os.path.isfile(path):
            return path
    sandbox_bundle = "/run/hatch/egress-tls/ca-bundle.pem"
    if os.path.isfile(sandbox_bundle):
        return sandbox_bundle
    return True


def build_client() -> httpx.AsyncClient:
    """Default client for live resolution (proxy-aware, env-safe)."""
    return httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(TIMEOUT_SECONDS),
        headers={"User-Agent": USER_AGENT},
        proxy=_proxy_from_env(),
        verify=_verify_from_env(),
        trust_env=False,
    )

@dataclass
class Hop:
    url: str
    status: int
    # HTTP method actually used for this hop ("HEAD" or "GET").
    method: str = "HEAD"
    # Human-readable note, e.g. "meta refresh (delay 5s)".
    note: str | None = None
    # Milliseconds this hop took.
    elapsed_ms: int = 0


@dataclass
class ResolveResult:
    original_url: str
    detected_provider: str
    final_url: str | None
    redirect_chain: list[Hop] = field(default_factory=list)
    http_status: int | None = None
    resolution_status: str = "Failed"
    error_message: str | None = None
    elapsed_ms: int = 0
    canonical_url: str | None = None
    canonical_source: str | None = None
    # Scam-safety facts (see app/safety.py).
    original_domain: str | None = None
    final_domain: str | None = None
    domain_changed: bool = False
    brand_mismatch: bool = False
    safety_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class _Fetched:
    status_code: int
    headers: dict
    text: str = ""
    # False when the response came from a HEAD request (no body available).
    body_fetched: bool = False
    # HTTP method actually used ("HEAD" or "GET").
    method: str = "HEAD"


async def _get_capped(client: httpx.AsyncClient, url: str) -> _Fetched:
    """GET with the response body capped at :data:`MAX_BODY_BYTES`."""
    async with client.stream("GET", url) as response:
        body = bytearray()
        async for chunk in response.aiter_bytes(65536):
            body += chunk
            if len(body) > MAX_BODY_BYTES:
                del body[MAX_BODY_BYTES:]
                break
        text = bytes(body).decode("utf-8", errors="replace")
        return _Fetched(
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            text=text,
            body_fetched=True,
            method="GET",
        )


async def _fetch_with_fallback(client: httpx.AsyncClient, url: str) -> _Fetched:
    """HEAD first; GET fallback when HEAD is refused or fails.

    Retries (up to :data:`MAX_RETRIES`) only on transient transport
    errors, with a short back-off.
    """
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        head: _Fetched | None = None
        try:
            response = await client.head(url)
            head = _Fetched(
                status_code=response.status_code,
                headers={k.lower(): v for k, v in response.headers.items()},
            )
        except httpx.TransportError as exc:
            last_exc = exc
        if head is not None and head.status_code not in HEAD_REFUSED_STATUSES:
            return head
        # GET fallback: server refused HEAD, or HEAD failed outright.
        try:
            return await _get_capped(client, url)
        except httpx.TransportError as exc:
            last_exc = exc
            if attempt < MAX_RETRIES:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            raise
    raise last_exc  # pragma: no cover - loop always raises or returns


async def resolve_url(
    url: str,
    *,
    client: httpx.AsyncClient | None = None,
    dns_resolver=None,
    max_hops: int = MAX_HOPS,
) -> dict:
    """Resolve ``url`` to its final destination. Returns a plain dict
    matching the ``/api/resolve`` response shape."""
    started = time.monotonic()
    original = (url or "").strip()

    def finish(**kwargs) -> dict:
        final_url = kwargs.get("final_url")
        safety = analyze_safety(original, final_url)
        result = ResolveResult(
            original_url=original,
            detected_provider=kwargs.pop("detected_provider", "generic"),
            final_url=final_url,
            redirect_chain=kwargs.pop("redirect_chain", []),
            http_status=kwargs.pop("http_status", None),
            resolution_status=kwargs.pop("resolution_status", "Failed"),
            error_message=kwargs.pop("error_message", None),
            elapsed_ms=int((time.monotonic() - started) * 1000),
            canonical_url=kwargs.pop("canonical_url", None),
            canonical_source=kwargs.pop("canonical_source", None),
            original_domain=safety["original_domain"],
            final_domain=safety["final_domain"],
            domain_changed=safety["domain_changed"],
            brand_mismatch=safety["brand_mismatch"],
            safety_notes=safety["safety_notes"],
        )
        return result.to_dict()

    # --- basic validation -------------------------------------------------
    try:
        check_url_basics(original)
    except BlockedError as exc:
        return finish(resolution_status="Blocked", error_message=str(exc))

    hostname = urlparse(original).hostname or ""
    provider, unsupported, reason = detect_provider(hostname)
    if unsupported:
        return finish(
            detected_provider=provider,
            resolution_status="Unsupported",
            error_message=reason,
        )

    # --- SSRF check on the first host --------------------------------------
    try:
        assert_public_host(hostname, dns_resolver)
    except BlockedError as exc:
        return finish(
            detected_provider=provider,
            resolution_status="Blocked",
            error_message=str(exc),
        )

    own_client = client is None
    if own_client:
        client = build_client()

    chain: list[Hop] = []
    canonical_url: str | None = None
    canonical_source: str | None = None
    current = original
    try:
        for _hop in range(max_hops):
            # Re-validate on EVERY hop (DNS-rebinding defense).
            hop_host = urlparse(current).hostname or ""
            try:
                assert_public_host(hop_host, dns_resolver)
            except BlockedError as exc:
                return finish(
                    detected_provider=provider,
                    final_url=current,
                    redirect_chain=chain,
                    resolution_status="Blocked",
                    error_message=str(exc),
                )

            hop_started = time.monotonic()
            fetched = await _fetch_with_fallback(client, current)
            hop = Hop(
                url=current,
                status=fetched.status_code,
                method=fetched.method,
                elapsed_ms=int((time.monotonic() - hop_started) * 1000),
            )
            chain.append(hop)

            if fetched.status_code in REDIRECT_STATUSES:
                location = fetched.headers.get("location")
                if not location:
                    return finish(
                        detected_provider=provider,
                        final_url=current,
                        redirect_chain=chain,
                        http_status=fetched.status_code,
                        resolution_status="Partially Resolved",
                        error_message=(
                            f"redirect status {fetched.status_code} "
                            "with no Location header"
                        ),
                    )
                current = urljoin(current, location)
                continue

            if 200 <= fetched.status_code < 300:
                # A HEAD response has no body, so a 2xx HTML page needs one
                # capped GET before meta-refresh / canonical can be checked.
                if (
                    "text/html" in fetched.headers.get("content-type", "")
                    and not fetched.body_fetched
                ):
                    try:
                        fetched = await _get_capped(client, current)
                        hop.method = "GET"
                        hop.elapsed_ms = int(
                            (time.monotonic() - hop_started) * 1000
                        )
                    except httpx.TransportError:
                        pass  # body unavailable; resolve without inspection
                if "text/html" in fetched.headers.get("content-type", ""):
                    signals = inspect_html(fetched.text)
                    if signals["canonical_url"]:
                        canonical_url = urljoin(
                            current, signals["canonical_url"]
                        )
                        canonical_source = signals["canonical_source"]
                    refresh = signals["meta_refresh"]
                    if refresh is not None:
                        delay, target = refresh
                        destination = urljoin(current, target)
                        hop.note = f"meta refresh (delay {delay}s)"
                        if _hop == max_hops - 1:
                            return finish(
                                detected_provider=provider,
                                final_url=destination,
                                redirect_chain=chain,
                                http_status=fetched.status_code,
                                resolution_status="Partially Resolved",
                                error_message=(
                                    "meta-refresh target found on the "
                                    "last allowed hop"
                                ),
                                canonical_url=canonical_url,
                                canonical_source=canonical_source,
                            )
                        current = destination
                        continue
                return finish(
                    detected_provider=provider,
                    final_url=current,
                    redirect_chain=chain,
                    http_status=fetched.status_code,
                    resolution_status="Resolved",
                    canonical_url=canonical_url,
                    canonical_source=canonical_source,
                )

            # Any other final status (4xx / 5xx): destination is known,
            # but the page itself did not load cleanly.
            return finish(
                detected_provider=provider,
                final_url=current,
                redirect_chain=chain,
                http_status=fetched.status_code,
                resolution_status="Partially Resolved",
                error_message=(
                    f"final destination returned HTTP {fetched.status_code}"
                ),
                canonical_url=canonical_url,
                canonical_source=canonical_source,
            )

        return finish(
            detected_provider=provider,
            final_url=current,
            redirect_chain=chain,
            resolution_status="Partially Resolved",
            error_message=f"redirect limit reached ({max_hops} hops)",
            canonical_url=canonical_url,
            canonical_source=canonical_source,
        )
    except httpx.TimeoutException:
        return finish(
            detected_provider=provider,
            final_url=current if chain else None,
            redirect_chain=chain,
            resolution_status="Failed",
            error_message="request timed out",
        )
    except httpx.TransportError as exc:
        return finish(
            detected_provider=provider,
            final_url=current if chain else None,
            redirect_chain=chain,
            resolution_status="Failed",
            error_message=f"network error: {exc}",
        )
    finally:
        if own_client:
            await client.aclose()
