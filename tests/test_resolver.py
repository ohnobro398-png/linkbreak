"""Resolver engine tests: chains, hop limit, meta refresh, canonical,
HEAD fallback, relative redirects."""

import asyncio

import httpx

from app.resolver import resolve_url

PUBLIC_DNS = lambda host: ["93.184.216.34"]


def _run(url, handler, **kwargs):
    transport = httpx.MockTransport(handler)
    async def _go():
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            return await resolve_url(url, client=client, dns_resolver=PUBLIC_DNS, **kwargs)
    return asyncio.run(_go())


def test_multi_hop_chain_recorded():
    def handler(request):
        path = request.url.path
        if path == "/a":
            return httpx.Response(302, headers={"location": "/b"})
        if path == "/b":
            return httpx.Response(301, headers={"location": "/c"})
        return httpx.Response(200, text="done")

    result = _run("http://example.com/a", handler)
    assert result["resolution_status"] == "Resolved"
    assert result["final_url"] == "http://example.com/c"
    assert [h["status"] for h in result["redirect_chain"]] == [302, 301, 200]
    assert [h["url"] for h in result["redirect_chain"]] == [
        "http://example.com/a",
        "http://example.com/b",
        "http://example.com/c",
    ]
    # Every hop records how it was fetched and how long it took.
    assert all(h["method"] == "HEAD" for h in result["redirect_chain"])
    assert all(h["elapsed_ms"] >= 0 for h in result["redirect_chain"])


def test_hop_limit_enforced():
    def handler(request):
        n = int(request.url.path.lstrip("/r"))
        return httpx.Response(302, headers={"location": f"/r{n + 1}"})

    result = _run("http://example.com/r0", handler, max_hops=10)
    assert result["resolution_status"] == "Partially Resolved"
    assert len(result["redirect_chain"]) == 10
    assert "redirect limit" in result["error_message"]


def test_meta_refresh_followed_with_delay_noted():
    html = (
        '<html><head>'
        '<meta http-equiv="refresh" content="5; url=/final">'
        "</head><body>redirecting</body></html>"
    )

    def handler(request):
        if request.method == "HEAD":
            return httpx.Response(200, headers={"content-type": "text/html"})
        if request.url.path == "/start":
            return httpx.Response(200, text=html, headers={"content-type": "text/html"})
        return httpx.Response(200, text="final page")

    result = _run("http://example.com/start", handler)
    assert result["resolution_status"] == "Resolved"
    assert result["final_url"] == "http://example.com/final"
    assert len(result["redirect_chain"]) == 2
    assert result["redirect_chain"][0]["note"] == "meta refresh (delay 5s)"
    assert result["redirect_chain"][0]["method"] == "GET"


def test_canonical_reported_not_substituted():
    html = (
        "<html><head>"
        '<link rel="canonical" href="http://example.com/real-page">'
        '<meta property="og:url" content="http://example.com/og-page">'
        "</head><body>hi</body></html>"
    )

    def handler(request):
        if request.method == "HEAD":
            return httpx.Response(200, headers={"content-type": "text/html"})
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    result = _run("http://example.com/page", handler)
    assert result["resolution_status"] == "Resolved"
    assert result["final_url"] == "http://example.com/page"
    assert result["canonical_url"] == "http://example.com/real-page"
    assert result["canonical_source"] == "rel=canonical"


def test_og_url_fallback_when_no_canonical():
    html = (
        "<html><head>"
        '<meta property="og:url" content="http://example.com/og-page">'
        "</head><body>hi</body></html>"
    )

    def handler(request):
        if request.method == "HEAD":
            return httpx.Response(200, headers={"content-type": "text/html"})
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    result = _run("http://example.com/page", handler)
    assert result["canonical_url"] == "http://example.com/og-page"
    assert result["canonical_source"] == "og:url"


def test_head_refused_falls_back_to_get():
    def handler(request):
        if request.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(200, text="body")

    result = _run("http://example.com/page", handler)
    assert result["resolution_status"] == "Resolved"
    assert result["redirect_chain"][0]["method"] == "GET"


def test_relative_redirect_resolved():
    def handler(request):
        if request.url.path == "/a":
            return httpx.Response(302, headers={"location": "b"})
        return httpx.Response(200, text="done")

    result = _run("http://example.com/a", handler)
    assert result["resolution_status"] == "Resolved"
    assert result["final_url"] == "http://example.com/b"


def test_non_2xx_final_is_partially_resolved():
    def handler(request):
        return httpx.Response(404, text="gone")

    result = _run("http://example.com/gone", handler)
    assert result["resolution_status"] == "Partially Resolved"
    assert result["http_status"] == 404
    assert result["final_url"] == "http://example.com/gone"


def test_safety_fields_present_on_resolved():
    def handler(request):
        return httpx.Response(200, text="ok")

    result = _run("http://example.com/page", handler)
    assert result["final_domain"] == "example.com"
    assert result["original_domain"] == "example.com"
    assert result["domain_changed"] is False
    assert result["brand_mismatch"] is False
    assert isinstance(result["safety_notes"], list)
