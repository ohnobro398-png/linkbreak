"""SSRF / DNS-rebinding defense tests.

The resolver is driven with an httpx MockTransport (no real network)
and an injected fake DNS resolver, so every case is hermetic.
"""

import asyncio

import httpx

from app.resolver import resolve_url

PUBLIC_DNS = lambda host: ["93.184.216.34"]  # a public IP (example.com)


def _run(url, handler, dns=PUBLIC_DNS):
    transport = httpx.MockTransport(handler)
    async def _go():
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            return await resolve_url(url, client=client, dns_resolver=dns)
    return asyncio.run(_go())


def _ok_200(request):
    return httpx.Response(200, text="ok")


def test_localhost_blocked():
    result = _run("http://localhost/admin", _ok_200)
    assert result["resolution_status"] == "Blocked"
    assert "local" in result["error_message"].lower()


def test_loopback_ip_blocked():
    result = _run("http://127.0.0.1/admin", _ok_200)
    assert result["resolution_status"] == "Blocked"


def test_private_10_blocked():
    result = _run("http://10.0.0.5/admin", _ok_200)
    assert result["resolution_status"] == "Blocked"


def test_private_192_168_blocked():
    result = _run("http://192.168.1.1/admin", _ok_200)
    assert result["resolution_status"] == "Blocked"


def test_private_172_16_blocked():
    result = _run("http://172.16.0.9/admin", _ok_200)
    assert result["resolution_status"] == "Blocked"


def test_ipv6_loopback_blocked():
    result = _run("http://[::1]/admin", _ok_200)
    assert result["resolution_status"] == "Blocked"


def test_link_local_blocked():
    result = _run("http://169.254.169.254/latest/meta-data/", _ok_200)
    assert result["resolution_status"] == "Blocked"


def test_redirect_to_private_ip_blocked():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/x"})

    result = _run("http://example.com/short", handler)
    assert result["resolution_status"] == "Blocked"
    assert len(result["redirect_chain"]) == 1  # hop 1 recorded, hop 2 refused


def test_redirect_to_host_resolving_private_blocked():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://evil.example.com/x"})

    def evil_dns(host):
        if host == "evil.example.com":
            return ["10.1.2.3"]
        return ["93.184.216.34"]

    result = _run("http://example.com/short", handler, dns=evil_dns)
    assert result["resolution_status"] == "Blocked"
    assert "10.1.2.3" in result["error_message"]


def test_public_host_allowed():
    result = _run("http://example.com/page", _ok_200)
    assert result["resolution_status"] == "Resolved"
    assert result["final_url"] == "http://example.com/page"


def test_unsupported_provider_never_fetched():
    def handler(request):
        raise AssertionError("unsupported host must never be fetched")

    url = "http://" + "linkvertise.com/abc"
    result = _run(url, handler)
    assert result["resolution_status"] == "Unsupported"
    assert "JavaScript" in result["error_message"] or "challenge" in result["error_message"]


def test_non_http_scheme_blocked():
    result = _run("ftp://example.com/file", _ok_200)
    assert result["resolution_status"] == "Blocked"
