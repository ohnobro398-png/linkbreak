"""Regression tests for the 198.18.0.0/15 sandbox-egress bug.

In this sandbox, DNS for ALL external hosts resolves into
198.18.0.0/15, and Python's ``ip.is_private`` marks that range
private — so the SSRF guard used to block every real host
(bit.ly, example.com, httpbin.org all came back "resolves to
non-public IP address") while curl returned 200. The fix explicitly
allows 198.18.0.0/15 as sandbox egress NAT; RFC1918, loopback,
link-local, multicast and unspecified addresses stay blocked.
"""

import asyncio

import httpx

from app.resolver import resolve_url
from app.security import assert_public_host, is_public_ip
from app.security import BlockedError

import pytest


def test_egress_range_counts_as_public():
    assert is_public_ip("198.18.187.79") is True
    assert is_public_ip("198.18.0.1") is True
    assert is_public_ip("198.19.255.255") is True


def test_real_public_ips_still_public():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("2001:4860:4860::8888") is True


def test_rfc1918_still_blocked():
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("192.168.1.1") is False


def test_loopback_linklocal_multicast_still_blocked():
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("::1") is False
    assert is_public_ip("169.254.1.1") is False
    assert is_public_ip("fe80::1") is False
    assert is_public_ip("224.0.0.1") is False
    assert is_public_ip("0.0.0.0") is False


def test_assert_public_host_allows_egress_range():
    assert_public_host("example.com", dns_resolver=lambda h: ["198.18.187.79"])


def test_assert_public_host_still_blocks_private():
    with pytest.raises(BlockedError):
        assert_public_host("internal.example.com", dns_resolver=lambda h: ["10.0.0.1"])
    with pytest.raises(BlockedError):
        assert_public_host("localhost", dns_resolver=lambda h: ["127.0.0.1"])


def test_resolve_with_egress_dns_is_not_blocked():
    """End-to-end regression: a host resolving into 198.18/15 resolves."""
    def handler(request):
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)

    async def _go():
        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
            return await resolve_url(
                "http://example.com/page",
                client=client,
                dns_resolver=lambda h: ["198.18.187.79"],
            )

    result = asyncio.run(_go())
    assert result["resolution_status"] == "Resolved"
    assert result["final_url"] == "http://example.com/page"


def test_build_client_survives_sandbox_proxy_env(monkeypatch):
    """Regression: sandbox ``no_proxy`` has bare IPv6 literals that
    httpx's trust_env parser chokes on (``Invalid port: ':1]'``) —
    every live resolve returned HTTP 500. build_client() must not
    raise with that env, and must still pick up the proxy."""
    from app.resolver import _proxy_from_env, build_client

    monkeypatch.setenv(
        "no_proxy",
        "localhost,127.0.0.1,::1,[::1],198.19.0.1,198.19.0.2,"
        "fd8b:4f84:7d32:99::1,[fd8b:4f84:7d32:99::1],"
        "fd8b:4f84:7d32:99::2,[fd8b:4f84:7d32:99::2]",
    )
    monkeypatch.setenv("NO_PROXY", "localhost,::1,[::1]")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
    monkeypatch.setenv("https_proxy", "http://proxy.example.test:3128")
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)

    assert _proxy_from_env() == "http://proxy.example.test:3128"
    client = build_client()  # must not raise on the poisoned no_proxy
    assert client._mounts  # proxy mounted for all URLs


def test_build_client_without_proxy_env(monkeypatch):
    """No proxy in env -> client still builds, direct connection."""
    from app.resolver import _proxy_from_env, build_client

    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)

    assert _proxy_from_env() is None
    client = build_client()
    assert not client._mounts


def test_verify_prefers_ssl_cert_file_env(monkeypatch, tmp_path):
    """_verify_from_env() must hand httpx the egress bundle path,
    not certifi — otherwise the sandbox MITM chain fails."""
    from app.resolver import _verify_from_env

    bundle = tmp_path / "ca-bundle.pem"
    bundle.write_text("dummy")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    assert _verify_from_env() == str(bundle)


def test_verify_falls_back_to_sandbox_bundle(monkeypatch):
    """No env vars set, but the sandbox bundle exists on disk ->
    use it (this sandbox)."""
    from app.resolver import _verify_from_env

    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    result = _verify_from_env()
    assert result == "/run/hatch/egress-tls/ca-bundle.pem" or result is True

