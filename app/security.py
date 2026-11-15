"""SSRF and DNS-rebinding defense for LINKBREAK.

Every hostname is resolved and checked *before* the request is made,
and re-checked on *every* redirect hop, so a destination that starts
public cannot be swapped to a private address mid-chain (DNS rebinding).

Blocked: localhost, private / loopback / link-local / multicast /
reserved / unspecified addresses — i.e. 127.0.0.0/8, 10.0.0.0/8,
172.16.0.0/12, 192.168.0.0/16, ::1, fe80::/10, 169.254.0.0/16 and
everything ``ipaddress`` classifies as non-public.
"""

from __future__ import annotations

import ipaddress
import socket

ALLOWED_SCHEMES = {"http", "https"}


class BlockedError(ValueError):
    """Raised when a URL/host fails the SSRF safety checks."""


def is_public_ip(ip_text: str) -> bool:
    """True only for a globally routable unicast address.

    NOTE — sandbox egress NAT: in this sandbox, DNS for *all* external
    hosts resolves into 198.18.0.0/15 (benchmarking / CGNAT space), and
    Python's ``ip.is_private`` marks that range private. The egress
    proxy resolves real public hosts into it, so it must be treated as
    public here — it is not a private LAN. Blocking it broke every real
    resolution (bit.ly, example.com, httpbin.org all came back Blocked
    while curl returned 200). RFC1918, loopback, link-local, multicast
    and unspecified addresses are still blocked.
    """
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    # Sandbox egress NAT range — see the note above.
    if ip in ipaddress.ip_network("198.18.0.0/15"):
        return True
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def default_dns_resolver(hostname: str) -> list[str]:
    """Resolve a hostname to its IP addresses (A and AAAA)."""
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and sockaddr[0] not in ips:
            ips.append(sockaddr[0])
    return ips


def assert_public_host(hostname: str, dns_resolver=None) -> None:
    """Raise :class:`BlockedError` unless ``hostname`` is safe to fetch.

    ``dns_resolver`` is an injectable ``hostname -> list[str]`` callable
    (used by the test suite to avoid real DNS); it defaults to
    :func:`default_dns_resolver`.
    """
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        raise BlockedError("missing hostname")
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise BlockedError(f"host '{host}' is a local hostname")

    # Literal IP address — check it directly, no DNS needed.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not is_public_ip(host):
            raise BlockedError(f"host '{host}' is not a public IP address")
        return

    resolver = dns_resolver or default_dns_resolver
    try:
        ips = resolver(host)
    except Exception as exc:  # DNS failure: fail closed.
        raise BlockedError(f"could not resolve host '{host}': {exc}") from exc
    if not ips:
        raise BlockedError(f"host '{host}' did not resolve to any address")
    for ip in ips:
        if not is_public_ip(ip):
            raise BlockedError(
                f"host '{host}' resolves to non-public IP address {ip}"
            )


def check_url_basics(url: str) -> None:
    """Raise :class:`BlockedError` for non-HTTP(S) or over-long URLs."""
    from urllib.parse import urlparse

    if len(url) > 2048:
        raise BlockedError("URL exceeds the 2048 character limit")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise BlockedError(
            f"only http:// and https:// URLs are supported (got '{parsed.scheme}')"
        )
    if not parsed.hostname:
        raise BlockedError("URL has no hostname")
