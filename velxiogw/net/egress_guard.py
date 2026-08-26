"""
Egress guard for the Pico W virtual network bridge.

The bridge opens REAL host-side sockets to whatever (ip, port) the
simulated chip asks for (see tcp_nat.py / udp_nat.py). Without a guard
that turns velxio.dev's backend into an open proxy: a sketch could reach
cloud-metadata endpoints (169.254.169.254), the server's private network
(RFC1918), or loopback services — classic SSRF / relay abuse.

Policy: ALLOW only globally-routable public addresses (the OWASP-preferred
allowlist-by-routability approach). Python's ``ipaddress.is_global`` is
False for private (RFC1918), loopback, link-local (every cloud metadata IP
included), shared/CGNAT, multicast, reserved and unspecified ranges, so a
single check covers them all without a bypass-prone denylist.

Applied at three points for defense in depth:
  - TCP connect          (tcp_nat._on_passive_syn)
  - UDP flow open         (udp_nat._open_flow)
  - resolved DNS answers  (dns._resolve_a) — drops non-global A-records so a
    rebinding domain (foo.com -> 169.254.169.254) never reaches the chip.

The env var ``VELXIO_EGRESS_ALLOW_PRIVATE=1`` disables the block. It is read
at call time (so tests can toggle it). NOT for the hosted service — only for
local/self-host debugging and for integration tests that stand up local
echo/DNS servers on 127.0.0.1 / 10.x.
"""

from __future__ import annotations

import ipaddress
import os


def _allow_private() -> bool:
    return os.environ.get('VELXIO_EGRESS_ALLOW_PRIVATE', '').strip().lower() in (
        '1', 'true', 'yes', 'on',
    )


def _ip_ok(ip: ipaddress._BaseAddress) -> bool:
    """True only for globally-routable unicast public addresses.

    is_global is already False for RFC1918, loopback, link-local (169.254.x
    incl. the 169.254.169.254 metadata IP), shared/CGNAT (100.64/10) and
    unspecified ranges. Some Python versions still report multicast/reserved
    as global, so exclude those explicitly.
    """
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def is_allowed_dst(ip_str: str, port: int) -> tuple[bool, str]:
    """Return ``(allowed, reason)``. ``reason`` is a short tag for logging."""
    if _allow_private():
        return True, 'allow_private_override'
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, 'invalid_ip'
    if not _ip_ok(ip):
        return False, 'non_global'
    return True, 'ok'


def filter_resolved_ips(ips: list[bytes]) -> list[bytes]:
    """Drop non-global A-record answers (DNS-rebinding defense).

    ``ips`` are 4-byte packed IPv4 addresses (as DnsResolver builds them).
    """
    if _allow_private():
        return list(ips)
    out: list[bytes] = []
    for packed in ips:
        try:
            ip = ipaddress.ip_address(packed)  # bytes -> IPv4Address
        except ValueError:
            continue
        if _ip_ok(ip):
            out.append(packed)
    return out
