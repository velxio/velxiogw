"""
DNS proxy — when MicroPython resolves a hostname (e.g. for
``urequests.get('http://example.com')``), the lwIP stack sends a
recursive query to ``DNS_IP``. We forward the request to the host's
real resolver and wrap the answer back into a DNS response.

Only A-records are answered; anything else returns an empty
authoritative reply so the client retries.

The resolution is async via ``asyncio.get_running_loop().getaddrinfo``
so the network bridge thread doesn't block.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Optional

from .consts import DNS_IP, GATEWAY_MAC, ip_to_bytes
from .egress_guard import filter_resolved_ips
from .protocols import (
    BROADCAST_MAC,
    DnsMessage,
    UDP,
    make_frame_ipv4,
)

logger = logging.getLogger(__name__)

# DNS flag bits
DNS_FLAG_QR = 0x8000      # 1 = response
DNS_FLAG_AA = 0x0400      # authoritative answer
DNS_FLAG_RA = 0x0080      # recursion available
DNS_FLAG_RD = 0x0100      # recursion desired
DNS_FLAG_RCODE_NOERROR = 0
DNS_FLAG_RCODE_SERVFAIL = 2
DNS_FLAG_RCODE_NXDOMAIN = 3

DNS_TYPE_A = 1
DNS_TYPE_AAAA = 28
DNS_CLASS_IN = 1

# How long an answer stays usable, and how many hostnames we keep. This is the
# TTL we also hand the chip, so nothing here outlives what the client was told.
_CACHE_TTL_S = 60.0
_CACHE_MAX = 512

# Longest we make the chip wait for a resolution before giving up on THIS query.
# lwIP retries a DNS lookup about once a second and gives up after a handful of
# tries, so a resolver that takes longer than this has already lost the race:
# holding the coroutine only guarantees the answer arrives after the client
# stopped caring. We drop the query instead and keep resolving in the
# background, so the client's own retry lands on a warm cache.
_RESOLVE_TIMEOUT_S = 1.5

# Resolutions slower than this are worth knowing about: an intermittent stall
# here is invisible from the sketch's side, which just sees a failed request.
_SLOW_RESOLVE_S = 0.5

# Process-wide, deliberately: a DnsResolver is created per bridge session, i.e.
# per Run, so a per-instance cache is cold every single time and every Run pays
# a full resolution before the chip gets its answer. That is what made a WiFi
# example fail on some Runs and not others. Answers are public data and the
# egress policy is re-applied on every hit (filter_resolved_ips), so sharing
# them across sessions costs nothing and cannot smuggle a private IP through.
_shared_cache: dict[str, tuple[float, list[bytes]]] = {}
_inflight: dict[str, "asyncio.Task[list[bytes]]"] = {}


def _cache_get(hostname: str) -> Optional[list[bytes]]:
    entry = _shared_cache.get(hostname)
    if entry is None:
        return None
    expires, addrs = entry
    if expires < asyncio.get_running_loop().time():
        _shared_cache.pop(hostname, None)
        return None
    return addrs


def _cache_put(hostname: str, addrs: list[bytes]) -> None:
    if len(_shared_cache) >= _CACHE_MAX:
        # Cheap eviction: drop whatever expires first.
        oldest = min(_shared_cache, key=lambda k: _shared_cache[k][0])
        _shared_cache.pop(oldest, None)
    _shared_cache[hostname] = (
        asyncio.get_running_loop().time() + _CACHE_TTL_S,
        addrs,
    )


class DnsResolver:
    """
    Async DNS resolver.

    Returns (chip_dst_ip, host_src_ip, udp_response) tuples that the
    bridge wraps into Ethernet+IPv4 and injects to the chip.
    """

    def __init__(self, on_egress=None) -> None:
        self._cache: dict[str, list[bytes]] = {}
        self._on_egress = on_egress or (lambda **kw: None)

    async def handle(
        self,
        chip_src_ip: bytes,
        udp: UDP,
    ) -> Optional[tuple[bytes, bytes, UDP]]:
        try:
            req = DnsMessage.parse(udp.payload)
        except ValueError:
            return None
        if not req.qd:
            return None
        qname, qtype, qclass = req.qd[0]

        # Build response skeleton (mirror txid + qd, RA flag).
        resp_flags = DNS_FLAG_QR | DNS_FLAG_RA | (req.flags & DNS_FLAG_RD)
        if qclass != DNS_CLASS_IN or qtype not in (DNS_TYPE_A, DNS_TYPE_AAAA):
            # Empty NOERROR reply.
            resp = DnsMessage(txid=req.txid, flags=resp_flags, qd=req.qd, an=[])
            return self._wrap(chip_src_ip, udp, resp)

        if qtype == DNS_TYPE_AAAA:
            # We don't proxy IPv6 — return NOERROR with no answers so the
            # client falls back to A-records.
            resp = DnsMessage(txid=req.txid, flags=resp_flags, qd=req.qd, an=[])
            return self._wrap(chip_src_ip, udp, resp)

        # velxiogw vendor patch: `host.velxio.internal` names the machine the
        # gateway runs on. Answered locally, never forwarded to the resolver.
        from .consts import HOST_ALIAS_HOSTNAME, HOST_ALIAS_IP
        if qname.lower().rstrip('.') == HOST_ALIAS_HOSTNAME:
            ip4 = socket.inet_aton(HOST_ALIAS_IP)
            self._on_egress(protocol='dns', verdict='allowed', dst_host=qname,
                            dst_ip=HOST_ALIAS_IP, reason='host_alias')
            resp = DnsMessage(txid=req.txid, flags=resp_flags, qd=req.qd,
                              an=[(qname, DNS_TYPE_A, DNS_CLASS_IN, 60, ip4)])
            return self._wrap(chip_src_ip, udp, resp)

        # A-record query. Resolve via host.
        addrs = await self._resolve_a(qname)
        if addrs is None:
            # Still resolving. Answering NXDOMAIN here would turn a slow
            # resolver into a hard failure for the sketch; saying nothing lets
            # lwIP's own retry pick up the cached answer a second later.
            return None
        if not addrs:
            # No usable answer: either NXDOMAIN or every A-record was a
            # non-global IP the egress filter dropped (rebinding attempt).
            self._on_egress(protocol='dns', verdict='blocked',
                            dst_host=qname, reason='no_answer')
            resp = DnsMessage(
                txid=req.txid,
                flags=resp_flags | DNS_FLAG_RCODE_NXDOMAIN,
                qd=req.qd,
                an=[],
            )
            return self._wrap(chip_src_ip, udp, resp)

        self._on_egress(protocol='dns', verdict='allowed', dst_host=qname,
                        dst_ip=socket.inet_ntoa(addrs[0]), reason='resolved')
        an = []
        for ip4 in addrs:
            an.append((qname, DNS_TYPE_A, DNS_CLASS_IN, 60, ip4))
        resp = DnsMessage(txid=req.txid, flags=resp_flags, qd=req.qd, an=an)
        return self._wrap(chip_src_ip, udp, resp)

    async def _resolve_a(self, hostname: str) -> Optional[list[bytes]]:
        """
        Resolve to A-records.

        Returns the (policy-filtered) addresses, an empty list for a definitive
        "no usable answer", or None when the resolution is taking longer than
        the client will wait — the caller then sends nothing and lets the chip
        retry, by which point the lookup has usually landed in the cache.

        The caches store the RAW resolution; filter_resolved_ips applies the
        egress policy on return (drops non-global answers — DNS-rebinding
        defense), so a rebinding domain never hands the chip a private or
        metadata IP even on a cache hit.
        """
        if hostname in self._cache:
            return filter_resolved_ips(self._cache[hostname])
        shared = _cache_get(hostname)
        if shared is not None:
            self._cache[hostname] = shared
            return filter_resolved_ips(shared)

        loop = asyncio.get_running_loop()
        task = _inflight.get(hostname)
        if task is None:
            task = loop.create_task(self._lookup(hostname))
            _inflight[hostname] = task
            task.add_done_callback(lambda _t, h=hostname: _inflight.pop(h, None))

        started = loop.time()
        try:
            deduped = await asyncio.wait_for(asyncio.shield(task), _RESOLVE_TIMEOUT_S)
        except asyncio.TimeoutError:
            # Leave the lookup running (shield keeps it alive) so the retry
            # this provokes finds it cached.
            logger.info(
                '[picow-dns] %s still resolving after %.1fs — dropping this query,'
                ' the client will retry', hostname, _RESOLVE_TIMEOUT_S,
            )
            return None
        except (socket.gaierror, OSError):
            return []

        elapsed = loop.time() - started
        if elapsed > _SLOW_RESOLVE_S:
            logger.info('[picow-dns] %s resolved in %.2fs (slow)', hostname, elapsed)
        self._cache[hostname] = deduped
        return filter_resolved_ips(deduped)

    async def _lookup(self, hostname: str) -> list[bytes]:
        """The actual host resolution, shared by everyone asking for this name."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                hostname, None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, OSError):
            _cache_put(hostname, [])
            return []
        addrs: list[bytes] = []
        for info in infos:
            sockaddr = info[4]
            if isinstance(sockaddr, tuple) and len(sockaddr) >= 1:
                ip = sockaddr[0]
                try:
                    addrs.append(socket.inet_aton(ip))
                except OSError:
                    continue
        # de-dup preserving order
        seen: set = set()
        deduped: list[bytes] = []
        for a in addrs:
            if a not in seen:
                deduped.append(a)
                seen.add(a)
        _cache_put(hostname, deduped)
        return deduped

    def _wrap(
        self,
        chip_src_ip: bytes,
        original_udp: UDP,
        resp: DnsMessage,
    ) -> tuple[bytes, bytes, UDP]:
        out_udp = UDP(
            src_port=53,
            dst_port=original_udp.src_port,
            payload=resp.to_bytes(),
        )
        return chip_src_ip, ip_to_bytes(DNS_IP), out_udp


def is_dns_traffic(udp: UDP) -> bool:
    return udp.dst_port == 53


def make_dns_frame(
    chip_mac: bytes,
    src_ip: bytes,
    dst_ip: bytes,
    udp: UDP,
) -> bytes:
    return make_frame_ipv4(
        dst_mac=chip_mac,
        src_mac=GATEWAY_MAC,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=17,
        l4_payload=udp.to_bytes(src_ip, dst_ip),
    )
