"""
PicowNetBridge — top-level orchestrator that ties every subsystem
together and exposes the same shape ``picow_net_bridge.py`` did before.

One bridge instance per simulated chip. The chip emits Ethernet frames
through the WebSocket; each frame goes through ``deliver_packet_out``
which demuxes by ethertype, then by IP protocol or UDP port.

Inbound (host → chip) traffic gets queued via ``inject`` and the WS
worker drains it through the ``picow_packet_in`` event channel.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from .arp import ArpResponder
from .consts import (
    ARP_REQUEST,
    BROADCAST_MAC,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    GATEWAY_IP,
    GATEWAY_MAC,
    IPPROTO_ICMP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    STA_IP,
    STA_MAC,
    ip_to_bytes,
)
from .dhcp import (
    DhcpServer,
    is_dhcp_traffic,
    make_dhcp_frame,
)
from . import egress_log
from .dns import DnsResolver, is_dns_traffic, make_dns_frame
from .icmp import IcmpResponder
from .protocols import Arp, Ethernet, IPv4, TCP, UDP, make_frame_arp
from .tcp_inbound import TcpInbound
from .tcp_nat import TcpNat
from .udp_nat import UdpNat

logger = logging.getLogger(__name__)

EmitFn = Callable[[str, dict], Awaitable[None]]


class PicowNetBridge:
    """Stack of L2..L7 network helpers for one Pico W simulation."""

    def __init__(
        self,
        client_id: str,
        emit: EmitFn,
        wifi_enabled: bool,
        *,
        user_id: str | None = None,
        project_id: str | None = None,
        session_id: str | None = None,
        board_kind: str = 'pi-pico-w',
    ) -> None:
        self.client_id = client_id
        self._emit = emit
        self.wifi_enabled = wifi_enabled
        # Owning identity for egress telemetry (resolved by the WS handler).
        self.user_id = user_id
        self.project_id = project_id
        self.session_id = session_id
        # Chip family for egress attribution only (cosmetic; the L2/L3 stack is
        # chip-agnostic). Threaded from the start_picow message so an ESP32
        # net-bridge (which reuses this same picow_net stack, P4.5) attributes to
        # 'esp32' instead of the Pico W default. Never affects NAT or egress_guard.
        self.board_kind = board_kind
        self.running = True
        self._chip_mac = STA_MAC

        self._arp = ArpResponder()
        self._dhcp = DhcpServer()
        self._dns = DnsResolver(on_egress=self._emit_egress)
        self._icmp = IcmpResponder()
        self._tcp = TcpNat(self._inject, on_egress=self._emit_egress)
        self._tcp_in = TcpInbound(self._inject, lambda: self._chip_mac)
        self._udp = UdpNat(self._inject, on_egress=self._emit_egress)

    def _emit_egress(
        self,
        *,
        protocol: str,
        verdict: str,
        dst_ip: str | None = None,
        dst_port: int | None = None,
        dst_host: str | None = None,
        reason: str = '',
    ) -> None:
        """Tag a network fact with this bridge's identity and hand it to the
        egress log sink (a no-op when no writer is installed). Never raises."""
        egress_log.record({
            'client_id': self.client_id,
            'user_id': self.user_id,
            'project_id': self.project_id,
            'session_id': self.session_id,
            'board_kind': self.board_kind,
            'protocol': protocol,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'dst_host': dst_host,
            'verdict': verdict,
            'reason': reason,
        })

    # ── lifecycle ──────────────────────────────────────────────────

    async def start(self) -> None:
        await self._emit('wifi_status', {
            'status': 'started',
            'ssid': 'Velxio-GUEST' if self.wifi_enabled else None,
            'ip': STA_IP if self.wifi_enabled else None,
        })

    async def stop(self) -> None:
        self.running = False
        await asyncio.gather(
            self._tcp.shutdown(),
            self._tcp_in.shutdown(),
            self._udp.shutdown(),
            return_exceptions=True,
        )

    # ── chip → host ────────────────────────────────────────────────

    async def deliver_packet_out(self, ether_bytes: bytes) -> None:
        if not self.running or not self.wifi_enabled:
            return
        try:
            frame = Ethernet.parse(ether_bytes)
        except ValueError:
            return

        # Track the chip's MAC. The first frame we see (often a DHCP
        # DISCOVER while ciaddr is 0.0.0.0) tells us what to use.
        if frame.src and any(b for b in frame.src):
            self._chip_mac = bytes(frame.src)

        if frame.ethertype == ETHERTYPE_ARP:
            reply = self._arp.handle(frame)
            if reply is not None:
                await self._inject(reply)
            return

        if frame.ethertype != ETHERTYPE_IPV4:
            return  # IPv6 dropped silently

        try:
            ip = IPv4.parse(frame.payload)
        except ValueError:
            return

        if ip.protocol == IPPROTO_ICMP:
            reply = self._icmp.handle(self._chip_mac, ip)
            if reply is not None:
                await self._inject(reply)
            return

        if ip.protocol == IPPROTO_UDP:
            try:
                udp = UDP.parse(ip.payload)
            except ValueError:
                return
            await self._handle_udp(self._chip_mac, ip, udp)
            return

        if ip.protocol == IPPROTO_TCP:
            try:
                tcp = TCP.parse(ip.payload)
            except ValueError:
                return
            # A reply to a connection WE opened into the chip's server (the
            # IoT gateway) takes priority over the chip-initiated NAT, which
            # would otherwise RST it as a stray segment.
            if self._tcp_in.matches(ip, tcp):
                await self._tcp_in.handle_chip_segment(ip, tcp)
                return
            await self._tcp.handle_chip_segment(self._chip_mac, ip, tcp)
            return

        # Unknown L4 — drop.

    async def _handle_udp(self, chip_mac: bytes, ip: IPv4, udp: UDP) -> None:
        # Special case: DHCP. We pretend to be the gateway/server.
        if is_dhcp_traffic(udp):
            result = self._dhcp.handle(chip_mac, udp)
            if result is None:
                return
            dst_ip, src_ip, out_udp = result
            frame = make_dhcp_frame(chip_mac, src_ip, dst_ip, out_udp)
            await self._inject(frame)
            return
        # Special case: DNS to our synthetic resolver.
        if is_dns_traffic(udp) and bytes(ip.dst) == ip_to_bytes(GATEWAY_IP):
            result = await self._dns.handle(bytes(ip.src), udp)
            if result is None:
                return
            chip_dst_ip, host_src_ip, out_udp = result
            await self._inject(make_dns_frame(chip_mac, host_src_ip, chip_dst_ip, out_udp))
            return
        # Anything else — generic UDP NAT.
        await self._udp.handle_chip_datagram(chip_mac, ip, udp)

    # ── host → chip: inbound HTTP (IoT gateway) ────────────────────

    async def ensure_chip_mac(self) -> bytes:
        """Prime the chip's ARP cache for the gateway before we open a
        connection into it, so its SYN+ACK doesn't stall on a lookup.

        The chip's on-wire MAC is deterministically DEFAULT_STA_MAC
        (frontend virtual-ap.ts), which equals our STA_MAC, so the default
        ``_chip_mac`` is already the right destination — we don't need to
        learn it. If the chip ever sent an outbound frame, the learned MAC
        is used instead. We still emit one gratuitous ARP for the STA so the
        chip resolves the gateway promptly, then return without blocking."""
        req = Arp(
            opcode=ARP_REQUEST,
            sha=GATEWAY_MAC,
            spa=ip_to_bytes(GATEWAY_IP),
            tha=b'\x00' * 6,
            tpa=ip_to_bytes(STA_IP),
        )
        await self._inject(make_frame_arp(BROADCAST_MAC, GATEWAY_MAC, req))
        await asyncio.sleep(0.05)
        return self._chip_mac

    async def http_into_chip(self, raw_http: bytes, timeout: float = 12.0) -> bytes | None:
        """Open a TCP connection to the chip's :80 server, send a raw HTTP
        request, and return the raw HTTP response bytes (or None)."""
        if not self.running or not self.wifi_enabled:
            return None
        await self.ensure_chip_mac()
        return await self._tcp_in.request(raw_http, timeout=timeout)

    # ── host → chip ────────────────────────────────────────────────

    async def _inject(self, frame: bytes) -> None:
        """Queue an Ethernet frame for the chip via the WS bridge."""
        if not self.running:
            return
        import base64
        await self._emit('picow_packet_in', {
            'ether_b64': base64.b64encode(frame).decode('ascii'),
        })


__all__ = ['PicowNetBridge']
