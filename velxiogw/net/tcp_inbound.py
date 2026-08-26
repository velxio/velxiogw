"""
TCP inbound — host-initiated connections INTO the chip's listening server.

The mirror image of ``tcp_nat.py``. Where TcpNat plays the *server* for
connections the chip opens outward, TcpInbound plays the *client* for
connections we open inward — so a browser can reach an HTTP server the
Pico W sketch is running on ``10.13.37.42:80``.

This is what makes Pico W web-server examples as useful as the ESP32
ones: the ESP32 server lives in QEMU and is reachable via slirp hostfwd,
but the Pico W server lives in the browser-side lwIP, reachable only by
injecting frames over the WebSocket bridge. We synthesize a TCP client
sourced from the gateway (``10.13.37.1``) and drive a one-shot HTTP
request/response, exactly the per-request shape the IoT-gateway proxy
already uses for the ESP32.

      CLOSED
        │ we send SYN
        ▼
      SYN_SENT          ── await chip SYN+ACK
        │ chip SYN+ACK; we send ACK + request
        ▼
      ESTABLISHED       ── pump response bytes chip → us, ACK them
        │ chip FIN (or Content-Length satisfied)
        ▼
      we ACK + FIN ──► CLOSED

Sequence arithmetic is modular-2³² and mirrors tcp_nat.py.
"""

from __future__ import annotations

import asyncio
import logging
import random
import struct
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, Optional, Tuple

from .consts import (
    GATEWAY_IP,
    GATEWAY_MAC,
    IPPROTO_TCP,
    STA_IP,
    TCP_ACK,
    TCP_FIN,
    TCP_MSS,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_WINDOW,
    ip_to_bytes,
)
from .protocols import IPv4, TCP, make_frame_ipv4, parse_tcp_options

logger = logging.getLogger(__name__)

InjectFn = Callable[[bytes], Awaitable[None]]
ChipMacFn = Callable[[], bytes]

_GW_IP = ip_to_bytes(GATEWAY_IP)
_STA_IP = ip_to_bytes(STA_IP)


def _seq_add(a: int, b: int) -> int:
    return (a + b) & 0xffffffff


class _State:
    SYN_SENT = 'SYN_SENT'
    ESTABLISHED = 'ESTABLISHED'
    CLOSED = 'CLOSED'


@dataclass
class _InboundConn:
    chip_port: int                  # = 80 (server port on the chip)
    our_port: int                   # ephemeral gateway-side port
    state: str = _State.SYN_SENT
    our_isn: int = 0
    our_seq: int = 0                # next seq we put on the wire chipward
    chip_seq: int = 0               # next seq we expect from the chip
    rx: bytearray = field(default_factory=bytearray)
    established: asyncio.Event = field(default_factory=asyncio.Event)
    finished: asyncio.Event = field(default_factory=asyncio.Event)
    data_event: asyncio.Event = field(default_factory=asyncio.Event)
    reset: bool = False


class TcpInbound:
    """One-shot host→chip TCP client used by the IoT gateway."""

    def __init__(self, inject: InjectFn, chip_mac: ChipMacFn) -> None:
        self._inject = inject
        self._chip_mac = chip_mac
        self._conns: Dict[int, _InboundConn] = {}   # keyed by our ephemeral port

    # ── routing predicate (called by the bridge before the outbound NAT) ──

    def matches(self, ip: IPv4, tcp: TCP) -> bool:
        return (
            tcp.dst_port in self._conns
            and tcp.src_port == self._conns[tcp.dst_port].chip_port
            and bytes(ip.src) == _STA_IP
            and bytes(ip.dst) == _GW_IP
        )

    # ── chip → us (segments from the chip's server) ────────────────────

    async def handle_chip_segment(self, ip: IPv4, tcp: TCP) -> None:
        conn = self._conns.get(tcp.dst_port)
        if conn is None:
            return

        if tcp.flags & TCP_RST:
            conn.reset = True
            conn.state = _State.CLOSED
            conn.established.set()
            conn.finished.set()
            return

        if conn.state == _State.SYN_SENT:
            if (tcp.flags & TCP_SYN) and (tcp.flags & TCP_ACK):
                conn.chip_seq = _seq_add(tcp.seq, 1)   # SYN consumes one seq
                conn.state = _State.ESTABLISHED
                await self._send(conn, TCP_ACK)        # complete the handshake
                conn.established.set()
            return

        if conn.state != _State.ESTABLISHED:
            # TIME_WAIT (or pre-handshake): re-ACK late retransmits so the chip
            # closes cleanly. Never let it reach the outbound NAT (RST).
            if tcp.payload or (tcp.flags & (TCP_FIN | TCP_SYN)):
                await self._send(conn, TCP_ACK)
            return

        # In-order data only; re-ACK and drop anything out of order so the
        # chip retransmits (these servers send tiny, in-order responses).
        if tcp.payload:
            if tcp.seq == conn.chip_seq:
                conn.rx.extend(tcp.payload)
                conn.chip_seq = _seq_add(conn.chip_seq, len(tcp.payload))
                await self._send(conn, TCP_ACK)
                conn.data_event.set()
            else:
                await self._send(conn, TCP_ACK)        # force retransmit
                return

        if tcp.flags & TCP_FIN:
            conn.chip_seq = _seq_add(conn.chip_seq, 1)
            # ACK the FIN, then send our own FIN to close cleanly.
            await self._send(conn, TCP_ACK)
            await self._send(conn, TCP_FIN | TCP_ACK)
            conn.our_seq = _seq_add(conn.our_seq, 1)
            conn.state = _State.CLOSED
            conn.finished.set()

    # ── public one-shot request ────────────────────────────────────────

    async def request(self, raw_http: bytes, timeout: float = 12.0) -> Optional[bytes]:
        """Open a connection to the chip's :80 server, send ``raw_http``,
        return the raw HTTP response bytes (or None on failure)."""
        our_port = self._alloc_port()
        our_isn = random.randint(0, 0xffffffff)
        conn = _InboundConn(
            chip_port=80,
            our_port=our_port,
            our_isn=our_isn,
            our_seq=_seq_add(our_isn, 1),   # our SYN consumes one seq
        )
        self._conns[our_port] = conn
        try:
            # SYN (advertise MSS, like the chip does).
            await self._send(conn, TCP_SYN, seq=our_isn,
                             options=b'\x02\x04' + struct.pack('!H', TCP_MSS))
            try:
                await asyncio.wait_for(conn.established.wait(), timeout=4.0)
            except asyncio.TimeoutError:
                logger.info('[picow-tcp-in] SYN to chip:80 timed out')
                return None
            if conn.reset or conn.state != _State.ESTABLISHED:
                return None

            # Send the HTTP request.
            await self._send(conn, TCP_PSH | TCP_ACK, payload=raw_http)
            conn.our_seq = _seq_add(conn.our_seq, len(raw_http))

            # Collect the response until the chip FINs, the body is complete
            # per Content-Length, or we go idle.
            deadline = asyncio.get_event_loop().time() + timeout
            while not conn.finished.is_set():
                if _http_response_complete(conn.rx):
                    break
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                conn.data_event.clear()
                try:
                    # Wake on new data; also poll so the idle/length checks run.
                    await asyncio.wait_for(conn.data_event.wait(), timeout=min(remaining, 1.5))
                except asyncio.TimeoutError:
                    if conn.rx and _http_headers_complete(conn.rx):
                        break   # got a full header block and went idle — good enough
            return bytes(conn.rx) if conn.rx else None
        finally:
            # TIME_WAIT: keep the connection around briefly so late chip
            # segments (a retransmitted FIN, a trailing ACK) still match this
            # connection and get absorbed/re-ACKed here, instead of falling
            # through to the chip-initiated NAT which would RST them — a RST
            # crashes blocking-socket sketches with ECONNRESET.
            conn.state = _State.CLOSED
            loop = asyncio.get_event_loop()
            loop.call_later(5.0, self._conns.pop, our_port, None)

    # ── frame emission ─────────────────────────────────────────────────

    async def _send(
        self,
        conn: _InboundConn,
        flags: int,
        seq: Optional[int] = None,
        options: bytes = b'',
        payload: bytes = b'',
    ) -> None:
        tcp = TCP(
            src_port=conn.our_port,
            dst_port=conn.chip_port,
            seq=(conn.our_seq if seq is None else seq) & 0xffffffff,
            ack=conn.chip_seq,
            flags=flags,
            window=TCP_WINDOW,
            options=options,
            payload=payload,
        )
        l4 = tcp.to_bytes(_GW_IP, _STA_IP)
        frame = make_frame_ipv4(
            dst_mac=self._chip_mac(),
            src_mac=GATEWAY_MAC,
            src_ip=_GW_IP,
            dst_ip=_STA_IP,
            protocol=IPPROTO_TCP,
            l4_payload=l4,
        )
        await self._inject(frame)

    def _alloc_port(self) -> int:
        for _ in range(64):
            port = random.randint(49152, 65535)
            if port not in self._conns:
                return port
        # Extremely unlikely; fall back to a linear scan.
        for port in range(49152, 65536):
            if port not in self._conns:
                return port
        raise RuntimeError('no free ephemeral port')

    async def shutdown(self) -> None:
        for conn in list(self._conns.values()):
            conn.reset = True
            conn.finished.set()
            conn.established.set()
        self._conns.clear()


# ─── HTTP framing helpers (just enough to know when a reply is done) ────

def _http_headers_complete(buf: bytearray) -> bool:
    return b'\r\n\r\n' in buf or b'\n\n' in buf


def _http_response_complete(buf: bytearray) -> bool:
    """True once we have a full header block plus a body matching
    Content-Length (if any). Without a length we wait for FIN/idle."""
    sep = buf.find(b'\r\n\r\n')
    sep_len = 4
    if sep < 0:
        sep = buf.find(b'\n\n')
        sep_len = 2
        if sep < 0:
            return False
    header_blob = bytes(buf[:sep]).lower()
    idx = header_blob.find(b'content-length:')
    if idx < 0:
        return False  # no declared length — rely on FIN / idle
    try:
        line = header_blob[idx:].split(b'\n', 1)[0]
        length = int(line.split(b':', 1)[1].strip())
    except (ValueError, IndexError):
        return False
    body_len = len(buf) - (sep + sep_len)
    return body_len >= length


__all__ = ['TcpInbound']
