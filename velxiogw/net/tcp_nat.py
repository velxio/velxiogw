"""
TCP NAT — chip-initiated outbound connections to the host network.

The implementation follows RFC 793 §3.4-§3.9 closely enough to handle
real-world MicroPython workloads:

  - Three-way handshake (SYN → SYN+ACK → ACK)
  - Bidirectional data flow with proper seq/ack accounting
  - Half-close handling (FIN from either side)
  - RST as the cheap escape hatch on protocol errors
  - MSS option negotiation (we advertise TCP_MSS = MTU - 40)
  - Window clamped to TCP_WINDOW (no window scaling)

Per-connection state lives in a TcpConnection object keyed by
(chip_port, dst_ip, dst_port). Each connection owns an asyncio
StreamReader/StreamWriter to the real host endpoint.

States we transition through, simplified to chip-initiated only:

      CLOSED
        │ chip SYN
        ▼
      SYN_RCVD          ── send SYN+ACK back to chip
        │ chip ACK
        ▼
      ESTABLISHED       ── pump bytes both ways
        │
        ├── chip FIN ──► CLOSE_WAIT  ── after host close: LAST_ACK ──► CLOSED
        └── host EOF ──► FIN_WAIT_1  ── after chip ACK:   FIN_WAIT_2 ──► CLOSED

We deliberately don't implement TIME_WAIT — the chip does, we just GC
once both sides have FIN'd. This is the same simplification slirp uses.

Sequence numbers wrap at 2³² — every comparison goes through
``_seq_lt`` / ``_seq_geq`` which use modular arithmetic.
"""

from __future__ import annotations

import asyncio
import logging
import random
import struct
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, Optional, Tuple

from .consts import (
    GATEWAY_MAC,
    IPPROTO_TCP,
    TCP_ACK,
    TCP_FIN,
    TCP_MSS,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_WINDOW,
    bytes_to_ip,
)
from .egress_guard import is_allowed_dst
from .protocols import IPv4, TCP, make_frame_ipv4, parse_tcp_options

logger = logging.getLogger(__name__)

# Per-attempt connect timeouts, in seconds. Each entry is one fresh socket and
# therefore one fresh SYN; the sum is the total budget a chip SYN can spend
# before we RST it. See TcpNat._connect_with_retries.
_CONNECT_ATTEMPT_TIMEOUTS = (0.6, 0.9, 1.5, 2.5, 4.0)

# How long the chip's SYN waits for a real host connection before we answer it
# anyway and open the socket underneath. Short enough that the guest never
# notices, long enough that a refusal or a fast failure still turns into the
# RST it should be. See TcpNat._on_passive_syn.
_EARLY_SYNACK_GRACE = 0.35

InjectFn = Callable[[bytes], Awaitable[None]]


# ─── Sequence number arithmetic (modular 32-bit) ─────────────────────

def _seq_add(a: int, b: int) -> int:
    return (a + b) & 0xffffffff


def _seq_lt(a: int, b: int) -> bool:
    """RFC 1323-style: a < b modulo 2^32."""
    return ((a - b) & 0xffffffff) >= 0x80000000


def _seq_leq(a: int, b: int) -> bool:
    return a == b or _seq_lt(a, b)


def _seq_diff(a: int, b: int) -> int:
    """Distance a - b modulo 2^32, signed."""
    d = (a - b) & 0xffffffff
    if d & 0x80000000:
        d -= 0x100000000
    return d


# ─── Per-connection state ────────────────────────────────────────────

class _State:
    SYN_RCVD = 'SYN_RCVD'
    ESTABLISHED = 'ESTABLISHED'
    FIN_WAIT_1 = 'FIN_WAIT_1'      # we (host side) sent FIN, waiting for chip ACK
    FIN_WAIT_2 = 'FIN_WAIT_2'      # chip ACKed our FIN
    CLOSE_WAIT = 'CLOSE_WAIT'      # chip sent FIN, host still has more to send
    LAST_ACK = 'LAST_ACK'          # both sides FIN'd, waiting for last ACK
    CLOSED = 'CLOSED'


@dataclass
class TcpConnection:
    chip_ip: bytes
    chip_port: int
    dst_ip: bytes
    dst_port: int
    chip_mac: bytes
    state: str = _State.CLOSED
    chip_isn: int = 0          # initial chip seq we observed
    our_isn: int = 0           # initial seq we picked
    our_seq: int = 0           # next seq we'll put on the wire chipward
    chip_seq: int = 0          # next seq we expect from chip
    chip_window: int = 0
    mss: int = TCP_MSS
    host_reader: Optional[asyncio.StreamReader] = None
    host_writer: Optional[asyncio.StreamWriter] = None
    host_pump_task: Optional[asyncio.Task] = None
    last_activity: float = 0.0
    # Set while the host-side socket is still being opened AFTER we have
    # already answered the chip's SYN. See TcpNat._on_passive_syn.
    pending_connect: Optional[asyncio.Task] = None
    pending_payload: bytearray = field(default_factory=bytearray)
    pending_eof: bool = False

    def key(self) -> Tuple[bytes, int, bytes, int]:
        return (self.chip_ip, self.chip_port, self.dst_ip, self.dst_port)


# ─── NAT manager ─────────────────────────────────────────────────────

class TcpNat:
    """
    Manages every chip-initiated TCP connection. ``inject`` is the
    callback the bridge gives us to push Ethernet frames back to the
    chip; calls into the manager are made from the bridge whenever an
    IP-with-protocol-TCP frame arrives from the chip.
    """

    def __init__(self, inject: InjectFn, on_egress=None) -> None:
        self._inject = inject
        # on_egress(**fields) -> None : bridge-provided egress telemetry sink
        # (tags the connection with user/project and logs it). Default no-op.
        self._on_egress = on_egress or (lambda **kw: None)
        self._conns: Dict[Tuple[bytes, int, bytes, int], TcpConnection] = {}
        # Connections whose host-side socket is still being opened. The chip
        # retransmits its SYN while it waits, and a second _on_passive_syn
        # would open a second socket with a second ISN.
        self._connecting: set[Tuple[bytes, int, bytes, int]] = set()

    # ── Entry point from the bridge ────────────────────────────────

    async def handle_chip_segment(
        self, chip_mac: bytes, ip: IPv4, tcp: TCP,
    ) -> None:
        key = (bytes(ip.src), tcp.src_port, bytes(ip.dst), tcp.dst_port)
        conn = self._conns.get(key)

        if tcp.flags & TCP_RST:
            # Chip aborted — tear down silently.
            if conn:
                await self._close(conn, send_rst=False)
            return

        if conn is None:
            if tcp.flags & TCP_SYN and not (tcp.flags & TCP_ACK):
                if key in self._connecting:
                    # SYN retransmit while we are still opening the host side.
                    # Dropping it is what a real gateway does: the chip's own
                    # retransmit timer keeps the attempt alive, and we answer
                    # once with the ISN we already picked.
                    return
                await self._on_passive_syn(chip_mac, ip, tcp)
            else:
                # Stray segment with no connection: respond with RST.
                await self._send_rst(chip_mac, ip, tcp)
            return

        # Update bookkeeping that's the same in every state.
        conn.chip_window = tcp.window

        if conn.state == _State.SYN_RCVD:
            await self._on_handshake_complete(conn, tcp)
        elif conn.state == _State.ESTABLISHED:
            await self._on_data(conn, tcp)
        elif conn.state == _State.FIN_WAIT_1:
            await self._on_fin_wait_1(conn, tcp)
        elif conn.state == _State.FIN_WAIT_2:
            await self._on_fin_wait_2(conn, tcp)
        elif conn.state == _State.CLOSE_WAIT:
            # Chip should be quiet; ignore unless RST/FIN retransmit.
            pass
        elif conn.state == _State.LAST_ACK:
            if tcp.flags & TCP_ACK and _seq_geq_or_eq(tcp.ack, _seq_add(conn.our_seq, 0)):
                await self._close(conn, send_rst=False)

    # ── State handlers ─────────────────────────────────────────────

    async def _on_passive_syn(self, chip_mac: bytes, ip: IPv4, tcp: TCP) -> None:
        """Chip is opening a new connection — we play the server."""
        opts = parse_tcp_options(tcp.options)
        mss = opts.get('mss', TCP_MSS)
        if mss > TCP_MSS:
            mss = TCP_MSS

        our_isn = random.randint(0, 0xffffffff)
        conn = TcpConnection(
            chip_ip=bytes(ip.src),
            chip_port=tcp.src_port,
            dst_ip=bytes(ip.dst),
            dst_port=tcp.dst_port,
            chip_mac=chip_mac,
            state=_State.CLOSED,
            chip_isn=tcp.seq,
            our_isn=our_isn,
            our_seq=_seq_add(our_isn, 1),     # SYN counts as 1 byte
            chip_seq=_seq_add(tcp.seq, 1),
            chip_window=tcp.window,
            mss=mss,
            last_activity=asyncio.get_event_loop().time(),
        )

        # Egress guard: refuse SSRF/relay targets (private, loopback,
        # link-local incl. cloud metadata 169.254.169.254). The backend would
        # otherwise open a real socket to whatever the chip asks for.
        dst_ip_str = bytes_to_ip(conn.dst_ip)
        # velxiogw vendor patch: host.velxio.internal resolves to HOST_ALIAS_IP;
        # the real socket goes to the machine's own loopback.
        from .consts import HOST_ALIAS_IP
        if dst_ip_str == HOST_ALIAS_IP:
            dst_ip_str = '127.0.0.1'
        allowed, reason = is_allowed_dst(dst_ip_str, conn.dst_port)
        if not allowed:
            logger.warning(
                '[picow-tcp] BLOCKED egress to %s:%d (%s)',
                dst_ip_str, conn.dst_port, reason,
            )
            self._on_egress(protocol='tcp', verdict='blocked',
                            dst_ip=dst_ip_str, dst_port=conn.dst_port, reason=reason)
            await self._send_rst(chip_mac, ip, tcp)
            return
        self._on_egress(protocol='tcp', verdict='allowed',
                        dst_ip=dst_ip_str, dst_port=conn.dst_port, reason='ok')

        # Open the host-side connection. A far side that answers — with a
        # SYN+ACK, a refusal, an unreachable — answers inside the grace, and
        # we hold the chip's SYN until we know. A far side that says nothing
        # is a different story: the guest's own connect timeout is shorter
        # than our budget for reaching it, so waiting here just guarantees the
        # sketch fails. Answer the chip, open the socket underneath, and hold
        # whatever it sends until the socket is there. This is what slirp and
        # every other user-mode NAT does with a slow connect.
        key = conn.key()
        self._connecting.add(key)
        connect_task = asyncio.create_task(
            self._connect_with_retries(dst_ip_str, conn.dst_port))
        done, _pending = await asyncio.wait({connect_task},
                                            timeout=_EARLY_SYNACK_GRACE)

        if connect_task in done:
            self._connecting.discard(key)
            opened = connect_task.result()
            if opened is None:
                await self._send_rst(chip_mac, ip, tcp)
                return
            conn.host_reader, conn.host_writer = opened
        else:
            conn.pending_connect = asyncio.create_task(
                self._finish_deferred_connect(conn, connect_task, key))

        conn.state = _State.SYN_RCVD
        self._conns[key] = conn

        # Send SYN+ACK back. Advertise our MSS option.
        await self._send(conn, flags=TCP_SYN | TCP_ACK,
                         seq=conn.our_isn, ack=conn.chip_seq,
                         options=_mss_option(conn.mss))

        # Start the host → chip pump. It will block until handshake completes.
        # A deferred connect starts its own pump once the socket exists.
        if conn.host_reader is not None:
            conn.host_pump_task = asyncio.create_task(self._pump_host_to_chip(conn))

    async def _finish_deferred_connect(
        self, conn: TcpConnection, connect_task: "asyncio.Task", key,
    ) -> None:
        """Attach the host socket to a connection the chip already believes in."""
        try:
            opened = await connect_task
        finally:
            self._connecting.discard(key)
        conn.pending_connect = None

        if conn.state == _State.CLOSED:
            # Torn down while we were still dialling.
            if opened is not None:
                try:
                    opened[1].close()
                except Exception:
                    pass
            return

        if opened is None:
            # The chip is holding an ESTABLISHED connection to nobody. RST is
            # the honest answer and the one its stack handles cleanly.
            logger.info(
                '[picow-tcp] %s:%d never answered; resetting the chip\'s connection',
                bytes_to_ip(conn.dst_ip), conn.dst_port,
            )
            await self._close(conn, send_rst=True)
            return

        conn.host_reader, conn.host_writer = opened
        if conn.pending_payload:
            held = bytes(conn.pending_payload)
            conn.pending_payload.clear()
            try:
                conn.host_writer.write(held)
                await conn.host_writer.drain()
            except (ConnectionError, OSError):
                await self._close(conn, send_rst=True)
                return
        if conn.pending_eof:
            conn.pending_eof = False
            try:
                conn.host_writer.write_eof()
            except (OSError, ConnectionError):
                pass
        conn.host_pump_task = asyncio.create_task(self._pump_host_to_chip(conn))

    async def _connect_with_retries(
        self, host: str, port: int,
    ) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        """
        Open the host-side socket, retrying a dropped SYN ourselves.

        Servers on the public internet drop SYNs — api.open-notify.org, which
        Pimoroni's own astronauts example talks to, drops roughly one in four.
        One socket with a long timeout does not survive that: the kernel's
        retransmit ladder is 1s, 3s, 7s, 15s, so a single lost SYN costs at
        least a second and often seven. The guest gives up long before that.
        arduino-pico's HTTPClient allows 5 s of GUEST time, and guest time can
        run up to IDLE_SKIP_OVERRUN times faster than the wall clock while the
        sketch sits in delay() — so the real budget here is under a second in
        the bad case, and the sketch prints HTTP -1.

        A fresh socket sends a fresh SYN immediately, so short attempts back to
        back beat one long wait: five tries inside the old 10 s budget, and a
        host dropping a quarter of its SYNs now fails about one connection in a
        thousand instead of one in four.
        """
        last: Optional[BaseException] = None
        for attempt, timeout in enumerate(_CONNECT_ATTEMPT_TIMEOUTS):
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout,
                )
            except asyncio.TimeoutError as e:
                # No answer yet. Almost always a dropped SYN — try a new socket.
                last = e
                continue
            except OSError as e:
                # Refused, unreachable, no route: a real answer from the far
                # side (or from our own stack). Retrying cannot change it.
                logger.info('[picow-tcp] connect %s:%d failed: %s', host, port, e)
                return None
        logger.info(
            '[picow-tcp] connect %s:%d gave up after %d attempts (%.1fs): %r',
            host, port, len(_CONNECT_ATTEMPT_TIMEOUTS),
            sum(_CONNECT_ATTEMPT_TIMEOUTS), last,
        )
        return None

    async def _on_handshake_complete(self, conn: TcpConnection, tcp: TCP) -> None:
        """We're SYN_RCVD; this should be the chip's ACK of our SYN+ACK."""
        if not (tcp.flags & TCP_ACK):
            return
        if tcp.ack != conn.our_seq:
            # Stale or duplicate; ignore.
            return
        conn.state = _State.ESTABLISHED
        # Some clients piggyback data on the final handshake ACK.
        if tcp.payload:
            await self._on_data(conn, tcp)

    async def _on_data(self, conn: TcpConnection, tcp: TCP) -> None:
        # Reject out-of-order. The chip will retransmit.
        if tcp.payload:
            if tcp.seq != conn.chip_seq:
                # Re-ACK what we have (forces retransmit).
                await self._ack_only(conn)
                return
            if conn.host_writer is None:
                # Host side still being opened — hold the bytes, ACK them, and
                # let _finish_deferred_connect flush them in order.
                conn.pending_payload += tcp.payload
            else:
                try:
                    conn.host_writer.write(tcp.payload)
                    await conn.host_writer.drain()
                except (ConnectionError, OSError):
                    await self._close(conn, send_rst=True)
                    return
            conn.chip_seq = _seq_add(conn.chip_seq, len(tcp.payload))
            await self._ack_only(conn)
        elif (tcp.flags & TCP_ACK) and tcp.ack and tcp.seq == conn.chip_seq:
            # Pure ACK or keep-alive — nothing to do.
            pass

        if tcp.flags & TCP_FIN:
            conn.chip_seq = _seq_add(conn.chip_seq, 1)
            conn.state = _State.CLOSE_WAIT
            # Tell the host side we're done sending.
            if conn.host_writer is not None:
                try:
                    conn.host_writer.write_eof()
                except (OSError, ConnectionError):
                    pass
            else:
                conn.pending_eof = True
            await self._ack_only(conn)
            # Stay in CLOSE_WAIT until the host pump finishes draining
            # whatever's still inbound, then it transitions to LAST_ACK.

    async def _on_fin_wait_1(self, conn: TcpConnection, tcp: TCP) -> None:
        # Waiting for the chip to ACK our FIN.
        if (tcp.flags & TCP_ACK) and tcp.ack == conn.our_seq:
            conn.state = _State.FIN_WAIT_2
        if tcp.flags & TCP_FIN:
            conn.chip_seq = _seq_add(conn.chip_seq, 1)
            await self._ack_only(conn)
            await self._close(conn, send_rst=False)

    async def _on_fin_wait_2(self, conn: TcpConnection, tcp: TCP) -> None:
        if tcp.flags & TCP_FIN:
            conn.chip_seq = _seq_add(conn.chip_seq, 1)
            await self._ack_only(conn)
            await self._close(conn, send_rst=False)

    # ── Host → chip pump ───────────────────────────────────────────

    async def _pump_host_to_chip(self, conn: TcpConnection) -> None:
        """Read bytes from the real host socket and segment them to the chip."""
        try:
            assert conn.host_reader is not None
            # Wait for handshake to complete before pushing.
            while conn.state == _State.SYN_RCVD:
                await asyncio.sleep(0.005)

            while conn.state in (_State.ESTABLISHED, _State.CLOSE_WAIT):
                chunk = await conn.host_reader.read(conn.mss)
                if not chunk:
                    break
                # Segment if needed (read() should already cap at mss).
                while chunk:
                    seg = chunk[:conn.mss]
                    chunk = chunk[conn.mss:]
                    await self._send(
                        conn, flags=TCP_ACK | TCP_PSH,
                        seq=conn.our_seq, ack=conn.chip_seq,
                        payload=seg,
                    )
                    conn.our_seq = _seq_add(conn.our_seq, len(seg))
                    conn.last_activity = asyncio.get_event_loop().time()

            # Host side EOF — send FIN.
            if conn.state == _State.ESTABLISHED:
                conn.state = _State.FIN_WAIT_1
                await self._send(conn, flags=TCP_ACK | TCP_FIN,
                                 seq=conn.our_seq, ack=conn.chip_seq)
                conn.our_seq = _seq_add(conn.our_seq, 1)
            elif conn.state == _State.CLOSE_WAIT:
                conn.state = _State.LAST_ACK
                await self._send(conn, flags=TCP_ACK | TCP_FIN,
                                 seq=conn.our_seq, ack=conn.chip_seq)
                conn.our_seq = _seq_add(conn.our_seq, 1)

        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception('[picow-tcp] pump crashed')
            await self._close(conn, send_rst=True)

    # ── Frame emission ─────────────────────────────────────────────

    async def _send(
        self,
        conn: TcpConnection,
        flags: int,
        seq: int,
        ack: int,
        options: bytes = b'',
        payload: bytes = b'',
    ) -> None:
        tcp = TCP(
            src_port=conn.dst_port,             # chip's "remote" = our destination
            dst_port=conn.chip_port,
            seq=seq & 0xffffffff,
            ack=ack & 0xffffffff,
            flags=flags,
            window=TCP_WINDOW,
            options=options,
            payload=payload,
        )
        # Note: we swap src/dst here because we're emitting the chip's
        # peer's segment — what would have come back from the host.
        ipv4_payload = tcp.to_bytes(conn.dst_ip, conn.chip_ip)
        frame = make_frame_ipv4(
            dst_mac=conn.chip_mac,
            src_mac=GATEWAY_MAC,
            src_ip=conn.dst_ip,
            dst_ip=conn.chip_ip,
            protocol=IPPROTO_TCP,
            l4_payload=ipv4_payload,
        )
        await self._inject(frame)

    async def _ack_only(self, conn: TcpConnection) -> None:
        await self._send(
            conn, flags=TCP_ACK,
            seq=conn.our_seq, ack=conn.chip_seq,
        )

    async def _send_rst(self, chip_mac: bytes, ip: IPv4, tcp: TCP) -> None:
        rst = TCP(
            src_port=tcp.dst_port,
            dst_port=tcp.src_port,
            seq=tcp.ack if (tcp.flags & TCP_ACK) else 0,
            ack=_seq_add(tcp.seq, 1 if (tcp.flags & TCP_SYN) else len(tcp.payload)),
            flags=TCP_RST | TCP_ACK,
            window=0,
        )
        ipv4_payload = rst.to_bytes(bytes(ip.dst), bytes(ip.src))
        frame = make_frame_ipv4(
            dst_mac=chip_mac,
            src_mac=GATEWAY_MAC,
            src_ip=bytes(ip.dst),
            dst_ip=bytes(ip.src),
            protocol=IPPROTO_TCP,
            l4_payload=ipv4_payload,
        )
        await self._inject(frame)

    # ── Teardown ───────────────────────────────────────────────────

    async def _close(self, conn: TcpConnection, send_rst: bool) -> None:
        if conn.state == _State.CLOSED:
            return
        conn.state = _State.CLOSED
        if send_rst:
            try:
                rst = TCP(
                    src_port=conn.dst_port,
                    dst_port=conn.chip_port,
                    seq=conn.our_seq,
                    ack=conn.chip_seq,
                    flags=TCP_RST,
                )
                ipv4_payload = rst.to_bytes(conn.dst_ip, conn.chip_ip)
                await self._inject(make_frame_ipv4(
                    dst_mac=conn.chip_mac,
                    src_mac=GATEWAY_MAC,
                    src_ip=conn.dst_ip,
                    dst_ip=conn.chip_ip,
                    protocol=IPPROTO_TCP,
                    l4_payload=ipv4_payload,
                ))
            except Exception:
                pass
        if conn.host_writer is not None:
            try:
                conn.host_writer.close()
            except Exception:
                pass
        if conn.host_pump_task is not None and not conn.host_pump_task.done():
            conn.host_pump_task.cancel()
        if conn.pending_connect is not None and not conn.pending_connect.done():
            conn.pending_connect.cancel()
        self._conns.pop(conn.key(), None)

    async def shutdown(self) -> None:
        for conn in list(self._conns.values()):
            await self._close(conn, send_rst=True)


# ─── helpers ────────────────────────────────────────────────────────

def _mss_option(mss: int) -> bytes:
    return b'\x02\x04' + struct.pack('!H', mss)


def _seq_geq_or_eq(a: int, b: int) -> bool:
    return a == b or not _seq_lt(a, b)
