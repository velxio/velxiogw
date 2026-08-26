"""End-to-end tests against a live GatewayServer on an ephemeral port.

The client side crafts real Ethernet frames with the vendored codecs — the
same bytes the browser's chip emulator would tunnel — so a pass here means
the whole path works: WebSocket handshake, pairing, base64 framing, the NAT
stack, and the host.velxio.internal alias.
"""

import asyncio
import base64
import json
import socket
import struct

import pytest
import websockets

from velxiogw.server import GatewayServer
from velxiogw.net.consts import (
    BROADCAST_IP, DNS_IP, GATEWAY_MAC, HOST_ALIAS_IP, STA_IP, ip_to_bytes,
)
from velxiogw.net.protocols import UDP, make_frame_ipv4

CHIP_MAC = bytes.fromhex('28cdc1000001')
CODE = '424242'


@pytest.fixture
async def gateway():
    server = GatewayServer(port=0, code=CODE)
    task = None

    # Bind manually on port 0 to learn the real port before yielding.
    from websockets.asyncio.server import serve

    async with serve(server._handler, '127.0.0.1', 0,
                     process_request=server._process_request) as ws_server:
        port = ws_server.sockets[0].getsockname()[1]
        yield port


async def _connect(port, code=CODE, client_id='t1'):
    return await websockets.connect(
        f'ws://127.0.0.1:{port}/simulation/ws/{client_id}?code={code}',
    )


def _msg(type_, **data):
    return json.dumps({'type': type_, 'data': data})


async def _recv_type(ws, wanted, timeout=5.0):
    """Read frames until one of type `wanted` arrives."""
    async with asyncio.timeout(timeout):
        while True:
            msg = json.loads(await ws.recv())
            if msg['type'] == wanted:
                return msg['data']


# ── Pairing ──────────────────────────────────────────────────────────

async def test_bad_code_is_refused(gateway):
    with pytest.raises(websockets.exceptions.InvalidStatus) as e:
        await _connect(gateway, code='000000')
    assert e.value.response.status_code == 401


async def test_bad_origin_is_refused(gateway):
    with pytest.raises(websockets.exceptions.InvalidStatus) as e:
        await websockets.connect(
            f'ws://127.0.0.1:{gateway}/simulation/ws/t1?code={CODE}',
            additional_headers={'Origin': 'https://evil.example'},
        )
    assert e.value.response.status_code == 403


async def test_velxio_origin_is_allowed(gateway):
    ws = await websockets.connect(
        f'ws://127.0.0.1:{gateway}/simulation/ws/t1?code={CODE}',
        additional_headers={'Origin': 'https://velxio.dev'},
    )
    await ws.close()


# ── Status endpoint ──────────────────────────────────────────────────

async def test_status_endpoint(gateway):
    reader, writer = await asyncio.open_connection('127.0.0.1', gateway)
    writer.write(b'GET /status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')
    await writer.drain()
    raw = await reader.read(4096)
    writer.close()
    head, _, body = raw.partition(b'\r\n\r\n')
    assert b'200' in head.split(b'\r\n')[0]
    doc = json.loads(body)
    assert doc['app'] == 'velxiogw'
    assert doc['protocol'] == 'picow-ws/1'


# ── The tunnel itself ────────────────────────────────────────────────

async def test_start_reports_wifi_status(gateway):
    ws = await _connect(gateway)
    await ws.send(_msg('start_picow', wifi_enabled=True))
    status = await _recv_type(ws, 'wifi_status')
    assert status['status'] == 'started'
    assert status['ip'] == STA_IP
    await ws.close()


def _dhcp_discover_frame():
    """A minimal but valid DHCP DISCOVER as the chip would send it."""
    xid = 0x1337
    bootp = struct.pack('!BBBBIHH4s4s4s4s16s192s',
                        1, 1, 6, 0, xid, 0, 0x8000,
                        b'\x00' * 4, b'\x00' * 4, b'\x00' * 4, b'\x00' * 4,
                        CHIP_MAC + b'\x00' * 10, b'\x00' * 192)
    options = bytes([99, 130, 83, 99,      # magic cookie
                     53, 1, 1,             # DHCP message type = DISCOVER
                     255])                 # end
    payload = bootp + options
    udp = UDP(src_port=68, dst_port=67, payload=payload)
    return make_frame_ipv4(
        src_mac=CHIP_MAC, dst_mac=b'\xff' * 6,
        src_ip=ip_to_bytes('0.0.0.0'), dst_ip=ip_to_bytes('255.255.255.255'),
        protocol=17, l4_payload=udp.to_bytes(ip_to_bytes('0.0.0.0'),
                                       ip_to_bytes('255.255.255.255')),
    )


async def test_dhcp_handshake_over_tunnel(gateway):
    ws = await _connect(gateway)
    await ws.send(_msg('start_picow', wifi_enabled=True))
    await _recv_type(ws, 'wifi_status')

    frame = _dhcp_discover_frame()
    await ws.send(_msg('picow_packet_out',
                       ether_b64=base64.b64encode(frame).decode()))
    reply = await _recv_type(ws, 'picow_packet_in')
    ether = base64.b64decode(reply['ether_b64'])
    # DHCP OFFER: IPv4 (0x0800), UDP src 67, and it offers the STA IP.
    assert ether[12:14] == b'\x08\x00'
    assert ip_to_bytes(STA_IP) in ether
    await ws.close()


def _dns_query_frame(hostname):
    q = b''.join(bytes([len(p)]) + p.encode() for p in hostname.split('.')) + b'\x00'
    payload = struct.pack('!HHHHHH', 0xbeef, 0x0100, 1, 0, 0, 0) + q + struct.pack('!HH', 1, 1)
    udp = UDP(src_port=53535, dst_port=53, payload=payload)
    return make_frame_ipv4(
        src_mac=CHIP_MAC, dst_mac=GATEWAY_MAC,
        src_ip=ip_to_bytes(STA_IP), dst_ip=ip_to_bytes(DNS_IP),
        protocol=17, l4_payload=udp.to_bytes(ip_to_bytes(STA_IP), ip_to_bytes(DNS_IP)),
    )


async def test_host_alias_resolves_to_alias_ip(gateway):
    ws = await _connect(gateway)
    await ws.send(_msg('start_picow', wifi_enabled=True))
    await _recv_type(ws, 'wifi_status')

    # Prime the bridge's chip-MAC tracking with any frame first (DHCP does it).
    await ws.send(_msg('picow_packet_out',
                       ether_b64=base64.b64encode(_dhcp_discover_frame()).decode()))
    await _recv_type(ws, 'picow_packet_in')

    frame = _dns_query_frame('host.velxio.internal')
    await ws.send(_msg('picow_packet_out',
                       ether_b64=base64.b64encode(frame).decode()))
    reply = await _recv_type(ws, 'picow_packet_in')
    ether = base64.b64decode(reply['ether_b64'])
    assert socket.inet_aton(HOST_ALIAS_IP) in ether
    await ws.close()
