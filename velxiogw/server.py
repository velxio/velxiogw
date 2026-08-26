"""
The WebSocket half of the gateway.

Speaks the exact protocol the browser's ``Cyw43Bridge`` already speaks to
velxio.dev — ``start_picow`` / ``picow_packet_out`` / ``stop_picow`` in,
``wifi_status`` / ``picow_packet_in`` / ``error`` out, Ethernet frames as
base64 — so pointing the frontend at ``ws://127.0.0.1:<port>`` is a change
of address, not of protocol. The URL path mirrors the hosted endpoint
(``/simulation/ws/<client_id>``) for the same reason.

Security model (fail closed):
  - binds to loopback only; nothing on the LAN can reach it
  - every WebSocket must present the session's pairing code (``?code=``)
  - browser Origins are allowlisted; a request from a random open tab is
    refused before the socket upgrades. Requests without an Origin header
    are local processes (curl, tests) and pass on the code alone.

``GET /status`` answers a small JSON document so the Velxio WiFi panel can
detect a running gateway without opening a WebSocket. It carries no secret
and is CORS-open on purpose; pairing still gates the actual tunnel.
"""

from __future__ import annotations

import asyncio
import base64
import http
import json
import logging
from urllib.parse import parse_qs, urlsplit

from websockets.asyncio.server import serve

from . import __version__
from .net import PicowNetBridge

logger = logging.getLogger(__name__)

DEFAULT_PORT = 9013

# Origins allowed to open the tunnel. ``null`` is what file:// pages send —
# refused. Everything on loopback is a developer's own dev server.
_ALLOWED_ORIGINS = (
    'https://velxio.dev',
    'https://vstaging.moontero.com',
)


def _origin_ok(origin: str | None, extra: tuple[str, ...]) -> bool:
    if origin is None:
        return True  # non-browser client on loopback; the code still gates it
    if origin in _ALLOWED_ORIGINS or origin in extra:
        return True
    try:
        parts = urlsplit(origin)
    except ValueError:
        return False
    return parts.scheme in ('http', 'https') and parts.hostname in ('localhost', '127.0.0.1')


class GatewayServer:
    def __init__(self, port: int, code: str, extra_origins: tuple[str, ...] = ()) -> None:
        self.port = port
        self.code = code
        self.extra_origins = extra_origins
        self._bridges: dict[str, PicowNetBridge] = {}

    # ── HTTP + handshake ─────────────────────────────────────────────

    def _process_request(self, connection, request):
        """Answer /status over plain HTTP; gate everything else on the code."""
        url = urlsplit(request.path)
        if url.path == '/status':
            body = json.dumps({
                'app': 'velxiogw',
                'version': __version__,
                'protocol': 'picow-ws/1',
                'sessions': len(self._bridges),
            }).encode()
            resp = connection.respond(http.HTTPStatus.OK, '')
            resp.body = body
            # websockets' Headers is a multidict: plain assignment APPENDS,
            # and respond() already set Content-Type/-Length for its empty
            # text. A second Content-Length is an RFC 9110 hard error that
            # Chrome enforces (net::ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_
            # LENGTH) while curl shrugs — delete before setting.
            del resp.headers['Content-Type']
            del resp.headers['Content-Length']
            resp.headers['Content-Type'] = 'application/json'
            resp.headers['Content-Length'] = str(len(body))
            resp.headers['Access-Control-Allow-Origin'] = '*'
            return resp

        origin = request.headers.get('Origin')
        if not _origin_ok(origin, self.extra_origins):
            logger.warning('refused origin %r', origin)
            return connection.respond(http.HTTPStatus.FORBIDDEN, 'origin not allowed\n')

        supplied = (parse_qs(url.query).get('code') or [''])[0]
        if supplied != self.code:
            logger.warning('refused connection with bad pairing code')
            return connection.respond(http.HTTPStatus.UNAUTHORIZED, 'pairing code required\n')

        return None  # proceed with the WebSocket upgrade

    # ── The tunnel ───────────────────────────────────────────────────

    async def _handler(self, websocket) -> None:
        path = urlsplit(websocket.request.path).path
        # /simulation/ws/<client_id> — same shape as the hosted endpoint.
        client_id = path.rsplit('/', 1)[-1] or 'local'
        logger.info('[%s] connected', client_id)

        async def emit(event_type: str, data: dict) -> None:
            try:
                await websocket.send(json.dumps({'type': event_type, 'data': data}))
            except Exception:
                pass  # socket died; the finally block cleans up

        try:
            async for raw in websocket:
                try:
                    msg = json.loads(raw)
                    msg_type = msg.get('type', '')
                    msg_data = msg.get('data') or {}
                except (ValueError, AttributeError):
                    continue

                if msg_type == 'start_picow':
                    old = self._bridges.pop(client_id, None)
                    if old is not None:
                        await old.stop()
                    bridge = PicowNetBridge(
                        client_id, emit,
                        wifi_enabled=bool(msg_data.get('wifi_enabled', False)),
                    )
                    self._bridges[client_id] = bridge
                    await bridge.start()

                elif msg_type == 'picow_packet_out':
                    bridge = self._bridges.get(client_id)
                    b64 = msg_data.get('ether_b64', '')
                    if bridge is not None and b64:
                        try:
                            ether = base64.b64decode(b64)
                        except (ValueError, TypeError):
                            continue
                        await bridge.deliver_packet_out(ether)

                elif msg_type == 'stop_picow':
                    bridge = self._bridges.pop(client_id, None)
                    if bridge is not None:
                        await bridge.stop()
        finally:
            bridge = self._bridges.pop(client_id, None)
            if bridge is not None:
                await bridge.stop()
            logger.info('[%s] disconnected', client_id)

    async def run(self) -> None:
        async with serve(
            self._handler, '127.0.0.1', self.port,
            process_request=self._process_request,
            max_size=4 * 1024 * 1024,
        ):
            await asyncio.get_running_loop().create_future()  # run forever
