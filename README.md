# velxiogw — Velxio IoT Network Gateway

Connect your Velxio simulated boards (ESP32 family, Pico W) to your **own
network**: the MQTT broker on your LAN, the API you are developing on
`localhost`, your Home Assistant — and the internet, without the round trip
through velxio.dev's servers.

The browser tunnels your board's raw Ethernet frames to this gateway over a
WebSocket; the gateway runs a userspace TCP/IP stack (DHCP, DNS, ARP, ICMP,
TCP/UDP NAT) and opens real sockets from your machine.

## Quick start

Download the zip for your platform from the
[latest release](../../releases/latest), unzip, run:

```
$ ./velxiogw
velxiogw 0.1.0 — Velxio IoT Network Gateway
  listening on   ws://127.0.0.1:9013
  pairing code   493028
  reach scope    your LAN + localhost + internet
  host alias     host.velxio.internal -> this machine
```

Then paste the pairing code into the WiFi panel in the Velxio editor.

> Connecting the gateway to the simulator is a **paid Velxio feature**
> (Maker plan and up). The binary is a free download and the source is
> public, but the "Connect to my local network" flow in the editor is
> gated by your plan — the same split Wokwi uses for its Private Gateway.

From your sketch, `host.velxio.internal` always names the machine the
gateway runs on:

```cpp
http.begin("http://host.velxio.internal:8000/api");
```

## Options

| Flag | Meaning |
|---|---|
| `--port N` | listen port (default 9013) |
| `--code XXXXXX` | fixed pairing code instead of a random one |
| `--allow-origin URL` | allow an extra browser origin (repeatable) |
| `--public-only` | hosted-gateway policy: refuse LAN/loopback targets |
| `-v` | debug logging |

## Security model

- Binds to **loopback only** — nothing on your LAN can reach the gateway.
- Every tunnel needs the session's **pairing code**; without it the WebSocket
  handshake is refused (401). A random web page you have open cannot drive it.
- Browser **origins are allowlisted** (velxio.dev, staging, localhost dev
  servers); anything else is refused (403) before the socket upgrades.
- `GET /status` is CORS-open on purpose so the Velxio WiFi panel can detect a
  running gateway; it exposes no secret and grants nothing.

By design the gateway reaches private addresses — that is its purpose. If you
want the hosted service's public-internet-only policy, run with
`--public-only`.

## Development

```bash
pip install -e . pytest pytest-asyncio
pytest            # 7 e2e tests: pairing, origins, DHCP over the tunnel, host alias
python -m velxiogw
```

`velxiogw/net/` is **vendored** from velxio-prod's `picow_net` stack — see
[VENDORED.md](./VENDORED.md) before touching it.

Releases: push a `v*` tag; CI builds Linux (x64/arm64), macOS (x64/arm64)
and Windows binaries and attaches wokwigw-style zips to the GitHub release.

## Roadmap

- [ ] Windows code signing + macOS notarization (reuse the desktop app's
      minisign/ECDSA pipeline — velxio-prod `pro/desktop/RELEASING.md`)
- [ ] `--forward host_port:board_ip:board_port` (today the hosted IoT gateway
      proxy covers the inbound case with zero config)
- [ ] Frontend: WiFi panel "Connect to my local network" flow (velxio-prod
      `project/wifi-custom-aps-2026-08`, phase P8)
