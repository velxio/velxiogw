# velxiogw/net — vendored code

`velxiogw/net/` is a snapshot of velxio-prod's
`pro/backend/app/services/picow_net/` (the userspace NAT behind the hosted
Pico W / ESP32-JS WiFi). **velxio-prod is canonical** — fix bugs there first,
then re-vendor with:

```bash
./scripts/sync-net.sh /path/to/velxio-prod
```

The sync script re-applies the three local patches this repo carries on top:

1. **consts.py** — appends `HOST_ALIAS_HOSTNAME` / `HOST_ALIAS_IP`
   (`host.velxio.internal` → `10.13.37.254`).
2. **dns.py** — answers the alias locally before consulting the host
   resolver (the chip can't be handed `127.0.0.1`: lwIP would route it to
   its own loopback, so it gets an on-subnet IP instead).
3. **tcp_nat.py / udp_nat.py** — rewrite `HOST_ALIAS_IP` to `127.0.0.1`
   when opening the real host socket.

Unpatched-by-design:

- `egress_guard.py` ships as-is; the CLI sets
  `VELXIO_EGRESS_ALLOW_PRIVATE=1` (upstream's own switch) unless
  `--public-only`.
- `egress_log.py` is a pluggable sink that no-ops when none is installed;
  the daemon installs none.
