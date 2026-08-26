"""Command line entry — banner, pairing code, and the asyncio loop."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import secrets
import sys

from . import __version__
from .server import DEFAULT_PORT, GatewayServer


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog='velxiogw',
        description='Velxio IoT Network Gateway — put your simulated board on your own network.',
    )
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'loopback port to listen on (default {DEFAULT_PORT})')
    parser.add_argument('--code', default=None,
                        help='fixed pairing code (default: random per launch)')
    parser.add_argument('--allow-origin', action='append', default=[],
                        metavar='ORIGIN',
                        help='extra browser origin to allow (repeatable)')
    parser.add_argument('--public-only', action='store_true',
                        help='refuse LAN/loopback targets, allow only public internet '
                             '(the hosted-gateway policy; not the point of running this, '
                             'but available)')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--version', action='version', version=f'velxiogw {__version__}')
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)-7s %(name)s: %(message)s',
        datefmt='%H:%M:%S',
    )

    # The vendored NAT ships velxio.dev's SSRF guard, which refuses private,
    # loopback and link-local targets — correct for a shared cloud service,
    # exactly backwards for a gateway whose purpose is the user's own LAN.
    # The guard reads this env var at call time.
    if not args.public_only:
        os.environ['VELXIO_EGRESS_ALLOW_PRIVATE'] = '1'

    code = args.code or f'{secrets.randbelow(10**6):06d}'
    server = GatewayServer(args.port, code, tuple(args.allow_origin))

    print(f'velxiogw {__version__} — Velxio IoT Network Gateway')
    print(f'  listening on   ws://127.0.0.1:{args.port}')
    print(f'  pairing code   {code}')
    print(f'  reach scope    {"public internet only" if args.public_only else "your LAN + localhost + internet"}')
    print(f'  host alias     host.velxio.internal -> this machine')
    print('Paste the pairing code into the Velxio WiFi panel. Ctrl+C to quit.')

    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        print('\nbye')
        sys.exit(0)
