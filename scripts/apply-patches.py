#!/usr/bin/env python3
"""Re-apply velxiogw's local patches to a freshly vendored net/ tree.

Idempotent: each patch is skipped when its marker is already present.
A missing anchor means upstream moved — fail loudly, never half-patch.
"""
import sys
from pathlib import Path

DST = Path(sys.argv[1] if len(sys.argv) > 1 else 'velxiogw/net')

CONSTS_APPEND = '''

# ── velxiogw vendor patch (see VENDORED.md) ──────────────────────────
# The IP the DNS proxy answers for `host.velxio.internal`. Two constraints:
# not 127.0.0.1 (lwIP routes that to the chip's own loopback), and not an
# address INSIDE the virtual subnet -- the chip would ARP for it as on-link
# and the browser-side net layer owns ARP, so the SYN never reaches the
# tunnel (found by the first staging e2e). TEST-NET-1 is reserved, never a
# real LAN, and off-subnet, so lwIP routes it via the gateway; the NATs
# rewrite it to the host's loopback when opening the real socket.
HOST_ALIAS_HOSTNAME = 'host.velxio.internal'
HOST_ALIAS_IP = '192.0.2.1'
'''

DNS_ANCHOR = """        # A-record query. Resolve via host.
        addrs = await self._resolve_a(qname)"""
DNS_NEW = """        # velxiogw vendor patch: `host.velxio.internal` names the machine the
        # gateway runs on. Answered locally, never forwarded to the resolver.
        from .consts import HOST_ALIAS_HOSTNAME, HOST_ALIAS_IP
        if qname.lower().rstrip('.') == HOST_ALIAS_HOSTNAME:
            ip4 = socket.inet_aton(HOST_ALIAS_IP)
            self._on_egress(protocol='dns', verdict='allowed', dst_host=qname,
                            dst_ip=HOST_ALIAS_IP, reason='host_alias')
            resp = DnsMessage(txid=req.txid, flags=resp_flags, qd=req.qd,
                              an=[(qname, DNS_TYPE_A, DNS_CLASS_IN, 60, ip4)])
            return self._wrap(chip_src_ip, udp, resp)

""" + DNS_ANCHOR

TCP_ANCHOR = """        dst_ip_str = bytes_to_ip(conn.dst_ip)
        allowed, reason = is_allowed_dst(dst_ip_str, conn.dst_port)"""
TCP_NEW = """        dst_ip_str = bytes_to_ip(conn.dst_ip)
        # velxiogw vendor patch: host.velxio.internal resolves to HOST_ALIAS_IP;
        # the real socket goes to the machine's own loopback.
        from .consts import HOST_ALIAS_IP
        if dst_ip_str == HOST_ALIAS_IP:
            dst_ip_str = '127.0.0.1'
        allowed, reason = is_allowed_dst(dst_ip_str, conn.dst_port)"""

UDP_ANCHOR = """        dst_ip_str = bytes_to_ip(bytes(ip.dst))
        allowed, reason = is_allowed_dst(dst_ip_str, udp.dst_port)"""
UDP_NEW = """        dst_ip_str = bytes_to_ip(bytes(ip.dst))
        # velxiogw vendor patch: see tcp_nat — same loopback rewrite.
        from .consts import HOST_ALIAS_IP
        if dst_ip_str == HOST_ALIAS_IP:
            dst_ip_str = '127.0.0.1'
        allowed, reason = is_allowed_dst(dst_ip_str, udp.dst_port)"""

UDP2_ANCHOR = """                remote_addr=(bytes_to_ip(bytes(ip.dst)), udp.dst_port),"""
UDP2_NEW = """                remote_addr=(dst_ip_str, udp.dst_port),"""


def patch(name, anchor, replacement, marker='velxiogw vendor patch'):
    p = DST / name
    s = p.read_text()
    if marker in s:
        print(f'  {name}: already patched')
        return
    if anchor not in s:
        sys.exit(f'FAIL {name}: anchor not found — upstream changed, re-derive the patch')
    p.write_text(s.replace(anchor, replacement, 1))
    print(f'  {name}: patched')


def patch_second(name, anchor, replacement):
    """A follow-up edit inside a file the marker check already passed on."""
    p = DST / name
    s = p.read_text()
    if anchor not in s:
        if replacement in s:
            return  # already applied
        sys.exit(f'FAIL {name}: secondary anchor not found')
    p.write_text(s.replace(anchor, replacement, 1))


# consts.py is an append, not a replace:
consts = DST / 'consts.py'
if 'HOST_ALIAS_IP' not in consts.read_text():
    consts.write_text(consts.read_text() + CONSTS_APPEND)
    print('  consts.py: patched')
else:
    print('  consts.py: already patched')

patch('dns.py', DNS_ANCHOR, DNS_NEW)
patch('tcp_nat.py', TCP_ANCHOR, TCP_NEW)
patch('udp_nat.py', UDP_ANCHOR, UDP_NEW)
patch_second('udp_nat.py', UDP2_ANCHOR, UDP2_NEW)
print('all patches applied')
