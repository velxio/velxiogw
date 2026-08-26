"""velxiogw — the Velxio IoT Network Gateway.

Runs on the user's machine and puts their simulated board on their own
network: the browser tunnels the board's Ethernet frames here instead of
to velxio.dev, and the vendored userspace NAT (``velxiogw.net``) opens
real sockets on this host — LAN, loopback and internet alike.
"""

__version__ = '0.1.2'
