"""
Egress log sink slot for the Pico W bridge.

picow_net must stay free of any DB / SQLAlchemy dependency (it imports
cleanly in the bare deploy venv and in the bridge unit tests). So instead of
writing rows itself, it exposes a pluggable sink: the pro safety layer
installs a buffered DB writer at startup via ``set_sink``; the bridge calls
``record`` for every outbound connection. When no sink is installed (OSS /
tests) ``record`` is a cheap no-op.

The sink MUST be non-blocking and must never raise — it runs on the hot
network path. The pro writer just appends to an in-memory buffer and flushes
in the background.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# event dict shape (all optional except protocol/verdict):
#   client_id, user_id, project_id, session_id, board_kind,
#   protocol ('tcp'|'udp'|'dns'), dst_ip, dst_port, dst_host,
#   bytes_sent, bytes_recv, verdict ('allowed'|'blocked'), reason
_sink: Optional[Callable[[dict], None]] = None


def set_sink(fn: Optional[Callable[[dict], None]]) -> None:
    """Install (or clear, with None) the egress sink."""
    global _sink
    _sink = fn


def record(event: dict) -> None:
    """Hand one egress event to the sink. Never raises, never blocks."""
    sink = _sink
    if sink is None:
        return
    try:
        sink(event)
    except Exception:  # pragma: no cover - defensive; the net path must not break
        logger.debug('[egress_log] sink raised', exc_info=True)
