"""Assignment 2 Flow/Connection Tracker package.

Assignment 3 adds an additive flow-context adapter for ``flow:`` rule
conditions; the Assignment 2 state machine and JSONL flow schema are unchanged.
"""

from .context import (
    ROLE_SOURCE_LOWER_PORT,
    ROLE_SOURCE_TCP_SYN,
    ROLE_SOURCE_UNKNOWN,
    ROLE_SOURCE_WELL_KNOWN,
    WELL_KNOWN_SERVER_PORTS,
    build_flow_context,
    infer_client_server,
)
from .tracker import (
    STATE_CLOSED,
    STATE_CLOSING,
    STATE_ESTABLISHED,
    STATE_HANDSHAKE,
    STATE_NEW,
    STATE_OPEN,
    STATE_RESET,
    Flow,
    FlowTracker,
)

__all__ = [
    "FlowTracker",
    "Flow",
    "STATE_NEW",
    "STATE_HANDSHAKE",
    "STATE_ESTABLISHED",
    "STATE_CLOSING",
    "STATE_CLOSED",
    "STATE_RESET",
    "STATE_OPEN",
    "ROLE_SOURCE_LOWER_PORT",
    "ROLE_SOURCE_TCP_SYN",
    "ROLE_SOURCE_UNKNOWN",
    "ROLE_SOURCE_WELL_KNOWN",
    "WELL_KNOWN_SERVER_PORTS",
    "build_flow_context",
    "infer_client_server",
]
