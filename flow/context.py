"""Flow context adapter for Assignment 3 ``flow:`` rule conditions.

The Assignment 2 tracker groups packets into bidirectional flows but does not
claim to know which endpoint is the client or the server. Assignment 3 needs
that information for ``flow:to_server`` / ``flow:to_client``, so this adapter
defines explicit, evidence-based role rules:

1. TCP: if a SYN without ACK was observed, its sender is the client.
2. Otherwise, if exactly one endpoint uses a well-known server port, that
   endpoint is the server.
3. Otherwise, if both ports are known and different, the lower port is treated
   as the server (documented heuristic).
4. Otherwise the role is unknown and ``to_server``/``to_client`` return
   ``None``; a rule requiring them will not match.

``role_source`` records which rule was used, so detection evidence is
explainable. For UDP the adapter never invents a TCP handshake: an active
(``OPEN``) UDP flow is considered ``established`` by documented policy.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only

    from .tracker import Flow


PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"

STATE_ESTABLISHED = "ESTABLISHED"
STATE_OPEN = "OPEN"

ROLE_SOURCE_TCP_SYN = "tcp_syn"
ROLE_SOURCE_WELL_KNOWN = "well_known_port"
ROLE_SOURCE_LOWER_PORT = "lower_port"
ROLE_SOURCE_UNKNOWN = "unknown"

#: Server ports recognised by the role heuristic. This is deliberately a small
#: documented set, not a full IANA service database.
WELL_KNOWN_SERVER_PORTS = frozenset(
    {
        20,
        21,
        22,
        23,
        25,
        53,
        67,
        68,
        69,
        80,
        110,
        111,
        123,
        135,
        137,
        138,
        139,
        143,
        161,
        162,
        179,
        389,
        443,
        445,
        465,
        514,
        515,
        587,
        631,
        636,
        993,
        995,
        1433,
        1521,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        9200,
        27017,
    }
)


def _endpoint(ip: str | None, port: int | None) -> dict[str, Any]:

    return {"ip": ip, "port": port}


def _port_known(port: int | None) -> bool:

    return isinstance(port, int) and not isinstance(port, bool)


def infer_client_server(flow: "Flow") -> tuple[
    tuple[str, int | None] | None,
    tuple[str, int | None] | None,
    str,
]:
    """Return ``(client_endpoint, server_endpoint, role_source)``."""

    a = flow.endpoint_a
    b = flow.endpoint_b

    syn_sender = getattr(flow, "syn_sender", None)

    if flow.protocol == PROTOCOL_TCP and syn_sender is not None:

        if syn_sender == a:

            return a, b, ROLE_SOURCE_TCP_SYN

        if syn_sender == b:

            return b, a, ROLE_SOURCE_TCP_SYN

    a_port = a[1] if len(a) > 1 else None
    b_port = b[1] if len(b) > 1 else None

    a_known = _port_known(a_port) and a_port in WELL_KNOWN_SERVER_PORTS
    b_known = _port_known(b_port) and b_port in WELL_KNOWN_SERVER_PORTS

    if a_known and not b_known:

        return b, a, ROLE_SOURCE_WELL_KNOWN

    if b_known and not a_known:

        return a, b, ROLE_SOURCE_WELL_KNOWN

    if a_known and b_known:

        # Both look like services: the lower port is the documented tie-break.
        if a_port <= b_port:

            return b, a, ROLE_SOURCE_WELL_KNOWN

        return a, b, ROLE_SOURCE_WELL_KNOWN

    if _port_known(a_port) and _port_known(b_port) and a_port != b_port:

        if a_port < b_port:

            return b, a, ROLE_SOURCE_LOWER_PORT

        return a, b, ROLE_SOURCE_LOWER_PORT

    return None, None, ROLE_SOURCE_UNKNOWN


def _packet_endpoints(event: dict[str, Any]) -> tuple[
    tuple[str | None, int | None],
    tuple[str | None, int | None],
]:

    transport = event.get("transport")

    if not isinstance(transport, dict):

        transport = {}

    src_port = event.get("src_port")

    if src_port is None:

        src_port = transport.get("src_port")

    dst_port = event.get("dst_port")

    if dst_port is None:

        dst_port = transport.get("dst_port")

    def coerce(value: Any) -> int | None:

        if value is None or isinstance(value, bool):

            return None

        try:

            return int(value)

        except (TypeError, ValueError):

            return None

    return (
        (event.get("src_ip"), coerce(src_port)),
        (event.get("dst_ip"), coerce(dst_port)),
    )


def build_flow_context(flow: "Flow", event: dict[str, Any]) -> dict[str, Any]:
    """Build the additive flow context consumed by the matching engine."""

    src_endpoint, dst_endpoint = _packet_endpoints(event)

    forward = src_endpoint == flow.endpoint_a

    if forward:

        direction = "forward"

    elif src_endpoint == flow.endpoint_b:

        direction = "backward"

    else:  # defensive: the tracker may have coerced a missing port to -1

        direction = "unknown"

    client, server, role_source = infer_client_server(flow)

    to_server: bool | None
    to_client: bool | None

    if client is None or server is None:

        to_server = None
        to_client = None

    else:

        to_server = src_endpoint == client and dst_endpoint == server
        to_client = src_endpoint == server and dst_endpoint == client

        if not to_server and not to_client:

            # Endpoint pair does not line up with the flow; do not guess.
            to_server = None
            to_client = None

    if flow.protocol == PROTOCOL_TCP:

        established = bool(getattr(flow, "ever_established", False))

    elif flow.protocol == PROTOCOL_UDP:

        # Documented UDP policy: an active/open flow counts as established.
        # No TCP handshake is simulated.
        established = flow.state == STATE_OPEN

    else:

        established = None

    return {
        "flow_id": flow.flow_id,
        "protocol": flow.protocol,
        "application_protocol": flow.application_protocol,
        "state": flow.state,
        "established": established,
        "endpoint_a": _endpoint(*flow.endpoint_a),
        "endpoint_b": _endpoint(*flow.endpoint_b),
        "client_endpoint": _endpoint(*client) if client is not None else None,
        "server_endpoint": _endpoint(*server) if server is not None else None,
        "role_source": role_source,
        "direction": direction,
        "to_server": to_server,
        "to_client": to_client,
        "start_time": flow.start_time,
        "last_seen": flow.last_seen,
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "forward_packet_count": flow.forward_packet_count,
        "backward_packet_count": flow.backward_packet_count,
        "forward_byte_count": flow.forward_byte_count,
        "backward_byte_count": flow.backward_byte_count,
    }


__all__ = [
    "ROLE_SOURCE_LOWER_PORT",
    "ROLE_SOURCE_TCP_SYN",
    "ROLE_SOURCE_UNKNOWN",
    "ROLE_SOURCE_WELL_KNOWN",
    "WELL_KNOWN_SERVER_PORTS",
    "build_flow_context",
    "infer_client_server",
]
