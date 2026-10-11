"""Assignment 2 Flow/Connection Tracker.

Groups TCP/UDP packets into bidirectional flows using the canonical 5-tuple
``(src_ip, dst_ip, src_port, dst_port, transport_protocol)``. Reversed
endpoints map to the same flow, while packet direction is still tracked.

Design notes
------------
* ``flow_id`` is a SHA-256 digest over the canonical key plus a per-key
  *generation* counter, so it is deterministic across runs (never Python's
  process-randomized ``hash()``) and a reused 5-tuple after expiry gets a fresh
  id.
* Byte counters use the full packet length (``packet_length``) when available;
  otherwise they fall back to ``payload_length`` and ``byte_count_basis``
  records which basis was used so packet bytes and payload bytes are never
  silently mixed.
* Expiry is driven by *event* timestamps, so offline PCAP replay and synthetic
  tests never depend on wall-clock sleeps.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any

PROTO_TCP = "TCP"
PROTO_UDP = "UDP"

STATE_NEW = "NEW"
STATE_HANDSHAKE = "HANDSHAKE"
STATE_ESTABLISHED = "ESTABLISHED"
STATE_CLOSING = "CLOSING"
STATE_CLOSED = "CLOSED"
STATE_RESET = "RESET"
STATE_OPEN = "OPEN"

TERMINAL_STATES = (STATE_CLOSED, STATE_RESET)

# Only these flag characters are meaningful; anything else is ignored so a
# stray byte in a flags string cannot corrupt the counters.
FLAG_ALPHABET = frozenset("FSRPAUECN")


def _coerce_float(value: Any) -> float | None:

    if value is None or isinstance(value, bool):

        return None

    try:

        return float(value)

    except (TypeError, ValueError):

        return None


def _coerce_port(value: Any) -> int | None:

    if value is None or isinstance(value, bool):

        return None

    try:

        return int(value)

    except (TypeError, ValueError):

        return None


def _canonical_key(
    src_ip: str,
    dst_ip: str,
    src_port: int | None,
    dst_port: int | None,
    protocol: str,
) -> tuple:

    a = (
        src_ip,
        src_port if src_port is not None else -1,
    )

    b = (
        dst_ip,
        dst_port if dst_port is not None else -1,
    )

    if a <= b:

        return (a, b, protocol)

    return (b, a, protocol)


def _stable_flow_id(key: tuple, generation: int) -> str:

    material = f"{key[0]}|{key[1]}|{key[2]}|{generation}"

    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()[:32]


@dataclass
class Flow:
    """Mutable per-flow state."""

    key: tuple
    flow_id: str
    protocol: str
    endpoint_a: tuple[str, int | None]
    endpoint_b: tuple[str, int | None]
    start_time: float

    state: str
    application_protocol: str = "UNKNOWN"
    last_seen: float = 0.0

    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    forward_byte_count: int = 0
    backward_byte_count: int = 0

    SYN_count: int = 0
    ACK_count: int = 0
    FIN_count: int = 0
    RST_count: int = 0

    byte_count_basis: str = "packet"

    handshake_syn: bool = False
    handshake_synack: bool = False
    fin_directions: set = field(default_factory=set)

    def to_record(
        self,
        finalization_reason: str,
    ) -> dict[str, Any]:
        """Serialize the flow into the documented JSONL schema."""

        duration = self.last_seen - self.start_time

        if duration < 0:
            duration = 0.0

        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "state": self.state,
            "endpoint_a": {
                "ip": self.endpoint_a[0],
                "port": self.endpoint_a[1],
            },
            "endpoint_b": {
                "ip": self.endpoint_b[0],
                "port": self.endpoint_b[1],
            },
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": round(duration, 6),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "byte_count_basis": self.byte_count_basis,
            "forward_packet_count": self.forward_packet_count,
            "backward_packet_count": self.backward_packet_count,
            "forward_byte_count": self.forward_byte_count,
            "backward_byte_count": self.backward_byte_count,
            "SYN_count": self.SYN_count,
            "ACK_count": self.ACK_count,
            "FIN_count": self.FIN_count,
            "RST_count": self.RST_count,
            "finalization_reason": finalization_reason,
        }


class FlowTracker:
    """Stateful bidirectional flow tracker."""

    def __init__(self, config: Any = None) -> None:

        self.tcp_idle_timeout = float(
            getattr(config, "tcp_idle_timeout", 120.0)
        )

        self.udp_idle_timeout = float(
            getattr(config, "udp_idle_timeout", 30.0)
        )

        self.flows: dict[tuple, Flow] = {}

        self._generation: dict[tuple, int] = {}

        self.finalized_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def process(self, event: Any) -> list[dict[str, Any]]:
        """
        Feed one normalized event.

        Returns the list of flow records finalized as a consequence of this
        event (idle timeouts plus a terminal TCP close/reset).
        """

        if not isinstance(event, dict):

            return []

        records: list[dict[str, Any]] = []

        timestamp = _coerce_float(event.get("timestamp"))

        if timestamp is not None:

            records.extend(self._expire(timestamp))

        endpoints = self._extract_endpoints(event)

        if endpoints is None:

            return records

        flow = self._get_or_create(endpoints, timestamp)

        self._update(flow, event, timestamp)

        if (
            flow.protocol == PROTO_TCP
            and flow.state in TERMINAL_STATES
        ):

            reason = (
                "reset"
                if flow.state == STATE_RESET
                else "closed"
            )

            records.append(self._finalize(flow, reason))

        return records

    def flush(self) -> list[dict[str, Any]]:
        """
        Finalize every remaining active flow.

        Called at end of a PCAP replay or when live capture stops, so no flow
        is left dangling in the active table.
        """

        return [
            self._finalize(flow, "flush")
            for flow in list(self.flows.values())
        ]

    def active_flow_count(self) -> int:

        return len(self.flows)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _extract_endpoints(
        self,
        event: dict[str, Any],
    ) -> tuple[str, str, int | None, int | None, str] | None:

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")

        if not src_ip or not dst_ip:

            return None

        transport = event.get("transport")

        if not isinstance(transport, dict):

            transport = {}

        protocol = (
            event.get("transport_protocol")
            or transport.get("protocol")
            or "UNKNOWN"
        )

        protocol = str(protocol).upper()

        if protocol not in (PROTO_TCP, PROTO_UDP):

            return None

        src_port = event.get("src_port")

        if src_port is None:
            src_port = transport.get("src_port")

        dst_port = event.get("dst_port")

        if dst_port is None:
            dst_port = transport.get("dst_port")

        return (
            str(src_ip),
            str(dst_ip),
            _coerce_port(src_port),
            _coerce_port(dst_port),
            protocol,
        )

    def _get_or_create(
        self,
        endpoints: tuple,
        timestamp: float | None,
    ) -> Flow:

        src_ip, dst_ip, src_port, dst_port, protocol = endpoints

        key = _canonical_key(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        )

        existing = self.flows.get(key)

        if existing is not None:

            return existing

        generation = self._generation.get(key, 0)
        self._generation[key] = generation + 1

        start = timestamp if timestamp is not None else 0.0

        flow = Flow(
            key=key,
            flow_id=_stable_flow_id(key, generation),
            protocol=protocol,
            endpoint_a=(src_ip, src_port),
            endpoint_b=(dst_ip, dst_port),
            start_time=start,
            state=STATE_NEW if protocol == PROTO_TCP else STATE_OPEN,
            last_seen=start,
        )

        self.flows[key] = flow

        return flow

    def _increment_counters(
        self,
        flow: Flow,
        event: dict[str, Any],
        forward: bool,
    ) -> None:

        length, basis = self._packet_bytes(event)

        flow.packet_count += 1
        flow.byte_count += length

        if basis != flow.byte_count_basis:

            if flow.packet_count == 1:

                flow.byte_count_basis = basis

            else:

                flow.byte_count_basis = "mixed"

        if forward:

            flow.forward_packet_count += 1
            flow.forward_byte_count += length

        else:

            flow.backward_packet_count += 1
            flow.backward_byte_count += length

    def _packet_bytes(
        self,
        event: dict[str, Any],
    ) -> tuple[int, str]:
        """Return ``(length, basis)`` for the byte counter."""

        packet_length = event.get("packet_length")

        if packet_length is None:

            packet_length = event.get("frame_length")

        if isinstance(packet_length, int) and packet_length > 0:

            return packet_length, "packet"

        payload_length = event.get("payload_length")

        if isinstance(payload_length, int) and payload_length >= 0:

            return payload_length, "payload"

        return 0, "payload"

    def _update(
        self,
        flow: Flow,
        event: dict[str, Any],
        timestamp: float | None,
    ) -> None:

        if timestamp is not None:

            if timestamp < flow.start_time:

                flow.start_time = timestamp

            if timestamp > flow.last_seen:

                flow.last_seen = timestamp

        src_ip = str(event.get("src_ip"))
        transport = event.get("transport")

        if not isinstance(transport, dict):

            transport = {}

        src_port = event.get("src_port")

        if src_port is None:
            src_port = transport.get("src_port")

        src_port = _coerce_port(src_port)

        forward = (src_ip, src_port) == flow.endpoint_a

        if not forward:

            backward = (src_ip, src_port) == flow.endpoint_b

            forward = not backward

        self._increment_counters(flow, event, forward)

        # Application protocol: never let UNKNOWN overwrite a known value.
        application_protocol = event.get("application_protocol")

        if not application_protocol:

            application = event.get("application")

            if isinstance(application, dict):

                application_protocol = application.get("protocol")

        application_protocol = str(
            application_protocol or "UNKNOWN"
        ).upper()

        if (
            flow.application_protocol == "UNKNOWN"
            and application_protocol != "UNKNOWN"
        ):

            flow.application_protocol = application_protocol

        if flow.protocol == PROTO_TCP:

            self._update_tcp_state(flow, transport, event, forward)

    def _update_tcp_state(
        self,
        flow: Flow,
        transport: dict[str, Any],
        event: dict[str, Any],
        forward: bool,
    ) -> None:

        flags = transport.get("flags")

        if flags is None:
            flags = event.get("flags")

        flags = str(flags or "").upper()

        flag_set = set(flags) & FLAG_ALPHABET

        if not flag_set:

            return

        syn = "S" in flag_set
        ack = "A" in flag_set
        fin = "F" in flag_set
        rst = "R" in flag_set

        if syn:
            flow.SYN_count += 1

        if ack:
            flow.ACK_count += 1

        if fin:
            flow.FIN_count += 1

        if rst:
            flow.RST_count += 1

        direction = "forward" if forward else "backward"

        # RST is terminal and wins over everything else.
        if rst:

            flow.state = STATE_RESET
            return

        if fin:

            flow.fin_directions.add(direction)

            if flow.state not in TERMINAL_STATES:

                if len(flow.fin_directions) >= 2:

                    flow.state = STATE_CLOSED

                elif flow.state in (
                    STATE_NEW,
                    STATE_HANDSHAKE,
                    STATE_ESTABLISHED,
                    STATE_CLOSING,
                ):

                    flow.state = STATE_CLOSING

            return

        if syn and not ack:

            flow.handshake_syn = True

            if flow.state == STATE_NEW:

                flow.state = STATE_HANDSHAKE

            return

        if syn and ack:

            flow.handshake_synack = True

            return

        if ack:

            if flow.state == STATE_HANDSHAKE:

                # Either the SYN/ACK was observed, or a pure ACK closes the
                # handshake for a capture that started mid-stream.
                flow.state = STATE_ESTABLISHED

            elif flow.state == STATE_NEW:

                # Mid-stream capture: an established connection whose
                # handshake we never saw.
                flow.state = STATE_ESTABLISHED

    def _expire(self, now: float) -> list[dict[str, Any]]:

        records: list[dict[str, Any]] = []

        for key in list(self.flows.keys()):

            flow = self.flows.get(key)

            if flow is None:

                continue

            timeout = (
                self.tcp_idle_timeout
                if flow.protocol == PROTO_TCP
                else self.udp_idle_timeout
            )

            if now - flow.last_seen > timeout:

                records.append(self._finalize(flow, "timeout"))

        return records

    def _finalize(
        self,
        flow: Flow,
        reason: str,
    ) -> dict[str, Any]:

        self.flows.pop(flow.key, None)

        self.finalized_count += 1

        return flow.to_record(reason)


__all__ = [
    "Flow",
    "FlowTracker",
    "STATE_NEW",
    "STATE_HANDSHAKE",
    "STATE_ESTABLISHED",
    "STATE_CLOSING",
    "STATE_CLOSED",
    "STATE_RESET",
    "STATE_OPEN",
]
