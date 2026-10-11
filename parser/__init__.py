import base64

from scapy.packet import Packet

from .application import parse_application
from .network import parse_network
from .normalized import (
    MAX_RAW_PAYLOAD_BYTES,
    NormalizedEvent,
)
from .transport import parse_transport


def _bounded_payload(payload: bytes) -> tuple[str | None, bool]:
    """
    Base64-encode a bounded prefix of the raw payload.

    Returns ``(encoded, truncated)``. ``encoded`` is ``None`` for empty
    payloads so that JSONL stays compact and no non-serializable ``bytes``
    leaks downstream.
    """

    if not payload:
        return None, False

    truncated = len(payload) > MAX_RAW_PAYLOAD_BYTES

    prefix = payload[:MAX_RAW_PAYLOAD_BYTES]

    return (
        base64.b64encode(prefix).decode("ascii"),
        truncated,
    )


def _packet_length(packet) -> int | None:
    """
    Best-effort full packet length. Returns ``None`` when Scapy cannot
    reliably compute it; the tracker then documents a payload-length
    fallback.
    """

    try:

        length = int(len(packet))

    except Exception:

        return None

    return length if length > 0 else None


def parse_packet(
    packet,
    packet_id: int,
) -> NormalizedEvent | None:
    """
    Main packet parsing pipeline.

    Raw Packet
        -> Network Parser
        -> Transport Parser
        -> Application Detector
        -> Application Parser
        -> Normalized IDS Event
    """

    if not isinstance(
        packet,
        Packet,
    ):
        return None

    packet_time = getattr(
        packet,
        "time",
        0,
    )

    try:

        timestamp = float(
            packet_time
        )

    except (
        TypeError,
        ValueError,
    ):

        timestamp = 0.0

    event = NormalizedEvent(
        packet_id=packet_id,
        timestamp=timestamp,
    )

    event.packet_length = _packet_length(packet)

    try:

        # -----------------------------------------
        # Network Parser
        # -----------------------------------------
        has_ipv4 = parse_network(
            packet,
            event,
        )

        if not has_ipv4:

            event.status = "IGNORED"

            event.errors.append(
                "Unsupported or missing IPv4 layer"
            )

            return event

        # -----------------------------------------
        # Transport Parser
        # -----------------------------------------
        payload = parse_transport(
            packet,
            event,
        )

        (
            event.raw_payload_b64,
            event.raw_payload_truncated,
        ) = _bounded_payload(payload)

        # -----------------------------------------
        # Application Parser
        # -----------------------------------------
        try:

            parse_application(
                packet,
                payload,
                event,
            )

        except Exception as exc:

            event.status = "PARSE_ERROR"

            event.errors.append(
                "Application parser error: "
                f"{type(exc).__name__}: {exc}"
            )

            event.application = {
                "protocol": "UNKNOWN"
            }

        return event

    except Exception as exc:

        event.status = "PARSE_ERROR"

        event.errors.append(
            "Packet parser error: "
            f"{type(exc).__name__}: {exc}"
        )

        return event
