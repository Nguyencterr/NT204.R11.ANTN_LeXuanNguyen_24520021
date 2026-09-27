from scapy.packet import Packet

from .application import parse_application
from .network import parse_network
from .normalized import NormalizedEvent
from .transport import parse_transport


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
