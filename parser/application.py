import re

from scapy.layers.dns import DNS

from .normalized import NormalizedEvent
from .protocols.dns import parse_dns
from .protocols.http import parse_http
from .protocols.smtp import parse_smtp


HTTP_REQUEST_RE = re.compile(
    rb"^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)"
    rb"\s+\S+\s+HTTP/1\.[01]"
)

HTTP_RESPONSE_RE = re.compile(
    rb"^HTTP/1\.[01]\s+\d{3}"
)


def detect_application(
    packet,
    payload: bytes,
) -> str:

    # DNS can be identified directly by the
    # presence of the DNS layer.
    if packet.haslayer(DNS):
        return "DNS"

    if not payload:
        return "UNKNOWN"

    # ---------------------------------------------
    # HTTP
    # ---------------------------------------------
    first_line = payload.split(
        b"\r\n",
        1,
    )[0]

    if HTTP_REQUEST_RE.match(
        first_line
    ):

        return "HTTP"

    if HTTP_RESPONSE_RE.match(
        first_line
    ):

        return "HTTP"

    # ---------------------------------------------
    # SMTP
    # ---------------------------------------------
    try:

        text = payload.decode(
            "latin-1",
            errors="replace",
        )

        line = (
            text.splitlines()[0]
            .strip()
        )

        upper = line.upper()

        if (
            upper.startswith("HELO ")
            or upper.startswith("EHLO ")
            or upper.startswith("MAIL FROM:")
            or upper.startswith("RCPT TO:")
        ):

            return "SMTP"

        if re.match(
            r"^\d{3}[\s-]",
            line,
        ):

            return "SMTP"

    except Exception:
        pass

    return "UNKNOWN"


def parse_application(
    packet,
    payload: bytes,
    event: NormalizedEvent,
) -> None:

    protocol = detect_application(
        packet,
        payload,
    )

    if protocol == "HTTP":

        event.application = parse_http(
            payload
        )

        return

    if protocol == "DNS":

        event.application = parse_dns(
            packet
        )

        return

    if protocol == "SMTP":

        event.application = parse_smtp(
            payload
        )

        return

    event.application = {
        "protocol": "UNKNOWN"
    }
