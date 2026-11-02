"""Assignment 3, section 4.4: shared header matching primitives.

Both the Rule Repository/Indexer (4.3) and the Rule Matching Engine (4.4) use
this module, so candidate pre-filtering can never disagree with the final
header decision.

Security note: ``->`` is strictly source-to-destination. Only ``<>`` is allowed
to match the reversed orientation, and the result records which orientation
matched.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..rule_parser.models import (
    DIRECTION_BIDIRECTIONAL,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    InternalRule,
)


ORIENTATION_FORWARD = "forward"
ORIENTATION_REVERSE = "reverse"


@dataclass(frozen=True)
class EventHeader:
    """The subset of a normalized event used for header matching."""

    protocol: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None


@dataclass(frozen=True)
class HeaderMatch:
    """Outcome of matching a rule header against one event."""

    matched: bool
    orientation: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:

        return {
            "matched": self.matched,
            "orientation": self.orientation,
            "reason": self.reason,
        }


def _coerce_port(value: Any) -> int | None:

    if value is None or isinstance(value, bool):

        return None

    try:

        return int(value)

    except (TypeError, ValueError):

        return None


def extract_event_header(event: Any) -> EventHeader | None:
    """Return a typed header view, or ``None`` for a non-mapping event."""

    if not isinstance(event, dict):

        return None

    transport = event.get("transport")

    if not isinstance(transport, dict):

        transport = {}

    protocol = (
        event.get("transport_protocol")
        or transport.get("protocol")
        or "UNKNOWN"
    )

    src_port = event.get("src_port")

    if src_port is None:

        src_port = transport.get("src_port")

    dst_port = event.get("dst_port")

    if dst_port is None:

        dst_port = transport.get("dst_port")

    return EventHeader(
        protocol=str(protocol).upper(),
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dst_ip"),
        src_port=_coerce_port(src_port),
        dst_port=_coerce_port(dst_port),
    )


def _orientation_matches(
    rule: InternalRule,
    header: EventHeader,
    *,
    reverse: bool,
) -> bool:

    if reverse:

        return (
            rule.src_address.matches(header.dst_ip)
            and rule.src_port.matches(header.dst_port)
            and rule.dst_address.matches(header.src_ip)
            and rule.dst_port.matches(header.src_port)
        )

    return (
        rule.src_address.matches(header.src_ip)
        and rule.src_port.matches(header.src_port)
        and rule.dst_address.matches(header.dst_ip)
        and rule.dst_port.matches(header.dst_port)
    )


def match_rule_header(
    rule: InternalRule,
    event: Any,
) -> HeaderMatch:
    """Match protocol, addresses, ports and direction for one rule."""

    header = extract_event_header(event)

    if header is None:

        return HeaderMatch(
            matched=False,
            reason="event is not a normalized mapping",
        )

    if header.protocol not in (PROTOCOL_TCP, PROTOCOL_UDP):

        return HeaderMatch(
            matched=False,
            reason=(
                "event transport protocol is not TCP/UDP: "
                f"{header.protocol!r}"
            ),
        )

    if header.protocol != rule.protocol:

        return HeaderMatch(
            matched=False,
            reason=(
                f"protocol mismatch: rule {rule.protocol}, "
                f"event {header.protocol}"
            ),
        )

    if _orientation_matches(rule, header, reverse=False):

        return HeaderMatch(
            matched=True,
            orientation=ORIENTATION_FORWARD,
        )

    if rule.direction == DIRECTION_BIDIRECTIONAL and _orientation_matches(
        rule,
        header,
        reverse=True,
    ):

        return HeaderMatch(
            matched=True,
            orientation=ORIENTATION_REVERSE,
        )

    return HeaderMatch(
        matched=False,
        reason=(
            "header mismatch: no orientation of the rule matches "
            f"{header.src_ip}:{header.src_port} -> "
            f"{header.dst_ip}:{header.dst_port} "
            f"(rule direction {rule.direction})"
        ),
    )


__all__ = [
    "EventHeader",
    "HeaderMatch",
    "ORIENTATION_FORWARD",
    "ORIENTATION_REVERSE",
    "extract_event_header",
    "match_rule_header",
]
