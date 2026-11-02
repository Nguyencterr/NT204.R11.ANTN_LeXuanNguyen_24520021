"""Assignment 3, section 4.4: TCP ``flags`` and ``dsize`` conditions."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Any

from ..rule_parser.models import InternalRule


@dataclass(frozen=True)
class FlagsMatch:
    matched: bool
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:

        return {
            "matched": self.matched,
            "reason": self.reason,
            "details": self.details,
        }


@dataclass(frozen=True)
class DsizeMatch:
    matched: bool
    payload_length: int | None = None
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:

        return {
            "matched": self.matched,
            "payload_length": self.payload_length,
            "reason": self.reason,
            "details": self.details,
        }


def _event_flags(event: dict[str, Any]) -> str | None:

    transport = event.get("transport")

    if isinstance(transport, dict):

        flags = transport.get("flags")

        if flags is not None:

            return str(flags).upper()

    flags = event.get("flags")

    if flags is not None:

        return str(flags).upper()

    return None


def match_rule_flags(
    rule: InternalRule,
    event: Any,
) -> FlagsMatch:
    """
    Match TCP flags.

    Semantics: every flag declared by the rule must be present in the event
    flags. Extra event flags do not prevent a match (``flags:S`` matches both
    ``S`` and ``SA``).
    """

    if rule.tcp_flags is None:

        return FlagsMatch(matched=True, details={"required": None})

    if not isinstance(event, dict):

        return FlagsMatch(
            matched=False,
            reason="event is not a mapping; TCP flags unavailable",
            details={"required": "".join(sorted(rule.tcp_flags))},
        )

    required = "".join(sorted(rule.tcp_flags))
    observed = _event_flags(event)

    if observed is None:

        return FlagsMatch(
            matched=False,
            reason="event has no TCP flags field",
            details={"required": required, "observed": None},
        )

    observed_set = set(observed)

    missing = set(rule.tcp_flags) - observed_set

    details = {
        "required": required,
        "observed": observed,
        "missing": "".join(sorted(missing)),
    }

    if missing:

        return FlagsMatch(
            matched=False,
            reason=(
                "TCP flags mismatch: required "
                f"{required}, observed {observed}"
            ),
            details=details,
        )

    return FlagsMatch(matched=True, details=details)


def payload_size(event: Any) -> int | None:
    """
    Return the packet payload length, never the full frame or flow bytes.

    ``payload_length`` from the Assignment 1/2 contract wins. If it is missing,
    the bounded raw payload bytes are used as a documented fallback.
    """

    if not isinstance(event, dict):

        return None

    value = event.get("payload_length")

    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:

        return value

    encoded = event.get("raw_payload_b64")

    if isinstance(encoded, str) and encoded:

        try:

            return len(base64.b64decode(encoded, validate=False))

        except (binascii.Error, ValueError):

            return None

    return None


def match_rule_dsize(
    rule: InternalRule,
    event: Any,
) -> DsizeMatch:
    """Match ``dsize`` against the packet payload length."""

    if rule.dsize is None:

        return DsizeMatch(matched=True, details={"required": None})

    size = payload_size(event)

    details = {
        "operator": rule.dsize.operator,
        "value": rule.dsize.value,
        "payload_length": size,
    }

    if size is None:

        return DsizeMatch(
            matched=False,
            payload_length=None,
            reason="payload length is unavailable; dsize cannot be evaluated",
            details=details,
        )

    matched = rule.dsize.matches(size)

    return DsizeMatch(
        matched=matched,
        payload_length=size,
        reason=None
        if matched
        else (
            "dsize mismatch: payload length "
            f"{size} does not satisfy {rule.dsize.operator}{rule.dsize.value}"
        ),
        details=details,
    )


__all__ = [
    "DsizeMatch",
    "FlagsMatch",
    "match_rule_dsize",
    "match_rule_flags",
    "payload_size",
]
