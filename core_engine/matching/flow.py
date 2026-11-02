"""Assignment 3, section 4.4: ``flow:`` condition matching.

The Assignment 2 Flow Tracker is packet/flow oriented, not client/server
oriented. ``flow/context.py`` adds an explicit adapter that infers client/server
roles from evidence (TCP SYN, then well-known server port, then lower port) and
records ``role_source`` so a match can be explained.

This module only consumes that adapter contract. If the context is missing, or
the role is unknown, a rule that requires a flow condition returns NO_MATCH with
a reason instead of inventing ``to_server`` or ``established``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..rule_parser.models import (
    FLOW_ESTABLISHED,
    FLOW_NOT_ESTABLISHED,
    FLOW_TO_CLIENT,
    FLOW_TO_SERVER,
    InternalRule,
)


@dataclass(frozen=True)
class FlowMatch:
    """Outcome of every ``flow:`` condition on one rule."""

    matched: bool
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:

        return {
            "matched": self.matched,
            "reason": self.reason,
            "details": self.details,
        }


def match_rule_flow(
    rule: InternalRule,
    flow_context: Any,
) -> FlowMatch:
    """Evaluate ``to_server``, ``to_client``, ``established`` conditions."""

    if not rule.flow:

        return FlowMatch(matched=True, details={"required": []})

    if not isinstance(flow_context, dict):

        return FlowMatch(
            matched=False,
            reason=(
                "rule requires flow context but the event has none: "
                + ",".join(rule.flow)
            ),
            details={"required": list(rule.flow)},
        )

    details: dict[str, Any] = {
        "required": list(rule.flow),
        "flow_id": flow_context.get("flow_id"),
        "state": flow_context.get("state"),
        "direction": flow_context.get("direction"),
        "role_source": flow_context.get("role_source"),
        "to_server": flow_context.get("to_server"),
        "to_client": flow_context.get("to_client"),
        "established": flow_context.get("established"),
    }

    for condition in rule.flow:

        if condition == FLOW_TO_SERVER:

            value = flow_context.get("to_server")

            if value is None:

                return FlowMatch(
                    matched=False,
                    reason=(
                        "flow:to_server cannot be evaluated: client/server "
                        "role is unknown for this flow"
                    ),
                    details=details,
                )

            if not value:

                return FlowMatch(
                    matched=False,
                    reason="flow:to_server does not match packet direction",
                    details=details,
                )

        elif condition == FLOW_TO_CLIENT:

            value = flow_context.get("to_client")

            if value is None:

                return FlowMatch(
                    matched=False,
                    reason=(
                        "flow:to_client cannot be evaluated: client/server "
                        "role is unknown for this flow"
                    ),
                    details=details,
                )

            if not value:

                return FlowMatch(
                    matched=False,
                    reason="flow:to_client does not match packet direction",
                    details=details,
                )

        elif condition == FLOW_ESTABLISHED:

            value = flow_context.get("established")

            if value is None:

                return FlowMatch(
                    matched=False,
                    reason=(
                        "flow:established cannot be evaluated from the "
                        "available flow state"
                    ),
                    details=details,
                )

            if not value:

                return FlowMatch(
                    matched=False,
                    reason=(
                        "flow:established does not match flow state "
                        f"{flow_context.get('state')!r}"
                    ),
                    details=details,
                )

        elif condition == FLOW_NOT_ESTABLISHED:

            value = flow_context.get("established")

            if value is None:

                return FlowMatch(
                    matched=False,
                    reason=(
                        "flow:not_established cannot be evaluated from the "
                        "available flow state"
                    ),
                    details=details,
                )

            if value:

                return FlowMatch(
                    matched=False,
                    reason="flow:not_established matched an established flow",
                    details=details,
                )

    return FlowMatch(matched=True, details=details)


__all__ = [
    "FlowMatch",
    "match_rule_flow",
]
