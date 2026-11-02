"""Assignment 3, section 4.6: Detection Event Generator.

One MATCH result plus its event and flow context becomes one JSON-compatible
Detection Event. Multiple matching rules produce independent Detection Events,
each with its own SID and rule metadata.

The generator does not print alerts; writing JSON Lines is the pipeline's job.
"""

from __future__ import annotations

from typing import Any

from ..matching.engine import RuleMatchResult
from ..rule_parser.models import InternalRule


SCHEMA_VERSION = "bt3.detection.v1"


def _coerce_port(value: Any) -> int | None:

    if value is None or isinstance(value, bool):

        return None

    try:

        return int(value)

    except (TypeError, ValueError):

        return None


def _coerce_timestamp(value: Any) -> float | None:

    if value is None or isinstance(value, bool):

        return None

    try:

        return float(value)

    except (TypeError, ValueError):

        return None


def _application_protocol(event: dict[str, Any]) -> str:

    value = event.get("application_protocol")

    if not value:

        application = event.get("application")

        if isinstance(application, dict):

            value = application.get("protocol")

    return str(value or "UNKNOWN").upper()


class DetectionEventGenerator:
    """Build structured Detection Events from MATCH results."""

    def generate(
        self,
        match: RuleMatchResult,
        event: Any,
        flow_context: Any = None,
    ) -> dict[str, Any]:
        """Return one JSON-serializable Detection Event."""

        if not isinstance(event, dict):

            event = {}

        rule = match.rule

        if not isinstance(rule, InternalRule):  # pragma: no cover - defensive

            raise ValueError("match result has no InternalRule")

        transport = event.get("transport")

        if not isinstance(transport, dict):

            transport = {}

        src_port = event.get("src_port")

        if src_port is None:

            src_port = transport.get("src_port")

        dst_port = event.get("dst_port")

        if dst_port is None:

            dst_port = transport.get("dst_port")

        context = flow_context if isinstance(flow_context, dict) else {}

        matched_info = match.to_dict()["matched_info"]
        matched_info["reason"] = match.reason
        matched_info["flow_conditions"] = context.get(
            "flow_conditions",
            match.details.get("flow", {}).get("details"),
        )

        return {
            "schema_version": SCHEMA_VERSION,
            "timestamp": _coerce_timestamp(event.get("timestamp")),
            "packet_id": event.get("packet_id"),
            "action": rule.action,
            "sid": rule.sid,
            "rev": rule.rev,
            "msg": rule.msg,
            "priority": rule.priority,
            "classtype": rule.classtype,
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "src_port": _coerce_port(src_port),
            "dst_port": _coerce_port(dst_port),
            "protocol": str(
                event.get("transport_protocol")
                or transport.get("protocol")
                or "UNKNOWN"
            ).upper(),
            "application_protocol": _application_protocol(event),
            "flow_id": context.get("flow_id"),
            "matched_info": matched_info,
            "rule": {
                "sid": rule.sid,
                "rev": rule.rev,
                "msg": rule.msg,
                "rule_ref": rule.rule_ref,
                "source_file": rule.source_file,
                "line_number": rule.line_number,
                "raw_text": rule.raw_text,
            },
        }


__all__ = [
    "DetectionEventGenerator",
    "SCHEMA_VERSION",
]
