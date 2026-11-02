"""Assignment 3, section 4.4: Rule Matching Engine.

The matcher receives one normalized event, one flow context and one valid
InternalRule. It returns a structured MATCH / NO_MATCH result; it never prints
alerts and never writes Detection Events.

Evaluation order (short-circuit):

1. header (protocol, addresses, ports, direction)
2. ``flow:`` state/direction conditions
3. TCP ``flags``
4. ``dsize``
5. ``content`` sequence

Header mismatch therefore returns before any content matching runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..rule_parser.models import InternalRule
from .buffers import extract_buffers
from .conditions import (
    DsizeMatch,
    FlagsMatch,
    match_rule_dsize,
    match_rule_flags,
)
from .content import ContentMatchOutcome, match_contents
from .flow import FlowMatch, match_rule_flow
from .header import HeaderMatch, match_rule_header


STATUS_MATCH = "MATCH"
STATUS_NO_MATCH = "NO_MATCH"


@dataclass(frozen=True)
class RuleMatchResult:
    """Result of matching one rule against one event."""

    status: str
    sid: int | None
    rule_ref: str | None
    msg: str | None
    reason: str | None = None
    orientation: str | None = None
    matched_contents: tuple[dict[str, Any], ...] = field(
        default_factory=tuple
    )
    buffer: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    rule: InternalRule | None = None

    @property
    def matched(self) -> bool:

        return self.status == STATUS_MATCH

    def to_dict(self) -> dict[str, Any]:

        return {
            "status": self.status,
            "sid": self.sid,
            "rule_ref": self.rule_ref,
            "msg": self.msg,
            "reason": self.reason,
            "matched_info": {
                "orientation": self.orientation,
                "buffer": self.buffer,
                "content_matches": list(self.matched_contents),
                "details": self.details,
            },
        }


class RuleMatchingEngine:
    """Header + flow + flags + dsize + content matcher."""

    def __init__(self) -> None:

        self.content_matcher = match_contents

    # -- public API ---------------------------------------------------------

    def match(
        self,
        event: Any,
        rule: InternalRule,
        flow_context: Any = None,
    ) -> RuleMatchResult:
        """Match one rule, isolating every unexpected error."""

        try:

            return self._match(event, rule, flow_context)

        except Exception as exc:  # noqa: BLE001 - never crash the pipeline

            return self._no_match(
                rule,
                f"matching error: {type(exc).__name__}: {exc}",
            )

    def match_contents(
        self,
        rule: InternalRule,
        buffers: list[Any],
    ) -> ContentMatchOutcome:
        """Separate method so tests can prove header short-circuiting."""

        return self.content_matcher(rule.contents, buffers)

    # -- internals ----------------------------------------------------------

    def _match(
        self,
        event: Any,
        rule: InternalRule,
        flow_context: Any,
    ) -> RuleMatchResult:

        header: HeaderMatch = match_rule_header(rule, event)

        if not header.matched:

            return self._no_match(
                rule,
                header.reason or "header mismatch",
                details={"header": header.to_dict()},
            )

        flow: FlowMatch = match_rule_flow(rule, flow_context)

        if not flow.matched:

            return self._no_match(
                rule,
                flow.reason or "flow condition mismatch",
                orientation=header.orientation,
                details={
                    "header": header.to_dict(),
                    "flow": flow.to_dict(),
                },
            )

        flags: FlagsMatch = match_rule_flags(rule, event)

        if not flags.matched:

            return self._no_match(
                rule,
                flags.reason or "TCP flags mismatch",
                orientation=header.orientation,
                details={
                    "header": header.to_dict(),
                    "flow": flow.to_dict(),
                    "flags": flags.to_dict(),
                },
            )

        dsize: DsizeMatch = match_rule_dsize(rule, event)

        if not dsize.matched:

            return self._no_match(
                rule,
                dsize.reason or "dsize mismatch",
                orientation=header.orientation,
                details={
                    "header": header.to_dict(),
                    "flow": flow.to_dict(),
                    "flags": flags.to_dict(),
                    "dsize": dsize.to_dict(),
                },
            )

        buffers = extract_buffers(event)
        content: ContentMatchOutcome = self.match_contents(rule, buffers)

        details = {
            "header": header.to_dict(),
            "flow": flow.to_dict(),
            "flags": flags.to_dict(),
            "dsize": dsize.to_dict(),
            "content": content.to_dict(),
        }

        if not content.matched:

            return self._no_match(
                rule,
                content.reason or "content mismatch",
                orientation=header.orientation,
                details=details,
            )

        return RuleMatchResult(
            status=STATUS_MATCH,
            sid=rule.sid,
            rule_ref=rule.rule_ref,
            msg=rule.msg,
            reason=None,
            orientation=header.orientation,
            matched_contents=tuple(
                match.to_dict()
                for match in content.matches
            ),
            buffer=content.buffer,
            details=details,
            rule=rule,
        )

    @staticmethod
    def _no_match(
        rule: InternalRule,
        reason: str,
        *,
        orientation: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> RuleMatchResult:

        return RuleMatchResult(
            status=STATUS_NO_MATCH,
            sid=rule.sid,
            rule_ref=rule.rule_ref,
            msg=rule.msg,
            reason=reason,
            orientation=orientation,
            details=details or {},
            rule=rule,
        )


__all__ = [
    "RuleMatchResult",
    "RuleMatchingEngine",
    "STATUS_MATCH",
    "STATUS_NO_MATCH",
]
