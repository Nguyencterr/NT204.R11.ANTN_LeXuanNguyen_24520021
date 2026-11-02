"""Assignment 3, section 4.3: Rule Repository / Indexer.

The repository stores *valid* InternalRule objects, keeps invalid/unsupported
parse diagnostics for auditability, and builds a protocol/port index so the
evaluation engine does not have to scan every rule.

Correctness contract: ``candidates(event)`` may return extra rules, but it must
never omit a rule that could match. The final authoritative decision is still
made by the matcher; the index only uses necessary header conditions.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from ..matching.header import (
    extract_event_header,
    match_rule_header,
)
from ..rule_parser.models import (
    DIRECTION_BIDIRECTIONAL,
    PORT_ANY,
    PORT_SINGLE,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    STATUS_INVALID,
    STATUS_UNSUPPORTED,
    STATUS_VALID,
    InternalRule,
    PortSelector,
    RuleParseResult,
)


DUPLICATE_SID_REJECT = "reject"
DUPLICATE_SID_WARN_KEEP = "warn_keep"

DUPLICATE_SID_POLICIES = (
    DUPLICATE_SID_REJECT,
    DUPLICATE_SID_WARN_KEEP,
)

CODE_DUPLICATE_SID = "DUPLICATE_SID"
CODE_INVALID_RULE = "INVALID_RULE"
CODE_UNSUPPORTED_RULE = "UNSUPPORTED_RULE"


@dataclass(frozen=True)
class RepositoryConfig:
    """Duplicate SID policy; no rule is ever silently overwritten."""

    duplicate_sid_policy: str = DUPLICATE_SID_REJECT

    def __post_init__(self) -> None:

        if self.duplicate_sid_policy not in DUPLICATE_SID_POLICIES:

            raise ValueError(
                "duplicate_sid_policy must be one of "
                f"{DUPLICATE_SID_POLICIES}, got "
                f"{self.duplicate_sid_policy!r}"
            )


@dataclass(frozen=True)
class RepositoryDiagnostic:
    """Why a loaded rule is not part of the matchable rule set."""

    status: str
    code: str
    message: str
    rule_ref: str | None = None
    sid: int | None = None
    source_file: str | None = None
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:

        return {
            "status": self.status,
            "code": self.code,
            "message": self.message,
            "rule_ref": self.rule_ref,
            "sid": self.sid,
            "source_file": self.source_file,
            "line_number": self.line_number,
        }


@dataclass(frozen=True)
class RepositoryDecision:
    """Outcome of adding one parse result to the repository."""

    accepted: bool
    code: str | None = None
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:

        return {
            "accepted": self.accepted,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True)
class CandidateSelection:
    """Candidate rules retrieved for one event, plus index statistics."""

    protocol: str | None
    rules: tuple[InternalRule, ...] = field(default_factory=tuple)
    pool_size: int = 0
    port_candidate_count: int = 0
    reason: str | None = None

    @property
    def candidate_count(self) -> int:

        return len(self.rules)

    def to_dict(self) -> dict[str, Any]:

        return {
            "protocol": self.protocol,
            "pool_size": self.pool_size,
            "port_candidate_count": self.port_candidate_count,
            "candidate_count": self.candidate_count,
            "sids": [rule.sid for rule in self.rules],
            "reason": self.reason,
        }


class _PortIndex:
    """Exact / any / range port buckets for one protocol and side."""

    def __init__(self) -> None:

        self.exact: dict[int, set[int]] = defaultdict(set)
        self.any: set[int] = set()
        self.ranges: set[int] = set()

    def add(self, index: int, selector: PortSelector) -> None:

        if selector.kind == PORT_ANY:

            self.any.add(index)
            return

        if selector.kind == PORT_SINGLE and selector.start is not None:

            self.exact[selector.start].add(index)
            return

        self.ranges.add(index)

    def matching(self, port: int | None) -> set[int]:

        ids = set(self.any) | set(self.ranges)

        if port is not None:

            ids |= self.exact.get(port, set())

        return ids


class RuleRepository:
    """In-memory valid-rule store with a protocol/port/IP candidate index."""

    def __init__(
        self,
        config: RepositoryConfig | None = None,
    ) -> None:

        self.config = config or RepositoryConfig()

        self._rules: list[InternalRule] = []
        self._by_sid: dict[int, InternalRule] = {}
        self._diagnostics: list[RepositoryDiagnostic] = []
        self._parse_results: list[RuleParseResult] = []

        self._by_protocol: dict[str, list[InternalRule]] = {
            PROTOCOL_TCP: [],
            PROTOCOL_UDP: [],
        }
        self._port_index: dict[
            str,
            dict[str, _PortIndex],
        ] = {}

        self._dirty = True
        self.duplicate_sid_count = 0

    # -- public API ---------------------------------------------------------

    def add_parse_result(
        self,
        result: RuleParseResult,
    ) -> RepositoryDecision:
        """Store a valid rule or retain a diagnostic for a rejected one."""

        self._parse_results.append(result)

        if result.status == STATUS_INVALID:

            self._diagnostics.append(
                RepositoryDiagnostic(
                    status=STATUS_INVALID,
                    code=CODE_INVALID_RULE,
                    message=result.reason or "invalid rule",
                    rule_ref=result.rule_ref,
                    source_file=result.source_file,
                    line_number=result.line_number,
                )
            )

            return RepositoryDecision(
                accepted=False,
                code=CODE_INVALID_RULE,
                message=result.reason or "invalid rule",
            )

        if result.status == STATUS_UNSUPPORTED:

            self._diagnostics.append(
                RepositoryDiagnostic(
                    status=STATUS_UNSUPPORTED,
                    code=CODE_UNSUPPORTED_RULE,
                    message=result.reason or "unsupported rule",
                    rule_ref=result.rule_ref,
                    source_file=result.source_file,
                    line_number=result.line_number,
                )
            )

            return RepositoryDecision(
                accepted=False,
                code=CODE_UNSUPPORTED_RULE,
                message=result.reason or "unsupported rule",
            )

        if result.status != STATUS_VALID or result.rule is None:

            message = (
                "parse result has no usable rule "
                f"(status={result.status!r})"
            )

            self._diagnostics.append(
                RepositoryDiagnostic(
                    status=STATUS_INVALID,
                    code=CODE_INVALID_RULE,
                    message=message,
                    rule_ref=result.rule_ref,
                    source_file=result.source_file,
                    line_number=result.line_number,
                )
            )

            return RepositoryDecision(
                accepted=False,
                code=CODE_INVALID_RULE,
                message=message,
            )

        rule = result.rule

        if rule.sid in self._by_sid:

            self.duplicate_sid_count += 1

            message = (
                f"duplicate sid {rule.sid}: already defined by "
                f"{self._by_sid[rule.sid].rule_ref}; policy="
                f"{self.config.duplicate_sid_policy}"
            )

            self._diagnostics.append(
                RepositoryDiagnostic(
                    status=STATUS_INVALID,
                    code=CODE_DUPLICATE_SID,
                    message=message,
                    rule_ref=rule.rule_ref,
                    sid=rule.sid,
                    source_file=rule.source_file,
                    line_number=rule.line_number,
                )
            )

            if self.config.duplicate_sid_policy == DUPLICATE_SID_REJECT:

                return RepositoryDecision(
                    accepted=False,
                    code=CODE_DUPLICATE_SID,
                    message=message,
                )

            # warn_keep is documented as keeping both rules; matching both is
            # visible in detection evidence by rule_ref, never silently merged.

        ordered = replace(rule, order=len(self._rules))

        self._rules.append(ordered)
        self._by_sid.setdefault(ordered.sid, ordered)

        self._dirty = True

        return RepositoryDecision(accepted=True)

    def add_results(
        self,
        results: Iterable[RuleParseResult],
    ) -> list[RepositoryDecision]:
        """Add many parse results; every rule is handled independently."""

        return [self.add_parse_result(result) for result in results]

    @classmethod
    def from_parse_results(
        cls,
        results: Iterable[RuleParseResult],
        config: RepositoryConfig | None = None,
    ) -> "RuleRepository":

        repository = cls(config)
        repository.add_results(results)

        return repository

    @property
    def valid_rules(self) -> tuple[InternalRule, ...]:

        return tuple(self._rules)

    @property
    def diagnostics(self) -> tuple[RepositoryDiagnostic, ...]:

        return tuple(self._diagnostics)

    @property
    def parse_results(self) -> tuple[RuleParseResult, ...]:

        return tuple(self._parse_results)

    def __len__(self) -> int:

        return len(self._rules)

    def rebuild_index(self) -> None:
        """Rebuild protocol/port buckets from the current valid rule list."""

        self._by_protocol = {
            PROTOCOL_TCP: [],
            PROTOCOL_UDP: [],
        }
        self._port_index = {
            PROTOCOL_TCP: {
                "src": _PortIndex(),
                "dst": _PortIndex(),
            },
            PROTOCOL_UDP: {
                "src": _PortIndex(),
                "dst": _PortIndex(),
            },
        }

        for index, rule in enumerate(self._rules):

            if rule.protocol not in self._by_protocol:

                # The parser only emits TCP/UDP; this guard keeps a manually
                # constructed rule from corrupting the index.
                continue

            self._by_protocol[rule.protocol].append(rule)

            self._port_index[rule.protocol]["src"].add(
                index,
                rule.src_port,
            )
            self._port_index[rule.protocol]["dst"].add(
                index,
                rule.dst_port,
            )

        self._dirty = False

    def candidates(self, event: Any) -> CandidateSelection:
        """Return a superset of rules whose headers could match ``event``."""

        header = extract_event_header(event)

        if header is None:

            return CandidateSelection(
                protocol=None,
                reason="event is not a normalized mapping",
            )

        if header.protocol not in (PROTOCOL_TCP, PROTOCOL_UDP):

            return CandidateSelection(
                protocol=header.protocol,
                reason=(
                    "event protocol is not TCP/UDP: "
                    f"{header.protocol!r}"
                ),
            )

        if self._dirty:

            self.rebuild_index()

        pool = self._by_protocol.get(header.protocol, [])

        if not pool:

            return CandidateSelection(
                protocol=header.protocol,
                reason="no valid rule for this protocol",
            )

        side_index = self._port_index[header.protocol]

        forward = (
            side_index["src"].matching(header.src_port)
            & side_index["dst"].matching(header.dst_port)
        )

        # Reverse orientation is only legal for '<>'. For a reversed event the
        # rule source selector is compared with the event destination port.
        reverse = (
            side_index["src"].matching(header.dst_port)
            & side_index["dst"].matching(header.src_port)
        )

        reverse = {
            index
            for index in reverse
            if self._rules[index].direction == DIRECTION_BIDIRECTIONAL
        }

        port_candidates = forward | reverse

        selected: list[InternalRule] = []

        for index in sorted(port_candidates):

            rule = self._rules[index]

            # Exact header pre-filter: shared with the matcher, so the index
            # cannot disagree with the authoritative decision.
            if match_rule_header(rule, event).matched:

                selected.append(rule)

        selected.sort(key=lambda rule: rule.order)

        reason = None if selected else "no candidate rule passed the header pre-filter"

        return CandidateSelection(
            protocol=header.protocol,
            rules=tuple(selected),
            pool_size=len(pool),
            port_candidate_count=len(port_candidates),
            reason=reason,
        )

    def statistics(self) -> dict[str, Any]:
        """Return auditable repository counters."""

        by_status: dict[str, int] = defaultdict(int)

        for result in self._parse_results:

            by_status[result.status] += 1

        return {
            "parse_results": len(self._parse_results),
            "valid": len(self._rules),
            "invalid": by_status.get(STATUS_INVALID, 0),
            "unsupported": by_status.get(STATUS_UNSUPPORTED, 0),
            "duplicate_sid": self.duplicate_sid_count,
            "diagnostics": len(self._diagnostics),
        }


__all__ = [
    "CODE_DUPLICATE_SID",
    "CODE_INVALID_RULE",
    "CODE_UNSUPPORTED_RULE",
    "CandidateSelection",
    "DUPLICATE_SID_POLICIES",
    "DUPLICATE_SID_REJECT",
    "DUPLICATE_SID_WARN_KEEP",
    "RepositoryConfig",
    "RepositoryDecision",
    "RepositoryDiagnostic",
    "RuleRepository",
]
