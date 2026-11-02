"""Assignment 3, section 4.5: Rule Evaluation Engine.

Per event:

1. increment ``events_evaluated``,
2. ask the repository/indexer for candidate rules,
3. evaluate **every** candidate through the matching engine,
4. collect all MATCH results (no stop at the first match),
5. hand them to the Detection Event Generator.

Errors are isolated per candidate and per detection event. An unmatched event
produces no Detection Event but is still counted in the statistics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..detection.generator import DetectionEventGenerator
from ..matching.engine import (
    RuleMatchResult,
    RuleMatchingEngine,
    STATUS_MATCH,
)
from ..rule_repository.repository import CandidateSelection, RuleRepository


DetectionHandler = Callable[[dict[str, Any]], None]


@dataclass
class EvaluationStatistics:
    """Cumulative counters, documented in the README.

    ``candidate_rules`` is cumulative across all evaluated events;
    ``candidates`` in an :class:`EventEvaluationResult` is per event.
    """

    events_evaluated: int = 0
    candidate_rules: int = 0
    matches: int = 0
    no_match_count: int = 0
    invalid_event_count: int = 0
    errors: int = 0
    detections_generated: int = 0

    def to_dict(self) -> dict[str, Any]:

        return {
            "events_evaluated": self.events_evaluated,
            "candidate_rules": self.candidate_rules,
            "matches": self.matches,
            "no_match_count": self.no_match_count,
            "invalid_event_count": self.invalid_event_count,
            "errors": self.errors,
            "detections_generated": self.detections_generated,
        }


@dataclass(frozen=True)
class EventEvaluationResult:
    """Everything that happened while evaluating one event."""

    packet_id: Any
    protocol: str | None
    pool_size: int = 0
    candidates: tuple[Any, ...] = field(default_factory=tuple)
    matches: tuple[RuleMatchResult, ...] = field(default_factory=tuple)
    detections: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    reason: str | None = None

    @property
    def candidate_count(self) -> int:

        return len(self.candidates)

    @property
    def match_count(self) -> int:

        return len(self.matches)

    def to_dict(self) -> dict[str, Any]:

        return {
            "packet_id": self.packet_id,
            "protocol": self.protocol,
            "pool_size": self.pool_size,
            "candidate_count": self.candidate_count,
            "candidate_sids": [rule.sid for rule in self.candidates],
            "matches": [match.to_dict() for match in self.matches],
            "detections": list(self.detections),
            "reason": self.reason,
        }


class RuleEvaluationEngine:
    """Candidate selection + matching + Detection Event generation."""

    def __init__(
        self,
        repository: RuleRepository,
        matching_engine: RuleMatchingEngine | None = None,
        detection_generator: DetectionEventGenerator | None = None,
        detection_handler: DetectionHandler | None = None,
    ) -> None:

        self.repository = repository
        self.matching_engine = matching_engine or RuleMatchingEngine()
        self.detection_generator = (
            detection_generator or DetectionEventGenerator()
        )
        self.detection_handler = detection_handler

        self.statistics = EvaluationStatistics()

    # -- public API ---------------------------------------------------------

    def evaluate(
        self,
        event: Any,
        flow_context: Any = None,
    ) -> EventEvaluationResult:
        """Evaluate one event; never raises for bad input or a bad rule."""

        self.statistics.events_evaluated += 1

        if not isinstance(event, dict):

            self.statistics.invalid_event_count += 1

            return EventEvaluationResult(
                packet_id=None,
                protocol=None,
                reason=(
                    "event is not a mapping: "
                    f"{type(event).__name__}"
                ),
            )

        if event.get("preprocess_status") == "invalid":

            self.statistics.invalid_event_count += 1

        try:

            selection: CandidateSelection = self.repository.candidates(event)

        except Exception as exc:  # noqa: BLE001 - pipeline must keep running

            self.statistics.errors += 1

            return EventEvaluationResult(
                packet_id=event.get("packet_id"),
                protocol=event.get("transport_protocol"),
                reason=(
                    "candidate selection error: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        self.statistics.candidate_rules += selection.candidate_count

        matches: list[RuleMatchResult] = []

        for rule in selection.rules:

            try:

                result = self.matching_engine.match(
                    event,
                    rule,
                    flow_context,
                )

            except Exception as exc:  # noqa: BLE001 - isolate one candidate

                self.statistics.errors += 1
                continue

            if result.status == STATUS_MATCH:

                matches.append(result)
                self.statistics.matches += 1

            else:

                self.statistics.no_match_count += 1

        detections: list[dict[str, Any]] = []

        for result in matches:

            try:

                detection = self.detection_generator.generate(
                    result,
                    event,
                    flow_context,
                )

            except Exception:  # noqa: BLE001 - isolate one detection

                self.statistics.errors += 1
                continue

            detections.append(detection)
            self.statistics.detections_generated += 1

            if self.detection_handler is not None:

                try:

                    self.detection_handler(detection)

                except Exception:  # noqa: BLE001 - isolated output failure

                    self.statistics.errors += 1

        return EventEvaluationResult(
            packet_id=event.get("packet_id"),
            protocol=selection.protocol,
            pool_size=selection.pool_size,
            candidates=selection.rules,
            matches=tuple(matches),
            detections=tuple(detections),
            reason=selection.reason,
        )

    def evaluate_many(
        self,
        events: Iterable[tuple[Any, Any]],
    ) -> list[EventEvaluationResult]:
        """Evaluate ``(event, flow_context)`` pairs independently."""

        return [
            self.evaluate(event, flow_context)
            for event, flow_context in events
        ]

    def reset_statistics(self) -> None:

        self.statistics = EvaluationStatistics()


__all__ = [
    "DetectionHandler",
    "EvaluationStatistics",
    "EventEvaluationResult",
    "RuleEvaluationEngine",
]
