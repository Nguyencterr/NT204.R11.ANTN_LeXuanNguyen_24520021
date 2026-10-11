"""Assignment 2 orchestration.

One pipeline object runs Decoder -> Preprocessor -> Flow/Connection Tracker
for both PCAP replay and live capture, so there is exactly one code path.
"""

from typing import Any, Callable

from config import PipelineConfig
from decoder import decode_event
from flow import FlowTracker
from preprocessor import ACTION_SKIP, preprocess_event

EventHandler = Callable[[dict[str, Any]], None]
FlowHandler = Callable[[dict[str, Any]], None]


class IdsPipeline:
    """Decoder -> Preprocessor -> Flow/Connection Tracker."""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        event_handler: EventHandler | None = None,
        flow_handler: FlowHandler | None = None,
    ) -> None:

        self.config = config or PipelineConfig()

        self.event_handler = event_handler
        self.flow_handler = flow_handler

        self.tracker = FlowTracker(self.config)

        self.processed_count = 0
        self.skipped_count = 0
        self.flow_count = 0

    def process(self, raw_event: Any) -> dict[str, Any] | None:
        """
        Run one raw parser event end-to-end.

        Returns the processed event, or ``None`` when the invalid-event policy
        skipped it. Flow records finalized during this event are forwarded to
        ``flow_handler``.
        """

        try:

            decoded = decode_event(raw_event, self.config)

            prepared = preprocess_event(decoded, self.config)

        except Exception as exc:  # pragma: no cover - defensive

            # A single bad event must never stop the pipeline.
            self.skipped_count += 1

            return {
                "pipeline_error": f"{type(exc).__name__}: {exc}",
                "processing_action": ACTION_SKIP,
                "preprocess_status": "invalid",
            }

        if prepared.get("processing_action") == ACTION_SKIP:

            self.skipped_count += 1

            return None

        self.processed_count += 1

        if self.event_handler is not None:

            self.event_handler(prepared)

        self._emit_flows(self.tracker.process(prepared))

        return prepared

    def flush(self) -> list[dict[str, Any]]:
        """Finalize remaining active flows (end of capture)."""

        return self._emit_flows(self.tracker.flush())

    def _emit_flows(
        self,
        records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        for record in records:

            self.flow_count += 1

            if self.flow_handler is not None:

                self.flow_handler(record)

        return records


__all__ = ["IdsPipeline"]
