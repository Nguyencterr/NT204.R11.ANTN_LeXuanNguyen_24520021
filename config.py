"""Shared configuration for the Assignment 2 pipeline.

The dataclass carries every tunable used by the Decoder, Preprocessor and
Flow/Connection Tracker. Defaults are intentionally documented here so the
CLI and the unit tests can rely on the same values.
"""

from dataclasses import dataclass


# Invalid / unsupported event policies understood by the Preprocessor.
POLICY_KEEP = "keep"
POLICY_MARK = "mark"
POLICY_SKIP = "skip"

INVALID_EVENT_POLICIES = (
    POLICY_KEEP,
    POLICY_MARK,
    POLICY_SKIP,
)


@dataclass
class PipelineConfig:
    """Configuration for the Decoder -> Preprocessor -> Tracker pipeline."""

    # Idle timeouts, in seconds. A flow that has been idle longer than the
    # timeout is finalized and removed from the active-flow table.
    tcp_idle_timeout: float = 120.0
    udp_idle_timeout: float = 30.0

    # Upper bound (in characters) for any decoded string. Decoding stops at
    # this size and the decode status becomes ``partial``.
    max_decoded_size: int = 65536

    # Upper bound (in bytes) for raw payload handling inside the Decoder.
    max_payload_size: int = 8192

    # How to handle invalid / unsupported events:
    #   keep -> keep the event, still flagged with its status
    #   mark -> keep the event but set processing_action="mark" (default)
    #   skip -> drop the event (processing_action="skip")
    invalid_event_policy: str = POLICY_MARK

    def __post_init__(self) -> None:

        if self.invalid_event_policy not in INVALID_EVENT_POLICIES:

            raise ValueError(
                "invalid_event_policy must be one of "
                f"{INVALID_EVENT_POLICIES}, got "
                f"{self.invalid_event_policy!r}"
            )
