from dataclasses import dataclass, field
from typing import Any


# Upper bound (in bytes) on how much raw application payload is preserved
# for downstream decoding. This is a privacy / data-volume trade-off: only a
# bounded prefix is kept. The raw bytes are base64-encoded so they can be
# stored in JSONL without placing non-serializable ``bytes`` into the output.
MAX_RAW_PAYLOAD_BYTES = 8192


@dataclass
class NormalizedEvent:
    """
    Standardized event produced by the packet parser.

    Downstream IDS modules should work only with this object,
    not directly with Scapy packets.
    """

    packet_id: int
    timestamp: float

    src_ip: str | None = None
    dst_ip: str | None = None

    network: dict[str, Any] = field(default_factory=dict)
    transport: dict[str, Any] = field(default_factory=dict)
    application: dict[str, Any] = field(
        default_factory=lambda: {
            "protocol": "UNKNOWN"
        }
    )

    payload_length: int = 0

    # Full L2/L3 packet length when reliably available (Scapy ``len()``).
    # Used as the preferred basis for flow byte counters. ``None`` means
    # unavailable, and the tracker falls back to ``payload_length``.
    packet_length: int | None = None

    # Bounded base64 copy of the raw application payload. Kept so the
    # Decoder can perform MIME / character decoding without depending on
    # Scapy objects. ``None`` when there is no payload.
    raw_payload_b64: str | None = None
    raw_payload_truncated: bool = False

    status: str = "OK"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the normalized event into a JSON-compatible dictionary.

        Assignment 1 fields keep their original meaning; Assignment 2
        metadata is additive.
        """

        return {
            "packet_id": self.packet_id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "network": self.network,
            "transport": self.transport,
            "application": self.application,
            "payload_length": self.payload_length,
            "packet_length": self.packet_length,
            "raw_payload_b64": self.raw_payload_b64,
            "raw_payload_truncated": self.raw_payload_truncated,
            "status": self.status,
            "errors": self.errors,
        }
