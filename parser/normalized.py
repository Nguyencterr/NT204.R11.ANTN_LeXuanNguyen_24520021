from dataclasses import dataclass, field
from typing import Any


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

    status: str = "OK"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the normalized event into a JSON-compatible dictionary.
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
            "status": self.status,
            "errors": self.errors,
        }
