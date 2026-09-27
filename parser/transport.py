from scapy.layers.inet import TCP, UDP

from .normalized import NormalizedEvent


def parse_transport(
    packet,
    event: NormalizedEvent,
) -> bytes:
    """
    Parse TCP or UDP information.

    Returns:
        Raw application payload as bytes.
    """

    # ---------------------------------------------
    # TCP
    # ---------------------------------------------
    if packet.haslayer(TCP):

        tcp = packet[TCP]

        payload = bytes(tcp.payload)

        event.transport = {
            "protocol": "TCP",
            "src_port": int(tcp.sport),
            "dst_port": int(tcp.dport),
            "seq": int(tcp.seq),
            "ack": int(tcp.ack),
            "flags": str(tcp.flags),
            "payload_length": len(payload),
        }

        event.payload_length = len(payload)

        return payload

    # ---------------------------------------------
    # UDP
    # ---------------------------------------------
    if packet.haslayer(UDP):

        udp = packet[UDP]

        payload = bytes(udp.payload)

        event.transport = {
            "protocol": "UDP",
            "src_port": int(udp.sport),
            "dst_port": int(udp.dport),
            "length": (
                int(udp.len)
                if udp.len is not None
                else None
            ),
            "payload_length": len(payload),
        }

        event.payload_length = len(payload)

        return payload

    # ---------------------------------------------
    # Unsupported transport protocol
    # ---------------------------------------------
    event.transport = {
        "protocol": "UNKNOWN"
    }

    event.payload_length = 0

    return b""
