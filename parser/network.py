from scapy.layers.inet import IP

from .normalized import NormalizedEvent


def parse_network(
    packet,
    event: NormalizedEvent,
) -> bool:
    """
    Parse IPv4 information from a Scapy packet.

    Returns:
        True  -> IPv4 layer exists.
        False -> IPv4 layer does not exist.
    """

    if not packet.haslayer(IP):
        return False

    ip = packet[IP]

    event.src_ip = getattr(ip, "src", None)
    event.dst_ip = getattr(ip, "dst", None)

    event.network = {
        "protocol": "IPv4",
        "ttl": int(getattr(ip, "ttl", 0)),
        "identification": int(getattr(ip, "id", 0)),
        "flags": str(getattr(ip, "flags", "")),
    }

    return True
