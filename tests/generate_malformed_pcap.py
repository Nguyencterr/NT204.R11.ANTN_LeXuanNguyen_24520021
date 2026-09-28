from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap


packets = [
    IP(
        src="192.168.1.10",
        dst="192.168.1.20"
    ) / TCP(
        sport=12345,
        dport=80
    ) / b"\xff\xfe\xfd\xfc"
]

wrpcap(
    "TEST/malformed/input.pcap",
    packets
)

print("Created TEST/malformed/input.pcap")

