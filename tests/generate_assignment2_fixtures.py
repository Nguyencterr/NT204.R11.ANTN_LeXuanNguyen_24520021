"""Generate Assignment 2 reproducible fixtures under TEST/assignment_2/.

Builds one mixed PCAP that exercises T01-T14 scenarios, then runs the real
Decoder -> Preprocessor -> Tracker pipeline over it and writes
``result_events.jsonl`` and ``result_flows.jsonl`` plus a short summary.

Run from the repository root with the project virtualenv:

    .venv/bin/python tests/generate_assignment2_fixtures.py
"""

import json
import sys
from pathlib import Path

# Make the repository root importable when run as a script from tests/.
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from config import PipelineConfig
from parser import parse_packet
from pipeline import IdsPipeline

OUT_DIR = Path("TEST") / "assignment_2"

CLIENT = "192.168.1.10"
SERVER = "192.168.1.20"
DNS_IP = "8.8.8.8"


def stamp(packet, timestamp: float):
    packet.time = timestamp
    return packet


def build_packets():
    """Return a list of (packet, description) covering T01-T14."""

    packets: list = []

    t = 1000.0

    # -------------------------------------------------------------
    # TCP three-way handshake (T07) + FIN close (T09)
    # -------------------------------------------------------------
    packets.append((
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(
            sport=50000, dport=80, flags="S", seq=1000), t),
        "TCP SYN",
    ))
    packets.append((
        stamp(Ether() / IP(src=SERVER, dst=CLIENT) / TCP(
            sport=80, dport=50000, flags="SA", seq=2000, ack=1001), t + 0.1),
        "TCP SYN+ACK",
    ))
    packets.append((
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(
            sport=50000, dport=80, flags="A", seq=1001, ack=2001), t + 0.2),
        "TCP ACK",
    ))
    packets.append((
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(
            sport=50000, dport=80, flags="FA", seq=1002, ack=2001), t + 0.3),
        "TCP FIN",
    ))
    packets.append((
        stamp(Ether() / IP(src=SERVER, dst=CLIENT) / TCP(
            sport=80, dport=50000, flags="FA", seq=2001, ack=1003), t + 0.4),
        "TCP FIN+ACK",
    ))

    # -------------------------------------------------------------
    # HTTP GET with percent-encoded path (T01) + HTML response (T02)
    # -------------------------------------------------------------
    http_get = (
        b"GET /search?q=%27%20OR%201%3D1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
    )

    packets.append((
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(
            sport=50001, dport=8080, flags="PA") / http_get, t + 1.0),
        "HTTP GET percent-encoded URI",
    ))

    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>"
    )

    packets.append((
        stamp(Ether() / IP(src=SERVER, dst=CLIENT) / TCP(
            sport=8080, dport=50001, flags="PA") / http_response, t + 1.1),
        "HTTP response with HTML entities",
    ))

    # -------------------------------------------------------------
    # SMTP MIME Base64 + Quoted-Printable (T03)
    # -------------------------------------------------------------
    mime_b64 = (
        b"EHLO example.com\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"SGVsbG8gV29ybGQ="
    )

    packets.append((
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(
            sport=50002, dport=25, flags="PA") / mime_b64, t + 2.0),
        "SMTP MIME Base64",
    ))

    mime_qp = (
        b"250 OK\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n"
        b"\r\n"
        b"Caf=C3=A9 =3D tasty"
    )

    packets.append((
        stamp(Ether() / IP(src=SERVER, dst=CLIENT) / TCP(
            sport=25, dport=50002, flags="PA") / mime_qp, t + 2.1),
        "SMTP MIME Quoted-Printable",
    ))

    # -------------------------------------------------------------
    # UDP DNS query/response (T10) + concurrent UDP flow (T11)
    # -------------------------------------------------------------
    packets.append((
        stamp(Ether() / IP(src=CLIENT, dst=DNS_IP) / UDP(
            sport=53000, dport=53) / DNS(
            id=4321, qr=0, qd=DNSQR(qname="example.com", qtype="A")),
            t + 3.0),
        "UDP DNS query",
    ))

    packets.append((
        stamp(Ether() / IP(src=DNS_IP, dst=CLIENT) / UDP(
            sport=53, dport=53000) / DNS(
            id=4321, qr=1, qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", ttl=300,
                     rdata="93.184.216.34")),
            t + 3.1),
        "UDP DNS response",
    ))

    packets.append((
        stamp(Ether() / IP(src="192.168.1.30", dst=DNS_IP) / UDP(
            sport=53001, dport=53) / DNS(
            id=9999, qr=0, qd=DNSQR(qname="other.org", qtype="A")),
            t + 3.2),
        "Concurrent UDP flow",
    ))

    # -------------------------------------------------------------
    # Invalid UTF-8 bytes (T04) and malformed payload (T14)
    # -------------------------------------------------------------
    packets.append((
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(
            sport=50003, dport=9999, flags="PA") / b"\xff\xfe\xfd\x01",
            t + 4.0),
        "Invalid UTF-8 payload",
    ))

    # -------------------------------------------------------------
    # A new packet long after the idle window forces expiry (T12/T13)
    # -------------------------------------------------------------
    t2 = t + 200.0

    packets.append((
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(
            sport=50004, dport=443, flags="S"), t2),
        "New TCP flow after idle window (timeout cleanup)",
    ))

    packets.append((
        stamp(Ether() / IP(src=SERVER, dst=CLIENT) / TCP(
            sport=443, dport=50004, flags="R"), t2 + 0.1),
        "TCP RST (T09)",
    ))

    return packets


def main() -> None:

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    packets = build_packets()

    pcap_path = OUT_DIR / "input_mixed.pcap"

    wrpcap(
        str(pcap_path),
        [p for p, _ in packets],
    )

    config = PipelineConfig(
        tcp_idle_timeout=5.0,
        udp_idle_timeout=3.0,
    )

    events_path = OUT_DIR / "result_events.jsonl"
    flows_path = OUT_DIR / "result_flows.jsonl"

    # Truncate previous artifacts instead of appending.
    for path in (events_path, flows_path):

        if path.exists():
            path.unlink()

    event_handle = events_path.open("a", encoding="utf-8")
    flow_handle = flows_path.open("a", encoding="utf-8")

    pipeline = IdsPipeline(
        config=config,
        event_handler=lambda rec: (
            event_handle.write(
                json.dumps(rec, ensure_ascii=False) + "\n"
            )
        ),
        flow_handler=lambda rec: (
            flow_handle.write(
                json.dumps(rec, ensure_ascii=False) + "\n"
            )
        ),
    )

    with event_handle, flow_handle:

        for i, (packet, description) in enumerate(packets, start=1):

            event = parse_packet(packet, i)

            if event is None:

                print(f"[{i:02d}] {description}: skipped (no event)")

                continue

            processed = pipeline.process(event)

            if processed is None:

                print(
                    f"[{i:02d}] {description}: "
                    "dropped (invalid-event policy)"
                )

                continue

            print(
                f"[{i:02d}] {description}: "
                f"{processed['preprocess_status']} / "
                f"{processed['application_protocol']}"
            )

        pipeline.flush()

    print(f"Written: {pcap_path}")
    print(f"Written: {events_path}")
    print(f"Written: {flows_path}")


if __name__ == "__main__":
    main()