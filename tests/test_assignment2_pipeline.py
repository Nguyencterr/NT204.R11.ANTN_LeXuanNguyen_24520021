"""Assignment 2 end-to-end pipeline tests (integration + T14)."""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from common.jsonl import JsonlWriter, read_jsonl
from config import PipelineConfig
from parser import parse_packet
from pipeline import IdsPipeline
from preprocessor import STATUS_INVALID


def normalized_event(
    src: str,
    dst: str,
    proto: str,
    sport: int,
    dport: int,
    ts: float,
    flags: str = "A",
    payload: bytes = b"",
    packet_length: int = 54,
) -> dict:

    transport = {"protocol": proto, "src_port": sport, "dst_port": dport}

    if proto == "TCP":
        transport["flags"] = flags

    return {
        "packet_id": 1,
        "timestamp": ts,
        "src_ip": src,
        "dst_ip": dst,
        "network": {"protocol": "IPv4"},
        "transport": transport,
        "application": {"protocol": "UNKNOWN"},
        "payload_length": len(payload),
        "packet_length": packet_length,
    }


class PipelineEndToEndTestCase(unittest.TestCase):
    """Full Decoder -> Preprocessor -> Tracker run over synthetic events."""

    def test_full_pipeline_with_timeout(self):

        config = PipelineConfig(
            tcp_idle_timeout=5.0,
            udp_idle_timeout=3.0,
        )

        events: list[dict] = []
        flows: list[dict] = []

        pipeline = IdsPipeline(
            config=config,
            event_handler=events.append,
            flow_handler=flows.append,
        )

        # TCP handshake
        pipeline.process(
            normalized_event(
                "10.0.0.1", "10.0.0.2",
                "TCP", 1000, 80, 1.0, flags="S",
            )
        )
        pipeline.process(
            normalized_event(
                "10.0.0.2", "10.0.0.1",
                "TCP", 80, 1000, 1.1, flags="SA",
            )
        )
        pipeline.process(
            normalized_event(
                "10.0.0.1", "10.0.0.2",
                "TCP", 1000, 80, 1.2, flags="A",
            )
        )

        # UDP query/response
        pipeline.process(
            normalized_event(
                "10.0.0.1", "8.8.8.8",
                "UDP", 53000, 53, 1.0,
            )
        )
        pipeline.process(
            normalized_event(
                "8.8.8.8", "10.0.0.1",
                "UDP", 53, 53000, 1.1,
            )
        )

        flush_records = pipeline.flush()

        self.assertEqual(len(flows), 2)
        self.assertEqual(len(flush_records), 2)
        self.assertEqual(pipeline.processed_count, 5)
        self.assertEqual(pipeline.skipped_count, 0)

        states = {f["state"] for f in flows}

        self.assertEqual(states, {"ESTABLISHED", "OPEN"})

        # Events carry decode + preprocess metadata and remain JSON-safe.
        for event in events:

            json.dumps(event)

            self.assertIn("decoded", event)
            self.assertIn("preprocess_status", event)
            self.assertIn("normalized", event)

    def test_jsonl_output_roundtrip(self):

        with tempfile.TemporaryDirectory() as tmp:

            event_path = Path(tmp) / "events.jsonl"
            flow_path = Path(tmp) / "flows.jsonl"

            with JsonlWriter(event_path) as event_writer:

                with JsonlWriter(flow_path) as flow_writer:

                    pipeline = IdsPipeline(
                        event_handler=event_writer.write,
                        flow_handler=flow_writer.write,
                    )

                    pipeline.process(
                        normalized_event(
                            "1.1.1.1", "2.2.2.2",
                            "TCP", 1234, 443, 1.0, flags="S",
                        )
                    )

                    pipeline.flush()

            lines = list(read_jsonl(event_path))
            flow_lines = list(read_jsonl(flow_path))

            self.assertEqual(len(lines), 1)
            self.assertEqual(len(flow_lines), 1)

            # Every line must parse as an independent JSON object.
            with event_path.open() as handle:

                for line in handle:

                    self.assertIsInstance(json.loads(line), dict)

            self.assertIn("flow_id", flow_lines[0])

    def test_invalid_policy_skip(self):

        config = PipelineConfig(invalid_event_policy="skip")

        pipeline = IdsPipeline(config=config)

        bad_event = normalized_event(
            "not-an-ip", "2.2.2.2",
            "TCP", 1234, 80, 1.0,
        )

        result = pipeline.process(bad_event)

        self.assertIsNone(result)
        self.assertEqual(pipeline.skipped_count, 1)


class TrackerMalformedTestCase(unittest.TestCase):
    """T14 - malformed / unsupported events must not crash the pipeline."""

    def test_invalid_event_then_valid_event(self):

        pipeline = IdsPipeline()

        # Event 1: missing everything. Default policy keeps+marks it.
        result = pipeline.process(
            {"packet_id": None, "timestamp": "oops"}
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["preprocess_status"], STATUS_INVALID)
        self.assertEqual(result["processing_action"], "mark")

        # Event 2 must still flow through successfully.
        result = pipeline.process(
            normalized_event(
                "1.1.1.1", "2.2.2.2",
                "TCP", 1000, 80, 1.0, flags="S",
            )
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["preprocess_status"], "partial")
        self.assertEqual(pipeline.processed_count, 2)

    def test_truncated_dict_input(self):

        pipeline = IdsPipeline()

        result = pipeline.process(
            {
                "packet_id": 1,
                "timestamp": 5.0,
                "src_ip": "1.1.1.1",
                "dst_ip": "2.2.2.2",
            }
        )

        # Missing transport/application is partial, not a crash.
        self.assertIsNotNone(result)
        self.assertEqual(result["processing_action"], "keep")
        self.assertEqual(result["preprocess_status"], "partial")


class ParserIntegrationTestCase(unittest.TestCase):
    """Real Scapy packets through parse_packet into the pipeline."""

    def _run(self, packets):

        events: list[dict] = []
        flows: list[dict] = []

        pipeline = IdsPipeline(
            event_handler=events.append,
            flow_handler=flows.append,
        )

        for i, packet in enumerate(packets, start=1):

            parsed = parse_packet(packet, i)

            self.assertIsNotNone(parsed)

            pipeline.process(parsed)

        pipeline.flush()

        return events, flows

    def test_http_get_packet(self):

        payload = (
            b"GET /search?q=%27%20OR%201%3D1 HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n"
        )

        packet = (
            Ether()
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=50000, dport=8080, flags="PA")
            / payload
        )

        events, flows = self._run([packet])

        self.assertEqual(len(events), 1)
        self.assertEqual(len(flows), 1)

        event = events[0]

        self.assertEqual(
            event["decoded"]["http"]["decoded_uri"],
            "/search?q=' OR 1=1",
        )
        self.assertEqual(
            event["decoded"]["http"]["raw_uri"],
            "/search?q=%27%20OR%201%3D1",
        )
        self.assertEqual(event["application_protocol"], "HTTP")
        self.assertEqual(flows[0]["application_protocol"], "HTTP")

        # Raw payload survives as bounded base64, never raw bytes.
        self.assertIsInstance(event["raw_payload_b64"], str)

    def test_dns_udp_packet(self):

        packet = (
            Ether()
            / IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(id=4321, qr=0, qd=DNSQR(qname="example.com", qtype="A"))
        )

        events, flows = self._run([packet])

        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["protocol"], "UDP")
        self.assertEqual(events[0]["application_protocol"], "DNS")

    def test_dns_response(self):

        packet = (
            Ether()
            / IP(src="8.8.8.8", dst="192.168.1.10")
            / UDP(sport=53, dport=53000)
            / DNS(
                id=4321,
                qr=1,
                qd=DNSQR(qname="example.com", qtype="A"),
                an=DNSRR(
                    rrname="example.com",
                    type="A",
                    ttl=300,
                    rdata="93.184.216.34",
                ),
            )
        )

        events, flows = self._run([packet])

        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["protocol"], "UDP")

    def test_smtp_mime_base64_packet(self):

        raw = (
            b"EHLO example.com\r\n"
            b"MAIL FROM:<a@example.com>\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8gV29ybGQ="
        )

        packet = (
            Ether()
            / IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=50000, dport=25, flags="PA")
            / raw
        )

        events, flows = self._run([packet])

        event = events[0]

        mime = event["decoded"]["mime"]

        self.assertIsNotNone(mime)
        self.assertEqual(mime["transfer_encoding"], "base64")
        self.assertEqual(mime["decoded_body"], "Hello World")


if __name__ == "__main__":
    unittest.main()