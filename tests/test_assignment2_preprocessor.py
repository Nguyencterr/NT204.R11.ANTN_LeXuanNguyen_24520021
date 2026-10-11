"""Assignment 2 Preprocessor tests (T05, T06 and malformed events)."""

import unittest

from config import PipelineConfig
from decoder import decode_event
from preprocessor import (
    ACTION_KEEP,
    ACTION_MARK,
    ACTION_SKIP,
    STATUS_INVALID,
    STATUS_PARTIAL,
    STATUS_VALID,
    preprocess_event,
)


def make_event(**overrides) -> dict:

    event = {
        "packet_id": 1,
        "timestamp": 100.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "network": {"protocol": "IPv4"},
        "transport": {
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 80,
        },
        "application": {"protocol": "UNKNOWN"},
        "payload_length": 0,
        "status": "OK",
        "errors": [],
    }

    event.update(overrides)
    return event


class PreprocessorNormalizationTestCase(unittest.TestCase):
    """T05 - normalization keeps raw values and produces a canonical view."""

    def test_protocol_and_header_normalization(self):

        event = make_event(
            application={
                "protocol": "http",
                "type": "request",
                "path": "/index.html",
                "headers": {
                    "Host": "EXAMPLE.com",
                    "Content-Type": "text/html",
                },
                "body": "",
            },
        )

        result = preprocess_event(event)

        self.assertEqual(result["preprocess_status"], STATUS_VALID)
        self.assertEqual(result["transport_protocol"], "TCP")
        self.assertEqual(result["application_protocol"], "HTTP")

        normalized = result["normalized"]

        self.assertEqual(
            normalized["http_headers"]["host"],
            "example.com",
        )
        self.assertEqual(
            normalized["http_headers"]["content-type"],
            "text/html",
        )
        self.assertEqual(normalized["host"], "example.com")

        # Raw headers remain untouched.
        self.assertEqual(
            result["application"]["headers"]["Host"],
            "EXAMPLE.com",
        )

    def test_ip_normalization(self):

        event = make_event(
            src_ip=" 192.168.1.10 ",
            dst_ip="2001:0DB8:0000:0000:0000:0000:0000:0001",
        )

        result = preprocess_event(event)

        self.assertEqual(
            result["normalized"]["src_ip"],
            "192.168.1.10",
        )
        self.assertEqual(
            result["normalized"]["dst_ip"],
            "2001:db8::1",
        )

    def test_leading_zero_ipv4_invalid(self):

        result = preprocess_event(
            make_event(src_ip="192.168.001.010")
        )

        self.assertEqual(
            result["preprocess_status"],
            STATUS_INVALID,
        )
        self.assertIn("invalid IP address", result["preprocess_reason"])

    def test_bad_ip_invalid(self):

        result = preprocess_event(
            make_event(src_ip="not-an-ip")
        )

        self.assertEqual(
            result["preprocess_status"],
            STATUS_INVALID,
        )
        self.assertIn("src_ip", result["preprocess_reason"])

    def test_timestamp_and_uri_normalization(self):

        event = make_event(
            timestamp=100,
            application={
                "protocol": "HTTP",
                "type": "request",
                "path": "/search?q=%27%20OR%201%3D1",
                "headers": {"Host": "Example.COM"},
                "body": "",
            },
        )

        # URI normalization uses the decoder output while keeping raw values.
        decoded = decode_event(event)
        result = preprocess_event(decoded)

        normalized = result["normalized"]

        self.assertEqual(normalized["timestamp"], 100.0)
        self.assertIsInstance(normalized["timestamp"], float)
        self.assertEqual(normalized["uri"], "/search?q=' OR 1=1")
        self.assertEqual(normalized["host"], "example.com")

        # Raw path is preserved by the decoder.
        self.assertEqual(
            result["decoded"]["http"]["raw_uri"],
            "/search?q=%27%20OR%201%3D1",
        )

    def test_unsupported_protocol_partial(self):

        event = make_event(
            transport={"protocol": "ICMP"},
            application={"protocol": "UNKNOWN"},
        )

        result = preprocess_event(event)

        self.assertEqual(
            result["preprocess_status"],
            STATUS_PARTIAL,
        )
        self.assertIn(
            "unrecognized transport protocol",
            result["preprocess_reason"],
        )


class PreprocessorMissingFieldsTestCase(unittest.TestCase):
    """T06 - missing optional fields become null/[] without exceptions."""

    def test_missing_optional_fields_no_crash(self):

        event = {
            "packet_id": 1,
            "timestamp": 100.0,
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "transport": {"protocol": "UDP"},
        }

        result = preprocess_event(event)

        self.assertEqual(result["preprocess_status"], STATUS_PARTIAL)
        self.assertEqual(result["application"]["protocol"], "UNKNOWN")
        self.assertEqual(result["errors"], [])
        self.assertIsNone(result["raw_payload_b64"])
        self.assertIsNone(result["packet_length"])
        self.assertEqual(result["payload_length"], 0)
        self.assertIsNone(result["src_port"])
        self.assertIsNone(result["dst_port"])

        # Missing headers is null in the normalized view for UDP.
        self.assertIsNone(result["normalized"]["http_headers"])

    def test_missing_required_field_invalid(self):

        result = preprocess_event(
            make_event(src_ip=None)
        )

        self.assertEqual(
            result["preprocess_status"],
            STATUS_INVALID,
        )
        self.assertIn("missing src_ip", result["preprocess_reason"])


class PreprocessorValidationTestCase(unittest.TestCase):

    def test_port_out_of_range_invalid(self):

        result = preprocess_event(
            make_event(
                transport={
                    "protocol": "TCP",
                    "src_port": 70000,
                    "dst_port": 80,
                }
            )
        )

        self.assertEqual(
            result["preprocess_status"],
            STATUS_INVALID,
        )
        self.assertIn("out of range", result["preprocess_reason"])

    def test_bad_timestamp_invalid(self):

        result = preprocess_event(
            make_event(timestamp="not-a-time")
        )

        self.assertEqual(
            result["preprocess_status"],
            STATUS_INVALID,
        )
        self.assertIn("timestamp", result["preprocess_reason"])

    def test_valid_event_keep(self):

        result = preprocess_event(
            make_event(
                application={
                    "protocol": "DNS",
                },
                transport={
                    "protocol": "UDP",
                    "src_port": 53000,
                    "dst_port": 53,
                },
            )
        )

        self.assertEqual(result["preprocess_status"], STATUS_VALID)
        self.assertEqual(result["processing_action"], ACTION_KEEP)

    def test_invalid_policy_mark(self):

        event = make_event(
            src_ip="not-an-ip",
            timestamp="bad",
        )

        result = preprocess_event(
            event,
            PipelineConfig(invalid_event_policy="mark"),
        )

        self.assertEqual(result["processing_action"], ACTION_MARK)

    def test_invalid_policy_skip(self):

        event = make_event(
            src_ip="not-an-ip",
            timestamp="bad",
        )

        result = preprocess_event(
            event,
            PipelineConfig(invalid_event_policy="skip"),
        )

        self.assertEqual(result["processing_action"], ACTION_SKIP)

    def test_invalid_policy_keep(self):

        event = make_event(
            src_ip="not-an-ip",
            timestamp="bad",
        )

        result = preprocess_event(
            event,
            PipelineConfig(invalid_event_policy="keep"),
        )

        self.assertEqual(result["processing_action"], ACTION_KEEP)


if __name__ == "__main__":
    unittest.main()