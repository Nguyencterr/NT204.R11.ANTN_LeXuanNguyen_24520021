"""Assignment 2 Decoder tests (T01-T04 and extra decode cases)."""

import base64
import unittest

from config import PipelineConfig
from decoder.decoder import (
    STATUS_ERROR,
    STATUS_NOT_APPLICABLE,
    STATUS_OK,
    STATUS_PARTIAL,
    decode_event,
)
from decoder.decoder import _decode_percent, _decode_urlencoded


def make_http_event(
    path: str = "/",
    body: str = "",
    content_type: str | None = None,
    method: str = "GET",
) -> dict:

    headers = {}

    if content_type is not None:
        headers["Content-Type"] = content_type

    return {
        "packet_id": 1,
        "timestamp": 100.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
        "transport": {
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 80,
            "flags": "PA",
        },
        "application": {
            "protocol": "HTTP",
            "type": "request",
            "method": method,
            "path": path,
            "version": "HTTP/1.1",
            "headers": headers,
            "body": body,
        },
        "payload_length": 0,
        "status": "OK",
        "errors": [],
    }


class DecoderHttpTestCase(unittest.TestCase):
    """T01 - HTTP URI percent-encoding."""

    def test_uri_percent_decoding(self):

        event = make_http_event(
            path="/search?q=%27%20OR%201%3D1",
        )

        result = decode_event(event)

        http = result["decoded"]["http"]

        self.assertEqual(
            http["raw_uri"],
            "/search?q=%27%20OR%201%3D1",
        )

        self.assertEqual(
            http["decoded_uri"],
            "/search?q=' OR 1=1",
        )

        self.assertEqual(
            http["decoded_path"],
            "/search",
        )

        # Raw URI must not be overwritten.
        self.assertEqual(
            result["application"]["path"],
            "/search?q=%27%20OR%201%3D1",
        )

        self.assertEqual(result["decode_status"], STATUS_OK)

    def test_form_plus_becomes_space(self):

        event = make_http_event(
            body="user=nguyen+admin&role=admin%20x",
            content_type="application/x-www-form-urlencoded",
            method="POST",
        )

        result = decode_event(event)

        form = result["decoded"]["http"]["form"]

        self.assertEqual(form["user"], "nguyen admin")
        self.assertEqual(form["role"], "admin x")

    def test_form_semantics_not_applied_to_path(self):

        decoded, status, _ = _decode_percent("/a+b/c", 1024)

        # '+' in a path is not a space.
        self.assertEqual(decoded, "/a+b/c")

        self.assertEqual(status, STATUS_OK)

    def test_unit_decode_urlencoded(self):

        form, status, _ = _decode_urlencoded(
            "a=1&b=%E1%BA%A1ch&empty=",
            1024,
        )

        self.assertEqual(status, STATUS_OK)
        self.assertEqual(form["a"], "1")
        self.assertEqual(form["b"], "ạch")
        self.assertEqual(form["empty"], "")

    def test_malformed_percent_reported_partial(self):

        decoded, status, reason = _decode_percent(
            "/path%zz",
            1024,
        )

        self.assertEqual(status, STATUS_PARTIAL)
        self.assertIn("malformed percent-encoding", reason or "")


class DecoderHtmlTestCase(unittest.TestCase):
    """T02 - HTML entity decoding."""

    def test_html_entities_decoded(self):

        event = make_http_event(
            body="&lt;script&gt;alert(1)&lt;/script&gt;",
            content_type="text/html",
        )

        result = decode_event(event)

        html_block = result["decoded"]["html"]

        self.assertIsNotNone(html_block)
        self.assertEqual(
            html_block["decoded_text"],
            "<script>alert(1)</script>",
        )
        self.assertTrue(html_block["changed"])

        # Raw body untouched.
        self.assertEqual(
            result["application"]["body"],
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        )

    def test_plain_body_not_html(self):

        event = make_http_event(
            body="user=nguyen&role=admin",
            content_type="application/x-www-form-urlencoded",
        )

        result = decode_event(event)

        self.assertIsNone(result["decoded"]["html"])

    def test_entity_decode_no_crash(self):

        event = make_http_event(
            body="&amp;&lt;&#x27;&apos;",
            content_type="text/html",
        )

        result = decode_event(event)

        self.assertEqual(
            result["decoded"]["html"]["decoded_text"],
            "&<''",
        )


class DecoderMimeTestCase(unittest.TestCase):
    """T03 - MIME Base64 and Quoted-Printable decoding."""

    def _event_with_payload(self, raw: bytes) -> dict:

        return {
            "packet_id": 7,
            "timestamp": 1.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "transport": {
                "protocol": "TCP",
                "src_port": 25,
                "dst_port": 50000,
                "flags": "PA",
            },
            "application": {"protocol": "SMTP"},
            "payload_length": len(raw),
            "packet_length": len(raw) + 54,
            "raw_payload_b64": base64.b64encode(raw).decode("ascii"),
            "raw_payload_truncated": False,
            "status": "OK",
            "errors": [],
        }

    def test_mime_base64(self):

        raw = (
            b"Content-Type: text/plain\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8gV29ybGQ="
        )

        result = decode_event(self._event_with_payload(raw))

        mime = result["decoded"]["mime"]

        self.assertIsNotNone(mime)
        self.assertEqual(mime["transfer_encoding"], "base64")
        self.assertEqual(mime["decoded_body"], "Hello World")
        self.assertEqual(mime["status"], STATUS_OK)

    def test_mime_quoted_printable(self):

        raw = (
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"Caf=C3=A9 =3D tasty"
        )

        result = decode_event(self._event_with_payload(raw))

        mime = result["decoded"]["mime"]

        self.assertIsNotNone(mime)
        self.assertEqual(
            mime["transfer_encoding"],
            "quoted-printable",
        )
        self.assertEqual(mime["decoded_body"], "Café = tasty")
        self.assertEqual(mime["status"], STATUS_OK)

    def test_invalid_base64_reported_error(self):

        raw = (
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"!!!not-base64!!!"
        )

        result = decode_event(self._event_with_payload(raw))

        mime = result["decoded"]["mime"]

        self.assertIsNotNone(mime)
        self.assertEqual(
            mime["transfer_encoding"],
            "base64",
        )
        self.assertEqual(mime["status"], STATUS_ERROR)

    def test_no_mime_header_is_not_forced(self):

        raw = b"EHLO example.com\r\n"

        result = decode_event(self._event_with_payload(raw))

        self.assertIsNone(result["decoded"]["mime"])


class DecoderCharactersTestCase(unittest.TestCase):
    """T04 - invalid byte sequences are marked, never fatal."""

    def test_valid_utf8_ok(self):

        raw = "xin chào".encode("utf-8")

        event = {
            "packet_id": 1,
            "timestamp": 1.0,
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "transport": {"protocol": "UDP"},
            "application": {"protocol": "DNS"},
            "payload_length": len(raw),
            "raw_payload_b64": base64.b64encode(raw).decode("ascii"),
        }

        result = decode_event(event)

        self.assertEqual(
            result["decoded"]["text"]["status"],
            STATUS_OK,
        )
        self.assertEqual(
            result["decoded"]["text"]["decoded"],
            "xin chào",
        )

    def test_invalid_utf8_partial(self):

        raw = b"\xff\xfe\xfd\x31\x32"

        event = {
            "packet_id": 1,
            "timestamp": 1.0,
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "transport": {"protocol": "UDP"},
            "application": {"protocol": "UNKNOWN"},
            "payload_length": len(raw),
            "raw_payload_b64": base64.b64encode(raw).decode("ascii"),
        }

        result = decode_event(event)

        self.assertEqual(
            result["decoded"]["text"]["status"],
            STATUS_PARTIAL,
        )
        self.assertEqual(
            result["decode_status"],
            STATUS_PARTIAL,
        )
        self.assertIn("invalid UTF-8", result["decode_reason"])

    def test_empty_payload_safe(self):

        event = {
            "packet_id": 1,
            "timestamp": 1.0,
            "src_ip": None,
            "dst_ip": None,
            "transport": {"protocol": "UNKNOWN"},
            "application": {"protocol": "UNKNOWN"},
        }

        result = decode_event(event)

        self.assertIsNone(result["decoded"]["text"])
        self.assertEqual(
            result["decode_status"],
            STATUS_NOT_APPLICABLE,
        )

    def test_size_limit_marks_partial(self):

        config = PipelineConfig(max_decoded_size=8)

        event = make_http_event(
            path="/" + "a" * 100,
        )

        result = decode_event(event, config)

        self.assertEqual(
            result["decode_status"],
            STATUS_PARTIAL,
        )
        self.assertEqual(
            len(result["decoded"]["http"]["decoded_uri"]),
            8,
        )


if __name__ == "__main__":
    unittest.main()