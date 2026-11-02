"""Assignment 3, section 4.4: safe search buffers extracted from an event.

The matcher must never search the JSON serialization of an event, because field
names and metadata would create false positives. Instead, this module extracts a
small, explicit list of application buffers:

* ``payload`` - bounded raw payload bytes preserved by the parser,
* ``decoded_payload`` - UTF-8 text produced by the Assignment 2 Decoder,
* ``http_uri`` - decoded URI/path when available,
* ``http_body`` - HTTP application body,
* ``http_decoded_body`` - HTML-entity-decoded body,
* ``mime_body`` - Base64/Quoted-Printable decoded MIME body,
* ``dns_name`` - DNS query/answer name.

Buffers are never concatenated: a content sequence must match inside one
buffer, which prevents matches that straddle two unrelated fields.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SearchBuffer:
    """One named byte buffer available to content matching."""

    name: str
    data: bytes
    source: str

    def to_dict(self) -> dict[str, Any]:

        return {
            "name": self.name,
            "length": len(self.data),
            "source": self.source,
        }


def _as_text(value: Any) -> str | None:

    if isinstance(value, str) and value:

        return value

    return None


def _nested(mapping: Any, *keys: str) -> Any:

    current = mapping

    for key in keys:

        if not isinstance(current, dict):

            return None

        current = current.get(key)

    return current


def _decode_payload(event: dict[str, Any]) -> bytes | None:

    encoded = event.get("raw_payload_b64")

    if not isinstance(encoded, str) or not encoded:

        return None

    try:

        data = base64.b64decode(encoded, validate=False)

    except (binascii.Error, ValueError):

        return None

    return data or None


def extract_buffers(event: Any) -> list[SearchBuffer]:
    """Return deterministic, de-duplicated search buffers for one event."""

    if not isinstance(event, dict):

        return []

    buffers: list[SearchBuffer] = []

    def add(name: str, value: str | bytes | None, source: str) -> None:

        if value is None:

            return

        data = value.encode("utf-8") if isinstance(value, str) else value

        if not data:

            return

        # Keep the first (most specific) name for identical bytes.
        if any(existing.data == data for existing in buffers):

            return

        buffers.append(
            SearchBuffer(name=name, data=data, source=source)
        )

    add("payload", _decode_payload(event), "raw_payload_b64")

    decoded = event.get("decoded")

    if isinstance(decoded, dict):

        add(
            "decoded_payload",
            _as_text(_nested(decoded, "text", "decoded")),
            "decoded.text.decoded",
        )

        http_decoded = decoded.get("http")

        if isinstance(http_decoded, dict):

            uri = (
                _as_text(http_decoded.get("decoded_uri"))
                or _as_text(http_decoded.get("raw_uri"))
            )

            add("http_uri", uri, "decoded.http.decoded_uri")

        add(
            "http_decoded_body",
            _as_text(_nested(decoded, "html", "decoded_text")),
            "decoded.html.decoded_text",
        )

        add(
            "mime_body",
            _as_text(_nested(decoded, "mime", "decoded_body")),
            "decoded.mime.decoded_body",
        )

    application = event.get("application")

    if isinstance(application, dict):

        add(
            "http_body",
            _as_text(application.get("body")),
            "application.body",
        )

        add(
            "dns_name",
            _as_text(_nested(application, "query", "domain"))
            or _as_text(_nested(application, "answer", "name")),
            "application.query.domain",
        )

    normalized = event.get("normalized")

    if isinstance(normalized, dict):

        add(
            "http_uri",
            _as_text(normalized.get("uri")),
            "normalized.uri",
        )

        add(
            "http_host",
            _as_text(normalized.get("host")),
            "normalized.host",
        )

    return buffers


__all__ = [
    "SearchBuffer",
    "extract_buffers",
]
