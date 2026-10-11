"""Assignment 2 Decoder.

Turns a normalized packet event into the same event plus a ``decoded`` block.
Every decoded value is kept *next to* the original raw value; nothing that was
produced by the parser is overwritten. Decode problems are reported through
``decode_status`` / ``decode_reason`` and never raise out of this module.
"""

import base64
import binascii
import html
import quopri
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, unquote_plus

from common.events import as_event_dict


# Decode status vocabulary.
STATUS_OK = "ok"
STATUS_PARTIAL = "partial"
STATUS_ERROR = "error"
STATUS_NOT_APPLICABLE = "not_applicable"

# Detects a stray '%' that is not followed by two hex digits.
_INVALID_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")

_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


def _worse(current: str, candidate: str) -> str:
    """Return the more severe of two decode statuses."""

    order = {
        STATUS_NOT_APPLICABLE: 0,
        STATUS_OK: 1,
        STATUS_PARTIAL: 2,
        STATUS_ERROR: 3,
    }

    if order.get(candidate, 0) > order.get(current, 0):

        return candidate

    return current


def _truncate(value: str, limit: int) -> tuple[str, bool]:
    """Truncate a decoded string to ``limit`` characters."""

    if limit is not None and limit > 0 and len(value) > limit:

        return value[:limit], True

    return value, False


def _decode_percent(
    value: Any,
    limit: int,
    as_form: bool = False,
) -> tuple[str | None, str, str | None]:
    """
    Percent-decode a URL/URI fragment.

    ``as_form`` selects ``+``-as-space semantics (only valid for form data and
    query strings, never for a raw path). Invalid UTF-8 bytes are replaced and
    reported as ``partial`` instead of raising.
    """

    if value is None:

        return None, STATUS_NOT_APPLICABLE, None

    raw = str(value)

    decoder = unquote_plus if as_form else unquote

    reason: str | None = None
    status = STATUS_OK

    if _INVALID_PERCENT_RE.search(raw):

        status = STATUS_PARTIAL
        reason = "malformed percent-encoding"

    try:

        decoded = decoder(raw, encoding="utf-8", errors="strict")

    except UnicodeDecodeError:

        decoded = decoder(raw, encoding="utf-8", errors="replace")
        status = _worse(status, STATUS_PARTIAL)
        reason = (
            "invalid UTF-8 byte sequence in percent-encoded data"
            if reason is None
            else f"{reason}; invalid UTF-8 byte sequence"
        )

    except Exception as exc:  # pragma: no cover - defensive

        return None, STATUS_ERROR, f"{type(exc).__name__}: {exc}"

    decoded, truncated = _truncate(decoded, limit)

    if truncated:

        status = _worse(status, STATUS_PARTIAL)
        reason = (
            "decoded value truncated"
            if reason is None
            else f"{reason}; decoded value truncated"
        )

    return decoded, status, reason


def _decode_urlencoded(
    body: str,
    limit: int,
) -> tuple[dict[str, str] | None, str, str | None]:
    """
    Decode an ``application/x-www-form-urlencoded`` body.

    ``+`` is treated as space and percent escapes are resolved, per form
    semantics.
    """

    if not body:

        return None, STATUS_NOT_APPLICABLE, None

    try:

        pairs = parse_qsl(
            body,
            keep_blank_values=True,
            encoding="utf-8",
            errors="replace",
        )

    except Exception as exc:  # pragma: no cover - defensive

        return None, STATUS_ERROR, f"{type(exc).__name__}: {exc}"

    form: dict[str, str] = {}

    for name, value in pairs:

        form[name] = _truncate(value, limit)[0]

    if not form:

        return None, STATUS_NOT_APPLICABLE, None

    return form, STATUS_OK, None


def _decode_html_entities(
    text: str,
    limit: int,
) -> tuple[dict[str, Any], str, str | None]:

    decoded = html.unescape(text)

    truncated = False

    decoded, truncated = _truncate(decoded, limit)

    status = STATUS_OK
    reason: str | None = None

    if truncated:

        status = STATUS_PARTIAL
        reason = "decoded HTML text truncated"

    return (
        {
            "raw_text": text,
            "decoded_text": decoded,
            "changed": decoded != text,
        },
        status,
        reason,
    )


def _raw_payload_bytes(
    event: dict[str, Any],
    max_bytes: int,
) -> bytes | None:
    """Recover bounded raw payload bytes from base64 metadata."""

    encoded = event.get("raw_payload_b64")

    if not isinstance(encoded, str) or not encoded:

        return None

    try:

        data = base64.b64decode(encoded, validate=False)

    except (binascii.Error, ValueError):

        return None

    if max_bytes and max_bytes > 0:

        return data[:max_bytes]

    return data


def _decode_character(
    data: bytes,
    limit: int,
) -> tuple[dict[str, Any], str, str | None]:

    status = STATUS_OK
    reason: str | None = None

    try:

        text = data.decode("utf-8", errors="strict")

    except UnicodeDecodeError:

        text = data.decode("utf-8", errors="replace")
        status = STATUS_PARTIAL
        reason = "invalid UTF-8 byte sequence"

    text, truncated = _truncate(text, limit)

    if truncated:

        status = _worse(status, STATUS_PARTIAL)
        reason = (
            "decoded text truncated"
            if reason is None
            else f"{reason}; decoded text truncated"
        )

    return (
        {
            "charset": "utf-8",
            "decoded": text,
            "status": status,
        },
        status,
        reason,
    )


def _split_headers_and_body(
    data: bytes,
) -> tuple[dict[str, str], bytes]:
    """Split a raw payload into MIME headers and body bytes."""

    for separator in (b"\r\n\r\n", b"\n\n"):

        if separator in data:

            header_blob, body = data.split(separator, 1)

            break

    else:

        # No blank line: everything is header (e.g. a bare SMTP command).
        # Treat it as an empty body so nothing is fabricated.
        return _parse_header_lines(data, b"\r\n"), b""

    headers = _parse_header_lines(
        header_blob,
        b"\n" if b"\r\n" not in header_blob else b"\r\n",
    )

    return headers, body


def _parse_header_lines(
    blob: bytes,
    separator: bytes,
) -> dict[str, str]:

    headers: dict[str, str] = {}

    for line in blob.split(separator):

        if b":" not in line:

            continue

        name, _, value = line.partition(b":")

        try:

            key = name.decode("ascii", errors="strict").strip().lower()

            val = value.decode("latin-1", errors="replace").strip()

        except Exception:  # pragma: no cover - defensive

            continue

        if key:

            headers[key] = val

    return headers


def _decode_mime(
    data: bytes | None,
    limit: int,
) -> tuple[dict[str, Any] | None, str, str | None]:
    """
    Decode a MIME body when a Content-Transfer-Encoding header says so.

    Only Base64 and Quoted-Printable are supported. A payload without that
    header is left untouched (users must not treat every body as MIME).
    """

    if not data:

        return None, STATUS_NOT_APPLICABLE, None

    headers, body = _split_headers_and_body(data)

    encoding = headers.get(
        "content-transfer-encoding",
        "",
    ).strip().lower()

    if encoding not in ("base64", "quoted-printable"):

        return None, STATUS_NOT_APPLICABLE, None

    if not body:

        return (
            {
                "transfer_encoding": encoding,
                "decoded_body": "",
                "raw_body_length": 0,
                "status": STATUS_NOT_APPLICABLE,
            },
            STATUS_NOT_APPLICABLE,
            None,
        )

    status = STATUS_OK
    reason: str | None = None

    try:

        if encoding == "base64":

            decoded_bytes = base64.b64decode(
                body,
                validate=False,
            )

        else:

            decoded_bytes = quopri.decodestring(body)

    except (binascii.Error, ValueError) as exc:

        return (
            {
                "transfer_encoding": encoding,
                "decoded_body": None,
                "raw_body_length": len(body),
                "status": STATUS_ERROR,
            },
            STATUS_ERROR,
            f"{encoding} decode failed: {exc}",
        )

    try:

        decoded_text = decoded_bytes.decode(
            "utf-8",
            errors="strict",
        )

    except UnicodeDecodeError:

        decoded_text = decoded_bytes.decode(
            "utf-8",
            errors="replace",
        )

        status = STATUS_PARTIAL
        reason = "invalid UTF-8 byte sequence in MIME body"

    decoded_text, truncated = _truncate(decoded_text, limit)

    if truncated:

        status = _worse(status, STATUS_PARTIAL)
        reason = (
            "decoded MIME body truncated"
            if reason is None
            else f"{reason}; decoded MIME body truncated"
        )

    return (
        {
            "transfer_encoding": encoding,
            "decoded_body": decoded_text,
            "raw_body_length": len(body),
            "status": status,
        },
        status,
        reason,
    )


def _header_lookup(
    headers: Any,
    name: str,
) -> str | None:

    if not isinstance(headers, dict):

        return None

    for key, value in headers.items():

        if str(key).lower() == name:

            return value if isinstance(value, str) else str(value)

    return None


def _decode_http(
    application: dict[str, Any],
    limit: int,
) -> tuple[dict[str, Any] | None, str, str | None]:

    if str(application.get("protocol", "")).upper() != "HTTP":

        return None, STATUS_NOT_APPLICABLE, None

    statuses: list[str] = []
    reasons: list[str] = []

    block: dict[str, Any] = {
        "type": application.get("type"),
        "raw_uri": None,
        "decoded_uri": None,
        "raw_path": None,
        "decoded_path": None,
        "raw_query": None,
        "decoded_query": None,
        "query_params": None,
        "form": None,
    }

    raw_path = application.get("path")

    if isinstance(raw_path, str):

        path, _, query = raw_path.partition("?")

        decoded_path, s1, r1 = _decode_percent(path, limit)

        block["raw_uri"] = raw_path
        block["raw_path"] = path
        block["decoded_path"] = decoded_path

        statuses.append(s1)

        if r1:
            reasons.append(r1)

        if query:

            decoded_query, s2, r2 = _decode_percent(
                query,
                limit,
                as_form=True,
            )

            block["raw_query"] = query
            block["decoded_query"] = decoded_query

            statuses.append(s2)

            if r2:
                reasons.append(r2)

            try:

                block["query_params"] = dict(
                    parse_qsl(
                        query,
                        keep_blank_values=True,
                        encoding="utf-8",
                        errors="replace",
                    )
                )

            except Exception:  # pragma: no cover - defensive

                block["query_params"] = None

        block["decoded_uri"] = (
            decoded_path
            if not query
            else f"{decoded_path}?{block['decoded_query']}"
        )

    content_type = (
        _header_lookup(
            application.get("headers"),
            "content-type",
        )
        or ""
    ).lower()

    body = application.get("body")

    if (
        isinstance(body, str)
        and body
        and _FORM_CONTENT_TYPE in content_type
    ):

        form, s3, r3 = _decode_urlencoded(body, limit)

        block["form"] = form

        statuses.append(s3)

        if r3:
            reasons.append(r3)

    status = STATUS_NOT_APPLICABLE

    for s in statuses:

        status = _worse(status, s)

    reason = "; ".join(reasons) if reasons else None

    return block, status, reason


def _decode_html_block(
    application: dict[str, Any],
    limit: int,
) -> tuple[dict[str, Any] | None, str, str | None]:

    if str(application.get("protocol", "")).upper() != "HTTP":

        return None, STATUS_NOT_APPLICABLE, None

    body = application.get("body")

    if not isinstance(body, str) or not body:

        return None, STATUS_NOT_APPLICABLE, None

    content_type = (
        _header_lookup(
            application.get("headers"),
            "content-type",
        )
        or ""
    ).lower()

    looks_html = (
        "html" in content_type
        or ("&" in body and ";" in body)
    )

    if not looks_html:

        return None, STATUS_NOT_APPLICABLE, None

    return _decode_html_entities(body, limit)


def decode_event(
    event: Any,
    config: Any = None,
) -> dict[str, Any]:
    """
    Decode one normalized event.

    Returns a new dictionary: the original fields plus ``decoded``,
    ``decode_status`` and ``decode_reason``. A failure in any single field is
    isolated and reported, never raised.
    """

    result = as_event_dict(event)

    max_decoded = getattr(config, "max_decoded_size", 65536)
    max_payload = getattr(config, "max_payload_size", 8192)

    decoded: dict[str, Any] = {
        "http": None,
        "html": None,
        "mime": None,
        "text": None,
    }

    status = STATUS_NOT_APPLICABLE
    reasons: list[str] = []

    application = result.get("application")

    if not isinstance(application, dict):

        application = {}

    protocol = str(application.get("protocol", "UNKNOWN")).upper()

    try:

        http_block, s, r = _decode_http(application, max_decoded)

        decoded["http"] = http_block

        status = _worse(status, s)

        if r:
            reasons.append(r)

    except Exception as exc:  # pragma: no cover - defensive

        status = STATUS_ERROR
        reasons.append(f"http decode error: {type(exc).__name__}: {exc}")

    raw_bytes = None

    try:

        raw_bytes = _raw_payload_bytes(result, max_payload)

    except Exception as exc:  # pragma: no cover - defensive

        status = STATUS_ERROR
        reasons.append(f"payload decode error: {type(exc).__name__}: {exc}")

    if raw_bytes:

        try:

            text_block, s, r = _decode_character(raw_bytes, max_decoded)

            decoded["text"] = text_block

            status = _worse(status, s)

            if r:
                reasons.append(r)

        except Exception as exc:  # pragma: no cover - defensive

            status = STATUS_ERROR
            reasons.append(
                f"character decode error: {type(exc).__name__}: {exc}"
            )

        try:

            mime_block, s, r = _decode_mime(raw_bytes, max_decoded)

            decoded["mime"] = mime_block

            status = _worse(status, s)

            if r:
                reasons.append(r)

        except Exception as exc:  # pragma: no cover - defensive

            status = STATUS_ERROR
            reasons.append(f"mime decode error: {type(exc).__name__}: {exc}")

    if protocol == "HTTP":

        try:

            html_block, s, r = _decode_html_block(
                application,
                max_decoded,
            )

            decoded["html"] = html_block

            status = _worse(status, s)

            if r:
                reasons.append(r)

        except Exception as exc:  # pragma: no cover - defensive

            status = STATUS_ERROR
            reasons.append(f"html decode error: {type(exc).__name__}: {exc}")

    result["decoded"] = decoded
    result["decode_status"] = status
    result["decode_reason"] = "; ".join(reasons) if reasons else None

    return result


__all__ = [
    "decode_event",
    "STATUS_OK",
    "STATUS_PARTIAL",
    "STATUS_ERROR",
    "STATUS_NOT_APPLICABLE",
]
