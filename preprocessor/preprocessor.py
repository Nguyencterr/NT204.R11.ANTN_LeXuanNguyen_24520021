"""Assignment 2 Preprocessor.

Validates and normalizes a decoded event, then labels it ``valid``,
``partial`` or ``invalid``. Missing *optional* data never raises; it becomes
``null`` / ``[]`` consistently. The invalid/unsupported policy is configurable
via ``config.invalid_event_policy``.
"""

import ipaddress
from typing import Any

from common.events import as_event_dict

from config import (
    POLICY_KEEP,
    POLICY_MARK,
    POLICY_SKIP,
)

STATUS_VALID = "valid"
STATUS_PARTIAL = "partial"
STATUS_INVALID = "invalid"

ACTION_KEEP = "keep"
ACTION_MARK = "mark"
ACTION_SKIP = "skip"

KNOWN_TRANSPORT = ("TCP", "UDP")

_KNOWN_APPLICATION = ("HTTP", "DNS", "SMTP", "UNKNOWN")


def _coerce_float(value: Any) -> float | None:
    """Return ``value`` as float, or ``None`` for anything non-numeric."""

    if value is None or isinstance(value, bool):

        return None

    try:

        return float(value)

    except (TypeError, ValueError):

        return None


def _coerce_port(value: Any) -> tuple[int | None, str | None]:
    """
    Coerce a port value into ``0..65535``.

    Returns ``(port, error)``. ``port`` is ``None`` when the value is missing
    or unparseable; ``error`` describes an out-of-range value.
    """

    if value is None:

        return None, None

    if isinstance(value, bool):

        return None, "port must be an integer"

    try:

        port = int(value)

    except (TypeError, ValueError):

        return None, "port is not an integer"

    if port < 0 or port > 65535:

        return None, f"port {port} out of range 0..65535"

    return port, None


def _normalize_ip(value: Any) -> tuple[str | None, str | None]:
    """
    Normalize an IPv4/IPv6 address string.

    Returns ``(normalized, error)``.
    """

    if value is None:

        return None, None

    if not isinstance(value, str):

        return None, "IP address must be a string"

    try:

        return str(ipaddress.ip_address(value.strip())), None

    except ValueError:

        return None, f"invalid IP address {value!r}"


def _normalize_headers(headers: Any) -> dict[str, str] | None:

    if not isinstance(headers, dict):

        return None

    normalized: dict[str, str] = {}

    for key, value in headers.items():

        if not isinstance(key, str):

            continue

        name = key.strip().lower()

        text = value if isinstance(value, str) else str(value)

        # The Host header value is a domain: lowercasing it is safe
        # canonicalization. Other header values are preserved verbatim.
        if name == "host":

            text = text.strip().lower()

        normalized[name] = text

    return normalized


def _application_protocol(application: dict[str, Any]) -> str:

    protocol = str(application.get("protocol", "UNKNOWN")).upper()

    if protocol not in _KNOWN_APPLICATION:

        return protocol or "UNKNOWN"

    return protocol


def preprocess_event(
    event: Any,
    config: Any = None,
) -> dict[str, Any]:
    """
    Validate and normalize one decoded event.

    The returned dict adds ``preprocess_status``, ``processing_action``,
    ``preprocess_reason``, ``preprocess_warnings`` and a ``normalized`` block
    while preserving every incoming field.
    """

    result = as_event_dict(event)

    policy = getattr(config, "invalid_event_policy", POLICY_MARK)

    if policy not in (POLICY_KEEP, POLICY_MARK, POLICY_SKIP):

        policy = POLICY_MARK

    errors: list[str] = []
    warnings: list[str] = []

    # -------------------------------------------------------------
    # Coerce the nested blocks so missing optional data is null/[].
    # -------------------------------------------------------------
    network = result.get("network")

    if not isinstance(network, dict):

        network = {}
        result["network"] = network

    transport = result.get("transport")

    if not isinstance(transport, dict):

        transport = {}
        result["transport"] = transport

    application = result.get("application")

    if not isinstance(application, dict):

        application = {"protocol": "UNKNOWN"}
        result["application"] = application

    if not isinstance(result.get("errors"), list):

        result["errors"] = []

    result.setdefault("raw_payload_b64", None)
    result.setdefault("raw_payload_truncated", False)
    result.setdefault("packet_length", None)
    result.setdefault("payload_length", 0)
    result.setdefault("decoded", None)

    # -------------------------------------------------------------
    # packet_id
    # -------------------------------------------------------------
    packet_id = result.get("packet_id")

    if packet_id is None or isinstance(packet_id, bool):

        errors.append("missing or invalid packet_id")

    # -------------------------------------------------------------
    # timestamp
    # -------------------------------------------------------------
    timestamp = _coerce_float(result.get("timestamp"))

    if timestamp is None:

        errors.append("missing or non-numeric timestamp")

    elif timestamp <= 0:

        warnings.append("non-positive timestamp")

    # -------------------------------------------------------------
    # IP addresses (required for flow tracking)
    # -------------------------------------------------------------
    src_ip, src_err = _normalize_ip(result.get("src_ip"))
    dst_ip, dst_err = _normalize_ip(result.get("dst_ip"))

    if src_err:
        errors.append(f"src_ip: {src_err}")

    if dst_err:
        errors.append(f"dst_ip: {dst_err}")

    if result.get("src_ip") is None:

        errors.append("missing src_ip")

    if result.get("dst_ip") is None:

        errors.append("missing dst_ip")

    # -------------------------------------------------------------
    # Transport protocol and ports
    # -------------------------------------------------------------
    transport_protocol = str(
        transport.get("protocol", "UNKNOWN") or "UNKNOWN"
    ).upper()

    if transport_protocol == "UNKNOWN":

        warnings.append("unsupported or unknown transport protocol")

    elif transport_protocol not in KNOWN_TRANSPORT:

        warnings.append(
            f"unrecognized transport protocol {transport_protocol!r}"
        )

    src_port, src_port_err = _coerce_port(transport.get("src_port"))
    dst_port, dst_port_err = _coerce_port(transport.get("dst_port"))

    if src_port_err:
        errors.append(f"src_port: {src_port_err}")

    if dst_port_err:
        errors.append(f"dst_port: {dst_port_err}")

    if (
        transport_protocol in KNOWN_TRANSPORT
        and (src_port is None or dst_port is None)
    ):

        warnings.append("missing src_port/dst_port")

    # -------------------------------------------------------------
    # Application protocol
    # -------------------------------------------------------------
    application_protocol = _application_protocol(application)

    if application_protocol == "UNKNOWN":

        warnings.append("unknown application protocol")

    # -------------------------------------------------------------
    # Normalized view
    # -------------------------------------------------------------
    normalized: dict[str, Any] = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "transport_protocol": transport_protocol,
        "application_protocol": application_protocol,
        "timestamp": timestamp,
        "http_headers": _normalize_headers(application.get("headers"))
        if application_protocol == "HTTP"
        else None,
        "host": None,
        "uri": None,
    }

    if application_protocol == "HTTP":

        headers = normalized["http_headers"] or {}

        host = headers.get("host")

        if isinstance(host, str):

            normalized["host"] = host.strip().lower()

        decoded = result.get("decoded")

        http_decoded = (
            decoded.get("http")
            if isinstance(decoded, dict)
            else None
        )

        if isinstance(http_decoded, dict):

            normalized["uri"] = (
                http_decoded.get("decoded_uri")
                if http_decoded.get("decoded_uri") is not None
                else http_decoded.get("raw_uri")
            )

        elif isinstance(application.get("path"), str):

            normalized["uri"] = application.get("path")

    result["normalized"] = normalized

    # -------------------------------------------------------------
    # Canonical fields for the tracker
    # -------------------------------------------------------------
    result["src_port"] = src_port
    result["dst_port"] = dst_port
    result["transport_protocol"] = transport_protocol
    result["application_protocol"] = application_protocol

    # -------------------------------------------------------------
    # Status and policy
    # -------------------------------------------------------------
    if errors:

        status = STATUS_INVALID

    elif warnings:

        status = STATUS_PARTIAL

    else:

        status = STATUS_VALID

    if status == STATUS_INVALID:

        if policy == POLICY_SKIP:
            action = ACTION_SKIP
        elif policy == POLICY_MARK:
            action = ACTION_MARK
        else:
            action = ACTION_KEEP

    else:

        action = ACTION_KEEP

    reason: str | None = None

    if errors:

        reason = "; ".join(errors)

    elif warnings:

        reason = "; ".join(warnings)

    result["preprocess_status"] = status
    result["processing_action"] = action
    result["preprocess_reason"] = reason
    result["preprocess_warnings"] = warnings

    return result


__all__ = [
    "preprocess_event",
    "STATUS_VALID",
    "STATUS_PARTIAL",
    "STATUS_INVALID",
    "ACTION_KEEP",
    "ACTION_MARK",
    "ACTION_SKIP",
]
