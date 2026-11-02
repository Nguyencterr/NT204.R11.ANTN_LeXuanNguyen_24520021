"""Shared helpers for the Assignment 3 test modules.

Keeping rule loading and event construction here ensures every test uses the
real loader/parser/repository path instead of hand-built InternalRule objects.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Iterable

from core_engine.rule_loader import RuleLoader, RuleLoaderConfig
from core_engine.rule_parser import RuleParserValidator, RuleParseResult
from core_engine.rule_repository import (
    DUPLICATE_SID_REJECT,
    RepositoryConfig,
    RuleRepository,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
BT3_ROOT = REPO_ROOT / "TEST" / "BT3"
RULES_DIR = BT3_ROOT / "rules"


def rule_paths(*names: str) -> list[Path]:

    return [RULES_DIR / name for name in names]


def load_parse(
    *names: str,
    base_dir: Path = RULES_DIR,
) -> list[RuleParseResult]:
    """Load ``.rules`` files with section 4.1 and parse them with 4.2."""

    config = RuleLoaderConfig(
        rule_files=[str(RULES_DIR / name) for name in names],
        base_dir=base_dir,
    )

    load_result = RuleLoader(config).load()

    return RuleParserValidator().parse_many(load_result.rules)


def build_repository(
    *names: str,
    duplicate_sid_policy: str = DUPLICATE_SID_REJECT,
) -> RuleRepository:
    """Parse fixtures and add every result to a real repository."""

    results = load_parse(*names)

    return RuleRepository.from_parse_results(
        results,
        RepositoryConfig(duplicate_sid_policy=duplicate_sid_policy),
    )


def rule_by_sid(repository: RuleRepository, sid: int) -> Any:

    for rule in repository.valid_rules:

        if rule.sid == sid:

            return rule

    raise AssertionError(f"rule sid {sid} not found in repository")


def results_by_sid(results: Iterable[RuleParseResult]) -> dict[int, RuleParseResult]:

    return {
        result.rule.sid: result
        for result in results
        if result.rule is not None
    }


def encode_payload(payload: str | bytes | None) -> str | None:

    if payload is None:

        return None

    data = payload.encode("utf-8") if isinstance(payload, str) else payload

    if not data:

        return None

    return base64.b64encode(data).decode("ascii")


def event(
    *,
    src: str = "192.168.1.10",
    dst: str = "192.168.1.20",
    protocol: str = "TCP",
    src_port: int | None = 12345,
    dst_port: int | None = 80,
    timestamp: float = 1000.0,
    payload: str | bytes | None = None,
    flags: str | None = "A",
    application: dict[str, Any] | None = None,
    decoded: dict[str, Any] | None = None,
    normalized: dict[str, Any] | None = None,
    payload_length: int | None = None,
    packet_length: int = 54,
    packet_id: int = 1,
) -> dict[str, Any]:
    """Build a normalized-event-shaped dict for matching tests."""

    data = (
        payload.encode("utf-8")
        if isinstance(payload, str)
        else payload
    ) or b""

    transport: dict[str, Any] = {
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "payload_length": len(data),
    }

    if protocol == "TCP" and flags is not None:

        transport["flags"] = flags

    app = application or {"protocol": "UNKNOWN"}

    return {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "src_ip": src,
        "dst_ip": dst,
        "network": {"protocol": "IPv4"},
        "transport": transport,
        "application": app,
        "payload_length": len(data) if payload_length is None else payload_length,
        "packet_length": packet_length,
        "raw_payload_b64": encode_payload(data),
        "raw_payload_truncated": False,
        "decoded": decoded
        or {"http": None, "html": None, "mime": None, "text": None},
        "decode_status": "ok",
        "decode_reason": None,
        "normalized": normalized
        or {
            "src_ip": src,
            "dst_ip": dst,
            "transport_protocol": protocol,
            "application_protocol": str(app.get("protocol", "UNKNOWN")).upper(),
            "timestamp": timestamp,
            "http_headers": None,
            "host": None,
            "uri": None,
        },
        "src_port": src_port,
        "dst_port": dst_port,
        "transport_protocol": protocol,
        "application_protocol": str(app.get("protocol", "UNKNOWN")).upper(),
        "preprocess_status": "valid",
        "processing_action": "keep",
        "preprocess_reason": None,
        "preprocess_warnings": [],
    }


def http_event(
    uri: str,
    *,
    body: str = "",
    **kwargs: Any,
) -> dict[str, Any]:
    """Build an HTTP event whose decoded URI is the primary content buffer."""

    application = {
        "protocol": "HTTP",
        "type": "request",
        "method": "GET",
        "path": uri,
        "headers": {},
        "body": body,
    }

    decoded = {
        "http": {
            "type": "request",
            "raw_uri": uri,
            "decoded_uri": uri,
            "raw_path": uri,
            "decoded_path": uri,
            "raw_query": None,
            "decoded_query": None,
            "query_params": None,
            "form": None,
        },
        "html": None,
        "mime": None,
        "text": None,
    }

    return event(application=application, decoded=decoded, **kwargs)


def flow_context(
    *,
    flow_id: str = "flow-test-1",
    protocol: str = "TCP",
    state: str = "ESTABLISHED",
    established: bool | None = True,
    direction: str = "forward",
    to_server: bool | None = True,
    to_client: bool | None = False,
    role_source: str = "tcp_syn",
) -> dict[str, Any]:

    return {
        "flow_id": flow_id,
        "protocol": protocol,
        "application_protocol": "HTTP",
        "state": state,
        "established": established,
        "endpoint_a": {"ip": "192.168.1.10", "port": 50000},
        "endpoint_b": {"ip": "192.168.1.20", "port": 80},
        "client_endpoint": {"ip": "192.168.1.10", "port": 50000},
        "server_endpoint": {"ip": "192.168.1.20", "port": 80},
        "role_source": role_source,
        "direction": direction,
        "to_server": to_server,
        "to_client": to_client,
        "start_time": 1000.0,
        "last_seen": 1000.5,
        "packet_count": 4,
        "byte_count": 240,
        "forward_packet_count": 3,
        "backward_packet_count": 1,
        "forward_byte_count": 180,
        "backward_byte_count": 60,
    }
