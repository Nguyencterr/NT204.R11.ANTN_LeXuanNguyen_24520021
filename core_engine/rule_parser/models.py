"""Assignment 3, section 4.2: typed Internal Rule Object and parse results.

The parser never returns a bare ``dict`` for a rule. Every accepted rule is an
:class:`InternalRule`, so the repository, matcher and detection generator all
share one explicit contract.

Scope reminder: this is a *subset* of Snort, not a full Snort parser. Anything
outside the documented subset is reported as ``unsupported`` instead of being
silently ignored.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Parse status vocabulary (section 4.2).
# ---------------------------------------------------------------------------

STATUS_VALID = "valid"
STATUS_INVALID = "invalid"
STATUS_UNSUPPORTED = "unsupported"

PARSE_STATUSES = (
    STATUS_VALID,
    STATUS_INVALID,
    STATUS_UNSUPPORTED,
)


# ---------------------------------------------------------------------------
# Selectors.
# ---------------------------------------------------------------------------

ADDRESS_ANY = "any"
ADDRESS_IPV4 = "ipv4"
ADDRESS_CIDR = "cidr"

PORT_ANY = "any"
PORT_SINGLE = "single"
PORT_RANGE = "range"

DIRECTION_FORWARD = "->"
DIRECTION_BIDIRECTIONAL = "<>"

DIRECTIONS = (
    DIRECTION_FORWARD,
    DIRECTION_BIDIRECTIONAL,
)

FLOW_TO_SERVER = "to_server"
FLOW_TO_CLIENT = "to_client"
FLOW_ESTABLISHED = "established"
FLOW_NOT_ESTABLISHED = "not_established"

SUPPORTED_FLOW_KEYWORDS = (
    FLOW_TO_SERVER,
    FLOW_TO_CLIENT,
    FLOW_ESTABLISHED,
    FLOW_NOT_ESTABLISHED,
)

#: TCP flags understood by ``flags:`` (section 3.4 of the assignment brief).
SUPPORTED_TCP_FLAGS = frozenset("SAFRPU")

DSIZE_OPERATORS = (">", "<", "=", ">=", "<=")

PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"

SUPPORTED_PROTOCOLS = (
    PROTOCOL_TCP,
    PROTOCOL_UDP,
)


# ---------------------------------------------------------------------------
# Diagnostics.
# ---------------------------------------------------------------------------

CODE_SYNTAX_ERROR = "SYNTAX_ERROR"
CODE_MISSING_REQUIRED_OPTION = "MISSING_REQUIRED_OPTION"
CODE_INVALID_VALUE = "INVALID_VALUE"
CODE_DUPLICATE_OPTION = "DUPLICATE_OPTION"
CODE_UNSUPPORTED_ACTION = "UNSUPPORTED_ACTION"
CODE_UNSUPPORTED_PROTOCOL = "UNSUPPORTED_PROTOCOL"
CODE_UNSUPPORTED_KEYWORD = "UNSUPPORTED_KEYWORD"
CODE_UNSUPPORTED_SYNTAX = "UNSUPPORTED_SYNTAX"
CODE_INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class RuleDiagnostic:
    """One machine-readable parse/validation diagnostic."""

    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:

        return {
            "code": self.code,
            "message": self.message,
        }

    def __str__(self) -> str:

        return f"{self.code}: {self.message}"


# ---------------------------------------------------------------------------
# Header selectors.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AddressSelector:
    """
    An IP selector: ``any``, a single IPv4 address or an IPv4 CIDR block.

    IPv6 is outside the assignment scope and is rejected as unsupported by the
    parser. ``matches`` therefore only accepts IPv4 values.
    """

    kind: str
    value: str | None = None
    network: ipaddress.IPv4Network | None = None

    def matches(self, ip: Any) -> bool:
        """Return ``True`` when ``ip`` falls inside this selector."""

        if self.kind == ADDRESS_ANY:

            return True

        if not isinstance(ip, str) or not ip.strip():

            return False

        try:

            address = ipaddress.ip_address(ip.strip())

        except ValueError:

            return False

        if not isinstance(address, ipaddress.IPv4Address):

            return False

        if self.network is None:  # defensive: a non-any selector needs a net

            return False

        return address in self.network

    def to_dict(self) -> dict[str, Any]:

        return {
            "kind": self.kind,
            "value": self.value,
        }


@dataclass(frozen=True)
class PortSelector:
    """
    A port selector: ``any``, one port or an inclusive ``start:end`` range.

    The open forms ``:1024`` and ``1024:`` are normalized to ``0:1024`` and
    ``1024:65535`` respectively (documented in the README).
    """

    kind: str
    start: int | None = None
    end: int | None = None

    def matches(self, port: Any) -> bool:

        if self.kind == PORT_ANY:

            return True

        if port is None or isinstance(port, bool):

            return False

        try:

            value = int(port)

        except (TypeError, ValueError):

            return False

        if self.start is None or self.end is None:

            return False

        return self.start <= value <= self.end

    def to_dict(self) -> dict[str, Any]:

        return {
            "kind": self.kind,
            "start": self.start,
            "end": self.end,
        }


@dataclass(frozen=True)
class DsizeCondition:
    """A ``dsize`` comparison against the packet payload length."""

    operator: str
    value: int

    def matches(self, size: int) -> bool:

        if self.operator == ">":

            return size > self.value

        if self.operator == "<":

            return size < self.value

        if self.operator == ">=":

            return size >= self.value

        if self.operator == "<=":

            return size <= self.value

        return size == self.value

    def to_dict(self) -> dict[str, Any]:

        return {
            "operator": self.operator,
            "value": self.value,
        }


@dataclass(frozen=True)
class ContentCondition:
    """
    One ``content`` option plus its sticky modifiers.

    ``pattern_text`` is the unescaped rule text and ``pattern`` is its UTF-8
    byte form, which is what the matcher searches. Keeping both makes the
    detection evidence readable without re-decoding bytes.
    """

    pattern_text: str
    pattern: bytes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None

    @property
    def is_relative(self) -> bool:
        """Relative matching is used only when distance/within is present."""

        return self.distance is not None or self.within is not None

    def to_dict(self) -> dict[str, Any]:

        return {
            "content": self.pattern_text,
            "nocase": self.nocase,
            "offset": self.offset,
            "depth": self.depth,
            "distance": self.distance,
            "within": self.within,
        }


@dataclass(frozen=True)
class InternalRule:
    """Validated rule shared by the repository and the matching engine."""

    action: str
    protocol: str
    src_address: AddressSelector
    src_port: PortSelector
    direction: str
    dst_address: AddressSelector
    dst_port: PortSelector

    msg: str
    sid: int
    rev: int = 1
    classtype: str | None = None
    priority: int | None = None

    contents: tuple[ContentCondition, ...] = field(default_factory=tuple)
    tcp_flags: frozenset[str] | None = None
    dsize: DsizeCondition | None = None
    flow: tuple[str, ...] = field(default_factory=tuple)

    source_file: str | None = None
    line_number: int | None = None
    rule_ref: str | None = None
    raw_text: str = ""

    #: Repository insertion order. The parser leaves it at 0; the repository
    #: replaces it so candidate ordering is deterministic and testable.
    order: int = 0

    def to_dict(self) -> dict[str, Any]:

        return {
            "action": self.action,
            "protocol": self.protocol,
            "header": {
                "src_address": self.src_address.to_dict(),
                "src_port": self.src_port.to_dict(),
                "direction": self.direction,
                "dst_address": self.dst_address.to_dict(),
                "dst_port": self.dst_port.to_dict(),
            },
            "msg": self.msg,
            "sid": self.sid,
            "rev": self.rev,
            "classtype": self.classtype,
            "priority": self.priority,
            "contents": [content.to_dict() for content in self.contents],
            "tcp_flags": "".join(sorted(self.tcp_flags))
            if self.tcp_flags is not None
            else None,
            "dsize": self.dsize.to_dict() if self.dsize is not None else None,
            "flow": list(self.flow),
            "source_file": self.source_file,
            "line_number": self.line_number,
            "rule_ref": self.rule_ref,
            "raw_text": self.raw_text,
            "order": self.order,
        }


@dataclass(frozen=True)
class RuleParseResult:
    """The parser's verdict for one loaded rule candidate."""

    raw_text: str
    source_file: str | None
    line_number: int | None
    rule_ref: str | None
    status: str
    reason: str | None = None
    diagnostics: tuple[RuleDiagnostic, ...] = field(default_factory=tuple)
    rule: InternalRule | None = None

    @property
    def is_valid(self) -> bool:

        return self.status == STATUS_VALID and self.rule is not None

    def to_dict(self) -> dict[str, Any]:

        return {
            "raw_text": self.raw_text,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "rule_ref": self.rule_ref,
            "status": self.status,
            "reason": self.reason,
            "diagnostics": [
                diagnostic.to_dict()
                for diagnostic in self.diagnostics
            ],
            "rule": self.rule.to_dict() if self.rule is not None else None,
        }


__all__ = [
    "ADDRESS_ANY",
    "ADDRESS_CIDR",
    "ADDRESS_IPV4",
    "AddressSelector",
    "CODE_DUPLICATE_OPTION",
    "CODE_INTERNAL_ERROR",
    "CODE_INVALID_VALUE",
    "CODE_MISSING_REQUIRED_OPTION",
    "CODE_SYNTAX_ERROR",
    "CODE_UNSUPPORTED_ACTION",
    "CODE_UNSUPPORTED_KEYWORD",
    "CODE_UNSUPPORTED_PROTOCOL",
    "CODE_UNSUPPORTED_SYNTAX",
    "ContentCondition",
    "DIRECTION_BIDIRECTIONAL",
    "DIRECTION_FORWARD",
    "DIRECTIONS",
    "DSIZE_OPERATORS",
    "DsizeCondition",
    "FLOW_ESTABLISHED",
    "FLOW_NOT_ESTABLISHED",
    "FLOW_TO_CLIENT",
    "FLOW_TO_SERVER",
    "InternalRule",
    "PARSE_STATUSES",
    "PORT_ANY",
    "PORT_RANGE",
    "PORT_SINGLE",
    "PROTOCOL_TCP",
    "PROTOCOL_UDP",
    "PortSelector",
    "RuleDiagnostic",
    "RuleParseResult",
    "STATUS_INVALID",
    "STATUS_UNSUPPORTED",
    "STATUS_VALID",
    "SUPPORTED_FLOW_KEYWORDS",
    "SUPPORTED_PROTOCOLS",
    "SUPPORTED_TCP_FLAGS",
]
