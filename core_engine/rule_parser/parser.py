"""Assignment 3, section 4.2: Rule Parser & Validator.

Parsing pipeline for one loaded candidate::

    raw text -> header/options split -> header validation
             -> option parsing/validation -> InternalRule

Every rule gets one of three verdicts:

``valid``
    Fully parsed and every component is inside the supported subset.
``invalid``
    Malformed syntax, missing required option, wrong type/value, invalid
    IP/port, a content modifier used without a content, ...
``unsupported``
    Well-formed rule/keyword that is outside the Assignment 3 subset (``pcre``,
    ``byte_test``, ``icmp``, non-``alert`` actions, ...).

A failure is always isolated to the current rule; the caller can keep parsing
the next candidate.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from .models import (
    ADDRESS_ANY,
    ADDRESS_CIDR,
    ADDRESS_IPV4,
    CODE_DUPLICATE_OPTION,
    CODE_INTERNAL_ERROR,
    CODE_INVALID_VALUE,
    CODE_MISSING_REQUIRED_OPTION,
    CODE_SYNTAX_ERROR,
    CODE_UNSUPPORTED_ACTION,
    CODE_UNSUPPORTED_KEYWORD,
    CODE_UNSUPPORTED_PROTOCOL,
    CODE_UNSUPPORTED_SYNTAX,
    DIRECTION_BIDIRECTIONAL,
    DIRECTION_FORWARD,
    FLOW_ESTABLISHED,
    FLOW_NOT_ESTABLISHED,
    FLOW_TO_CLIENT,
    FLOW_TO_SERVER,
    PORT_ANY,
    PORT_RANGE,
    PORT_SINGLE,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
    STATUS_INVALID,
    STATUS_UNSUPPORTED,
    STATUS_VALID,
    SUPPORTED_FLOW_KEYWORDS,
    SUPPORTED_PROTOCOLS,
    SUPPORTED_TCP_FLAGS,
    AddressSelector,
    ContentCondition,
    DsizeCondition,
    InternalRule,
    PortSelector,
    RuleDiagnostic,
    RuleParseResult,
)
from .tokenizer import (
    RuleSyntaxError,
    RuleUnsupportedError,
    decode_quoted_content,
    decode_quoted_string,
    split_header_and_options,
    split_option_token,
    split_option_tokens,
    unquote_if_needed,
)


_DIGITS_RE = re.compile(r"^[0-9]+$")
_DSIZE_RE = re.compile(r"^(>=|<=|>|<|=)?\s*([0-9]+)$")
_CLASSTYPE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

_MAX_PORT = 65535


@dataclass
class _ContentBuilder:
    """Mutable builder used while sticky modifiers are collected."""

    pattern_text: str
    pattern: bytes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None

    @property
    def is_relative(self) -> bool:
        """``distance``/``within`` anchor to the previous content match."""

        return self.distance is not None or self.within is not None

    def build(self) -> ContentCondition:

        return ContentCondition(
            pattern_text=self.pattern_text,
            pattern=self.pattern,
            nocase=self.nocase,
            offset=self.offset,
            depth=self.depth,
            distance=self.distance,
            within=self.within,
        )


@dataclass
class RuleParserConfig:
    """Contract choices that are documented in the README."""

    #: ``sid`` and ``msg`` are required by this implementation.
    require_msg: bool = True
    #: ``rev`` is optional and defaults to 1 (Snort-like revision default).
    require_rev: bool = False
    default_rev: int = 1


class RuleParserValidator:
    """Parse and validate Assignment 3 rule candidates."""

    def __init__(
        self,
        config: RuleParserConfig | None = None,
    ) -> None:

        self.config = config or RuleParserConfig()

    # -- public API ---------------------------------------------------------

    def parse(
        self,
        candidate: Any,
        *,
        source_file: str | None = None,
        line_number: int | None = None,
        rule_ref: str | None = None,
    ) -> RuleParseResult:
        """
        Parse one candidate.

        ``candidate`` may be a ``RuleSourceEntry`` from the Rule Loader, a
        plain string, or any object exposing ``raw_text``.
        """

        raw_text, meta = self._candidate_fields(
            candidate,
            source_file=source_file,
            line_number=line_number,
            rule_ref=rule_ref,
        )

        try:

            rule = self._parse_text(raw_text, meta)

        except RuleUnsupportedError as exc:

            return self._result(
                raw_text,
                meta,
                STATUS_UNSUPPORTED,
                str(exc),
                RuleDiagnostic(CODE_UNSUPPORTED_SYNTAX, str(exc)),
            )

        except RuleSyntaxError as exc:

            return self._result(
                raw_text,
                meta,
                STATUS_INVALID,
                str(exc),
                RuleDiagnostic(CODE_SYNTAX_ERROR, str(exc)),
            )

        except Exception as exc:  # noqa: BLE001 - one bad rule must not stop parsing

            message = f"internal parser error: {type(exc).__name__}: {exc}"

            return self._result(
                raw_text,
                meta,
                STATUS_INVALID,
                message,
                RuleDiagnostic(CODE_INTERNAL_ERROR, message),
            )

        return self._result(
            raw_text,
            meta,
            STATUS_VALID,
            None,
            rule=rule,
        )

    def parse_many(
        self,
        candidates: Iterable[Any],
    ) -> list[RuleParseResult]:
        """Parse candidates independently; a bad rule never stops the rest."""

        results: list[RuleParseResult] = []

        for candidate in candidates:

            results.append(self.parse(candidate))

        return results

    # -- candidate metadata -------------------------------------------------

    @staticmethod
    def _candidate_fields(
        candidate: Any,
        *,
        source_file: str | None,
        line_number: int | None,
        rule_ref: str | None,
    ) -> tuple[str, dict[str, Any]]:

        if isinstance(candidate, str):

            raw_text = candidate

            meta = {
                "source_file": source_file,
                "line_number": line_number,
                "rule_ref": rule_ref,
            }

            return raw_text, meta

        raw_text = getattr(candidate, "raw_text", None)

        if not isinstance(raw_text, str):

            raise TypeError(
                "rule candidate must be a string or expose raw_text, got "
                f"{type(candidate).__name__}"
            )

        resolved_ref = rule_ref or getattr(candidate, "rule_ref", None)

        meta = {
            "source_file": source_file
            or getattr(candidate, "source_file", None),
            "line_number": line_number
            if line_number is not None
            else getattr(candidate, "line_number", None),
            "rule_ref": resolved_ref,
        }

        return raw_text, meta

    @staticmethod
    def _result(
        raw_text: str,
        meta: dict[str, Any],
        status: str,
        reason: str | None,
        diagnostic: RuleDiagnostic | None = None,
        rule: InternalRule | None = None,
    ) -> RuleParseResult:

        diagnostics = (diagnostic,) if diagnostic is not None else ()

        return RuleParseResult(
            raw_text=raw_text,
            source_file=meta.get("source_file"),
            line_number=meta.get("line_number"),
            rule_ref=meta.get("rule_ref"),
            status=status,
            reason=reason,
            diagnostics=diagnostics,
            rule=rule,
        )

    # -- parsing ------------------------------------------------------------

    def _parse_text(
        self,
        raw_text: str,
        meta: dict[str, Any],
    ) -> InternalRule:

        header_text, options_text = split_header_and_options(raw_text)

        header = self._parse_header(header_text)

        option_state = self._parse_options(options_text, header.protocol)

        return InternalRule(
            action=header.action,
            protocol=header.protocol,
            src_address=header.src_address,
            src_port=header.src_port,
            direction=header.direction,
            dst_address=header.dst_address,
            dst_port=header.dst_port,
            msg=option_state.msg,
            sid=option_state.sid,
            rev=option_state.rev,
            classtype=option_state.classtype,
            priority=option_state.priority,
            contents=tuple(
                builder.build()
                for builder in option_state.contents
            ),
            tcp_flags=option_state.tcp_flags,
            dsize=option_state.dsize,
            flow=tuple(option_state.flow),
            source_file=meta.get("source_file"),
            line_number=meta.get("line_number"),
            rule_ref=meta.get("rule_ref"),
            raw_text=raw_text,
        )

    # -- header -------------------------------------------------------------

    @dataclass(frozen=True)
    class _Header:
        action: str
        protocol: str
        src_address: AddressSelector
        src_port: PortSelector
        direction: str
        dst_address: AddressSelector
        dst_port: PortSelector

    def _parse_header(self, header_text: str) -> "_Header":

        tokens = header_text.split()

        if len(tokens) != 7:

            raise RuleSyntaxError(
                "rule header must have 7 fields "
                "(action protocol src_ip src_port direction dst_ip dst_port), "
                f"got {len(tokens)}"
            )

        action, protocol, src_ip, src_port, direction, dst_ip, dst_port = tokens

        normalized_action = action.strip().lower()

        if normalized_action != "alert":

            raise RuleUnsupportedError(
                f"action {action!r} is not supported; only 'alert' is in scope"
            )

        normalized_protocol = protocol.strip().upper()

        if normalized_protocol not in SUPPORTED_PROTOCOLS:

            raise RuleUnsupportedError(
                f"protocol {protocol!r} is not supported; "
                "only 'tcp' and 'udp' are in scope"
            )

        if direction not in (DIRECTION_FORWARD, DIRECTION_BIDIRECTIONAL):

            raise RuleSyntaxError(
                f"direction must be '->' or '<>', got {direction!r}"
            )

        return self._Header(
            action=normalized_action,
            protocol=normalized_protocol,
            src_address=self._parse_address(src_ip, "source address"),
            src_port=self._parse_port(src_port, "source port"),
            direction=direction,
            dst_address=self._parse_address(dst_ip, "destination address"),
            dst_port=self._parse_port(dst_port, "destination port"),
        )

    # -- selectors ----------------------------------------------------------

    def _parse_address(self, value: str, label: str) -> AddressSelector:

        text = value.strip()

        if not text:

            raise RuleSyntaxError(f"{label} must not be empty")

        if text.lower() == "any":

            return AddressSelector(kind=ADDRESS_ANY, value="any")

        if text.startswith("!"):

            raise RuleUnsupportedError(
                f"negated {label} {value!r} is not supported"
            )

        if text.startswith("$"):

            raise RuleUnsupportedError(
                f"Snort variable {value!r} in {label} is not supported; "
                "use any, an IPv4 address or an IPv4 CIDR block"
            )

        if "," in text:

            raise RuleUnsupportedError(
                f"address list {value!r} in {label} is not supported"
            )

        if ":" in text:

            # IPv6 or an unsupported address/port combination.
            try:

                ipaddress.IPv6Address(text)

            except ValueError:

                pass

            else:

                raise RuleUnsupportedError(
                    f"IPv6 {label} {value!r} is not supported"
                )

            raise RuleSyntaxError(f"invalid {label} {value!r}")

        try:

            if "/" in text:

                network = ipaddress.IPv4Network(text, strict=False)

                return AddressSelector(
                    kind=ADDRESS_CIDR,
                    value=str(network),
                    network=network,
                )

            address = ipaddress.IPv4Address(text)

        except ValueError as exc:

            raise RuleSyntaxError(
                f"invalid {label} {value!r}: {exc}"
            ) from exc

        network = ipaddress.IPv4Network(f"{address}/32")

        return AddressSelector(
            kind=ADDRESS_IPV4,
            value=str(address),
            network=network,
        )

    def _parse_port(self, value: str, label: str) -> PortSelector:

        text = value.strip()

        if not text:

            raise RuleSyntaxError(f"{label} must not be empty")

        if text.lower() == "any":

            return PortSelector(kind=PORT_ANY)

        if text.startswith("!"):

            raise RuleUnsupportedError(
                f"negated {label} {value!r} is not supported"
            )

        if "," in text:

            raise RuleUnsupportedError(
                f"port list {value!r} in {label} is not supported"
            )

        if ":" in text:

            if text.count(":") != 1:

                raise RuleSyntaxError(
                    f"invalid {label} range {value!r}; use start:end"
                )

            start_text, end_text = text.split(":", 1)

            start = 0 if not start_text else self._parse_uint(
                start_text,
                label,
            )

            end = _MAX_PORT if not end_text else self._parse_uint(
                end_text,
                label,
            )

            if start > end:

                raise RuleSyntaxError(
                    f"invalid {label} range {value!r}: start is greater "
                    "than end"
                )

            return PortSelector(
                kind=PORT_RANGE,
                start=start,
                end=end,
            )

        port = self._parse_uint(text, label)

        if port > _MAX_PORT:

            raise RuleSyntaxError(
                f"{label} {port} is outside 0..{_MAX_PORT}"
            )

        return PortSelector(
            kind=PORT_SINGLE,
            start=port,
            end=port,
        )

    def _parse_uint(self, value: str, label: str) -> int:

        text = value.strip()

        if not text:

            raise RuleSyntaxError(f"{label} must not be empty")

        if text.startswith("-"):

            raise RuleSyntaxError(f"{label} must be non-negative, got {value!r}")

        if not _DIGITS_RE.match(text):

            raise RuleSyntaxError(f"{label} must be an integer, got {value!r}")

        number = int(text)

        if number > _MAX_PORT and label.endswith("port"):

            raise RuleSyntaxError(
                f"{label} {number} is outside 0..{_MAX_PORT}"
            )

        return number

    # -- options ------------------------------------------------------------

    @dataclass
    class _OptionState:
        msg: str | None = None
        sid: int | None = None
        rev: int | None = None
        classtype: str | None = None
        priority: int | None = None
        contents: list[_ContentBuilder] = field(default_factory=list)
        tcp_flags: frozenset[str] | None = None
        dsize: DsizeCondition | None = None
        flow: list[str] = field(default_factory=list)

    def _parse_options(
        self,
        options_text: str,
        protocol: str,
    ) -> "_OptionState":

        state = self._OptionState()
        seen: set[str] = set()

        for token in split_option_tokens(options_text):

            key, value = split_option_token(token)

            if not key:

                raise RuleSyntaxError("empty option name")

            key = key.lower()

            if key == "content":

                self._add_content(state, value)
                continue

            if key in _CONTENT_MODIFIERS:

                self._apply_content_modifier(state, key, value, seen)
                continue

            if key == "nocase":

                self._apply_content_modifier(state, key, value, seen)
                continue

            if key == "msg":

                self._require_single(seen, key)
                state.msg = self._parse_msg(value)

            elif key == "sid":

                self._require_single(seen, key)
                state.sid = self._parse_positive_int(value, "sid")

            elif key == "rev":

                self._require_single(seen, key)
                state.rev = self._parse_positive_int(value, "rev")

            elif key == "classtype":

                self._require_single(seen, key)
                state.classtype = self._parse_classtype(value)

            elif key == "priority":

                self._require_single(seen, key)
                state.priority = self._parse_positive_int(
                    value,
                    "priority",
                )

            elif key == "flags":

                self._require_single(seen, key)
                state.tcp_flags = self._parse_flags(value)

            elif key == "dsize":

                self._require_single(seen, key)
                state.dsize = self._parse_dsize(value)

            elif key == "flow":

                self._require_single(seen, key)
                state.flow = self._parse_flow(value)

            else:

                if value is None and key not in _UNSUPPORTED_FLAG_OPTIONS:

                    # Snort options take ``name:value`` except for a small
                    # documented set of no-value modifiers. A bare unknown
                    # token is malformed, not merely out of scope.
                    raise RuleSyntaxError(
                        f"option {key!r} is malformed; expected 'name:value'"
                    )

                raise RuleUnsupportedError(
                    f"option {key!r} is not supported by this subset"
                )

        if state.sid is None:

            raise RuleSyntaxError("missing required option 'sid'")

        if self.config.require_msg and state.msg is None:

            raise RuleSyntaxError("missing required option 'msg'")

        if self.config.require_rev and state.rev is None:

            raise RuleSyntaxError("missing required option 'rev'")

        if state.rev is None:

            state.rev = self.config.default_rev

        if state.msg is None:

            state.msg = ""

        if protocol == PROTOCOL_UDP and state.tcp_flags is not None:

            raise RuleSyntaxError(
                "option 'flags' is only valid for TCP, not UDP"
            )

        return state

    @staticmethod
    def _require_single(seen: set[str], key: str) -> None:

        if key in seen:

            raise RuleSyntaxError(
                f"option {key!r} appears more than once"
            )

        seen.add(key)

    def _parse_msg(self, value: str | None) -> str:

        if value is None or not value.strip():

            raise RuleSyntaxError("msg requires a quoted value")

        msg = decode_quoted_string(value, option="msg")

        if not msg:

            raise RuleSyntaxError("msg must not be empty")

        return msg

    def _parse_positive_int(self, value: str | None, label: str) -> int:

        if value is None or not value.strip():

            raise RuleSyntaxError(f"{label} requires an integer value")

        text = value.strip()

        if not _DIGITS_RE.match(text):

            raise RuleSyntaxError(
                f"{label} must be a positive integer, got {value!r}"
            )

        number = int(text)

        if number < 1:

            raise RuleSyntaxError(f"{label} must be at least 1, got {number}")

        return number

    def _parse_non_negative_int(self, value: str | None, label: str) -> int:

        if value is None or not value.strip():

            raise RuleSyntaxError(f"{label} requires an integer value")

        text = value.strip()

        if not _DIGITS_RE.match(text):

            raise RuleSyntaxError(
                f"{label} must be a non-negative integer, got {value!r}"
            )

        return int(text)

    def _parse_classtype(self, value: str | None) -> str:

        if value is None or not value.strip():

            raise RuleSyntaxError("classtype requires a value")

        text = unquote_if_needed(value)

        if not _CLASSTYPE_RE.match(text):

            raise RuleSyntaxError(
                "classtype must be a simple identifier, got "
                f"{value!r}"
            )

        return text

    def _parse_flags(self, value: str | None) -> frozenset[str]:

        if value is None or not value.strip():

            raise RuleSyntaxError("flags requires a value")

        text = unquote_if_needed(value).strip().upper()

        if not text:

            raise RuleSyntaxError("flags must not be empty")

        modifiers = set("+*!")

        if any(char in modifiers for char in text):

            raise RuleUnsupportedError(
                f"flags modifiers in {value!r} are not supported"
            )

        unsupported = set(text) - SUPPORTED_TCP_FLAGS

        if unsupported:

            raise RuleUnsupportedError(
                "TCP flag(s) "
                f"{''.join(sorted(unsupported))} are outside the supported "
                f"set {''.join(sorted(SUPPORTED_TCP_FLAGS))}"
            )

        return frozenset(text)

    def _parse_dsize(self, value: str | None) -> DsizeCondition:

        if value is None or not value.strip():

            raise RuleSyntaxError("dsize requires a value")

        text = value.strip()

        if text.startswith("!"):

            raise RuleUnsupportedError(
                f"dsize operator in {value!r} is not supported"
            )

        match = _DSIZE_RE.match(text)

        if match is None:

            if text.startswith("-"):

                raise RuleSyntaxError("dsize must be non-negative")

            if ":" in text or "<>" in text or "!=" in text:

                raise RuleUnsupportedError(
                    f"dsize range/operator form {value!r} is not supported"
                )

            raise RuleSyntaxError(f"invalid dsize value {value!r}")

        operator = match.group(1) or "="
        number = int(match.group(2))

        return DsizeCondition(operator=operator, value=number)

    def _parse_flow(self, value: str | None) -> list[str]:

        if value is None or not value.strip():

            raise RuleSyntaxError("flow requires a value")

        raw_tokens = [
            token.strip().lower()
            for token in value.split(",")
        ]

        if any(not token for token in raw_tokens):

            raise RuleSyntaxError("flow contains an empty condition")

        conditions: list[str] = []

        for token in raw_tokens:

            if token not in SUPPORTED_FLOW_KEYWORDS:

                raise RuleUnsupportedError(
                    f"flow condition {token!r} is not supported"
                )

            if token in conditions:

                raise RuleSyntaxError(
                    f"flow condition {token!r} appears more than once"
                )

            conditions.append(token)

        if {FLOW_TO_SERVER, FLOW_TO_CLIENT}.issubset(conditions):

            raise RuleSyntaxError(
                "flow cannot require both to_server and to_client"
            )

        if {FLOW_ESTABLISHED, FLOW_NOT_ESTABLISHED}.issubset(conditions):

            raise RuleSyntaxError(
                "flow cannot require both established and not_established"
            )

        return conditions

    # -- content ------------------------------------------------------------

    def _add_content(
        self,
        state: "_OptionState",
        value: str | None,
    ) -> None:

        if value is None or not value.strip():

            raise RuleSyntaxError("content requires a quoted value")

        text = value.strip()

        if text.startswith("!"):

            raise RuleUnsupportedError(
                "negated content (!\"...\") is not supported"
            )

        pattern_text = decode_quoted_content(text)

        if not pattern_text:

            raise RuleSyntaxError("content must not be empty")

        state.contents.append(
            _ContentBuilder(
                pattern_text=pattern_text,
                pattern=pattern_text.encode("utf-8"),
            )
        )

    def _apply_content_modifier(
        self,
        state: "_OptionState",
        key: str,
        value: str | None,
        seen: set[str],
    ) -> None:

        if not state.contents:

            raise RuleSyntaxError(
                f"content modifier {key!r} has no preceding content option"
            )

        builder = state.contents[-1]

        if key == "nocase":

            if value is not None:

                raise RuleSyntaxError("nocase does not take a value")

            if builder.nocase:

                raise RuleSyntaxError(
                    "nocase modifier appears more than once for one content"
                )

            builder.nocase = True
            return

        if value is None or not value.strip():

            raise RuleSyntaxError(f"{key} requires an integer value")

        number = self._parse_non_negative_int(value, key)

        if key == "offset":

            if builder.offset is not None:

                raise RuleSyntaxError(
                    "offset modifier appears more than once for one content"
                )

            if builder.is_relative:

                raise RuleSyntaxError(
                    "offset/depth cannot be combined with distance/within "
                    "on the same content"
                )

            builder.offset = number

        elif key == "depth":

            if builder.depth is not None:

                raise RuleSyntaxError(
                    "depth modifier appears more than once for one content"
                )

            if builder.is_relative:

                raise RuleSyntaxError(
                    "offset/depth cannot be combined with distance/within "
                    "on the same content"
                )

            builder.depth = number

        elif key == "distance":

            if builder.distance is not None:

                raise RuleSyntaxError(
                    "distance modifier appears more than once for one content"
                )

            if builder.offset is not None or builder.depth is not None:

                raise RuleSyntaxError(
                    "distance/within cannot be combined with offset/depth "
                    "on the same content"
                )

            if len(state.contents) == 1:

                raise RuleSyntaxError(
                    "distance/within requires a previous content match"
                )

            builder.distance = number

        elif key == "within":

            if builder.within is not None:

                raise RuleSyntaxError(
                    "within modifier appears more than once for one content"
                )

            if builder.offset is not None or builder.depth is not None:

                raise RuleSyntaxError(
                    "distance/within cannot be combined with offset/depth "
                    "on the same content"
                )

            if len(state.contents) == 1:

                raise RuleSyntaxError(
                    "distance/within requires a previous content match"
                )

            builder.within = number

        else:  # pragma: no cover - the caller restricts the key set

            raise RuleUnsupportedError(
                f"content modifier {key!r} is not supported"
            )


#: Keys that attach to the preceding ``content`` option.
_CONTENT_MODIFIERS = frozenset(
    ("offset", "depth", "distance", "within")
)

#: Well-known Snort options that take no value but are outside this subset.
#: They are reported as ``unsupported`` (not ``invalid``) because they are
#: valid Snort keywords; any other bare token is malformed syntax.
_UNSUPPORTED_FLAG_OPTIONS = frozenset(
    (
        "file_data",
        "fast_pattern",
        "http_client_body",
        "http_cookie",
        "http_header",
        "http_method",
        "http_raw_cookie",
        "http_raw_header",
        "http_raw_uri",
        "http_stat_code",
        "http_stat_msg",
        "http_uri",
        "isdataat",
        "no_content",
        "norm",
        "pkt_data",
        "rawbytes",
        "sameip",
        "uricontent",
    )
)


__all__ = [
    "RuleParserConfig",
    "RuleParserValidator",
]
