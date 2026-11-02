"""Assignment 3, section 4.4: Rule Matching Engine package."""

from .buffers import SearchBuffer, extract_buffers
from .conditions import (
    DsizeMatch,
    FlagsMatch,
    match_rule_dsize,
    match_rule_flags,
    payload_size,
)
from .content import ContentMatch, ContentMatchOutcome, match_contents
from .engine import (
    RuleMatchResult,
    RuleMatchingEngine,
    STATUS_MATCH,
    STATUS_NO_MATCH,
)
from .flow import FlowMatch, match_rule_flow
from .header import (
    EventHeader,
    HeaderMatch,
    ORIENTATION_FORWARD,
    ORIENTATION_REVERSE,
    extract_event_header,
    match_rule_header,
)

__all__ = [
    "ContentMatch",
    "ContentMatchOutcome",
    "DsizeMatch",
    "EventHeader",
    "FlagsMatch",
    "FlowMatch",
    "HeaderMatch",
    "ORIENTATION_FORWARD",
    "ORIENTATION_REVERSE",
    "RuleMatchResult",
    "RuleMatchingEngine",
    "STATUS_MATCH",
    "STATUS_NO_MATCH",
    "SearchBuffer",
    "extract_buffers",
    "extract_event_header",
    "match_contents",
    "match_rule_dsize",
    "match_rule_flags",
    "match_rule_flow",
    "match_rule_header",
    "payload_size",
]
