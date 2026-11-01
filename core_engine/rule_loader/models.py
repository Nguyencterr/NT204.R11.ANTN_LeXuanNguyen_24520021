"""Data contract between the Rule Loader and the Rule Parser & Validator.

Section 4.1 only *loads* rule text and remembers where it came from. The loader
never decides whether the text is valid Snort syntax, so a candidate carries no
``valid`` / ``invalid`` / ``unsupported`` status: those belong to the Rule
Parser & Validator (section 4.2).

Every object here is a plain dataclass with ``to_dict()``, so a candidate can be
logged as JSON or written to JSON Lines without extra conversion.
"""

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Warning / error codes.
#
# These describe *loading* problems only (files, configuration, forwarding),
# never rule syntax.
# ---------------------------------------------------------------------------

CODE_FILE_DISABLED = "FILE_DISABLED"
CODE_FILE_NOT_FOUND = "FILE_NOT_FOUND"
CODE_FILE_NOT_REGULAR = "FILE_NOT_REGULAR"
CODE_FILE_UNREADABLE = "FILE_UNREADABLE"
CODE_FILE_ENCODING_ERROR = "FILE_ENCODING_ERROR"
CODE_FILE_IO_ERROR = "FILE_IO_ERROR"
CODE_EXTENSION_NOT_ALLOWED = "EXTENSION_NOT_ALLOWED"
CODE_FILE_EMPTY = "FILE_EMPTY"
CODE_FILE_NO_RULES = "FILE_NO_RULES"
CODE_RULE_DISABLED = "RULE_DISABLED"
CODE_UNKNOWN_RULE_OVERRIDE = "UNKNOWN_RULE_OVERRIDE"
CODE_INVALID_CONFIG = "INVALID_CONFIG"
CODE_CANDIDATE_HANDLER_ERROR = "CANDIDATE_HANDLER_ERROR"

# Severity levels. ``info`` marks an expected skip (disabled file/rule, empty
# file); ``warning`` marks something the operator should look at; ``error``
# marks a file that could not be loaded or a candidate that could not be
# forwarded.
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_ERROR = "error"

SEVERITIES = (
    SEVERITY_INFO,
    SEVERITY_WARNING,
    SEVERITY_ERROR,
)


@dataclass(frozen=True)
class RuleSourceEntry:
    """
    One rule candidate read from a ``.rules`` file.

    ``raw_text`` is the original line with only its line terminator removed:
    the loader never rewrites, trims or re-serializes rule text.
    """

    #: Original rule text, exactly as written in the file (no trailing newline).
    raw_text: str

    #: Path shown to the operator, relative to the loader ``base_dir`` when the
    #: file lives under it, otherwise an absolute POSIX path.
    source_file: str

    #: Absolute, normalized path of the file, kept for traceability.
    path: str

    #: 1-based line number inside ``source_file``.
    line_number: int

    #: Stable identifier of the rule origin, ``<source_file>:<line_number>``.
    rule_ref: str

    #: Position of the file in the configured file list (0-based), so the
    #: configured order stays observable downstream.
    file_index: int = 0

    #: Final enable state. Candidates returned in ``RuleLoadResult.rules`` are
    #: always enabled; disabled rules are reported separately with ``False``.
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of the candidate."""

        return {
            "raw_text": self.raw_text,
            "source_file": self.source_file,
            "path": self.path,
            "line_number": self.line_number,
            "rule_ref": self.rule_ref,
            "file_index": self.file_index,
            "enabled": self.enabled,
        }


@dataclass(frozen=True)
class RuleLoadWarning:
    """A single diagnostic produced while loading rules."""

    code: str
    message: str
    severity: str = SEVERITY_WARNING
    source_file: str | None = None
    line_number: int | None = None
    rule_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of the diagnostic."""

        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "rule_ref": self.rule_ref,
        }

    def __str__(self) -> str:
        """Return a one-line, human readable form used for logging."""

        location = self.rule_ref or self.source_file or "-"

        return f"[{self.severity}] {self.code} ({location}): {self.message}"


@dataclass
class RuleFileSummary:
    """Per-file counters, so the loader result is auditable file by file."""

    source_file: str
    path: str
    enabled: bool = True
    loaded: bool = False
    skipped_reason: str | None = None
    error_code: str | None = None
    lines_read: int = 0
    blank_lines: int = 0
    comment_lines: int = 0
    rules_read: int = 0
    rules_disabled: int = 0
    rules_emitted: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of the file summary."""

        return {
            "source_file": self.source_file,
            "path": self.path,
            "enabled": self.enabled,
            "loaded": self.loaded,
            "skipped_reason": self.skipped_reason,
            "error_code": self.error_code,
            "lines_read": self.lines_read,
            "blank_lines": self.blank_lines,
            "comment_lines": self.comment_lines,
            "rules_read": self.rules_read,
            "rules_disabled": self.rules_disabled,
            "rules_emitted": self.rules_emitted,
        }


@dataclass
class RuleLoadStatistics:
    """Aggregate counters required by section 4.7."""

    files_configured: int = 0
    files_loaded: int = 0
    files_disabled: int = 0
    files_failed: int = 0
    files_skipped_extension: int = 0
    files_empty: int = 0
    lines_read: int = 0
    lines_skipped_blank: int = 0
    lines_skipped_comment: int = 0
    rules_read: int = 0
    rules_disabled: int = 0
    rules_emitted: int = 0
    rules_forwarded: int = 0
    rules_failed: int = 0
    warnings: int = 0
    errors: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of the statistics."""

        return {
            "files_configured": self.files_configured,
            "files_loaded": self.files_loaded,
            "files_disabled": self.files_disabled,
            "files_failed": self.files_failed,
            "files_skipped_extension": self.files_skipped_extension,
            "files_empty": self.files_empty,
            "lines_read": self.lines_read,
            "lines_skipped_blank": self.lines_skipped_blank,
            "lines_skipped_comment": self.lines_skipped_comment,
            "rules_read": self.rules_read,
            "rules_disabled": self.rules_disabled,
            "rules_emitted": self.rules_emitted,
            "rules_forwarded": self.rules_forwarded,
            "rules_failed": self.rules_failed,
            "warnings": self.warnings,
            "errors": self.errors,
        }


@dataclass
class RuleLoadResult:
    """
    Everything the Rule Loader hands to the next stage.

    ``rules`` holds the enabled candidates in configuration order (file order,
    then line order); the next stage consumes it directly::

        result = RuleLoader(config).load()
        for candidate in result.rules:
            parser_validator.parse(candidate)
    """

    rules: list[RuleSourceEntry] = field(default_factory=list)
    warnings: list[RuleLoadWarning] = field(default_factory=list)
    statistics: RuleLoadStatistics = field(default_factory=RuleLoadStatistics)
    disabled_rules: list[RuleSourceEntry] = field(default_factory=list)
    file_results: list[RuleFileSummary] = field(default_factory=list)

    @property
    def errors(self) -> list[RuleLoadWarning]:
        """Return only the diagnostics with ``error`` severity."""

        return [
            warning
            for warning in self.warnings
            if warning.severity == SEVERITY_ERROR
        ]

    @property
    def has_errors(self) -> bool:
        """Return ``True`` when at least one file or candidate failed."""

        return bool(self.errors)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of the whole load result."""

        return {
            "statistics": self.statistics.to_dict(),
            "rules": [rule.to_dict() for rule in self.rules],
            "disabled_rules": [
                rule.to_dict()
                for rule in self.disabled_rules
            ],
            "files": [
                summary.to_dict()
                for summary in self.file_results
            ],
            "warnings": [
                warning.to_dict()
                for warning in self.warnings
            ],
        }


__all__ = [
    "CODE_CANDIDATE_HANDLER_ERROR",
    "CODE_EXTENSION_NOT_ALLOWED",
    "CODE_FILE_DISABLED",
    "CODE_FILE_EMPTY",
    "CODE_FILE_ENCODING_ERROR",
    "CODE_FILE_IO_ERROR",
    "CODE_FILE_NOT_FOUND",
    "CODE_FILE_NOT_REGULAR",
    "CODE_FILE_NO_RULES",
    "CODE_FILE_UNREADABLE",
    "CODE_INVALID_CONFIG",
    "CODE_RULE_DISABLED",
    "CODE_UNKNOWN_RULE_OVERRIDE",
    "RuleFileSummary",
    "RuleLoadResult",
    "RuleLoadStatistics",
    "RuleLoadWarning",
    "RuleSourceEntry",
    "SEVERITIES",
    "SEVERITY_ERROR",
    "SEVERITY_INFO",
    "SEVERITY_WARNING",
]
