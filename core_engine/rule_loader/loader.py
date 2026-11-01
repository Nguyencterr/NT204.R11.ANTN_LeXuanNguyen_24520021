"""Assignment 3 Rule Loader (section 4.1).

The loader is the entry point of the Core Engine. It reads one or more
``.rules`` files, drops blank lines and comment lines, and hands the remaining
lines to the next stage as :class:`RuleSourceEntry` candidates.

The loader deliberately does **not** interpret Snort syntax: it never extracts
SID/msg/content and never labels a line valid/invalid/unsupported. That is the
job of the Rule Parser & Validator (section 4.2).

Error isolation is the central rule of this module. A broken file, a malformed
configuration entry or a failing candidate handler only produces a diagnostic;
every other file and rule keeps being processed.
"""

import logging
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from .config import (
    EXTENSION_POLICY_LENIENT,
    RuleFileConfig,
    RuleLoaderConfig,
    coerce_rule_file,
)
from .models import (
    CODE_CANDIDATE_HANDLER_ERROR,
    CODE_EXTENSION_NOT_ALLOWED,
    CODE_FILE_DISABLED,
    CODE_FILE_EMPTY,
    CODE_FILE_ENCODING_ERROR,
    CODE_FILE_IO_ERROR,
    CODE_FILE_NOT_FOUND,
    CODE_FILE_NOT_REGULAR,
    CODE_FILE_NO_RULES,
    CODE_FILE_UNREADABLE,
    CODE_INVALID_CONFIG,
    CODE_RULE_DISABLED,
    CODE_UNKNOWN_RULE_OVERRIDE,
    SEVERITY_ERROR,
    SEVERITY_INFO,
    SEVERITY_WARNING,
    RuleFileSummary,
    RuleLoadResult,
    RuleLoadStatistics,
    RuleLoadWarning,
    RuleSourceEntry,
)


#: Optional callback that receives every enabled candidate. Section 4.2 will
#: pass ``RuleParserValidator.parse`` here (or iterate ``result.rules``).
RuleCandidateHandler = Callable[[RuleSourceEntry], None]


@dataclass
class _ReadOutcome:
    """Internal result of reading a single file."""

    entries: list[RuleSourceEntry] = field(default_factory=list)
    lines_read: int = 0
    blank_lines: int = 0
    comment_lines: int = 0
    error_code: str | None = None
    error_message: str | None = None


class RuleLoader:
    """
    Load rule candidates from configured ``.rules`` files.

    Configuration can be given once (``RuleLoader(config)``) or per call
    (``loader.load(config=...)``); the call argument wins.
    """

    def __init__(
        self,
        config: RuleLoaderConfig | None = None,
        logger: logging.Logger | None = None,
    ) -> None:

        self.config = config if config is not None else RuleLoaderConfig()

        self.logger = (
            logger
            if logger is not None
            else logging.getLogger(__name__)
        )

    # -- public API ---------------------------------------------------------

    def load(
        self,
        rule_files: Any = None,
        config: RuleLoaderConfig | None = None,
        handler: RuleCandidateHandler | None = None,
    ) -> RuleLoadResult:
        """
        Load rule candidates.

        ``rule_files`` (a path, a :class:`RuleFileConfig`, a mapping or an
        iterable of them) overrides ``config.rule_files`` when given.
        ``handler`` is called once per enabled candidate; an exception raised
        by the handler is isolated to that candidate.
        """

        active = config if config is not None else self.config

        warnings: list[RuleLoadWarning] = []
        statistics = RuleLoadStatistics()
        candidates: list[RuleSourceEntry] = []
        disabled: list[RuleSourceEntry] = []
        file_results: list[RuleFileSummary] = []
        matched_overrides: set[str] = set()

        for problem in active.problems:

            self._diagnose(warnings, CODE_INVALID_CONFIG, problem)

        base_dir = self._resolve_base_dir(active)

        files, problems = self._configured_files(rule_files, active)

        for problem in problems:

            self._diagnose(warnings, CODE_INVALID_CONFIG, problem)

        statistics.files_configured = len(files)

        overrides = active.rule_overrides

        for index, file_config in enumerate(files):

            display, absolute = self._paths(file_config.path, base_dir)

            summary = RuleFileSummary(
                source_file=display,
                path=absolute.as_posix(),
                enabled=file_config.enabled,
            )

            file_results.append(summary)

            if not file_config.enabled:

                # A disabled file is never read, so a per-rule override can
                # never re-enable a rule inside it (see README).
                statistics.files_disabled += 1
                summary.skipped_reason = "disabled"

                self._diagnose(
                    warnings,
                    CODE_FILE_DISABLED,
                    f"rule file disabled by configuration: {display}",
                    severity=SEVERITY_INFO,
                    source_file=display,
                )

                continue

            if not self._extension_allowed(absolute, active):

                message = (
                    "rule file does not use an allowed extension "
                    f"{list(active.allowed_suffixes)}: {display} "
                    f"(extension_policy={active.extension_policy})"
                )

                if active.extension_policy == EXTENSION_POLICY_LENIENT:

                    self._diagnose(
                        warnings,
                        CODE_EXTENSION_NOT_ALLOWED,
                        f"{message}; loading it anyway (lenient policy)",
                        source_file=display,
                    )

                else:

                    statistics.files_skipped_extension += 1
                    summary.skipped_reason = "extension"

                    self._diagnose(
                        warnings,
                        CODE_EXTENSION_NOT_ALLOWED,
                        f"{message}; skipping file (strict policy)",
                        source_file=display,
                    )

                    continue

            outcome = self._read_file(absolute, display, index, active)

            statistics.lines_read += outcome.lines_read

            summary.lines_read = outcome.lines_read
            summary.blank_lines = outcome.blank_lines
            summary.comment_lines = outcome.comment_lines

            if outcome.error_code is not None:

                # The file failed as a whole: candidates read before the
                # failure are discarded so no partially decoded rule leaks out.
                statistics.files_failed += 1
                summary.error_code = outcome.error_code

                self._diagnose(
                    warnings,
                    outcome.error_code,
                    outcome.error_message or "cannot read rule file",
                    severity=SEVERITY_ERROR,
                    source_file=display,
                )

                continue

            statistics.files_loaded += 1
            summary.loaded = True

            statistics.lines_skipped_blank += outcome.blank_lines
            statistics.lines_skipped_comment += outcome.comment_lines
            statistics.rules_read += len(outcome.entries)
            summary.rules_read = len(outcome.entries)

            if not outcome.entries:

                statistics.files_empty += 1

                if outcome.lines_read == 0:

                    code = CODE_FILE_EMPTY
                    message = f"rule file is empty: {display}"

                else:

                    code = CODE_FILE_NO_RULES
                    message = (
                        f"rule file contains no rule candidate "
                        f"({outcome.lines_read} line(s), all blank or "
                        f"comments): {display}"
                    )

                self._diagnose(
                    warnings,
                    code,
                    message,
                    severity=SEVERITY_INFO,
                    source_file=display,
                )

            for entry in outcome.entries:

                if entry.rule_ref in overrides:

                    matched_overrides.add(entry.rule_ref)

                    if not overrides[entry.rule_ref]:

                        statistics.rules_disabled += 1
                        summary.rules_disabled += 1

                        disabled.append(
                            replace(entry, enabled=False)
                        )

                        self._diagnose(
                            warnings,
                            CODE_RULE_DISABLED,
                            "rule disabled by rule_overrides",
                            severity=SEVERITY_INFO,
                            source_file=entry.source_file,
                            line_number=entry.line_number,
                            rule_ref=entry.rule_ref,
                        )

                        continue

                candidates.append(entry)
                summary.rules_emitted += 1

        for rule_ref in sorted(set(overrides) - matched_overrides):

            self._diagnose(
                warnings,
                CODE_UNKNOWN_RULE_OVERRIDE,
                "rule override does not match any loaded rule: "
                f"{rule_ref}",
                rule_ref=rule_ref,
            )

        statistics.rules_emitted = len(candidates)

        if handler is not None:

            self._forward(candidates, handler, warnings, statistics)

        statistics.warnings = sum(
            1
            for warning in warnings
            if warning.severity == SEVERITY_WARNING
        )

        statistics.errors = sum(
            1
            for warning in warnings
            if warning.severity == SEVERITY_ERROR
        )

        result = RuleLoadResult(
            rules=candidates,
            warnings=warnings,
            statistics=statistics,
            disabled_rules=disabled,
            file_results=file_results,
        )

        self.logger.info(
            "rule loader finished: %s",
            self._summary(statistics),
        )

        return result

    # -- configuration ------------------------------------------------------

    def _configured_files(
        self,
        rule_files: Any,
        config: RuleLoaderConfig,
    ) -> tuple[list[RuleFileConfig], list[str]]:
        """Return the ordered file list plus per-entry configuration problems."""

        if rule_files is None:

            return list(config.rule_files), []

        if isinstance(rule_files, (str, Path, RuleFileConfig)):

            items: list[Any] = [rule_files]

        else:

            try:

                items = list(rule_files)

            except TypeError:

                return [], [
                    "rule_files must be a path, a RuleFileConfig or an "
                    "iterable of them, got "
                    f"{type(rule_files).__name__}"
                ]

        files: list[RuleFileConfig] = []
        problems: list[str] = []

        for index, item in enumerate(items):

            try:

                files.append(coerce_rule_file(item))

            except (TypeError, ValueError) as exc:

                problems.append(f"rule_files[{index}]: {exc}")

        return files, problems

    @staticmethod
    def _resolve_base_dir(config: RuleLoaderConfig) -> Path:
        """Resolve ``base_dir`` once so results never depend on late chdir()."""

        if config.base_dir is None:

            return Path(os.path.abspath(Path.cwd()))

        return Path(os.path.abspath(Path(config.base_dir).expanduser()))

    @staticmethod
    def _paths(
        raw_path: str,
        base_dir: Path,
    ) -> tuple[str, Path]:
        """
        Return ``(display_path, absolute_path)`` for a configured file.

        ``display_path`` is repository/config relative when possible, so the
        derived ``rule_ref`` stays stable across working directories.
        """

        candidate = Path(raw_path).expanduser()

        if not candidate.is_absolute():

            candidate = base_dir / candidate

        absolute = Path(os.path.abspath(candidate))

        try:

            relative = os.path.relpath(absolute, base_dir)

        except ValueError:  # pragma: no cover - different drives on Windows

            return absolute.as_posix(), absolute

        if relative == os.pardir or relative.startswith(
            os.pardir + os.sep
        ):

            return absolute.as_posix(), absolute

        return Path(relative).as_posix(), absolute

    @staticmethod
    def _extension_allowed(path: Path, config: RuleLoaderConfig) -> bool:

        return path.suffix.lower() in config.allowed_suffixes

    # -- file reading -------------------------------------------------------

    def _read_file(
        self,
        absolute: Path,
        display: str,
        file_index: int,
        config: RuleLoaderConfig,
    ) -> _ReadOutcome:
        """
        Read one file into candidates.

        Comment detection only looks at the first non-whitespace character, so
        a ``#`` inside a rule body is preserved verbatim.
        """

        outcome = _ReadOutcome()

        try:

            handle = absolute.open(
                "r",
                encoding=config.encoding,
                errors=config.encoding_errors,
            )

        except FileNotFoundError:

            outcome.error_code = CODE_FILE_NOT_FOUND
            outcome.error_message = f"rule file not found: {display}"

            return outcome

        except IsADirectoryError:

            outcome.error_code = CODE_FILE_NOT_REGULAR
            outcome.error_message = (
                f"rule file path is a directory, not a regular file: {display}"
            )

            return outcome

        except PermissionError:

            outcome.error_code = CODE_FILE_UNREADABLE
            outcome.error_message = f"permission denied reading rule file: {display}"

            return outcome

        except OSError as exc:

            outcome.error_code = CODE_FILE_IO_ERROR
            outcome.error_message = f"cannot open rule file {display}: {exc}"

            return outcome

        try:

            with handle:

                for line_number, line in enumerate(handle, start=1):

                    outcome.lines_read += 1

                    # Only the line terminator is removed: the rule text itself
                    # is never rewritten.
                    text = line.rstrip("\r\n")

                    if not text.strip():

                        outcome.blank_lines += 1

                        continue

                    if text.lstrip().startswith("#"):

                        outcome.comment_lines += 1

                        continue

                    outcome.entries.append(
                        RuleSourceEntry(
                            raw_text=text,
                            source_file=display,
                            path=absolute.as_posix(),
                            line_number=line_number,
                            rule_ref=f"{display}:{line_number}",
                            file_index=file_index,
                        )
                    )

        except UnicodeDecodeError as exc:

            return _ReadOutcome(
                lines_read=outcome.lines_read,
                blank_lines=outcome.blank_lines,
                comment_lines=outcome.comment_lines,
                error_code=CODE_FILE_ENCODING_ERROR,
                error_message=(
                    f"cannot decode rule file {display} as "
                    f"{config.encoding} (encoding_errors="
                    f"{config.encoding_errors}): {exc.reason} at byte "
                    f"{exc.start} of the failing line; file skipped"
                ),
            )

        except OSError as exc:

            return _ReadOutcome(
                lines_read=outcome.lines_read,
                blank_lines=outcome.blank_lines,
                comment_lines=outcome.comment_lines,
                error_code=CODE_FILE_IO_ERROR,
                error_message=f"error reading rule file {display}: {exc}",
            )

        return outcome

    # -- candidate forwarding ----------------------------------------------

    def _forward(
        self,
        candidates: list[RuleSourceEntry],
        handler: RuleCandidateHandler,
        warnings: list[RuleLoadWarning],
        statistics: RuleLoadStatistics,
    ) -> None:
        """Hand each candidate to ``handler``, isolating per-candidate errors."""

        for entry in candidates:

            try:

                handler(entry)

            except Exception as exc:  # noqa: BLE001 - one bad rule must not stop the rest

                statistics.rules_failed += 1

                self._diagnose(
                    warnings,
                    CODE_CANDIDATE_HANDLER_ERROR,
                    "candidate handler failed for "
                    f"{entry.rule_ref}: {type(exc).__name__}: {exc}",
                    severity=SEVERITY_ERROR,
                    source_file=entry.source_file,
                    line_number=entry.line_number,
                    rule_ref=entry.rule_ref,
                )

            else:

                statistics.rules_forwarded += 1

    # -- diagnostics --------------------------------------------------------

    def _diagnose(
        self,
        warnings: list[RuleLoadWarning],
        code: str,
        message: str,
        severity: str = SEVERITY_WARNING,
        source_file: str | None = None,
        line_number: int | None = None,
        rule_ref: str | None = None,
    ) -> RuleLoadWarning:
        """Record a diagnostic and mirror it to the module logger."""

        warning = RuleLoadWarning(
            code=code,
            message=message,
            severity=severity,
            source_file=source_file,
            line_number=line_number,
            rule_ref=rule_ref,
        )

        warnings.append(warning)

        if severity == SEVERITY_ERROR:

            self.logger.error("%s", warning)

        elif severity == SEVERITY_WARNING:

            self.logger.warning("%s", warning)

        else:

            self.logger.info("%s", warning)

        return warning

    @staticmethod
    def _summary(statistics: RuleLoadStatistics) -> str:

        return (
            f"{statistics.files_loaded}/{statistics.files_configured} "
            f"file(s) loaded, {statistics.files_disabled} disabled, "
            f"{statistics.files_failed} failed, "
            f"{statistics.rules_emitted} candidate(s) emitted, "
            f"{statistics.rules_disabled} disabled"
        )


__all__ = [
    "RuleCandidateHandler",
    "RuleLoader",
]
