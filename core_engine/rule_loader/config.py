"""Configuration objects for the Assignment 3 Rule Loader.

The repository has no YAML dependency and no configuration-file convention yet,
so the rule loader configuration uses JSON (Python standard library only). A
configuration file looks like this::

    {
      "rule_files": [
        {"path": "web.rules",   "enabled": true},
        {"path": "dos.rules",   "enabled": false},
        {"path": "local.rules"}
      ],
      "rule_overrides": {
        "web.rules:12": false,
        "web.rules:18": {"enabled": true}
      }
    }

Rules of the schema:

* ``rule_files`` is an ordered list; each entry is a path string or an object
  with ``path`` and an optional boolean ``enabled`` (default: ``true``).
* Relative paths resolve against ``base_dir`` (default: the directory of the
  configuration file, or the current working directory for programmatic use).
* ``rule_overrides`` keys are ``rule_ref`` values (``<source_file>:<line>``),
  values are a boolean or ``{"enabled": bool}``.
* A malformed entry never aborts loading: it is recorded in ``problems`` and
  the remaining entries keep loading. Only a structurally unusable document
  (not an object, ``rule_files`` not a list, ...) raises
  :class:`RuleLoaderConfigError`.
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

#: A rule file must end with one of these suffixes to be loaded.
DEFAULT_ALLOWED_SUFFIXES: tuple[str, ...] = (".rules",)

#: ``strict`` refuses files with a different suffix; ``lenient`` loads them but
#: still records an ``EXTENSION_NOT_ALLOWED`` warning.
EXTENSION_POLICY_STRICT = "strict"
EXTENSION_POLICY_LENIENT = "lenient"

EXTENSION_POLICIES = (
    EXTENSION_POLICY_STRICT,
    EXTENSION_POLICY_LENIENT,
)

#: ``strict`` fails the whole file on invalid bytes (no silent mutation);
#: ``replace`` decodes them with U+FFFD and is documented as lossy.
ENCODING_STRICT = "strict"
ENCODING_REPLACE = "replace"

ENCODING_ERROR_POLICIES = (
    ENCODING_STRICT,
    ENCODING_REPLACE,
)

DEFAULT_ENCODING = "utf-8"


class RuleLoaderConfigError(ValueError):
    """Raised when a rule loader configuration cannot be used at all."""


@dataclass(frozen=True)
class RuleFileConfig:
    """One configured rule file and its enable state."""

    path: str
    enabled: bool = True


def normalize_rule_ref(rule_ref: str) -> str:
    """
    Normalize a ``rule_ref`` (``<source_file>:<line>``) for comparison.

    The line suffix is preserved; only redundant separators, a leading ``./``
    and backslashes are cleaned up so a selector keeps matching even when the
    operator writes the path slightly differently.
    """

    if not isinstance(rule_ref, str):

        raise TypeError(
            "rule_ref must be a string, got "
            f"{type(rule_ref).__name__}"
        )

    text = rule_ref.strip().replace("\\", "/")

    while text.startswith("./"):

        text = text[2:]

    if not text or text == ".":

        raise ValueError("rule_ref must not be empty")

    return os.path.normpath(text).replace("\\", "/")


def coerce_rule_file(value: Any) -> RuleFileConfig:
    """
    Coerce a configured rule file entry into :class:`RuleFileConfig`.

    Accepts a path string, a :class:`RuleFileConfig` or a mapping with
    ``path`` and optional ``enabled``. Raises ``ValueError`` with a readable
    reason for anything else.
    """

    if isinstance(value, RuleFileConfig):

        return value

    if isinstance(value, (str, Path)):

        text = str(value).strip()

        if not text:

            raise ValueError("rule file path must not be empty")

        return RuleFileConfig(path=text)

    if isinstance(value, Mapping):

        unknown = set(value) - {"path", "enabled"}

        if unknown:

            raise ValueError(
                "unknown rule file key(s) "
                f"{sorted(unknown)}, expected 'path' and 'enabled'"
            )

        path = value.get("path")

        if not isinstance(path, str) or not path.strip():

            raise ValueError(
                "'path' must be a non-empty string, got "
                f"{type(path).__name__}"
            )

        enabled = value.get("enabled", True)

        if not isinstance(enabled, bool):

            raise ValueError(
                f"'enabled' must be a boolean, got {type(enabled).__name__}"
            )

        return RuleFileConfig(
            path=path.strip(),
            enabled=enabled,
        )

    raise ValueError(
        "rule file entry must be a path string or an object with 'path', got "
        f"{type(value).__name__}"
    )


@dataclass
class RuleLoaderConfig:
    """
    Configuration for :class:`core_engine.rule_loader.loader.RuleLoader`.

    Defaults are explicit: a configured file is **enabled** unless it says
    ``"enabled": false``, and a rule is **enabled** unless a ``rule_overrides``
    entry disables it. ``problems`` collects entry-level configuration errors
    so loading can continue with the remaining entries.
    """

    rule_files: list[Any] = field(default_factory=list)
    rule_overrides: dict[str, Any] = field(default_factory=dict)
    base_dir: Path | None = None
    encoding: str = DEFAULT_ENCODING
    encoding_errors: str = ENCODING_STRICT
    allowed_suffixes: tuple[str, ...] = DEFAULT_ALLOWED_SUFFIXES
    extension_policy: str = EXTENSION_POLICY_STRICT
    problems: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:

        if self.extension_policy not in EXTENSION_POLICIES:

            raise ValueError(
                "extension_policy must be one of "
                f"{EXTENSION_POLICIES}, got {self.extension_policy!r}"
            )

        if self.encoding_errors not in ENCODING_ERROR_POLICIES:

            raise ValueError(
                "encoding_errors must be one of "
                f"{ENCODING_ERROR_POLICIES}, got {self.encoding_errors!r}"
            )

        if not isinstance(self.encoding, str) or not self.encoding.strip():

            raise ValueError("encoding must be a non-empty string")

        self.allowed_suffixes = tuple(
            suffix.lower() if suffix.startswith(".")
            else f".{suffix.lower()}"
            for suffix in self.allowed_suffixes
        )

        self.rule_files = self._coerce_rule_files()
        self.rule_overrides = self._normalize_overrides()

    def _coerce_rule_files(self) -> list[RuleFileConfig]:
        """Coerce every entry, recording (not raising) invalid ones."""

        entries = list(self.rule_files)
        coerced: list[RuleFileConfig] = []

        for index, entry in enumerate(entries):

            try:

                coerced.append(coerce_rule_file(entry))

            except (TypeError, ValueError) as exc:

                self.problems.append(
                    f"rule_files[{index}]: {exc}"
                )

        return coerced

    def _normalize_overrides(self) -> dict[str, bool]:
        """Normalize selector keys and coerce values to booleans."""

        normalized: dict[str, bool] = {}

        for key, value in dict(self.rule_overrides).items():

            try:

                ref = normalize_rule_ref(key)

            except (TypeError, ValueError) as exc:

                self.problems.append(
                    f"rule_overrides[{key!r}]: {exc}"
                )

                continue

            enabled = value

            if isinstance(value, Mapping):

                enabled = value.get("enabled", True)

            if not isinstance(enabled, bool):

                self.problems.append(
                    f"rule_overrides[{ref!r}]: value must be a boolean "
                    "or {\"enabled\": bool}, got "
                    f"{type(value).__name__}"
                )

                continue

            if ref in normalized and normalized[ref] != enabled:

                # Documented precedence: a disabled entry always wins, so a
                # duplicate selector can never silently re-enable a rule.
                self.problems.append(
                    f"rule_overrides[{ref!r}]: conflicting values, "
                    "keeping the disabled state"
                )

                enabled = False

            normalized[ref] = enabled

        return normalized

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        base_dir: str | Path | None = None,
    ) -> "RuleLoaderConfig":
        """
        Build a configuration from a mapping (for example parsed JSON).

        Raises :class:`RuleLoaderConfigError` only when the document is
        structurally unusable; individual bad entries become ``problems``.
        """

        if not isinstance(data, Mapping):

            raise RuleLoaderConfigError(
                "rule loader configuration must be a JSON object/mapping, got "
                f"{type(data).__name__}"
            )

        problems: list[str] = []

        for key in sorted(set(data) - {"rule_files", "rule_overrides"}):

            problems.append(
                f"unknown configuration key {key!r} "
                "(expected 'rule_files' and/or 'rule_overrides')"
            )

        rule_files = data.get("rule_files", [])

        if not isinstance(rule_files, (list, tuple)):

            raise RuleLoaderConfigError(
                "'rule_files' must be a list, got "
                f"{type(rule_files).__name__}"
            )

        rule_overrides = data.get("rule_overrides", {})

        if not isinstance(rule_overrides, Mapping):

            raise RuleLoaderConfigError(
                "'rule_overrides' must be an object/mapping, got "
                f"{type(rule_overrides).__name__}"
            )

        config = cls(
            rule_files=list(rule_files),
            rule_overrides=dict(rule_overrides),
            base_dir=Path(base_dir) if base_dir is not None else None,
        )

        # Keep document-level problems first, before per-entry problems.
        config.problems[:0] = problems

        return config

    @classmethod
    def from_json_file(
        cls,
        path: str | Path,
        *,
        base_dir: str | Path | None = None,
    ) -> "RuleLoaderConfig":
        """
        Read a JSON configuration file.

        ``base_dir`` defaults to the directory holding the configuration file,
        which keeps relative rule paths independent of the current working
        directory.
        """

        config_path = Path(path).expanduser()

        try:

            text = config_path.read_text(encoding="utf-8")

        except FileNotFoundError as exc:

            raise RuleLoaderConfigError(
                f"rule loader configuration file not found: {config_path}"
            ) from exc

        except IsADirectoryError as exc:

            raise RuleLoaderConfigError(
                "rule loader configuration path is a directory, not a file: "
                f"{config_path}"
            ) from exc

        except OSError as exc:

            raise RuleLoaderConfigError(
                f"cannot read rule loader configuration {config_path}: {exc}"
            ) from exc

        try:

            data = json.loads(text)

        except json.JSONDecodeError as exc:

            raise RuleLoaderConfigError(
                f"invalid JSON in rule loader configuration {config_path}: "
                f"line {exc.lineno} column {exc.colno}: {exc.msg}"
            ) from exc

        resolved_base = (
            Path(base_dir)
            if base_dir is not None
            else config_path.parent
        )

        return cls.from_mapping(data, base_dir=resolved_base)


__all__ = [
    "DEFAULT_ALLOWED_SUFFIXES",
    "DEFAULT_ENCODING",
    "ENCODING_ERROR_POLICIES",
    "ENCODING_REPLACE",
    "ENCODING_STRICT",
    "EXTENSION_POLICIES",
    "EXTENSION_POLICY_LENIENT",
    "EXTENSION_POLICY_STRICT",
    "RuleFileConfig",
    "RuleLoaderConfig",
    "RuleLoaderConfigError",
    "coerce_rule_file",
    "normalize_rule_ref",
]
