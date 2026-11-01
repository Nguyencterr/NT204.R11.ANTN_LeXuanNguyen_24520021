"""Assignment 3 Rule Loader package (section 4.1).

Public surface::

    from core_engine.rule_loader import RuleLoader, RuleLoaderConfig

    result = RuleLoader(RuleLoaderConfig.from_json_file("rules/rule_loader.json")).load()

    for candidate in result.rules:
        ...  # section 4.2 Rule Parser & Validator
"""

from .config import (
    DEFAULT_ALLOWED_SUFFIXES,
    DEFAULT_ENCODING,
    ENCODING_REPLACE,
    ENCODING_STRICT,
    EXTENSION_POLICY_LENIENT,
    EXTENSION_POLICY_STRICT,
    RuleFileConfig,
    RuleLoaderConfig,
    RuleLoaderConfigError,
    coerce_rule_file,
    normalize_rule_ref,
)
from .loader import RuleCandidateHandler, RuleLoader
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

__all__ = [
    "RuleLoader",
    "RuleCandidateHandler",
    "RuleLoaderConfig",
    "RuleLoaderConfigError",
    "RuleFileConfig",
    "coerce_rule_file",
    "normalize_rule_ref",
    "RuleSourceEntry",
    "RuleLoadResult",
    "RuleLoadStatistics",
    "RuleLoadWarning",
    "RuleFileSummary",
    "DEFAULT_ALLOWED_SUFFIXES",
    "DEFAULT_ENCODING",
    "ENCODING_REPLACE",
    "ENCODING_STRICT",
    "EXTENSION_POLICY_LENIENT",
    "EXTENSION_POLICY_STRICT",
    "SEVERITY_INFO",
    "SEVERITY_WARNING",
    "SEVERITY_ERROR",
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
]
