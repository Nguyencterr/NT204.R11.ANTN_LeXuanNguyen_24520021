"""Assignment 3 Rule Loader tests (RL01-RL14, section 4.1).

The loader only loads rule text and manages rule sources. These tests never
assert anything about Snort syntax: syntax belongs to the Rule Parser &
Validator (section 4.2), which is not implemented yet.

Run with::

    python -m unittest tests.test_rule_loader -v
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from core_engine.rule_loader import (
    CODE_CANDIDATE_HANDLER_ERROR,
    CODE_EXTENSION_NOT_ALLOWED,
    CODE_FILE_DISABLED,
    CODE_FILE_EMPTY,
    CODE_FILE_ENCODING_ERROR,
    CODE_FILE_NOT_FOUND,
    CODE_FILE_NOT_REGULAR,
    CODE_FILE_NO_RULES,
    CODE_FILE_UNREADABLE,
    CODE_INVALID_CONFIG,
    CODE_RULE_DISABLED,
    CODE_UNKNOWN_RULE_OVERRIDE,
    SEVERITY_ERROR,
    RuleLoader,
    RuleLoaderConfig,
    RuleLoaderConfigError,
)


REPO_ROOT = Path(__file__).resolve().parents[1]

FIXTURES = REPO_ROOT / "TEST" / "BT3" / "rule_loader" / "fixtures"

SHIPPED_CONFIG = REPO_ROOT / "rules" / "rule_loader.json"


def load(
    rule_files,
    *,
    overrides=None,
    base_dir=FIXTURES,
    handler=None,
    **config_options,
):
    """Build a config and run one load, the way section 4.2 will call it."""

    config = RuleLoaderConfig(
        rule_files=list(rule_files),
        rule_overrides=dict(overrides or {}),
        base_dir=base_dir,
        **config_options,
    )

    return RuleLoader(config).load(handler=handler)


def refs(result) -> list[str]:
    """Return the rule_ref of every emitted candidate, in order."""

    return [rule.rule_ref for rule in result.rules]


def codes(result) -> list[str]:
    """Return the diagnostic codes of a load result, in order."""

    return [warning.code for warning in result.warnings]


def warnings_for(result, code):
    """Return the diagnostics of a load result that use ``code``."""

    return [
        warning
        for warning in result.warnings
        if warning.code == code
    ]


class RuleFileParsingTestCase(unittest.TestCase):
    """RL01 - rule candidates, comments and blank lines."""

    def test_comments_and_blank_lines_are_skipped(self):

        result = load(["web.rules"])

        self.assertEqual(
            refs(result),
            [
                "web.rules:4",
                "web.rules:6",
                "web.rules:8",
            ],
        )

        self.assertEqual(result.statistics.files_loaded, 1)
        self.assertEqual(result.statistics.lines_read, 8)
        self.assertEqual(result.statistics.lines_skipped_blank, 2)
        self.assertEqual(result.statistics.lines_skipped_comment, 3)
        self.assertEqual(result.statistics.rules_read, 3)
        self.assertEqual(result.statistics.rules_emitted, 3)
        self.assertEqual(result.statistics.rules_forwarded, 0)
        self.assertFalse(result.has_errors)

        first = result.rules[0]

        self.assertEqual(
            first.raw_text,
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
            '(msg:"RL01 web rule one"; content:"GET /index.html"; '
            "sid:1000001; rev:1;)",
        )
        self.assertEqual(first.source_file, "web.rules")
        self.assertEqual(first.line_number, 4)
        self.assertEqual(
            first.path,
            (FIXTURES / "web.rules").as_posix(),
        )
        self.assertEqual(first.file_index, 0)
        self.assertTrue(first.enabled)

    def test_raw_text_is_not_rewritten(self):

        # Only the line terminator may be removed: trailing spaces and a CRLF
        # line ending must not change the rule text itself.
        with tempfile.TemporaryDirectory() as tmp:

            fixture = Path(tmp) / "keep_raw.rules"
            fixture.write_bytes(
                b'alert tcp any any -> any 80 (msg:"keep"; sid:1;)   \r\n'
            )

            result = load(["keep_raw.rules"], base_dir=tmp)

        self.assertEqual(len(result.rules), 1)
        self.assertEqual(
            result.rules[0].raw_text,
            'alert tcp any any -> any 80 (msg:"keep"; sid:1;)   ',
        )
        self.assertNotIn("\r", result.rules[0].raw_text)

    def test_result_is_json_serializable(self):

        result = load(["web.rules", "local.rules"])

        decoded = json.loads(json.dumps(result.to_dict()))

        self.assertEqual(len(decoded["rules"]), 6)
        self.assertEqual(
            decoded["rules"][0]["rule_ref"],
            "web.rules:4",
        )
        self.assertEqual(
            decoded["statistics"]["files_loaded"],
            2,
        )
        self.assertEqual(
            decoded["statistics"]["rules_emitted"],
            6,
        )
        self.assertEqual(len(decoded["files"]), 2)


class MultiFileTestCase(unittest.TestCase):
    """RL02 - several files, order preserved, metadata not mixed."""

    def test_files_and_rules_keep_configured_order(self):

        result = load(["web.rules", "local.rules"])

        self.assertEqual(
            refs(result),
            [
                "web.rules:4",
                "web.rules:6",
                "web.rules:8",
                "local.rules:4",
                "local.rules:6",
                "local.rules:7",
            ],
        )
        self.assertEqual(
            [rule.file_index for rule in result.rules],
            [0, 0, 0, 1, 1, 1],
        )
        self.assertEqual(
            [rule.source_file for rule in result.rules],
            ["web.rules"] * 3 + ["local.rules"] * 3,
        )
        self.assertEqual(result.statistics.files_configured, 2)
        self.assertEqual(result.statistics.files_loaded, 2)
        self.assertEqual(result.statistics.rules_read, 6)

    def test_file_order_follows_configuration(self):

        result = load(["local.rules", "web.rules"])

        self.assertEqual(refs(result)[0], "local.rules:4")
        self.assertEqual(refs(result)[3], "web.rules:4")
        self.assertEqual(result.rules[0].file_index, 0)
        self.assertEqual(result.rules[3].file_index, 1)


class RuleFileEnableTestCase(unittest.TestCase):
    """RL03 - a disabled file is never read."""

    def test_disabled_file_produces_no_candidate(self):

        result = load(
            [
                {"path": "web.rules", "enabled": True},
                {"path": "local.rules", "enabled": False},
            ]
        )

        self.assertEqual(
            refs(result),
            ["web.rules:4", "web.rules:6", "web.rules:8"],
        )
        self.assertEqual(result.statistics.files_configured, 2)
        self.assertEqual(result.statistics.files_disabled, 1)
        self.assertEqual(result.statistics.files_loaded, 1)

        summary = result.file_results[1]

        self.assertEqual(summary.source_file, "local.rules")
        self.assertFalse(summary.enabled)
        self.assertFalse(summary.loaded)
        self.assertEqual(summary.skipped_reason, "disabled")
        self.assertEqual(summary.rules_read, 0)

        warning = warnings_for(result, CODE_FILE_DISABLED)[0]

        self.assertEqual(warning.source_file, "local.rules")
        self.assertEqual(warning.severity, "info")

    def test_enabled_file_is_the_documented_default(self):

        result = load(["web.rules"])

        self.assertEqual(result.statistics.files_disabled, 0)
        self.assertTrue(result.file_results[0].enabled)


class PerRuleEnableTestCase(unittest.TestCase):
    """RL04 - one rule can be disabled without touching the others."""

    def test_single_rule_can_be_disabled(self):

        result = load(
            ["local.rules"],
            overrides={"local.rules:6": False},
        )

        self.assertEqual(
            refs(result),
            ["local.rules:4", "local.rules:7"],
        )
        self.assertEqual(result.statistics.rules_read, 3)
        self.assertEqual(result.statistics.rules_disabled, 1)
        self.assertEqual(result.statistics.rules_emitted, 2)

        self.assertEqual(
            [rule.rule_ref for rule in result.disabled_rules],
            ["local.rules:6"],
        )
        self.assertFalse(result.disabled_rules[0].enabled)

        warning = warnings_for(result, CODE_RULE_DISABLED)[0]

        self.assertEqual(warning.rule_ref, "local.rules:6")
        self.assertEqual(warning.line_number, 6)
        self.assertEqual(warning.severity, "info")

    def test_explicit_enable_keeps_the_rule(self):

        result = load(
            ["local.rules"],
            overrides={"local.rules:6": True},
        )

        self.assertEqual(len(result.rules), 3)
        self.assertEqual(result.statistics.rules_disabled, 0)
        self.assertEqual(
            warnings_for(result, CODE_UNKNOWN_RULE_OVERRIDE),
            [],
        )

    def test_config_file_controls_files_and_rules(self):

        with tempfile.TemporaryDirectory() as tmp:

            config_path = Path(tmp) / "loader.json"
            config_path.write_text(
                json.dumps(
                    {
                        "rule_files": [
                            {"path": "web.rules"},
                            {"path": "local.rules", "enabled": False},
                        ],
                        "rule_overrides": {
                            "web.rules:6": {"enabled": False},
                        },
                    }
                ),
                encoding="utf-8",
            )

            config = RuleLoaderConfig.from_json_file(
                config_path,
                base_dir=FIXTURES,
            )

        self.assertEqual(config.problems, [])

        result = RuleLoader(config).load()

        self.assertEqual(
            refs(result),
            ["web.rules:4", "web.rules:8"],
        )
        self.assertEqual(result.statistics.files_disabled, 1)
        self.assertEqual(result.statistics.rules_disabled, 1)


class EmptyFileTestCase(unittest.TestCase):
    """RL08 - empty and comment-only files are not errors."""

    def test_empty_file_returns_no_candidate(self):

        result = load(["empty.rules"])

        self.assertEqual(result.rules, [])
        self.assertEqual(result.statistics.files_loaded, 1)
        self.assertEqual(result.statistics.files_empty, 1)
        self.assertEqual(result.statistics.lines_read, 0)
        self.assertFalse(result.has_errors)
        self.assertIn(CODE_FILE_EMPTY, codes(result))

    def test_comment_only_file_returns_no_candidate(self):

        result = load(["comments_only.rules"])

        self.assertEqual(result.rules, [])
        self.assertEqual(result.statistics.lines_read, 3)
        self.assertEqual(result.statistics.lines_skipped_comment, 3)
        self.assertEqual(result.statistics.lines_skipped_blank, 0)
        self.assertFalse(result.has_errors)
        self.assertIn(CODE_FILE_NO_RULES, codes(result))


class CommentDetectionTestCase(unittest.TestCase):
    """RL09/RL10 - comment detection and '#' preservation."""

    def test_comment_with_leading_whitespace_is_skipped(self):

        result = load(["web.rules"])

        self.assertNotIn("web.rules:5", refs(result))
        self.assertEqual(result.statistics.lines_skipped_comment, 3)

    def test_hash_inside_rule_body_is_preserved(self):

        result = load(["hash_in_content.rules"])

        self.assertEqual(
            refs(result),
            [
                "hash_in_content.rules:2",
                "hash_in_content.rules:3",
            ],
        )
        self.assertEqual(
            result.rules[0].raw_text,
            'alert tcp any any -> any 80 (msg:"hash # in message"; '
            'content:"a#b"; sid:3000001; rev:1;)',
        )
        self.assertIn("#", result.rules[0].raw_text)
        self.assertIn("2024#1", result.rules[1].raw_text)
        self.assertTrue(
            result.rules[1].raw_text.endswith("sid:3000002; rev:1;)")
        )


class RulePathTestCase(unittest.TestCase):
    """RL11 - relative paths and stable rule_ref values."""

    def test_relative_path_resolves_against_base_dir(self):

        result = load(
            ["TEST/BT3/rule_loader/fixtures/web.rules"],
            base_dir=REPO_ROOT,
        )

        self.assertEqual(
            refs(result),
            [
                "TEST/BT3/rule_loader/fixtures/web.rules:4",
                "TEST/BT3/rule_loader/fixtures/web.rules:6",
                "TEST/BT3/rule_loader/fixtures/web.rules:8",
            ],
        )
        self.assertEqual(
            result.rules[0].path,
            (FIXTURES / "web.rules").as_posix(),
        )

    def test_rule_ref_does_not_depend_on_working_directory(self):

        expected = refs(
            load(
                ["TEST/BT3/rule_loader/fixtures/web.rules"],
                base_dir=REPO_ROOT,
            )
        )

        original = Path.cwd()

        with tempfile.TemporaryDirectory() as tmp:

            os.chdir(tmp)

            try:

                result = load(
                    ["TEST/BT3/rule_loader/fixtures/web.rules"],
                    base_dir=REPO_ROOT,
                )

            finally:

                os.chdir(original)

        self.assertEqual(refs(result), expected)
        self.assertEqual(
            result.rules[0].path,
            (FIXTURES / "web.rules").as_posix(),
        )

    def test_absolute_path_under_base_dir_gets_relative_ref(self):

        result = load(
            [str(FIXTURES / "web.rules")],
            base_dir=FIXTURES,
        )

        self.assertEqual(refs(result)[0], "web.rules:4")

    def test_nested_relative_path(self):

        result = load(["nested/deep.rules"])

        self.assertEqual(refs(result), ["nested/deep.rules:2"])


class RuleOverrideTestCase(unittest.TestCase):
    """RL12 - selectors that match nothing are reported."""

    def test_unknown_selector_warns_and_keeps_other_rules(self):

        result = load(
            ["web.rules"],
            overrides={"web.rules:999": False},
        )

        self.assertEqual(len(result.rules), 3)
        self.assertEqual(result.statistics.rules_disabled, 0)

        warning = warnings_for(result, CODE_UNKNOWN_RULE_OVERRIDE)[0]

        self.assertEqual(warning.rule_ref, "web.rules:999")
        self.assertIn("web.rules:999", warning.message)

    def test_override_in_disabled_file_does_not_load_the_file(self):

        result = load(
            [{"path": "local.rules", "enabled": False}],
            overrides={"local.rules:6": True},
        )

        self.assertEqual(result.rules, [])
        self.assertEqual(result.statistics.files_disabled, 1)
        self.assertIn(CODE_UNKNOWN_RULE_OVERRIDE, codes(result))

    def test_selector_path_variants_are_normalized(self):

        result = load(
            ["local.rules"],
            overrides={"./local.rules:6": False},
        )

        self.assertEqual(
            refs(result),
            ["local.rules:4", "local.rules:7"],
        )
        self.assertEqual(result.statistics.rules_disabled, 1)


class RuleLoaderConfigTestCase(unittest.TestCase):
    """RL13 - bad configuration is reported, not silently fatal."""

    def test_bad_entry_does_not_disable_other_files(self):

        result = load([{"enabled": False}, "web.rules"])

        self.assertEqual(len(result.rules), 3)
        self.assertEqual(result.statistics.files_configured, 1)
        self.assertIn(CODE_INVALID_CONFIG, codes(result))

    def test_bad_override_value_is_reported(self):

        result = load(
            ["local.rules"],
            overrides={"local.rules:6": "no"},
        )

        self.assertEqual(len(result.rules), 3)
        self.assertIn(CODE_INVALID_CONFIG, codes(result))

    def test_unknown_config_key_is_reported(self):

        config = RuleLoaderConfig.from_mapping(
            {"rule_files": ["web.rules"], "rule_file": []},
            base_dir=FIXTURES,
        )

        result = RuleLoader(config).load()

        self.assertEqual(len(result.rules), 3)
        self.assertIn(CODE_INVALID_CONFIG, codes(result))

    def test_structurally_invalid_config_raises(self):

        with self.assertRaises(RuleLoaderConfigError):

            RuleLoaderConfig.from_mapping(["web.rules"])

        with self.assertRaises(RuleLoaderConfigError):

            RuleLoaderConfig.from_mapping({"rule_files": "web.rules"})

        with self.assertRaises(RuleLoaderConfigError):

            RuleLoaderConfig.from_mapping(
                {"rule_files": [], "rule_overrides": ["x"]}
            )

    def test_invalid_json_config_raises_with_reason(self):

        with tempfile.TemporaryDirectory() as tmp:

            config_path = Path(tmp) / "broken.json"
            config_path.write_text("{not json", encoding="utf-8")

            with self.assertRaises(RuleLoaderConfigError) as context:

                RuleLoaderConfig.from_json_file(config_path)

        message = str(context.exception)

        self.assertIn("invalid JSON", message)
        self.assertIn(str(config_path), message)

    def test_missing_config_file_raises_with_path(self):

        with self.assertRaises(RuleLoaderConfigError) as context:

            RuleLoaderConfig.from_json_file(
                FIXTURES / "no_such_config.json"
            )

        self.assertIn("not found", str(context.exception))

    def test_invalid_bytes_fail_the_file_without_leaking_candidates(self):

        result = load(["invalid_utf8.rules", "web.rules"])

        self.assertEqual(len(result.rules), 3)
        self.assertEqual(result.statistics.files_failed, 1)
        self.assertFalse(
            any(
                rule.source_file == "invalid_utf8.rules"
                for rule in result.rules
            )
        )

        warning = warnings_for(result, CODE_FILE_ENCODING_ERROR)[0]

        self.assertIn("invalid_utf8.rules", warning.message)
        self.assertIn("utf-8", warning.message)

    def test_replace_policy_is_explicit_and_lossy(self):

        result = load(
            ["invalid_utf8.rules"],
            encoding_errors="replace",
        )

        self.assertEqual(len(result.rules), 1)
        self.assertIn("\ufffd", result.rules[0].raw_text)


class ShippedConfigTestCase(unittest.TestCase):
    """The example configuration in ``rules/`` must stay loadable."""

    def test_repository_config_loads(self):

        config = RuleLoaderConfig.from_json_file(SHIPPED_CONFIG)

        self.assertEqual(config.problems, [])

        result = RuleLoader(config).load()

        self.assertEqual(
            refs(result),
            [
                "web.rules:5",
                "web.rules:7",
                "web.rules:9",
                "local.rules:4",
                "local.rules:8",
            ],
        )
        self.assertEqual(result.statistics.files_configured, 3)
        self.assertEqual(result.statistics.files_disabled, 1)
        self.assertEqual(result.statistics.rules_disabled, 1)
        self.assertFalse(result.has_errors)

        self.assertEqual(
            sorted(codes(result)),
            [CODE_FILE_DISABLED, CODE_RULE_DISABLED],
        )


if __name__ == "__main__":

    unittest.main()
