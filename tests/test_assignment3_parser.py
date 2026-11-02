"""Assignment 3, section 4.2 tests: Rule Parser & Validator (TC02-TC04)."""

import unittest

from core_engine.rule_parser import (
    DIRECTION_BIDIRECTIONAL,
    DIRECTION_FORWARD,
    PORT_ANY,
    PORT_RANGE,
    PORT_SINGLE,
    STATUS_INVALID,
    STATUS_UNSUPPORTED,
    STATUS_VALID,
)
from core_engine.rule_repository import RuleRepository

from tests import bt3_support as support


class TC02InvalidRuleTestCase(unittest.TestCase):
    """TC02 - a malformed rule is invalid, the next rule still parses."""

    def test_malformed_rules_do_not_stop_parsing(self):

        results = support.load_parse("invalid_rules.rules")

        self.assertEqual(len(results), 4)

        self.assertEqual(
            [result.status for result in results],
            [
                STATUS_INVALID,
                STATUS_INVALID,
                STATUS_INVALID,
                STATUS_VALID,
            ],
        )

        self.assertEqual(
            [result.rule_ref for result in results],
            [
                "invalid_rules.rules:2",
                "invalid_rules.rules:3",
                "invalid_rules.rules:4",
                "invalid_rules.rules:5",
            ],
        )

        for result in results[:3]:

            self.assertIsNone(result.rule)
            self.assertTrue(result.reason)
            self.assertTrue(result.diagnostics)
            self.assertEqual(
                result.diagnostics[0].code,
                "SYNTAX_ERROR",
            )

        valid = results[-1]

        self.assertIsNotNone(valid.rule)
        self.assertEqual(valid.rule.sid, 4100204)
        self.assertEqual(valid.rule.msg, "TC02 valid after invalid")
        self.assertEqual(valid.rule.contents[0].pattern_text, "ok")

    def test_parser_never_raises_for_garbage_text(self):

        from core_engine.rule_parser import RuleParserValidator

        parser = RuleParserValidator()

        for text in (
            "",
            "alert tcp",
            "alert tcp any any -> any 80",
            'alert tcp any any -> any 80 (msg:"x";)',
            'alert tcp any any -> any 80 (msg:"x"; sid:1; extra)',
        ):

            result = parser.parse(text, rule_ref="inline:1")

            self.assertEqual(result.status, STATUS_INVALID)
            self.assertTrue(result.reason)


class TC03UnsupportedKeywordTestCase(unittest.TestCase):
    """TC03 - out-of-scope keywords are unsupported and never matchable."""

    def test_unsupported_keywords_are_classified_and_isolated(self):

        results = support.load_parse("unsupported_rules.rules")

        self.assertEqual(
            [result.status for result in results],
            [
                STATUS_UNSUPPORTED,
                STATUS_UNSUPPORTED,
                STATUS_UNSUPPORTED,
                STATUS_VALID,
            ],
        )

        self.assertIn("pcre", results[0].reason)
        self.assertIn("byte_test", results[1].reason)
        self.assertIn("icmp", results[2].reason)

        self.assertEqual(results[3].rule.sid, 4100304)

    def test_repository_excludes_unsupported_rules_but_keeps_diagnostics(self):

        results = support.load_parse("unsupported_rules.rules")

        repository = RuleRepository.from_parse_results(results)

        self.assertEqual(len(repository), 1)
        self.assertEqual(
            [rule.sid for rule in repository.valid_rules],
            [4100304],
        )

        stats = repository.statistics()

        self.assertEqual(stats["unsupported"], 3)
        self.assertEqual(stats["valid"], 1)

        codes = [diagnostic.code for diagnostic in repository.diagnostics]

        self.assertEqual(codes, ["UNSUPPORTED_RULE"] * 3)


class TC04HeaderParsingTestCase(unittest.TestCase):
    """TC04 - TCP/UDP header selectors, any/IPv4/CIDR, port/range."""

    @classmethod
    def setUpClass(cls):

        cls.results = support.load_parse("header_rules.rules")
        cls.repository = RuleRepository.from_parse_results(cls.results)

    def test_every_header_rule_is_valid(self):

        self.assertEqual(
            [result.status for result in self.results],
            [STATUS_VALID] * 7,
        )

    def test_any_selectors_and_forward_direction(self):

        rule = support.rule_by_sid(self.repository, 4100101)

        self.assertEqual(rule.protocol, "TCP")
        self.assertEqual(rule.src_address.kind, "any")
        self.assertEqual(rule.src_port.kind, PORT_ANY)
        self.assertEqual(rule.dst_address.kind, "any")
        self.assertEqual(rule.dst_port.kind, PORT_ANY)
        self.assertEqual(rule.direction, DIRECTION_FORWARD)

    def test_cidr_range_ipv4_and_port(self):

        rule = support.rule_by_sid(self.repository, 4100102)

        self.assertEqual(rule.src_address.kind, "cidr")
        self.assertEqual(rule.src_address.value, "192.168.1.0/24")
        self.assertTrue(rule.src_address.matches("192.168.1.55"))
        self.assertFalse(rule.src_address.matches("192.168.2.55"))

        self.assertEqual(rule.src_port.kind, PORT_RANGE)
        self.assertEqual((rule.src_port.start, rule.src_port.end), (1024, 2000))
        self.assertTrue(rule.src_port.matches(1024))
        self.assertTrue(rule.src_port.matches(2000))
        self.assertFalse(rule.src_port.matches(2001))

        self.assertEqual(rule.dst_address.kind, "ipv4")
        self.assertEqual(rule.dst_address.value, "10.0.0.5")
        self.assertEqual(rule.dst_port.kind, PORT_SINGLE)
        self.assertTrue(rule.dst_port.matches(80))

    def test_single_ipv4_and_single_port(self):

        rule = support.rule_by_sid(self.repository, 4100103)

        self.assertEqual(rule.src_address.value, "192.168.1.10")
        self.assertEqual(rule.src_port.start, 12345)
        self.assertEqual(rule.dst_address.value, "192.168.1.20")
        self.assertEqual(rule.dst_port.start, 80)

    def test_udp_and_bidirectional_header(self):

        udp = support.rule_by_sid(self.repository, 4100104)

        self.assertEqual(udp.protocol, "UDP")
        self.assertEqual(udp.dst_port.start, 53)

        bidirectional = support.rule_by_sid(self.repository, 4100105)

        self.assertEqual(bidirectional.direction, DIRECTION_BIDIRECTIONAL)
        self.assertEqual(bidirectional.src_address.value, "8.8.8.0/24")
        self.assertEqual(bidirectional.dst_address.value, "192.168.1.0/24")

    def test_open_ended_port_ranges(self):

        low = support.rule_by_sid(self.repository, 4100106)
        high = support.rule_by_sid(self.repository, 4100107)

        self.assertEqual((low.src_port.start, low.src_port.end), (0, 1024))
        self.assertEqual((high.src_port.start, high.src_port.end), (1024, 65535))

    def test_invalid_ip_port_and_direction_are_invalid(self):

        results = support.load_parse("header_invalid.rules")

        self.assertEqual(
            [result.status for result in results],
            [STATUS_INVALID] * 4 + [STATUS_VALID],
        )

        self.assertIn("invalid source address", results[0].reason)
        self.assertIn("outside 0..65535", results[1].reason)
        self.assertIn("start is greater than end", results[2].reason)
        self.assertIn("direction", results[3].reason)

        self.assertEqual(results[-1].rule.sid, 4100114)


class ParserOptionContractTestCase(unittest.TestCase):
    """Additional parser unit tests for the documented option contract."""

    def test_quoted_delimiters_are_preserved(self):

        result = support.load_parse("quoted.rules")[0]

        self.assertEqual(result.status, STATUS_VALID)

        self.assertEqual(
            result.rule.msg,
            'semi; colon: comma, parens () and quote " inside',
        )
        self.assertEqual(result.rule.contents[0].pattern_text, "a;b:c,d(e)")

    def test_sid_and_msg_are_required(self):

        results = support.load_parse("required.rules")

        self.assertEqual(
            [result.status for result in results],
            [STATUS_INVALID, STATUS_INVALID],
        )
        self.assertIn("sid", results[0].reason)
        self.assertIn("msg", results[1].reason)

    def test_content_modifier_misuse_is_invalid(self):

        results = support.load_parse("modifiers_invalid.rules")

        self.assertEqual(
            [result.status for result in results],
            [STATUS_INVALID] * 3,
        )
        self.assertIn("no preceding content", results[0].reason)
        self.assertIn("previous content", results[1].reason)
        self.assertIn("cannot be combined", results[2].reason)

    def test_flow_contradictions_and_unknown_condition(self):

        results = support.load_parse("flow_invalid.rules")

        self.assertEqual(
            [result.status for result in results],
            [STATUS_INVALID, STATUS_INVALID, STATUS_UNSUPPORTED],
        )
        self.assertIn("to_server and to_client", results[0].reason)
        self.assertIn("established and not_established", results[1].reason)
        self.assertIn("only_stream", results[2].reason)

    def test_dsize_value_validation(self):

        results = support.load_parse("dsize_invalid.rules")

        self.assertEqual(
            [result.status for result in results],
            [STATUS_INVALID, STATUS_UNSUPPORTED, STATUS_INVALID],
        )

    def test_udp_flags_is_invalid(self):

        results = support.load_parse("flags_invalid.rules")

        self.assertEqual(
            [result.status for result in results],
            [STATUS_INVALID, STATUS_VALID],
        )
        self.assertIn("only valid for TCP", results[0].reason)


if __name__ == "__main__":

    unittest.main()
