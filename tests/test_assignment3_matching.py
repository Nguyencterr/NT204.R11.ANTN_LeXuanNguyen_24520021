"""Assignment 3, section 4.4 tests: Rule Matching Engine (TC05-TC12)."""

import unittest
from unittest.mock import patch

from config import PipelineConfig
from core_engine.matching import (
    ORIENTATION_FORWARD,
    ORIENTATION_REVERSE,
    RuleMatchingEngine,
    STATUS_MATCH,
    STATUS_NO_MATCH,
)
from flow import FlowTracker

from tests import bt3_support as support


class TC05DirectionTestCase(unittest.TestCase):
    """TC05 - ``->`` is one-way; ``<>`` matches forward and reverse."""

    @classmethod
    def setUpClass(cls):

        cls.repository = support.build_repository("direction_rules.rules")
        cls.engine = RuleMatchingEngine()
        cls.one_way = support.rule_by_sid(cls.repository, 4100401)
        cls.bidirectional = support.rule_by_sid(cls.repository, 4100402)

    def test_forward_event_matches_both_rules(self):

        event = support.event(
            src="192.168.1.10",
            dst="192.168.1.20",
            src_port=12345,
            dst_port=8080,
            payload="GET / HTTP/1.1",
        )

        forward = self.engine.match(event, self.one_way)
        both = self.engine.match(event, self.bidirectional)

        self.assertEqual(forward.status, STATUS_MATCH)
        self.assertEqual(forward.orientation, ORIENTATION_FORWARD)

        self.assertEqual(both.status, STATUS_MATCH)
        self.assertEqual(both.orientation, ORIENTATION_FORWARD)

    def test_reverse_event_only_matches_bidirectional_rule(self):

        event = support.event(
            src="192.168.1.20",
            dst="192.168.1.10",
            src_port=8080,
            dst_port=12345,
            payload="GET / HTTP/1.1",
        )

        one_way = self.engine.match(event, self.one_way)
        both = self.engine.match(event, self.bidirectional)

        self.assertEqual(one_way.status, STATUS_NO_MATCH)
        self.assertIn("header mismatch", one_way.reason)

        self.assertEqual(both.status, STATUS_MATCH)
        self.assertEqual(both.orientation, ORIENTATION_REVERSE)


class TC07HeaderShortCircuitTestCase(unittest.TestCase):
    """TC07 - header mismatch returns before content matching runs."""

    def test_content_matcher_is_not_called_on_header_mismatch(self):

        repository = support.build_repository("direction_rules.rules")
        rule = support.rule_by_sid(repository, 4100401)
        engine = RuleMatchingEngine()

        reverse = support.event(
            src="192.168.1.20",
            dst="192.168.1.10",
            src_port=8080,
            dst_port=12345,
            payload="GET / HTTP/1.1",
        )

        with patch.object(
            engine,
            "match_contents",
            wraps=engine.match_contents,
        ) as spy:

            result = engine.match(reverse, rule)

            self.assertEqual(result.status, STATUS_NO_MATCH)
            self.assertIn("header mismatch", result.reason)
            spy.assert_not_called()

        forward = support.event(
            src="192.168.1.10",
            dst="192.168.1.20",
            src_port=12345,
            dst_port=8080,
            payload="GET / HTTP/1.1",
        )

        with patch.object(
            engine,
            "match_contents",
            wraps=engine.match_contents,
        ) as spy:

            result = engine.match(forward, rule)

            self.assertEqual(result.status, STATUS_MATCH)
            spy.assert_called_once()


class TC08FlowStateTestCase(unittest.TestCase):
    """TC08 - flow:to_server/established from real tracker context."""

    def setUp(self):

        self.repository = support.build_repository("flow_rules.rules")
        self.engine = RuleMatchingEngine()

        self.tracker = FlowTracker(PipelineConfig())
        self.client = ("192.168.1.10", 50000)
        self.server = ("192.168.1.20", 80)

        self.tracker.process(
            support.event(
                src=self.client[0],
                dst=self.server[0],
                src_port=self.client[1],
                dst_port=self.server[1],
                flags="S",
            )
        )
        self.tracker.process(
            support.event(
                src=self.server[0],
                dst=self.client[0],
                src_port=self.server[1],
                dst_port=self.client[1],
                flags="SA",
            )
        )
        self.handshake_context = self.tracker.last_context

        self.ack = support.event(
            src=self.client[0],
            dst=self.server[0],
            src_port=self.client[1],
            dst_port=self.server[1],
            flags="A",
            payload="GET / HTTP/1.1",
        )
        self.tracker.process(self.ack)
        self.established_context = self.tracker.last_context

    def test_context_adapter_records_role_evidence(self):

        context = self.established_context

        self.assertEqual(context["state"], "ESTABLISHED")
        self.assertTrue(context["established"])
        self.assertTrue(context["to_server"])
        self.assertFalse(context["to_client"])
        self.assertEqual(context["role_source"], "tcp_syn")
        self.assertEqual(context["direction"], "forward")

    def test_to_server_established_matches(self):

        to_server = support.rule_by_sid(self.repository, 4100701)
        to_client = support.rule_by_sid(self.repository, 4100702)
        not_established = support.rule_by_sid(self.repository, 4100703)
        flow_required = support.rule_by_sid(self.repository, 4100704)

        self.assertEqual(
            self.engine.match(
                self.ack,
                to_server,
                self.established_context,
            ).status,
            STATUS_MATCH,
        )
        self.assertEqual(
            self.engine.match(
                self.ack,
                to_client,
                self.established_context,
            ).status,
            STATUS_NO_MATCH,
        )
        self.assertEqual(
            self.engine.match(
                self.ack,
                not_established,
                self.established_context,
            ).status,
            STATUS_NO_MATCH,
        )
        self.assertEqual(
            self.engine.match(
                self.ack,
                flow_required,
                self.established_context,
            ).status,
            STATUS_MATCH,
        )

    def test_handshake_is_not_established_yet(self):

        to_server = support.rule_by_sid(self.repository, 4100701)
        not_established = support.rule_by_sid(self.repository, 4100703)

        handshake_event = support.event(
            src=self.server[0],
            dst=self.client[0],
            src_port=self.server[1],
            dst_port=self.client[1],
            flags="SA",
            payload="GET proxy",
        )

        self.assertEqual(
            self.handshake_context["state"],
            "HANDSHAKE",
        )
        self.assertFalse(self.handshake_context["established"])

        self.assertEqual(
            self.engine.match(
                handshake_event,
                to_server,
                self.handshake_context,
            ).status,
            STATUS_NO_MATCH,
        )
        self.assertEqual(
            self.engine.match(
                handshake_event,
                not_established,
                self.handshake_context,
            ).status,
            STATUS_MATCH,
        )

    def test_to_client_matches_server_to_client_packet(self):

        server_data = support.event(
            src=self.server[0],
            dst=self.client[0],
            src_port=self.server[1],
            dst_port=self.client[1],
            flags="A",
            payload="GET /response",
        )

        self.tracker.process(server_data)
        context = self.tracker.last_context

        self.assertEqual(context["direction"], "backward")
        self.assertTrue(context["to_client"])
        self.assertFalse(context["to_server"])

        to_client = support.rule_by_sid(self.repository, 4100702)
        to_server = support.rule_by_sid(self.repository, 4100701)

        self.assertEqual(
            self.engine.match(server_data, to_client, context).status,
            STATUS_MATCH,
        )
        self.assertEqual(
            self.engine.match(server_data, to_server, context).status,
            STATUS_NO_MATCH,
        )

    def test_missing_flow_context_never_invents_state(self):

        to_server = support.rule_by_sid(self.repository, 4100701)

        result = self.engine.match(self.ack, to_server, None)

        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("requires flow context", result.reason)

    def test_udp_open_flow_is_documented_established(self):

        tracker = FlowTracker(PipelineConfig())
        udp_event = support.event(
            src="192.168.1.10",
            dst="8.8.8.8",
            protocol="UDP",
            src_port=53000,
            dst_port=53,
            flags=None,
            payload="dns query",
        )
        tracker.process(udp_event)
        context = tracker.last_context

        self.assertEqual(context["state"], "OPEN")
        self.assertTrue(context["established"])
        self.assertTrue(context["to_server"])
        self.assertEqual(context["role_source"], "well_known_port")

        rule = support.rule_by_sid(self.repository, 4100705)

        self.assertEqual(
            self.engine.match(udp_event, rule, context).status,
            STATUS_MATCH,
        )


class TC09ContentNocaseTestCase(unittest.TestCase):
    """TC09 - case-sensitive by default; ``nocase`` folds ASCII case."""

    @classmethod
    def setUpClass(cls):

        cls.repository = support.build_repository("content_rules.rules")
        cls.engine = RuleMatchingEngine()
        cls.sensitive = support.rule_by_sid(cls.repository, 4100501)
        cls.insensitive = support.rule_by_sid(cls.repository, 4100502)

    def test_exact_case_matches_both_rules(self):

        event = support.event(payload="Admin access")

        sensitive = self.engine.match(event, self.sensitive)
        insensitive = self.engine.match(event, self.insensitive)

        self.assertEqual(sensitive.status, STATUS_MATCH)
        self.assertEqual(insensitive.status, STATUS_MATCH)
        self.assertEqual(sensitive.buffer, "payload")
        self.assertEqual(sensitive.matched_contents[0]["content"], "Admin")
        self.assertEqual(sensitive.matched_contents[0]["position"], 0)
        self.assertFalse(sensitive.matched_contents[0]["nocase"])
        self.assertTrue(insensitive.matched_contents[0]["nocase"])

    def test_lowercase_payload_only_matches_nocase_rule(self):

        event = support.event(payload="admin access")

        self.assertEqual(
            self.engine.match(event, self.sensitive).status,
            STATUS_NO_MATCH,
        )

        insensitive = self.engine.match(event, self.insensitive)

        self.assertEqual(insensitive.status, STATUS_MATCH)
        self.assertEqual(insensitive.matched_contents[0]["position"], 0)

    def test_uppercase_payload_only_matches_nocase_rule(self):

        event = support.event(payload="ADMIN access")

        self.assertEqual(
            self.engine.match(event, self.sensitive).status,
            STATUS_NO_MATCH,
        )
        self.assertEqual(
            self.engine.match(event, self.insensitive).status,
            STATUS_MATCH,
        )


class TC10OffsetDepthTestCase(unittest.TestCase):
    """TC10 - absolute offset/depth windows and boundaries."""

    @classmethod
    def setUpClass(cls):

        cls.repository = support.build_repository("content_rules.rules")
        cls.engine = RuleMatchingEngine()
        cls.hit = support.rule_by_sid(cls.repository, 4100503)
        cls.miss = support.rule_by_sid(cls.repository, 4100504)
        cls.exact = support.rule_by_sid(cls.repository, 4100508)
        cls.too_short = support.rule_by_sid(cls.repository, 4100509)

    def test_content_inside_window_matches(self):

        event = support.event(payload="0123456789EVILtail")

        self.assertEqual(
            self.engine.match(event, self.hit).status,
            STATUS_MATCH,
        )
        self.assertEqual(
            self.engine.match(event, self.miss).status,
            STATUS_NO_MATCH,
        )

    def test_window_boundary_is_inclusive_of_a_full_pattern(self):

        event = support.event(payload="0123456789EVIL")

        match = self.engine.match(event, self.exact)

        self.assertEqual(match.status, STATUS_MATCH)
        self.assertEqual(match.matched_contents[0]["position"], 10)
        self.assertEqual(match.matched_contents[0]["window_start"], 10)
        self.assertEqual(match.matched_contents[0]["window_end"], 14)

        self.assertEqual(
            self.engine.match(event, self.too_short).status,
            STATUS_NO_MATCH,
        )

    def test_pattern_crossing_window_end_does_not_match(self):

        event = support.event(payload="0123456789xEVIL")

        self.assertEqual(
            self.engine.match(event, self.exact).status,
            STATUS_NO_MATCH,
        )

        # The wide window still contains the pattern at position 11.
        wide = self.engine.match(event, self.hit)

        self.assertEqual(wide.status, STATUS_MATCH)
        self.assertEqual(wide.matched_contents[0]["position"], 11)

    def test_content_after_window_does_not_match(self):

        event = support.event(payload="0123456789EVILtail")

        self.assertEqual(
            self.engine.match(event, self.miss).status,
            STATUS_NO_MATCH,
        )


class TC11DistanceWithinTestCase(unittest.TestCase):
    """TC11 - relative distance/within and backtracking."""

    @classmethod
    def setUpClass(cls):

        cls.repository = support.build_repository("content_rules.rules")
        cls.engine = RuleMatchingEngine()
        cls.hit = support.rule_by_sid(cls.repository, 4100505)
        cls.miss = support.rule_by_sid(cls.repository, 4100506)
        cls.backtrack = support.rule_by_sid(cls.repository, 4100507)

    def test_second_content_is_found_relative_to_first(self):

        event = support.event(payload="BEGINxxEND")

        result = self.engine.match(event, self.hit)

        self.assertEqual(result.status, STATUS_MATCH)
        positions = [
            match["position"]
            for match in result.matched_contents
        ]
        self.assertEqual(positions, [0, 7])

    def test_first_absolute_occurrence_is_not_used_for_relative_search(self):

        event = support.event(payload="ENDxxBEGINxxEND")

        result = self.engine.match(event, self.hit)

        self.assertEqual(result.status, STATUS_MATCH)
        positions = [
            match["position"]
            for match in result.matched_contents
        ]
        # The END at position 0 must not satisfy the relative rule.
        self.assertEqual(positions, [5, 12])

    def test_content_too_far_does_not_match(self):

        event = support.event(payload="BEGINxxxxEND")

        self.assertEqual(
            self.engine.match(event, self.hit).status,
            STATUS_NO_MATCH,
        )

    def test_distance_miss_rule_does_not_match(self):

        event = support.event(payload="BEGINxxEND")

        self.assertEqual(
            self.engine.match(event, self.miss).status,
            STATUS_NO_MATCH,
        )

    def test_backtracking_tries_later_first_content(self):

        event = support.event(payload="XYaXYbZZ")

        result = self.engine.match(event, self.backtrack)

        self.assertEqual(result.status, STATUS_MATCH)
        positions = [
            match["position"]
            for match in result.matched_contents
        ]
        # The XY at 0 is followed by another XY before ZZ; a first-match-only
        # implementation would return NO_MATCH here.
        self.assertEqual(positions, [3, 6])


class TC12FlagsDsizeTestCase(unittest.TestCase):
    """TC12 - TCP flags semantics and payload-length dsize."""

    @classmethod
    def setUpClass(cls):

        cls.repository = support.build_repository("flags_dsize.rules")
        cls.engine = RuleMatchingEngine()
        cls.syn = support.rule_by_sid(cls.repository, 4100601)
        cls.synack = support.rule_by_sid(cls.repository, 4100602)
        cls.greater = support.rule_by_sid(cls.repository, 4100603)
        cls.equal = support.rule_by_sid(cls.repository, 4100604)
        cls.at_most = support.rule_by_sid(cls.repository, 4100605)

    def test_flags_require_every_declared_flag(self):

        syn_event = support.event(flags="S", payload="")
        synack_event = support.event(flags="SA", payload="")
        ack_event = support.event(flags="A", payload="")

        self.assertEqual(
            self.engine.match(syn_event, self.syn).status,
            STATUS_MATCH,
        )
        self.assertEqual(
            self.engine.match(syn_event, self.synack).status,
            STATUS_NO_MATCH,
        )

        self.assertEqual(
            self.engine.match(synack_event, self.syn).status,
            STATUS_MATCH,
        )
        self.assertEqual(
            self.engine.match(synack_event, self.synack).status,
            STATUS_MATCH,
        )

        self.assertEqual(
            self.engine.match(ack_event, self.syn).status,
            STATUS_NO_MATCH,
        )

    def test_missing_flags_is_no_match_not_a_crash(self):

        event = support.event(flags=None, payload="")

        result = self.engine.match(event, self.syn)

        self.assertEqual(result.status, STATUS_NO_MATCH)
        self.assertIn("no TCP flags", result.reason)

    def test_dsize_uses_payload_length_not_packet_length(self):

        event = support.event(
            payload="12345",
            payload_length=5,
            packet_length=1500,
        )

        greater = self.engine.match(event, self.greater)
        equal = self.engine.match(event, self.equal)
        at_most = self.engine.match(event, self.at_most)

        self.assertEqual(greater.status, STATUS_MATCH)
        self.assertEqual(greater.details["dsize"]["payload_length"], 5)

        self.assertEqual(equal.status, STATUS_NO_MATCH)
        self.assertEqual(at_most.status, STATUS_NO_MATCH)

    def test_dsize_boundary_at_four_bytes(self):

        event = support.event(
            payload="1234",
            payload_length=4,
            packet_length=1500,
        )

        self.assertEqual(
            self.engine.match(event, self.greater).status,
            STATUS_NO_MATCH,
        )
        self.assertEqual(
            self.engine.match(event, self.equal).status,
            STATUS_MATCH,
        )
        self.assertEqual(
            self.engine.match(event, self.at_most).status,
            STATUS_MATCH,
        )


if __name__ == "__main__":

    unittest.main()
