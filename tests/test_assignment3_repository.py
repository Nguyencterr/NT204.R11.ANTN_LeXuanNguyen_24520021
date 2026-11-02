"""Assignment 3, section 4.3 tests: Rule Repository / Indexer (TC06)."""

import unittest

from core_engine.rule_repository import (
    CODE_DUPLICATE_SID,
    DUPLICATE_SID_WARN_KEEP,
    RepositoryConfig,
    RuleRepository,
)

from tests import bt3_support as support


class TC06IndexerTestCase(unittest.TestCase):
    """TC06 - protocol/port/IP candidate pre-filtering never loses a rule."""

    @classmethod
    def setUpClass(cls):

        cls.repository = support.build_repository("header_rules.rules")

    def sids(self, event):

        return [
            rule.sid
            for rule in self.repository.candidates(event).rules
        ]

    def test_tcp_any_single_and_high_range_are_candidates(self):

        event = support.event(
            src="192.168.1.10",
            dst="192.168.1.20",
            src_port=12345,
            dst_port=80,
        )

        selection = self.repository.candidates(event)

        self.assertEqual(
            [rule.sid for rule in selection.rules],
            [4100101, 4100103, 4100107],
        )

        # The any rule is never lost.
        self.assertIn(4100101, [rule.sid for rule in selection.rules])

        # A CIDR + range rule whose source port does not match is excluded.
        self.assertNotIn(4100102, [rule.sid for rule in selection.rules])

        # UDP rules are not candidates for a TCP event.
        self.assertNotIn(4100104, [rule.sid for rule in selection.rules])
        self.assertNotIn(4100105, [rule.sid for rule in selection.rules])

        self.assertEqual(selection.protocol, "TCP")

        # Proof that the index reduced the search: TCP pool has 5 rules,
        # only 3 are candidates for this event.
        self.assertEqual(selection.pool_size, 5)
        self.assertEqual(selection.candidate_count, 3)
        self.assertLess(selection.candidate_count, selection.pool_size)

    def test_open_ended_low_range_is_not_lost(self):

        event = support.event(
            src="192.168.1.10",
            dst="10.0.0.5",
            src_port=500,
            dst_port=80,
        )

        selection = self.repository.candidates(event)

        self.assertEqual(
            [rule.sid for rule in selection.rules],
            [4100101, 4100106],
        )

        self.assertEqual(selection.pool_size, 5)
        self.assertLess(selection.candidate_count, selection.pool_size)

    def test_udp_and_bidirectional_reverse_candidate(self):

        event = support.event(
            src="192.168.1.20",
            dst="8.8.8.8",
            protocol="UDP",
            src_port=53000,
            dst_port=53,
        )

        selection = self.repository.candidates(event)

        self.assertEqual(
            [rule.sid for rule in selection.rules],
            [4100104, 4100105],
        )

        # 4100105 only matches in the reversed orientation.
        self.assertIn(4100105, [rule.sid for rule in selection.rules])

        for rule in selection.rules:

            self.assertEqual(rule.protocol, "UDP")

        self.assertNotIn(4100101, [rule.sid for rule in selection.rules])

        self.assertEqual(selection.pool_size, 2)

    def test_candidate_order_is_stable_across_rebuild(self):

        event = support.event(
            src="192.168.1.10",
            dst="192.168.1.20",
            src_port=12345,
            dst_port=80,
        )

        first = self.sids(event)
        second = self.sids(event)

        self.repository.rebuild_index()
        third = self.sids(event)

        self.assertEqual(first, second)
        self.assertEqual(first, third)
        self.assertEqual(first, sorted(first))

    def test_unknown_protocol_returns_no_candidate(self):

        event = support.event(
            protocol="ICMP",
            src_port=None,
            dst_port=None,
            flags=None,
        )

        selection = self.repository.candidates(event)

        self.assertEqual(selection.candidate_count, 0)
        self.assertIn("not TCP/UDP", selection.reason)


class RepositoryDiagnosticsTestCase(unittest.TestCase):
    """Repository must never overwrite a duplicate SID silently."""

    def test_duplicate_sid_rejected_by_default(self):

        results = support.load_parse("duplicate_sid.rules")

        repository = RuleRepository.from_parse_results(results)

        self.assertEqual(len(repository), 1)
        self.assertEqual(repository.valid_rules[0].msg, "TC duplicate first")
        self.assertEqual(repository.duplicate_sid_count, 1)

        duplicate = [
            diagnostic
            for diagnostic in repository.diagnostics
            if diagnostic.code == CODE_DUPLICATE_SID
        ]

        self.assertEqual(len(duplicate), 1)
        self.assertEqual(duplicate[0].sid, 4101101)
        self.assertIn("duplicate sid", duplicate[0].message)

    def test_duplicate_sid_warn_keep_keeps_both_rules(self):

        results = support.load_parse("duplicate_sid.rules")

        repository = RuleRepository.from_parse_results(
            results,
            RepositoryConfig(
                duplicate_sid_policy=DUPLICATE_SID_WARN_KEEP,
            ),
        )

        self.assertEqual(len(repository), 2)
        self.assertEqual(
            [rule.msg for rule in repository.valid_rules],
            ["TC duplicate first", "TC duplicate second"],
        )
        self.assertEqual(repository.duplicate_sid_count, 1)
        self.assertEqual(
            repository.statistics()["duplicate_sid"],
            1,
        )

    def test_invalid_rules_are_counted_but_not_stored(self):

        repository = support.build_repository("invalid_rules.rules")

        self.assertEqual(len(repository), 1)
        stats = repository.statistics()

        self.assertEqual(stats["parse_results"], 4)
        self.assertEqual(stats["invalid"], 3)
        self.assertEqual(stats["valid"], 1)
        self.assertEqual(stats["diagnostics"], 3)


if __name__ == "__main__":

    unittest.main()
