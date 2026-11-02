"""Assignment 3, sections 4.5-4.6 tests: evaluation and detections (TC13-TC14)."""

import json
import unittest

from core_engine.evaluation import RuleEvaluationEngine
from core_engine.matching import RuleMatchingEngine

from tests import bt3_support as support


class TC13MultipleMatchesTestCase(unittest.TestCase):
    """TC13 - one event can match several rules; evaluation does not stop."""

    def test_all_matching_rules_produce_independent_detections(self):

        repository = support.build_repository("multi_match.rules")
        engine = RuleEvaluationEngine(repository)

        event = support.event(
            src="192.168.1.10",
            dst="192.168.1.20",
            src_port=12345,
            dst_port=80,
            payload="GET /index HTTP/1.1",
        )

        result = engine.evaluate(event, support.flow_context())

        self.assertEqual(
            [match.sid for match in result.matches],
            [4100801, 4100802],
        )
        self.assertNotIn(4100803, [match.sid for match in result.matches])

        self.assertEqual(len(result.detections), 2)
        self.assertEqual(
            [detection["sid"] for detection in result.detections],
            [4100801, 4100802],
        )
        self.assertEqual(
            [detection["msg"] for detection in result.detections],
            ["TC13 first GET", "TC13 second index"],
        )

        statistics = engine.statistics

        self.assertEqual(statistics.events_evaluated, 1)
        self.assertEqual(statistics.matches, 2)
        self.assertEqual(statistics.detections_generated, 2)
        self.assertEqual(statistics.no_match_count, 1)

    def test_every_detection_is_json_serializable(self):

        repository = support.build_repository("multi_match.rules")
        engine = RuleEvaluationEngine(repository)

        event = support.event(payload="GET /index HTTP/1.1")
        result = engine.evaluate(event, support.flow_context())

        for detection in result.detections:

            decoded = json.loads(json.dumps(detection))

            self.assertEqual(decoded["sid"], detection["sid"])
            self.assertIn("matched_info", decoded)


class TC14DetectionEventTestCase(unittest.TestCase):
    """TC14 - Detection Event carries every required field."""

    def setUp(self):

        self.repository = support.build_repository("detection_rules.rules")
        self.engine = RuleEvaluationEngine(self.repository)

        self.event = support.http_event(
            "/x?id=1 OR 1=1",
            src="192.168.1.10",
            dst="203.0.113.9",
            src_port=50000,
            dst_port=8080,
            timestamp=1234.5,
            packet_id=42,
        )
        self.event["decoded"]["http"]["raw_uri"] = "/x?id=1%20OR%201=1"
        self.event["decoded"]["http"]["decoded_uri"] = "/x?id=1 OR 1=1"

        self.flow = support.flow_context(flow_id="ctx-flow-123")

        self.result = self.engine.evaluate(self.event, self.flow)

    def test_one_detection_is_generated(self):

        self.assertEqual(len(self.result.matches), 1)
        self.assertEqual(len(self.result.detections), 1)

    def test_required_fields_are_present(self):

        detection = self.result.detections[0]

        self.assertEqual(detection["timestamp"], 1234.5)
        self.assertEqual(detection["packet_id"], 42)
        self.assertEqual(detection["sid"], 4100901)
        self.assertEqual(detection["rev"], 3)
        self.assertEqual(detection["msg"], "TC14 suspicious URI")
        self.assertEqual(detection["priority"], 1)
        self.assertEqual(
            detection["classtype"],
            "web-application-attack",
        )
        self.assertEqual(detection["src_ip"], "192.168.1.10")
        self.assertEqual(detection["dst_ip"], "203.0.113.9")
        self.assertEqual(detection["src_port"], 50000)
        self.assertEqual(detection["dst_port"], 8080)
        self.assertEqual(detection["protocol"], "TCP")
        self.assertEqual(detection["application_protocol"], "HTTP")
        self.assertEqual(detection["flow_id"], "ctx-flow-123")

    def test_matched_info_explains_the_match(self):

        detection = self.result.detections[0]
        matched = detection["matched_info"]

        self.assertEqual(matched["orientation"], "forward")
        self.assertEqual(matched["buffer"], "http_uri")

        content_matches = matched["content_matches"]

        self.assertEqual(len(content_matches), 1)
        self.assertEqual(content_matches[0]["content"], "OR 1=1")
        self.assertEqual(content_matches[0]["buffer"], "http_uri")
        self.assertEqual(content_matches[0]["position"], 8)
        self.assertEqual(content_matches[0]["end"], 14)
        self.assertTrue(content_matches[0]["nocase"])

        self.assertIn("flow", matched["details"])
        self.assertIn("flags", matched["details"])

    def test_detection_roundtrips_through_json(self):

        detection = self.result.detections[0]

        encoded = json.dumps(detection)

        decoded = json.loads(encoded)

        self.assertEqual(decoded, detection)
        self.assertEqual(decoded["rule"]["sid"], 4100901)
        self.assertEqual(decoded["rule"]["rule_ref"], "detection_rules.rules:2")
        self.assertEqual(decoded["rule"]["line_number"], 2)


class EvaluationStatisticsAndIsolationTestCase(unittest.TestCase):
    """4.5 statistics + error isolation."""

    def test_no_match_counts_without_detection(self):

        repository = support.build_repository("multi_match.rules")
        engine = RuleEvaluationEngine(repository)

        event = support.event(payload="PATCH /nothing HTTP/1.1")

        result = engine.evaluate(event, support.flow_context())

        self.assertEqual(result.match_count, 0)
        self.assertEqual(len(result.detections), 0)
        self.assertEqual(engine.statistics.events_evaluated, 1)
        self.assertEqual(engine.statistics.matches, 0)
        self.assertEqual(engine.statistics.no_match_count, 3)
        self.assertEqual(engine.statistics.detections_generated, 0)

    def test_non_mapping_event_is_counted_and_isolated(self):

        repository = support.build_repository("multi_match.rules")
        engine = RuleEvaluationEngine(repository)

        result = engine.evaluate(None, None)

        self.assertEqual(result.match_count, 0)
        self.assertEqual(engine.statistics.events_evaluated, 1)
        self.assertEqual(engine.statistics.invalid_event_count, 1)

    def test_one_failing_candidate_does_not_stop_the_others(self):

        repository = support.build_repository("multi_match.rules")
        real_engine = RuleMatchingEngine()

        class ExplodingEngine:
            def match(self, event, rule, flow_context=None):

                if rule.sid == 4100801:

                    raise RuntimeError("candidate double failed")

                return real_engine.match(event, rule, flow_context)

        engine = RuleEvaluationEngine(
            repository,
            matching_engine=ExplodingEngine(),
        )

        event = support.event(payload="GET /index HTTP/1.1")
        result = engine.evaluate(event, support.flow_context())

        self.assertEqual(
            [match.sid for match in result.matches],
            [4100802],
        )
        self.assertEqual(engine.statistics.errors, 1)
        self.assertEqual(engine.statistics.matches, 1)


if __name__ == "__main__":

    unittest.main()
