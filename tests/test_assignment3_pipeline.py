"""Assignment 3 integration tests: TC01 loader pipeline and end-to-end PCAP."""

import json
import tempfile
import unittest
from pathlib import Path

from capture.pcap import read_pcap
from common.jsonl import JsonlWriter, read_jsonl
from config import PipelineConfig
from core_engine.evaluation import RuleEvaluationEngine
from core_engine.rule_loader import RuleLoader, RuleLoaderConfig
from core_engine.rule_parser import RuleParserValidator
from core_engine.rule_repository import RepositoryConfig, RuleRepository
from parser import parse_packet
from pipeline import IdsPipeline

from tests import bt3_support as support


MIXED_PCAP = support.REPO_ROOT / "TEST" / "assignment_2" / "input_mixed.pcap"


def build_smoke_engine() -> RuleEvaluationEngine:

    config = RuleLoaderConfig(
        rule_files=[support.RULES_DIR / "smoke.rules"],
        base_dir=support.RULES_DIR,
    )

    load_result = RuleLoader(config).load()
    results = RuleParserValidator().parse_many(load_result.rules)
    repository = RuleRepository.from_parse_results(
        results,
        RepositoryConfig(),
    )

    return RuleEvaluationEngine(repository)


def run_pcap(rule_engine=None):

    events: list[dict] = []
    flows: list[dict] = []
    detections: list[dict] = []

    pipeline = IdsPipeline(
        config=PipelineConfig(),
        event_handler=events.append,
        flow_handler=flows.append,
        rule_engine=rule_engine,
        detection_handler=detections.append,
    )

    packet_id = 0

    for packet in read_pcap(MIXED_PCAP):

        packet_id += 1
        event = parse_packet(packet, packet_id)

        if event is not None:

            pipeline.process(event)

    pipeline.flush()

    return pipeline, events, flows, detections


class TC01LoaderIntegrationTestCase(unittest.TestCase):
    """TC01 - comments/blank lines are skipped, candidates keep order/metadata."""

    def test_only_rule_candidates_reach_the_parser(self):

        forwarded: list[str] = []

        config = RuleLoaderConfig(
            rule_files=[support.RULES_DIR / "loading.rules"],
            base_dir=support.RULES_DIR,
        )

        load_result = RuleLoader(config).load(
            handler=lambda candidate: forwarded.append(candidate.rule_ref)
        )

        self.assertEqual(
            forwarded,
            [
                "loading.rules:2",
                "loading.rules:4",
                "loading.rules:6",
            ],
        )
        self.assertEqual(
            [rule.rule_ref for rule in load_result.rules],
            forwarded,
        )
        self.assertEqual(load_result.statistics.lines_skipped_comment, 2)
        self.assertEqual(load_result.statistics.lines_skipped_blank, 1)
        self.assertEqual(load_result.statistics.rules_read, 3)

        results = RuleParserValidator().parse_many(load_result.rules)

        self.assertEqual(
            [result.status for result in results],
            ["valid", "valid", "valid"],
        )
        self.assertEqual(
            [result.rule.sid for result in results],
            [4100001, 4100002, 4100003],
        )
        self.assertEqual(
            [result.rule_ref for result in results],
            forwarded,
        )
        self.assertEqual(
            [result.rule.line_number for result in results],
            [2, 4, 6],
        )
        self.assertEqual(
            [result.rule.source_file for result in results],
            ["loading.rules", "loading.rules", "loading.rules"],
        )


class PipelineIntegrationTestCase(unittest.TestCase):
    """End-to-end: PCAP -> Decoder -> Preprocessor -> Tracker -> Rules."""

    def test_smoke_pcap_generates_expected_detections(self):

        engine = build_smoke_engine()

        pipeline, events, flows, detections = run_pcap(engine)

        self.assertGreater(pipeline.processed_count, 0)
        self.assertGreater(pipeline.flow_count, 0)
        self.assertEqual(pipeline.detection_count, len(detections))

        sids = [detection["sid"] for detection in detections]

        self.assertIn(4101001, sids)
        self.assertIn(4101002, sids)
        self.assertIn(4101003, sids)

        self.assertEqual(len(detections), 3)

        for detection in detections:

            self.assertIn("flow_id", detection)
            self.assertTrue(detection["flow_id"])

            decoded = json.loads(json.dumps(detection))

            self.assertEqual(decoded["sid"], detection["sid"])
            self.assertIn("matched_info", decoded)

        stats = engine.statistics.to_dict()

        self.assertEqual(stats["events_evaluated"], pipeline.processed_count)
        self.assertEqual(stats["detections_generated"], len(detections))

    def test_pipeline_without_rules_keeps_assignment_2_behaviour(self):

        with_rules, with_events, with_flows, detections = run_pcap(
            build_smoke_engine()
        )
        without_rules, plain_events, plain_flows, plain_detections = run_pcap()

        self.assertEqual(
            with_rules.processed_count,
            without_rules.processed_count,
        )
        self.assertEqual(
            with_rules.flow_count,
            without_rules.flow_count,
        )
        self.assertEqual(len(with_events), len(plain_events))
        self.assertEqual(len(with_flows), len(plain_flows))
        self.assertEqual(len(detections), 3)
        self.assertEqual(plain_detections, [])

    def test_detections_are_written_as_valid_jsonl(self):

        engine = build_smoke_engine()

        with tempfile.TemporaryDirectory() as tmp:

            event_path = Path(tmp) / "events.jsonl"
            flow_path = Path(tmp) / "flows.jsonl"
            detection_path = Path(tmp) / "detections.jsonl"

            with JsonlWriter(event_path) as event_writer:

                with JsonlWriter(flow_path) as flow_writer:

                    with JsonlWriter(detection_path) as detection_writer:

                        pipeline = IdsPipeline(
                            config=PipelineConfig(),
                            event_handler=event_writer.write,
                            flow_handler=flow_writer.write,
                            rule_engine=engine,
                            detection_handler=detection_writer.write,
                        )

                        packet_id = 0

                        for packet in read_pcap(MIXED_PCAP):

                            packet_id += 1
                            event = parse_packet(packet, packet_id)

                            if event is not None:

                                pipeline.process(event)

                        pipeline.flush()

            detection_lines = list(read_jsonl(detection_path))
            event_lines = list(read_jsonl(event_path))
            flow_lines = list(read_jsonl(flow_path))

            self.assertEqual(len(detection_lines), 3)
            self.assertGreater(len(event_lines), 0)
            self.assertGreater(len(flow_lines), 0)

            with detection_path.open(encoding="utf-8") as handle:

                for line in handle:

                    self.assertIsInstance(json.loads(line), dict)


if __name__ == "__main__":

    unittest.main()
