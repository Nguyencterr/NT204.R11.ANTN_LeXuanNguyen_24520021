"""Generate reproducible Assignment 3 evidence artifacts.

Run from the repository root::

    .venv/bin/python tests/generate_bt3_evidence.py

The script only uses the real loader/parser/repository/pipeline/CLI code paths, so
every JSONL file and log under ``TEST/BT3/evidence/`` can be regenerated.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Make the repository root importable when run as a script from tests/.
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

from core_engine.rule_loader import RuleLoader, RuleLoaderConfig
from core_engine.rule_parser import RuleParserValidator
from core_engine.rule_repository import RepositoryConfig, RuleRepository


REPO_ROOT = Path(__file__).resolve().parents[1]
BT3_ROOT = REPO_ROOT / "TEST" / "BT3"
RULES_DIR = BT3_ROOT / "rules"
EVIDENCE = BT3_ROOT / "evidence"
JSONL_DIR = EVIDENCE / "jsonl"
OTHER_DIR = EVIDENCE / "other"
TEST_LOG_DIR = EVIDENCE / "test_logs"


#: One log per testcase plus the contract/regression suites.
TEST_LOG_TARGETS = {
    "TC01_loader": ["tests.test_assignment3_pipeline.TC01LoaderIntegrationTestCase"],
    "TC01_pipeline": ["tests.test_assignment3_pipeline.PipelineIntegrationTestCase"],
    "TC02": ["tests.test_assignment3_parser.TC02InvalidRuleTestCase"],
    "TC03": ["tests.test_assignment3_parser.TC03UnsupportedKeywordTestCase"],
    "TC04": ["tests.test_assignment3_parser.TC04HeaderParsingTestCase"],
    "TC05": ["tests.test_assignment3_matching.TC05DirectionTestCase"],
    "TC06": ["tests.test_assignment3_repository.TC06IndexerTestCase"],
    "TC07": ["tests.test_assignment3_matching.TC07HeaderShortCircuitTestCase"],
    "TC08": ["tests.test_assignment3_matching.TC08FlowStateTestCase"],
    "TC09": ["tests.test_assignment3_matching.TC09ContentNocaseTestCase"],
    "TC10": ["tests.test_assignment3_matching.TC10OffsetDepthTestCase"],
    "TC11": ["tests.test_assignment3_matching.TC11DistanceWithinTestCase"],
    "TC12": ["tests.test_assignment3_matching.TC12FlagsDsizeTestCase"],
    "TC13": ["tests.test_assignment3_evaluation.TC13MultipleMatchesTestCase"],
    "TC14": ["tests.test_assignment3_evaluation.TC14DetectionEventTestCase"],
    "contract_parser": ["tests.test_assignment3_parser.ParserOptionContractTestCase"],
    "contract_repository": [
        "tests.test_assignment3_repository.RepositoryDiagnosticsTestCase"
    ],
    "contract_evaluation": [
        "tests.test_assignment3_evaluation.EvaluationStatisticsAndIsolationTestCase"
    ],
    "assignment3_suite": [
        "tests.test_assignment3_parser",
        "tests.test_assignment3_repository",
        "tests.test_assignment3_matching",
        "tests.test_assignment3_evaluation",
        "tests.test_assignment3_pipeline",
    ],
}


def _run_and_log(name: str, targets: list[str]) -> None:

    args = [sys.executable, "-m", "unittest", *targets, "-v"]
    completed = subprocess.run(
        args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    lines = [
        "# command: .venv/bin/python -m unittest " + " ".join(targets) + " -v",
        completed.stdout.rstrip() + completed.stderr.rstrip(),
        f"# exit code: {completed.returncode}",
    ]

    (TEST_LOG_DIR / f"run_{name}.log").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def generate_test_logs() -> None:

    TEST_LOG_DIR.mkdir(parents=True, exist_ok=True)

    for name, targets in TEST_LOG_TARGETS.items():

        _run_and_log(name, targets)

    # Full repository regression, including Assignment 1/2 and section 4.1.
    args = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    completed = subprocess.run(
        args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    (TEST_LOG_DIR / "run_full_suite.log").write_text(
        "\n".join(
            [
                "# command: .venv/bin/python -m unittest discover -s tests -v",
                completed.stdout.rstrip() + completed.stderr.rstrip(),
                f"# exit code: {completed.returncode}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict]) -> None:

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as handle:

        for row in rows:

            handle.write(
                json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            )


def generate_parse_evidence() -> None:

    rule_files = sorted(RULES_DIR.glob("*.rules"))

    config = RuleLoaderConfig(
        rule_files=[str(path) for path in rule_files],
        base_dir=RULES_DIR,
    )

    load_result = RuleLoader(config).load()
    parse_results = RuleParserValidator().parse_many(load_result.rules)

    _write_jsonl(
        JSONL_DIR / "parse_results_all_rules.jsonl",
        [result.to_dict() for result in parse_results],
    )

    repository = RuleRepository.from_parse_results(
        parse_results,
        RepositoryConfig(),
    )

    _write_jsonl(
        JSONL_DIR / "repository_diagnostics.jsonl",
        [diagnostic.to_dict() for diagnostic in repository.diagnostics],
    )


def generate_candidate_evidence() -> None:

    config = RuleLoaderConfig(
        rule_files=[str(RULES_DIR / "header_rules.rules")],
        base_dir=RULES_DIR,
    )

    load_result = RuleLoader(config).load()
    parse_results = RuleParserValidator().parse_many(load_result.rules)
    repository = RuleRepository.from_parse_results(
        parse_results,
        RepositoryConfig(),
    )

    queries = [
        {
            "label": "tcp forward any/any",
            "event": {
                "transport_protocol": "TCP",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.20",
                "src_port": 12345,
                "dst_port": 80,
            },
        },
        {
            "label": "tcp reverse for <> CIDR rule",
            "event": {
                "transport_protocol": "TCP",
                "src_ip": "10.0.0.5",
                "dst_ip": "192.168.1.10",
                "src_port": 80,
                "dst_port": 12345,
            },
        },
        {
            "label": "udp dns",
            "event": {
                "transport_protocol": "UDP",
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "src_port": 53000,
                "dst_port": 53,
            },
        },
        {
            "label": "unsupported protocol",
            "event": {
                "transport_protocol": "ICMP",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.20",
                "src_port": None,
                "dst_port": None,
            },
        },
    ]

    rows: list[dict] = []

    for query in queries:

        selection = repository.candidates(query["event"])

        rows.append(
            {
                "query": query["label"],
                "event": query["event"],
                "selection": selection.to_dict(),
            }
        )

    _write_jsonl(JSONL_DIR / "candidate_selection.jsonl", rows)


def run_cli_smoke() -> None:

    JSONL_DIR.mkdir(parents=True, exist_ok=True)
    OTHER_DIR.mkdir(parents=True, exist_ok=True)

    outputs = {
        "events": "TEST/BT3/evidence/jsonl/smoke_events.jsonl",
        "flows": "TEST/BT3/evidence/jsonl/smoke_flows.jsonl",
        "detections": "TEST/BT3/evidence/jsonl/smoke_detections.jsonl",
    }

    args = [
        sys.executable,
        "main.py",
        "--pcap",
        "TEST/assignment_2/input_mixed.pcap",
        "--rules",
        "TEST/BT3/rules/smoke.rules",
        "--output",
        outputs["events"],
        "--flows-output",
        outputs["flows"],
        "--detections-output",
        outputs["detections"],
    ]

    completed = subprocess.run(
        args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    log_lines = [
        "# command: " + " ".join(args),
        f"# exit code: {completed.returncode}",
        completed.stdout.rstrip(),
    ]

    if completed.stderr.strip():

        log_lines.extend(
            ["# stderr:", completed.stderr.rstrip()]
        )

    (OTHER_DIR / "run_cli_smoke.log").write_text(
        "\n".join(log_lines) + "\n",
        encoding="utf-8",
    )

    print("\n".join(log_lines))


def run_cli_without_rules() -> None:

    args = [
        sys.executable,
        "main.py",
        "--pcap",
        "TEST/assignment_2/input_mixed.pcap",
        "--output",
        "TEST/BT3/evidence/jsonl/no_rules_events.jsonl",
        "--flows-output",
        "TEST/BT3/evidence/jsonl/no_rules_flows.jsonl",
    ]

    completed = subprocess.run(
        args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    lines = [
        "# command: " + " ".join(args),
        f"# exit code: {completed.returncode}",
        completed.stdout.rstrip(),
    ]

    if completed.stderr.strip():

        lines.extend(["# stderr:", completed.stderr.rstrip()])

    (OTHER_DIR / "run_cli_no_rules.log").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print("\n".join(lines))


def main() -> None:

    generate_test_logs()
    generate_parse_evidence()
    generate_candidate_evidence()
    run_cli_smoke()
    run_cli_without_rules()


if __name__ == "__main__":

    main()
