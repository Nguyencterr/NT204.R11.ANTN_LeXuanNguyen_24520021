"""Generate reproducible Assignment 3 evidence artifacts.

Run from the repository root::

    .venv/bin/python tests/generate_bt3_evidence.py

The script only uses the real loader/parser/repository/CLI code paths, so every
JSONL file and log under ``TEST/BT3/evidence/`` can be regenerated.
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

    generate_parse_evidence()
    generate_candidate_evidence()
    run_cli_smoke()
    run_cli_without_rules()


if __name__ == "__main__":

    main()
