import argparse
import sys
from pathlib import Path

from scapy.all import get_if_list

from capture.live import start_live_capture
from capture.pcap import read_pcap
from common.jsonl import JsonlWriter, reset_file
from config import (
    INVALID_EVENT_POLICIES,
    PipelineConfig,
)
from core_engine.evaluation import RuleEvaluationEngine
from core_engine.rule_loader import (
    RuleLoader,
    RuleLoaderConfig,
    RuleLoaderConfigError,
)
from core_engine.rule_parser import RuleParserValidator
from core_engine.rule_repository import (
    DUPLICATE_SID_POLICIES,
    DUPLICATE_SID_REJECT,
    RepositoryConfig,
    RuleRepository,
)
from parser import parse_packet
from pipeline import IdsPipeline


def expand_rule_paths(paths: list[str] | None) -> list[str]:
    """Expand files/directories into an ordered list of rule files."""

    expanded: list[str] = []

    for raw in paths or []:

        path = Path(raw)

        if path.is_dir():

            expanded.extend(
                str(candidate)
                for candidate in sorted(path.glob("*.rules"))
            )

        else:

            # Keep missing paths so the loader reports FILE_NOT_FOUND with
            # source metadata instead of silently dropping the input.
            expanded.append(raw)

    return expanded


def build_rule_engine(
    rule_paths: list[str] | None,
    rule_config: str | None,
    duplicate_sid_policy: str,
) -> RuleEvaluationEngine | None:
    """Load rules, parse them and build the Assignment 3 evaluation engine."""

    if rule_config:

        config = RuleLoaderConfig.from_json_file(rule_config)

    else:

        files = expand_rule_paths(rule_paths)

        if not files:

            return None

        config = RuleLoaderConfig(rule_files=files)

    load_result = RuleLoader(config).load()

    for warning in load_result.warnings:

        if warning.severity in ("warning", "error"):

            print(f"[rules] {warning}", file=sys.stderr)

    parser = RuleParserValidator()

    parse_results = parser.parse_many(load_result.rules)

    for result in parse_results:

        if not result.is_valid:

            print(
                f"[rules] {result.status.upper()} "
                f"{result.rule_ref or '<unknown>'}: {result.reason}",
                file=sys.stderr,
            )

    repository = RuleRepository(
        RepositoryConfig(duplicate_sid_policy=duplicate_sid_policy)
    )
    repository.add_results(parse_results)

    for diagnostic in repository.diagnostics:

        print(
            f"[rules] {diagnostic.code} "
            f"{diagnostic.rule_ref or '<unknown>'}: {diagnostic.message}",
            file=sys.stderr,
        )

    stats = repository.statistics()

    print(
        "Rules: "
        f"{stats['parse_results']} candidate(s), "
        f"{stats['valid']} valid, "
        f"{stats['invalid']} invalid, "
        f"{stats['unsupported']} unsupported"
    )

    return RuleEvaluationEngine(repository)


def build_pipeline(
    config: PipelineConfig,
    output_file: Path,
    flows_output: Path,
    rule_engine: RuleEvaluationEngine | None = None,
    detections_output: Path | None = None,
) -> tuple[
    IdsPipeline,
    JsonlWriter,
    JsonlWriter,
    JsonlWriter | None,
]:
    """Create a pipeline that writes events, flows and detections separately."""

    # Avoid accidentally appending old results.
    reset_file(output_file)
    reset_file(flows_output)

    event_writer = JsonlWriter(output_file)
    flow_writer = JsonlWriter(flows_output)

    detection_writer: JsonlWriter | None = None

    if rule_engine is not None:

        if detections_output is None:

            detections_output = Path("output/detections.jsonl")

        reset_file(detections_output)

        detection_writer = JsonlWriter(detections_output)

    pipeline = IdsPipeline(
        config=config,
        event_handler=event_writer.write,
        flow_handler=flow_writer.write,
        rule_engine=rule_engine,
        detection_handler=(
            detection_writer.write
            if detection_writer is not None
            else None
        ),
    )

    return pipeline, event_writer, flow_writer, detection_writer


def _close_writers(*writers: JsonlWriter | None) -> None:

    for writer in writers:

        if writer is not None:

            writer.close()


def process_pcap(
    pcap_file: str,
    output_file: Path,
    flows_output: Path,
    config: PipelineConfig,
    rule_engine: RuleEvaluationEngine | None = None,
    detections_output: Path | None = None,
) -> None:

    pipeline, event_writer, flow_writer, detection_writer = build_pipeline(
        config,
        output_file,
        flows_output,
        rule_engine,
        detections_output,
    )

    packet_id = 0

    try:

        for packet in read_pcap(pcap_file):

            packet_id += 1

            event = parse_packet(
                packet,
                packet_id,
            )

            if event is not None:

                pipeline.process(event)

        pipeline.flush()

    finally:

        _close_writers(event_writer, flow_writer, detection_writer)

    print(
        f"Finished processing "
        f"{packet_id} packets."
    )

    print(
        f"Events: {output_file} "
        f"({pipeline.processed_count} written, "
        f"{pipeline.skipped_count} skipped)"
    )

    print(
        f"Flows:  {flows_output} "
        f"({pipeline.flow_count} finalized)"
    )

    if rule_engine is not None:

        print(
            f"Detections: {detections_output} "
            f"({pipeline.detection_count} written)"
        )

        print(
            "Rule evaluation: "
            f"{rule_engine.statistics.to_dict()}"
        )


def process_live(
    interface: str,
    output_file: Path,
    flows_output: Path,
    count: int,
    config: PipelineConfig,
    rule_engine: RuleEvaluationEngine | None = None,
    detections_output: Path | None = None,
) -> None:

    pipeline, event_writer, flow_writer, detection_writer = build_pipeline(
        config,
        output_file,
        flows_output,
        rule_engine,
        detections_output,
    )

    packet_id = 0

    def handle_packet(packet):

        nonlocal packet_id

        packet_id += 1

        event = parse_packet(
            packet,
            packet_id,
        )

        if event is None:
            return

        processed = pipeline.process(event)

        if processed is None:
            return

        print(
            f"[{packet_id}] "
            f"{processed.get('src_ip')} -> "
            f"{processed.get('dst_ip')} | "
            f"{processed.get('transport_protocol', 'UNKNOWN')} | "
            f"{processed.get('application_protocol', 'UNKNOWN')}"
        )

    try:

        start_live_capture(
            interface=interface,
            callback=handle_packet,
            count=count,
        )

    except KeyboardInterrupt:

        print("\nCapture interrupted. Flushing active flows...")

    finally:

        pipeline.flush()

        _close_writers(event_writer, flow_writer, detection_writer)

    print(
        f"Events: {output_file} "
        f"({pipeline.processed_count} written, "
        f"{pipeline.skipped_count} skipped)"
    )

    print(
        f"Flows:  {flows_output} "
        f"({pipeline.flow_count} finalized)"
    )

    if rule_engine is not None:

        print(
            f"Detections: {detections_output} "
            f"({pipeline.detection_count} written)"
        )

        print(
            "Rule evaluation: "
            f"{rule_engine.statistics.to_dict()}"
        )


def list_interfaces() -> None:

    print("Available interfaces:")

    for interface in get_if_list():

        print(
            f" - {interface}"
        )


def build_parser():

    parser = argparse.ArgumentParser(
        description=(
            "Packet Capture & Parser for IDS "
            "(Decoder -> Preprocessor -> Flow Tracker -> Rule Engine)"
        )
    )

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--interface",
        help="Network interface for live capture",
    )

    group.add_argument(
        "--pcap",
        help="PCAP file to parse",
    )

    parser.add_argument(
        "--output",
        default="output/events.jsonl",
        help="Event JSONL output path",
    )

    parser.add_argument(
        "--flows-output",
        default="output/flows.jsonl",
        help="Finalized flow JSONL output path",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="0 = unlimited live capture",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
    )

    parser.add_argument(
        "--tcp-idle-timeout",
        type=float,
        default=PipelineConfig.tcp_idle_timeout,
        help="TCP idle timeout in seconds (default: %(default)s)",
    )

    parser.add_argument(
        "--udp-idle-timeout",
        type=float,
        default=PipelineConfig.udp_idle_timeout,
        help="UDP idle timeout in seconds (default: %(default)s)",
    )

    parser.add_argument(
        "--max-decoded-size",
        type=int,
        default=PipelineConfig.max_decoded_size,
        help="Max decoded string size in characters (default: %(default)s)",
    )

    parser.add_argument(
        "--max-payload-size",
        type=int,
        default=PipelineConfig.max_payload_size,
        help="Max raw payload size handled by the Decoder (default: %(default)s)",
    )

    parser.add_argument(
        "--invalid-event-policy",
        choices=INVALID_EVENT_POLICIES,
        default=PipelineConfig.invalid_event_policy,
        help="Handling of invalid/unsupported events (default: %(default)s)",
    )

    parser.add_argument(
        "--rules",
        action="append",
        metavar="PATH",
        help=(
            "Assignment 3 rule file or directory (repeatable). "
            "Directories are expanded to *.rules in sorted order."
        ),
    )

    parser.add_argument(
        "--rule-config",
        metavar="PATH",
        help="JSON rule loader configuration (section 4.1)",
    )

    parser.add_argument(
        "--detections-output",
        default="output/detections.jsonl",
        help="Detection Event JSONL output path (default: %(default)s)",
    )

    parser.add_argument(
        "--duplicate-sid-policy",
        choices=DUPLICATE_SID_POLICIES,
        default=DUPLICATE_SID_REJECT,
        help=(
            "Policy for duplicate SID values (default: %(default)s); "
            "duplicates are never overwritten silently"
        ),
    )

    return parser


def main():

    args = build_parser().parse_args()

    if args.list_interfaces:

        list_interfaces()
        return

    if not args.interface and not args.pcap:

        print(
            "Error: specify "
            "--interface or --pcap"
        )

        return

    config = PipelineConfig(
        tcp_idle_timeout=args.tcp_idle_timeout,
        udp_idle_timeout=args.udp_idle_timeout,
        max_decoded_size=args.max_decoded_size,
        max_payload_size=args.max_payload_size,
        invalid_event_policy=args.invalid_event_policy,
    )

    try:

        rule_engine = build_rule_engine(
            args.rules,
            args.rule_config,
            args.duplicate_sid_policy,
        )

    except RuleLoaderConfigError as exc:

        print(f"Rule configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)

    output_file = Path(
        args.output
    )

    flows_output = Path(
        args.flows_output
    )

    detections_output = Path(
        args.detections_output
    )

    if args.pcap:

        pcap_path = Path(
            args.pcap
        )

        if not pcap_path.exists():

            raise FileNotFoundError(
                f"PCAP file not found: "
                f"{args.pcap}"
            )

        process_pcap(
            args.pcap,
            output_file,
            flows_output,
            config,
            rule_engine,
            detections_output,
        )

        return

    process_live(
        args.interface,
        output_file,
        flows_output,
        args.count,
        config,
        rule_engine,
        detections_output,
    )


if __name__ == "__main__":
    main()
