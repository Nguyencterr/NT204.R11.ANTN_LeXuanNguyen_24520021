import argparse
from pathlib import Path

from scapy.all import get_if_list

from capture.live import start_live_capture
from capture.pcap import read_pcap
from common.jsonl import JsonlWriter, reset_file
from config import (
    INVALID_EVENT_POLICIES,
    PipelineConfig,
)
from parser import parse_packet
from pipeline import IdsPipeline


def build_pipeline(
    config: PipelineConfig,
    output_file: Path,
    flows_output: Path,
) -> tuple[IdsPipeline, JsonlWriter, JsonlWriter]:
    """Create a pipeline that writes events and flows to separate JSONL files."""

    # Avoid accidentally appending old results.
    reset_file(output_file)
    reset_file(flows_output)

    event_writer = JsonlWriter(output_file)
    flow_writer = JsonlWriter(flows_output)

    pipeline = IdsPipeline(
        config=config,
        event_handler=event_writer.write,
        flow_handler=flow_writer.write,
    )

    return pipeline, event_writer, flow_writer


def process_pcap(
    pcap_file: str,
    output_file: Path,
    flows_output: Path,
    config: PipelineConfig,
) -> None:

    pipeline, event_writer, flow_writer = build_pipeline(
        config,
        output_file,
        flows_output,
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

        event_writer.close()
        flow_writer.close()

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


def process_live(
    interface: str,
    output_file: Path,
    flows_output: Path,
    count: int,
    config: PipelineConfig,
) -> None:

    pipeline, event_writer, flow_writer = build_pipeline(
        config,
        output_file,
        flows_output,
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

        event_writer.close()
        flow_writer.close()

    print(
        f"Events: {output_file} "
        f"({pipeline.processed_count} written, "
        f"{pipeline.skipped_count} skipped)"
    )

    print(
        f"Flows:  {flows_output} "
        f"({pipeline.flow_count} finalized)"
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
            "(Decoder -> Preprocessor -> Flow Tracker)"
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

    output_file = Path(
        args.output
    )

    flows_output = Path(
        args.flows_output
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
        )

        return

    process_live(
        args.interface,
        output_file,
        flows_output,
        args.count,
        config,
    )


if __name__ == "__main__":
    main()
