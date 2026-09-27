import argparse
import json
from pathlib import Path

from scapy.all import get_if_list

from capture.live import start_live_capture
from capture.pcap import read_pcap
from parser import parse_packet


def write_event(
    event,
    output_file: Path,
) -> None:

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_file.open(
        "a",
        encoding="utf-8",
    ) as f:

        json.dump(
            event.to_dict(),
            f,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        f.write("\n")


def process_pcap(
    pcap_file: str,
    output_file: Path,
) -> None:

    # Avoid accidentally appending old results.
    if output_file.exists():
        output_file.unlink()

    packet_id = 0

    for packet in read_pcap(
        pcap_file
    ):

        packet_id += 1

        event = parse_packet(
            packet,
            packet_id,
        )

        if event is not None:

            write_event(
                event,
                output_file,
            )

    print(
        f"Finished processing "
        f"{packet_id} packets."
    )

    print(
        f"Output: {output_file}"
    )


def process_live(
    interface: str,
    output_file: Path,
    count: int,
) -> None:

    if output_file.exists():
        output_file.unlink()

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

        write_event(
            event,
            output_file,
        )

        print(
            f"[{packet_id}] "
            f"{event.src_ip} -> "
            f"{event.dst_ip} | "
            f"{event.transport.get('protocol', 'UNKNOWN')} | "
            f"{event.application.get('protocol', 'UNKNOWN')}"
        )

    start_live_capture(
        interface=interface,
        callback=handle_packet,
        count=count,
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
            "Packet Capture & Parser for IDS"
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

    output_file = Path(
        args.output
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
        )

        return

    process_live(
        args.interface,
        output_file,
        args.count,
    )


if __name__ == "__main__":
    main()
