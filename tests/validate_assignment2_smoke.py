"""Validate the Assignment 2 smoke-test JSONL outputs.

Reads the event and flow JSONL produced by main.py, checks every line is
independently parseable JSON, and prints a compact summary that the reports
cite as evidence. No values are hard-coded: everything is derived from the
actual files.

    .venv/bin/python tests/validate_assignment2_smoke.py \
        TEST/assignment_2/evidence/smoke_events.jsonl \
        TEST/assignment_2/evidence/smoke_flows.jsonl
"""

import json
import sys
from pathlib import Path


def main() -> int:

    if len(sys.argv) != 3:

        print(
            "usage: validate_assignment2_smoke.py <events.jsonl> <flows.jsonl>"
        )

        return 2

    events_path = Path(sys.argv[1])
    flows_path = Path(sys.argv[2])

    events = _load(events_path)
    flows = _load(flows_path)

    if events is None or flows is None:

        return 1

    print(f"events file: {events_path}")
    print(f"  lines parsed OK: {len(events)}")
    print(f"flows file:  {flows_path}")
    print(f"  lines parsed OK: {len(flows)}")

    print("\n-- flows --")

    for flow in flows:

        print(
            f"{flow['state']:<12} {flow['protocol']:<4} "
            f"{flow['application_protocol']:<8} "
            f"pkts={flow['packet_count']} "
            f"fwd={flow['forward_packet_count']} "
            f"bwd={flow['backward_packet_count']} "
            f"bytes={flow['byte_count']} "
            f"syn={flow['SYN_count']} ack={flow['ACK_count']} "
            f"fin={flow['FIN_count']} rst={flow['RST_count']} "
            f"reason={flow['finalization_reason']}"
        )

    print("\n-- decoded highlights --")

    for event in events:

        decoded = event.get("decoded") or {}

        http = decoded.get("http") or {}

        if http.get("raw_uri") and http.get("decoded_uri") != http.get("raw_uri"):

            print(
                f"T01 packet_id={event['packet_id']} "
                f"raw={http['raw_uri']!r} decoded={http['decoded_uri']!r}"
            )

        html = decoded.get("html") or {}

        if html.get("changed"):

            print(
                f"T02 packet_id={event['packet_id']} "
                f"html_decoded={html['decoded_text']!r}"
            )

        mime = decoded.get("mime") or {}

        if mime.get("decoded_body"):

            print(
                f"T03 packet_id={event['packet_id']} "
                f"{mime['transfer_encoding']} "
                f"body={mime['decoded_body']!r} status={mime['status']}"
            )

        text = decoded.get("text") or {}

        if text.get("status") == "partial":

            print(
                f"T04 packet_id={event['packet_id']} "
                f"text_status={text['status']} "
                f"decode_status={event.get('decode_status')}"
            )

    return 0


def _load(path: Path):

    if not path.exists():

        print(f"missing file: {path}")

        return None

    records = []

    bad = 0

    with path.open("r", encoding="utf-8") as handle:

        for line_number, line in enumerate(handle, start=1):

            line = line.strip()

            if not line:
                continue

            try:

                parsed = json.loads(line)

            except json.JSONDecodeError as exc:

                bad += 1

                print(f"  line {line_number}: JSON ERROR: {exc}")

                continue

            records.append(parsed)

    if bad:

        print(f"  {bad} malformed line(s) in {path}")

        return None

    return records


if __name__ == "__main__":
    raise SystemExit(main())