"""Assignment 2 Flow/Connection Tracker tests (T07-T13)."""

import unittest

from config import PipelineConfig
from flow import FlowTracker


TCP_EVENT_TEMPLATE = {
    "transport": {"protocol": "TCP"},
    "application": {"protocol": "UNKNOWN"},
}


def tcp_event(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    flags: str,
    ts: float,
    payload: bytes = b"",
    packet_length: int = 54,
    app: str = "UNKNOWN",
) -> dict:

    event = dict(TCP_EVENT_TEMPLATE)

    event.update(
        {
            "packet_id": 1,
            "timestamp": ts,
            "src_ip": src,
            "dst_ip": dst,
            "transport": {
                "protocol": "TCP",
                "src_port": sport,
                "dst_port": dport,
                "flags": flags,
            },
            "application": {"protocol": app},
            "payload_length": len(payload),
            "packet_length": packet_length,
        }
    )

    return event


def udp_event(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    ts: float,
    payload: bytes = b"",
    packet_length: int = 42,
) -> dict:

    return {
        "packet_id": 1,
        "timestamp": ts,
        "src_ip": src,
        "dst_ip": dst,
        "transport": {
            "protocol": "UDP",
            "src_port": sport,
            "dst_port": dport,
        },
        "application": {"protocol": "UNKNOWN"},
        "payload_length": len(payload),
        "packet_length": packet_length,
    }


class TrackerHandshakeTestCase(unittest.TestCase):
    """T07 - TCP three-way handshake."""

    def setUp(self):

        self.tracker = FlowTracker()

    def test_handshake_reaches_established(self):

        self.assertEqual(
            self.tracker.process(
                tcp_event(
                    "10.0.0.1", "10.0.0.2",
                    1000, 80, "S", 1.0,
                )
            ),
            [],
        )

        self.assertEqual(
            self.tracker.process(
                tcp_event(
                    "10.0.0.2", "10.0.0.1",
                    80, 1000, "SA", 1.1,
                )
            ),
            [],
        )

        self.assertEqual(
            self.tracker.process(
                tcp_event(
                    "10.0.0.1", "10.0.0.2",
                    1000, 80, "A", 1.2,
                )
            ),
            [],
        )

        flow = self.tracker.flush()[0]

        self.assertEqual(flow["state"], "ESTABLISHED")
        self.assertEqual(flow["packet_count"], 3)
        self.assertEqual(flow["SYN_count"], 2)
        self.assertEqual(flow["ACK_count"], 2)
        self.assertEqual(flow["forward_packet_count"], 2)
        self.assertEqual(flow["backward_packet_count"], 1)

    def test_syn_counts_each_syn_packet(self):

        self.tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 10, 20, "S", 1.0)
        )
        self.tracker.process(
            tcp_event("2.2.2.2", "1.1.1.1", 20, 10, "SA", 1.1)
        )

        flow = self.tracker.flush()[0]

        self.assertEqual(flow["SYN_count"], 2)


class TrackerBidirectionalTestCase(unittest.TestCase):
    """T08 - reversed endpoints map to the same flow with directions."""

    def test_reversed_endpoints_same_flow(self):

        tracker = FlowTracker()

        tracker.process(
            tcp_event(
                "10.0.0.1", "10.0.0.2",
                5000, 443, "PA", 1.0,
                payload=b"hello",
                packet_length=60,
            )
        )

        tracker.process(
            tcp_event(
                "10.0.0.2", "10.0.0.1",
                443, 5000, "PA", 1.1,
                payload=b"world",
                packet_length=60,
            )
        )

        self.assertEqual(tracker.active_flow_count(), 1)

        flow = tracker.flush()[0]

        self.assertEqual(flow["forward_packet_count"], 1)
        self.assertEqual(flow["backward_packet_count"], 1)
        self.assertEqual(flow["forward_byte_count"], 60)
        self.assertEqual(flow["backward_byte_count"], 60)
        self.assertEqual(flow["packet_count"], 2)
        self.assertEqual(flow["byte_count"], 120)


class TrackerCloseTestCase(unittest.TestCase):
    """T09 - FIN/ACK close and RST behavior."""

    def test_fin_both_directions_closes_immediately(self):

        tracker = FlowTracker()

        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 100, 200, "A", 1.0)
        )
        tracker.process(
            tcp_event("2.2.2.2", "1.1.1.1", 200, 100, "A", 1.1)
        )

        records = tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 100, 200, "FA", 1.2)
        )

        self.assertEqual(records, [])
        self.assertEqual(tracker.active_flow_count(), 1)

        records = tracker.process(
            tcp_event("2.2.2.2", "1.1.1.1", 200, 100, "FA", 1.3)
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "CLOSED")
        self.assertEqual(records[0]["finalization_reason"], "closed")
        self.assertEqual(records[0]["FIN_count"], 2)
        self.assertEqual(tracker.active_flow_count(), 0)

    def test_fin_moves_to_closing(self):

        tracker = FlowTracker()

        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 100, 200, "A", 1.0)
        )

        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 100, 200, "FA", 1.1)
        )

        active = list(tracker.flows.values())[0]

        self.assertEqual(active.state, "CLOSING")

    def test_rst_is_terminal(self):

        tracker = FlowTracker()

        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 100, 200, "A", 1.0)
        )

        self.assertEqual(tracker.active_flow_count(), 1)

        records = tracker.process(
            tcp_event("2.2.2.2", "1.1.1.1", 200, 100, "R", 1.1)
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "RESET")
        self.assertEqual(records[0]["finalization_reason"], "reset")
        self.assertEqual(records[0]["RST_count"], 1)
        self.assertEqual(tracker.active_flow_count(), 0)


class TrackerUdpTestCase(unittest.TestCase):
    """T10 - bidirectional UDP query/response."""

    def test_udp_query_response_single_flow(self):

        tracker = FlowTracker()

        tracker.process(
            udp_event(
                "192.168.1.1", "8.8.8.8",
                53000, 53, 1.0,
                payload=b"\x12\x34",
            )
        )

        tracker.process(
            udp_event(
                "8.8.8.8", "192.168.1.1",
                53, 53000, 1.1,
                payload=b"\x56\x78",
            )
        )

        self.assertEqual(tracker.active_flow_count(), 1)

        flow = tracker.flush()[0]

        self.assertEqual(flow["protocol"], "UDP")
        self.assertEqual(flow["state"], "OPEN")
        self.assertEqual(flow["packet_count"], 2)
        self.assertEqual(flow["forward_packet_count"], 1)
        self.assertEqual(flow["backward_packet_count"], 1)
        self.assertEqual(flow["byte_count"], 84)


class TrackerConcurrentTestCase(unittest.TestCase):
    """T11 - concurrent flows with distinct endpoints stay distinct."""

    def test_distinct_5_tuples_distinct_flows(self):

        tracker = FlowTracker()

        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 1000, 80, "S", 1.0)
        )
        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 2000, 80, "S", 1.0)
        )
        tracker.process(
            tcp_event("3.3.3.3", "2.2.2.2", 3000, 80, "S", 1.0)
        )

        self.assertEqual(tracker.active_flow_count(), 3)

        flows = tracker.flush()

        self.assertEqual(len(flows), 3)
        self.assertEqual(
            len({f["flow_id"] for f in flows}),
            3,
        )

    def test_same_flow_updates_instead_of_duplicating(self):

        tracker = FlowTracker()

        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 1000, 80, "S", 1.0)
        )
        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 1000, 80, "A", 1.5)
        )

        self.assertEqual(tracker.active_flow_count(), 1)

        flow = tracker.flush()[0]

        self.assertEqual(flow["packet_count"], 2)


class TrackerTimeoutTestCase(unittest.TestCase):
    """T12 - idle timeout finalizes and removes flows."""

    def test_tcp_idle_timeout(self):

        config = PipelineConfig(
            tcp_idle_timeout=10.0,
            udp_idle_timeout=5.0,
        )

        tracker = FlowTracker(config)

        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 1000, 80, "S", 100.0)
        )

        self.assertEqual(tracker.active_flow_count(), 1)

        # New packet long after the idle window: old flow expires first.
        records = tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 1000, 80, "A", 111.0)
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["finalization_reason"], "timeout")
        self.assertEqual(records[0]["state"], "HANDSHAKE")

        # And the new packet belongs to a brand-new flow with a new id.
        self.assertEqual(tracker.active_flow_count(), 1)

        flows = tracker.flush()

        self.assertEqual(len(flows), 1)
        self.assertNotEqual(flows[0]["flow_id"], records[0]["flow_id"])

    def test_udp_idle_timeout(self):

        config = PipelineConfig(
            tcp_idle_timeout=10.0,
            udp_idle_timeout=5.0,
        )

        tracker = FlowTracker(config)

        tracker.process(
            udp_event("1.1.1.1", "2.2.2.2", 53000, 53, 100.0)
        )

        records = tracker.process(
            udp_event("1.1.1.1", "2.2.2.2", 53000, 53, 106.0)
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["finalization_reason"], "timeout")

    def test_within_timeout_no_expiry(self):

        tracker = FlowTracker(
            PipelineConfig(tcp_idle_timeout=10.0)
        )

        tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 1000, 80, "S", 100.0)
        )

        records = tracker.process(
            tcp_event("1.1.1.1", "2.2.2.2", 1000, 80, "A", 105.0)
        )

        self.assertEqual(records, [])
        self.assertEqual(tracker.active_flow_count(), 1)


class TrackerStatsTestCase(unittest.TestCase):
    """T13 - counters, byte totals and duration."""

    def test_counters_and_duration(self):

        config = PipelineConfig(tcp_idle_timeout=60.0)
        tracker = FlowTracker(config)

        tracker.process(
            tcp_event(
                "1.1.1.1", "2.2.2.2",
                1000, 80, "S", 10.0,
                packet_length=60,
            )
        )
        tracker.process(
            tcp_event(
                "2.2.2.2", "1.1.1.1",
                80, 1000, "SA", 10.5,
                packet_length=60,
            )
        )
        tracker.process(
            tcp_event(
                "1.1.1.1", "2.2.2.2",
                1000, 80, "A", 11.0,
                packet_length=60,
            )
        )
        tracker.process(
            tcp_event(
                "1.1.1.1", "2.2.2.2",
                1000, 80, "PA", 11.5,
                payload=b"GET / HTTP/1.1",
                packet_length=74,
                app="HTTP",
            )
        )

        flow = tracker.flush()[0]

        self.assertEqual(flow["protocol"], "TCP")
        self.assertEqual(flow["application_protocol"], "HTTP")
        self.assertEqual(flow["packet_count"], 4)
        self.assertEqual(flow["byte_count"], 60 + 60 + 60 + 74)
        self.assertEqual(flow["byte_count_basis"], "packet")
        self.assertEqual(flow["forward_packet_count"], 3)
        self.assertEqual(flow["backward_packet_count"], 1)
        self.assertEqual(flow["forward_byte_count"], 60 + 60 + 74)
        self.assertEqual(flow["backward_byte_count"], 60)
        self.assertEqual(flow["SYN_count"], 2)
        self.assertEqual(flow["ACK_count"], 3)
        self.assertAlmostEqual(flow["duration"], 1.5)
        self.assertEqual(flow["start_time"], 10.0)
        self.assertEqual(flow["last_seen"], 11.5)

    def test_unknown_does_not_overwrite_known_app(self):

        tracker = FlowTracker()

        tracker.process(
            tcp_event(
                "1.1.1.1", "2.2.2.2",
                1000, 80, "PA", 1.0,
                app="HTTP",
            )
        )

        tracker.process(
            tcp_event(
                "2.2.2.2", "1.1.1.1",
                80, 1000, "PA", 1.1,
                app="UNKNOWN",
            )
        )

        flow = tracker.flush()[0]

        self.assertEqual(flow["application_protocol"], "HTTP")

    def test_payload_fallback_basis(self):

        tracker = FlowTracker()

        event = tcp_event(
            "1.1.1.1", "2.2.2.2",
            1000, 80, "A", 1.0,
            payload=b"12345",
        )

        event.pop("packet_length", None)

        tracker.process(event)

        flow = tracker.flush()[0]

        self.assertEqual(flow["byte_count"], 5)
        self.assertEqual(flow["byte_count_basis"], "payload")


if __name__ == "__main__":
    unittest.main()