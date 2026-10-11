"""
test_baseline.py — Tests for baseline.py learning, persistence, and comparison.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR

from baseline import Baseline, BaselineSnapshot
from parsers import parse_packet, ICMP_ECHO_REQUEST


def _make_syn(src="10.0.0.1", dst="10.0.0.2", dport=80):
    return parse_packet(
        Ether() / IP(src=src, dst=dst) / TCP(sport=50000, dport=dport, flags="S")
    )


def _make_icmp(src="10.0.0.1"):
    return parse_packet(
        Ether() / IP(src=src, dst="10.0.0.2") / ICMP(type=ICMP_ECHO_REQUEST)
    )


def _make_dns_query(src="10.0.0.1", name="example.com"):
    return parse_packet(
        Ether()
        / IP(src=src, dst="8.8.8.8")
        / __import__("scapy.layers.inet", fromlist=["UDP"]).UDP(sport=1234, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=name))
    )


class TestBaselineLearning(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.baseline_file = Path(self.tmpdir) / "baseline.json"
        self.baseline = Baseline(self.baseline_file, learning_duration_seconds=5)

    def test_update_increments_total_packets(self):
        self.baseline.update(_make_syn())
        self.assertEqual(self.baseline.live_total_packets, 1)

    def test_update_tracks_protocols(self):
        self.baseline.update(_make_syn())
        self.baseline.update(_make_icmp())
        counts = self.baseline.live_protocol_counts
        self.assertIn("TCP", counts)
        self.assertIn("ICMP", counts)

    def test_finalize_saves_file(self):
        self.baseline.start_learning()
        for _ in range(3):
            self.baseline.update(_make_syn())
        snapshot = self.baseline.finalize()
        self.assertTrue(self.baseline_file.exists())
        self.assertGreater(snapshot.total_packets, 0)

    def test_finalize_snapshot_contents(self):
        self.baseline.start_learning()
        for port in range(80, 83):
            self.baseline.update(_make_syn(dport=port))
        snapshot = self.baseline.finalize()
        self.assertIn("10.0.0.1", snapshot.tcp_port_diversity)
        self.assertGreater(snapshot.tcp_port_diversity["10.0.0.1"], 0)


class TestBaselinePersistence(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.baseline_file = Path(self.tmpdir) / "baseline.json"

    def test_load_after_save(self):
        b1 = Baseline(self.baseline_file, learning_duration_seconds=5)
        b1.start_learning()
        for _ in range(5):
            b1.update(_make_icmp())
        b1.finalize()

        b2 = Baseline(self.baseline_file, learning_duration_seconds=5)
        loaded = b2.load()
        self.assertTrue(loaded)
        self.assertIsNotNone(b2.stored_snapshot)
        self.assertEqual(b2.stored_snapshot.total_packets, 5)

    def test_load_missing_file_returns_false(self):
        b = Baseline(Path(self.tmpdir) / "missing.json", learning_duration_seconds=5)
        result = b.load()
        self.assertFalse(result)
        self.assertIsNone(b.stored_snapshot)

    def test_load_corrupt_file_returns_false(self):
        self.baseline_file.write_text("THIS IS NOT JSON", encoding="utf-8")
        b = Baseline(self.baseline_file, learning_duration_seconds=5)
        result = b.load()
        self.assertFalse(result)

    def test_reset_deletes_file(self):
        b = Baseline(self.baseline_file, learning_duration_seconds=5)
        b.start_learning()
        b.update(_make_syn())
        b.finalize()
        self.assertTrue(self.baseline_file.exists())
        b.reset()
        self.assertFalse(self.baseline_file.exists())
        self.assertIsNone(b.stored_snapshot)


class TestBaselineComparison(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.baseline_file = Path(self.tmpdir) / "baseline.json"

    def test_no_baseline_returns_no_anomalies(self):
        b = Baseline(self.baseline_file, learning_duration_seconds=5)
        comparison = b.compare()
        self.assertFalse(comparison.has_baseline)
        self.assertEqual(comparison.tcp_diversity_anomalies, {})
        self.assertEqual(comparison.new_hosts, [])

    def test_tcp_diversity_anomaly_detected(self):
        # Create a baseline with 2 ports for 10.0.0.1
        b = Baseline(
            self.baseline_file,
            learning_duration_seconds=5,
            anomaly_multiplier=2.0,
        )
        b.start_learning()
        for port in range(80, 82):   # 2 ports
            b.update(_make_syn(dport=port))
        b.finalize()

        # Now feed many more ports (live data).
        b2 = Baseline(
            self.baseline_file,
            learning_duration_seconds=5,
            anomaly_multiplier=2.0,
        )
        b2.load()
        for port in range(100, 110):  # 10 distinct ports > 2*2=4
            b2.update(_make_syn(dport=port))

        comparison = b2.compare()
        self.assertTrue(comparison.has_baseline)
        self.assertIn("10.0.0.1", comparison.tcp_diversity_anomalies)

    def test_new_host_detected(self):
        b = Baseline(self.baseline_file, learning_duration_seconds=5)
        b.start_learning()
        b.update(_make_syn(src="10.0.0.1"))
        b.finalize()

        b2 = Baseline(self.baseline_file, learning_duration_seconds=5)
        b2.load()
        b2.update(_make_syn(src="10.0.0.99"))  # never seen before

        comparison = b2.compare()
        self.assertIn("10.0.0.99", comparison.new_hosts)

    def test_normal_traffic_no_anomaly(self):
        """Traffic within baseline bounds should not produce anomalies."""
        b = Baseline(
            self.baseline_file,
            learning_duration_seconds=5,
            anomaly_multiplier=2.0,
        )
        b.start_learning()
        for port in range(80, 90):   # 10 ports
            b.update(_make_syn(dport=port))
        b.finalize()

        b2 = Baseline(
            self.baseline_file,
            learning_duration_seconds=5,
            anomaly_multiplier=2.0,
        )
        b2.load()
        # 5 ports — well within 2 × 10 = 20
        for port in range(80, 85):
            b2.update(_make_syn(dport=port))

        comparison = b2.compare()
        self.assertEqual(comparison.tcp_diversity_anomalies, {})


class TestBaselineSnapshotSerialization(unittest.TestCase):
    def test_round_trip(self):
        snap = BaselineSnapshot(
            created_utc="2024-01-01T00:00:00.000Z",
            learning_duration_seconds=300,
            total_packets=100,
            protocol_counts={"TCP": 50, "UDP": 30},
            host_counts={"10.0.0.1": 80},
            tcp_port_diversity={"10.0.0.1": 5},
            icmp_request_counts={"10.0.0.1": 10},
            dns_query_counts={"10.0.0.1": 20},
        )
        d = snap.to_dict()
        restored = BaselineSnapshot.from_dict(d)
        self.assertEqual(restored.total_packets, 100)
        self.assertEqual(restored.protocol_counts["TCP"], 50)
        self.assertEqual(restored.tcp_port_diversity["10.0.0.1"], 5)


if __name__ == "__main__":
    unittest.main()
