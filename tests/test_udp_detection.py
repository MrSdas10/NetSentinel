"""
test_udp_detection.py — Tests for UDP-001 (port diversity detection).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

from config_loader import Config, UdpConfig
from alert_manager import UdpPortDiversityRule
from parsers import parse_packet


def _make_udp(src="10.0.0.1", dst="10.0.0.2", dport=53):
    return parse_packet(
        Ether() / IP(src=src, dst=dst) / UDP(sport=50000, dport=dport)
    )


def _make_config(threshold=5, window=60, excluded=None):
    config = Config()
    config.udp = UdpConfig(
        enabled=True,
        port_diversity_threshold=threshold,
        observation_window_seconds=window,
        excluded_sources=excluded or [],
    )
    return config


class TestUdpAboveThreshold(unittest.TestCase):
    def test_triggers_at_threshold(self):
        config = _make_config(threshold=5)
        rule = UdpPortDiversityRule(config, time_fn=lambda: 0.0)
        evidence = None
        for port in range(1000, 1005):
            evidence = rule.process(_make_udp(dport=port))
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["rule_id"], "UDP-001")

    def test_evidence_fields(self):
        config = _make_config(threshold=3)
        rule = UdpPortDiversityRule(config, time_fn=lambda: 0.0)
        evidence = None
        for port in range(2000, 2003):
            evidence = rule.process(_make_udp(dport=port))
        self.assertIsNotNone(evidence)
        self.assertIn("distinct_dst_ports", evidence)
        self.assertIn("threshold", evidence)
        self.assertIn("source_ip", evidence)


class TestUdpBelowThreshold(unittest.TestCase):
    def test_no_alert_below_threshold(self):
        config = _make_config(threshold=10)
        rule = UdpPortDiversityRule(config, time_fn=lambda: 0.0)
        for port in range(53, 58):
            evidence = rule.process(_make_udp(dport=port))
            self.assertIsNone(evidence)


class TestUdpExcludedSource(unittest.TestCase):
    def test_excluded_source_no_alert(self):
        config = _make_config(threshold=2, excluded=["10.0.0.1"])
        rule = UdpPortDiversityRule(config, time_fn=lambda: 0.0)
        for port in range(1, 100):
            self.assertIsNone(rule.process(_make_udp(src="10.0.0.1", dport=port)))


class TestUdpSlidingWindow(unittest.TestCase):
    def test_old_entries_expire(self):
        current_time = [0.0]

        def clock():
            return current_time[0]

        config = _make_config(threshold=5, window=30)
        rule = UdpPortDiversityRule(config, time_fn=clock)

        for port in range(100, 104):
            rule.process(_make_udp(dport=port))

        current_time[0] = 35.0
        # One more port after expiry — should not trigger.
        evidence = rule.process(_make_udp(dport=200))
        self.assertIsNone(evidence)


class TestUdpDisabledRule(unittest.TestCase):
    def test_disabled_never_triggers(self):
        config = _make_config(threshold=1)
        config.udp.enabled = False
        rule = UdpPortDiversityRule(config, time_fn=lambda: 0.0)
        for port in range(1, 100):
            self.assertIsNone(rule.process(_make_udp(dport=port)))


if __name__ == "__main__":
    unittest.main()
