"""
test_tcp_detection.py — Tests for TCP-001 (port scan detection).

Uses a controllable clock to avoid real-time delays.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from config_loader import Config, TcpConfig
from alert_manager import TcpPortScanRule
from parsers import parse_packet


def _make_syn(src="10.0.0.1", dst="10.0.0.2", dport=80):
    return parse_packet(
        Ether() / IP(src=src, dst=dst) / TCP(sport=50000, dport=dport, flags="S")
    )


def _make_config(threshold=5, window=60, excluded=None):
    config = Config()
    config.tcp = TcpConfig(
        enabled=True,
        syn_port_threshold=threshold,
        observation_window_seconds=window,
        excluded_sources=excluded or [],
    )
    return config


class TestTcpPortScanAboveThreshold(unittest.TestCase):
    """TCP-001 MUST trigger when distinct ports exceed the threshold."""

    def test_triggers_above_threshold(self):
        fake_time = [0.0]

        def clock():
            return fake_time[0]

        config = _make_config(threshold=5, window=60)
        rule = TcpPortScanRule(config, time_fn=clock)

        # Send SYNs to 5 distinct ports; alert should appear on the 5th.
        results = []
        for port in range(80, 85):  # ports 80–84 = 5 distinct
            pkt = _make_syn(dport=port)
            evidence = rule.process(pkt)
            results.append(evidence)

        # At least the last call should have produced evidence.
        self.assertIsNotNone(results[-1])
        self.assertEqual(results[-1]["rule_id"], "TCP-001")
        self.assertGreaterEqual(results[-1]["distinct_dst_ports"], 5)

    def test_evidence_contains_required_fields(self):
        fake_time = [0.0]
        config = _make_config(threshold=3)
        rule = TcpPortScanRule(config, time_fn=lambda: fake_time[0])

        evidence = None
        for port in range(100, 104):
            evidence = rule.process(_make_syn(dport=port))

        self.assertIsNotNone(evidence)
        for field in ("distinct_dst_ports", "threshold",
                      "observation_window_seconds", "source_ip"):
            self.assertIn(field, evidence, f"Missing field: {field}")


class TestTcpPortScanBelowThreshold(unittest.TestCase):
    """TCP-001 must NOT trigger below the threshold."""

    def test_no_alert_below_threshold(self):
        config = _make_config(threshold=10)
        rule = TcpPortScanRule(config, time_fn=lambda: 0.0)

        for port in range(80, 85):  # only 5 ports, threshold is 10
            evidence = rule.process(_make_syn(dport=port))
            self.assertIsNone(evidence)

    def test_single_syn_no_alert(self):
        config = _make_config(threshold=5)
        rule = TcpPortScanRule(config, time_fn=lambda: 0.0)
        evidence = rule.process(_make_syn(dport=443))
        self.assertIsNone(evidence)


class TestTcpExcludedSource(unittest.TestCase):
    def test_excluded_source_never_triggers(self):
        config = _make_config(threshold=2, excluded=["10.0.0.1"])
        rule = TcpPortScanRule(config, time_fn=lambda: 0.0)
        for port in range(80, 90):
            evidence = rule.process(_make_syn(src="10.0.0.1", dport=port))
            self.assertIsNone(evidence)


class TestTcpSlidingWindowExpiry(unittest.TestCase):
    """Ports seen before the window should not count."""

    def test_old_ports_expire_from_window(self):
        current_time = [0.0]

        def clock():
            return current_time[0]

        config = _make_config(threshold=5, window=30)
        rule = TcpPortScanRule(config, time_fn=clock)

        # Add 4 ports at t=0
        for port in range(80, 84):
            rule.process(_make_syn(dport=port))

        # Advance time past the window.
        current_time[0] = 31.0

        # Add 1 more port — should not trigger because the old ones expired.
        evidence = rule.process(_make_syn(dport=90))
        self.assertIsNone(evidence)


class TestTcpSynAckNotCounted(unittest.TestCase):
    """SYN-ACK packets must not be counted as port scan indicators."""

    def test_syn_ack_not_counted(self):
        config = _make_config(threshold=3)
        rule = TcpPortScanRule(config, time_fn=lambda: 0.0)

        for port in range(80, 90):
            pkt = parse_packet(
                Ether()
                / IP(src="10.0.0.1", dst="10.0.0.2")
                / TCP(sport=50000, dport=port, flags="SA")
            )
            evidence = rule.process(pkt)
            self.assertIsNone(evidence)


class TestTcpDisabledRule(unittest.TestCase):
    def test_disabled_never_triggers(self):
        config = _make_config(threshold=1)
        config.tcp.enabled = False
        rule = TcpPortScanRule(config, time_fn=lambda: 0.0)
        for port in range(80, 90):
            self.assertIsNone(rule.process(_make_syn(dport=port)))


if __name__ == "__main__":
    unittest.main()
