"""
test_icmp_detection.py — Tests for ICMP-001 (echo request rate detection).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP

from config_loader import Config, IcmpConfig
from alert_manager import IcmpRateRule
from parsers import parse_packet, ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY


def _make_request(src="10.0.0.1", dst="10.0.0.2"):
    return parse_packet(
        Ether() / IP(src=src, dst=dst) / ICMP(type=ICMP_ECHO_REQUEST, code=0)
    )


def _make_reply(src="10.0.0.2", dst="10.0.0.1"):
    return parse_packet(
        Ether() / IP(src=src, dst=dst) / ICMP(type=ICMP_ECHO_REPLY, code=0)
    )


def _make_config(threshold=10, window=30, excluded=None):
    config = Config()
    config.icmp = IcmpConfig(
        enabled=True,
        echo_request_threshold=threshold,
        observation_window_seconds=window,
        excluded_sources=excluded or [],
    )
    return config


class TestIcmpAboveThreshold(unittest.TestCase):
    def test_triggers_at_threshold(self):
        config = _make_config(threshold=5, window=30)
        rule = IcmpRateRule(config, time_fn=lambda: 0.0)
        evidence = None
        for _ in range(5):
            evidence = rule.process(_make_request())
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["rule_id"], "ICMP-001")
        self.assertGreaterEqual(evidence["echo_request_count"], 5)

    def test_evidence_contains_required_fields(self):
        config = _make_config(threshold=3)
        rule = IcmpRateRule(config, time_fn=lambda: 0.0)
        evidence = None
        for _ in range(3):
            evidence = rule.process(_make_request())
        self.assertIsNotNone(evidence)
        for field in ("echo_request_count", "threshold",
                      "observation_window_seconds", "source_ip"):
            self.assertIn(field, evidence)


class TestIcmpBelowThreshold(unittest.TestCase):
    def test_no_alert_below_threshold(self):
        config = _make_config(threshold=10)
        rule = IcmpRateRule(config, time_fn=lambda: 0.0)
        for _ in range(9):
            evidence = rule.process(_make_request())
            self.assertIsNone(evidence)


class TestIcmpRepliesNotCounted(unittest.TestCase):
    """Echo replies must not count toward the threshold."""

    def test_replies_dont_trigger(self):
        config = _make_config(threshold=5)
        rule = IcmpRateRule(config, time_fn=lambda: 0.0)
        for _ in range(100):
            evidence = rule.process(_make_reply())
            self.assertIsNone(evidence)


class TestIcmpExcludedSource(unittest.TestCase):
    def test_excluded_never_alerts(self):
        config = _make_config(threshold=2, excluded=["10.0.0.1"])
        rule = IcmpRateRule(config, time_fn=lambda: 0.0)
        for _ in range(100):
            self.assertIsNone(rule.process(_make_request(src="10.0.0.1")))


class TestIcmpSlidingWindow(unittest.TestCase):
    def test_old_requests_expire(self):
        current_time = [0.0]

        def clock():
            return current_time[0]

        config = _make_config(threshold=5, window=30)
        rule = IcmpRateRule(config, time_fn=clock)

        for _ in range(4):
            rule.process(_make_request())

        current_time[0] = 35.0  # Window expired.
        evidence = rule.process(_make_request())
        self.assertIsNone(evidence)  # Count reset to 1 after expiry.


class TestIcmpDisabledRule(unittest.TestCase):
    def test_disabled_never_triggers(self):
        config = _make_config(threshold=1)
        config.icmp.enabled = False
        rule = IcmpRateRule(config, time_fn=lambda: 0.0)
        for _ in range(100):
            self.assertIsNone(rule.process(_make_request()))


if __name__ == "__main__":
    unittest.main()
