"""Tests for the ICMP-001 echo-request rate rule."""

from __future__ import annotations

import unittest

from alert_manager import IcmpEchoRateRule
from parsers import ParsedPacket
from utils import to_utc_iso

EPOCH = 1_700_000_000.0


def _icmp(src_ip: str, dst_ip: str, icmp_type: int, epoch: float) -> ParsedPacket:
    return ParsedPacket(
        timestamp_utc=to_utc_iso(epoch),
        timestamp_epoch=epoch,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_proto=1,
        icmp_type=icmp_type,
        icmp_code=0,
        protocol="ICMP",
    )


class IcmpEchoRateRuleTests(unittest.TestCase):

    def test_below_threshold_does_not_fire(self):
        rule = IcmpEchoRateRule(window_seconds=5, threshold=10)
        for i in range(5):
            result = rule.process(
                _icmp("10.0.0.1", "10.0.0.2", 8, EPOCH + i * 0.2),
                EPOCH + i * 0.2,
            )
            self.assertIsNone(result)

    def test_above_threshold_fires(self):
        rule = IcmpEchoRateRule(window_seconds=5, threshold=5)
        alert = None
        for i in range(6):
            alert = rule.process(
                _icmp("10.0.0.1", "10.0.0.2", 8, EPOCH + i * 0.2),
                EPOCH + i * 0.2,
            )
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.rule_id, "ICMP-001")
        self.assertGreaterEqual(alert.evidence["echo_requests"], 5)
        self.assertIn("note", alert.evidence)

    def test_echo_replies_are_not_counted(self):
        rule = IcmpEchoRateRule(window_seconds=5, threshold=3)
        for i in range(20):
            result = rule.process(
                _icmp("10.0.0.2", "10.0.0.1", 0, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)

    def test_other_icmp_types_are_ignored(self):
        rule = IcmpEchoRateRule(window_seconds=5, threshold=3)
        # Type 3 = Destination Unreachable
        for i in range(10):
            result = rule.process(
                _icmp("10.0.0.1", "10.0.0.2", 3, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)

    def test_window_expiry(self):
        rule = IcmpEchoRateRule(window_seconds=1.0, threshold=3)
        for i in range(2):
            rule.process(
                _icmp("10.0.0.1", "10.0.0.2", 8, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
        # Next request is outside the 1s window; only one should remain.
        result = rule.process(
            _icmp("10.0.0.1", "10.0.0.2", 8, EPOCH + 5.0), EPOCH + 5.0
        )
        self.assertIsNone(result)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()