"""Tests for the UDP-001 destination-port diversity rule."""

from __future__ import annotations

import unittest

from alert_manager import UdpPortDiversityRule
from parsers import ParsedPacket
from utils import to_utc_iso

EPOCH = 1_700_000_000.0


def _udp(src_ip: str, dst_ip: str, dst_port: int, epoch: float) -> ParsedPacket:
    return ParsedPacket(
        timestamp_utc=to_utc_iso(epoch),
        timestamp_epoch=epoch,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        ip_proto=17,
        protocol="UDP",
    )


class UdpPortDiversityRuleTests(unittest.TestCase):

    def test_below_threshold_does_not_fire(self):
        rule = UdpPortDiversityRule(window_seconds=10, threshold=10)
        for i in range(5):
            result = rule.process(
                _udp("10.0.0.1", "10.0.0.2", 5000 + i, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)

    def test_above_threshold_fires(self):
        rule = UdpPortDiversityRule(window_seconds=10, threshold=5)
        alert = None
        for i in range(6):
            alert = rule.process(
                _udp("10.0.0.1", "10.0.0.2", 5000 + i, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.rule_id, "UDP-001")
        self.assertGreaterEqual(alert.evidence["distinct_destination_ports"], 5)
        self.assertIn("note", alert.evidence)

    def test_repeated_ports_do_not_inflate_count(self):
        rule = UdpPortDiversityRule(window_seconds=10, threshold=3)
        for i in range(20):
            result = rule.process(
                _udp("10.0.0.1", "10.0.0.2", 53, EPOCH + i * 0.05),
                EPOCH + i * 0.05,
            )
            self.assertIsNone(result)

    def test_trusted_host_is_exempt(self):
        rule = UdpPortDiversityRule(
            window_seconds=10, threshold=3, trusted_hosts={"10.0.0.9"}
        )
        for i in range(10):
            result = rule.process(
                _udp("10.0.0.9", "10.0.0.2", 1000 + i, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()