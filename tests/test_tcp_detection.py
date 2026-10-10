"""Tests for the TCP-001 destination-port diversity rule."""

from __future__ import annotations

import unittest

from alert_manager import TcpPortScanRule
from parsers import ParsedPacket
from utils import to_utc_iso

EPOCH = 1_700_000_000.0


def _syn(src_ip: str, dst_ip: str, dst_port: int, epoch: float) -> ParsedPacket:
    return ParsedPacket(
        timestamp_utc=to_utc_iso(epoch),
        timestamp_epoch=epoch,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        tcp_syn=True,
        tcp_ack=False,
        tcp_flags="S",
        ip_proto=6,
        protocol="TCP",
    )


class TcpPortScanRuleTests(unittest.TestCase):

    def test_below_threshold_does_not_fire(self):
        rule = TcpPortScanRule(window_seconds=10, threshold=20)
        for i, port in enumerate([80, 443, 22, 25, 53]):
            result = rule.process(_syn("10.0.0.1", "10.0.0.2", port, EPOCH + i * 0.1), EPOCH + i * 0.1)
            self.assertIsNone(result)

    def test_above_threshold_fires_once_ports_cross(self):
        rule = TcpPortScanRule(window_seconds=10, threshold=5)
        alert = None
        for i in range(6):
            alert = rule.process(
                _syn("10.0.0.1", "10.0.0.2", 1000 + i, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.rule_id, "TCP-001")
        self.assertEqual(alert.source_ip, "10.0.0.1")
        self.assertGreaterEqual(alert.evidence["distinct_destination_ports"], 5)

    def test_retransmissions_to_same_port_do_not_count_as_distinct(self):
        rule = TcpPortScanRule(window_seconds=10, threshold=3)
        for i in range(10):
            result = rule.process(
                _syn("10.0.0.1", "10.0.0.2", 80, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)

    def test_outside_window_ports_expire(self):
        rule = TcpPortScanRule(window_seconds=1.0, threshold=3)
        # Two ports at t=0, two more at t=5 (outside window). Should not fire.
        rule.process(_syn("10.0.0.1", "10.0.0.2", 80, EPOCH), EPOCH)
        rule.process(_syn("10.0.0.1", "10.0.0.2", 81, EPOCH + 0.1), EPOCH + 0.1)
        result = rule.process(
            _syn("10.0.0.1", "10.0.0.2", 82, EPOCH + 5.0), EPOCH + 5.0
        )
        self.assertIsNone(result)

    def test_syn_ack_does_not_count(self):
        rule = TcpPortScanRule(window_seconds=10, threshold=2)
        pkt = _syn("10.0.0.1", "10.0.0.2", 80, EPOCH)
        pkt.tcp_ack = True  # SYN+ACK is a response, not a connection attempt
        self.assertIsNone(rule.process(pkt, EPOCH))

    def test_trusted_host_is_exempt(self):
        rule = TcpPortScanRule(
            window_seconds=10, threshold=3, trusted_hosts={"10.0.0.5"}
        )
        for i in range(10):
            result = rule.process(
                _syn("10.0.0.5", "10.0.0.2", 100 + i, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)

    def test_excluded_destination_ports_are_ignored(self):
        rule = TcpPortScanRule(window_seconds=10, threshold=3, excluded_ports=[80, 443])
        for i in range(10):
            result = rule.process(
                _syn("10.0.0.1", "10.0.0.2", 80 if i % 2 else 443, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()