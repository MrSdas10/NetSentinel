"""Tests for the DNS-001 and DNS-002 rules."""

from __future__ import annotations

import unittest

from alert_manager import DnsNxdomainRule, DnsQueryRateRule
from parsers import ParsedPacket
from utils import to_utc_iso

EPOCH = 1_700_000_000.0


def _query(src_ip: str, server_ip: str, qname: str, epoch: float) -> ParsedPacket:
    return ParsedPacket(
        timestamp_utc=to_utc_iso(epoch),
        timestamp_epoch=epoch,
        src_ip=src_ip,
        dst_ip=server_ip,
        src_port=40000,
        dst_port=53,
        ip_proto=17,
        dns_is_query=True,
        dns_is_response=False,
        dns_qname=qname,
        dns_qtype="A",
        protocol="DNS",
    )


def _response(
    server_ip: str, client_ip: str, qname: str, rcode: int, epoch: float
) -> ParsedPacket:
    return ParsedPacket(
        timestamp_utc=to_utc_iso(epoch),
        timestamp_epoch=epoch,
        src_ip=server_ip,
        dst_ip=client_ip,
        src_port=53,
        dst_port=40000,
        ip_proto=17,
        dns_is_query=False,
        dns_is_response=True,
        dns_qname=qname,
        dns_rcode=rcode,
        dns_rcode_name="NXDOMAIN" if rcode == 3 else "NOERROR",
        protocol="DNS",
    )


class DnsQueryRateRuleTests(unittest.TestCase):

    def test_below_threshold(self):
        rule = DnsQueryRateRule(window_seconds=10, threshold=10)
        for i in range(5):
            result = rule.process(
                _query("10.0.0.1", "8.8.8.8", f"host{i}.example", EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)

    def test_above_threshold_fires(self):
        rule = DnsQueryRateRule(window_seconds=10, threshold=5)
        alert = None
        for i in range(6):
            alert = rule.process(
                _query("10.0.0.1", "8.8.8.8", f"host{i}.example", EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.rule_id, "DNS-001")
        self.assertGreaterEqual(alert.evidence["query_count"], 5)
        self.assertIn("sample_queries", alert.evidence)

    def test_responses_are_not_counted_as_queries(self):
        rule = DnsQueryRateRule(window_seconds=10, threshold=3)
        for i in range(20):
            result = rule.process(
                _response("8.8.8.8", "10.0.0.1", "example.com", 0, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)


class DnsNxdomainRuleTests(unittest.TestCase):

    def test_insufficient_response_volume_does_not_fire(self):
        rule = DnsNxdomainRule(
            window_seconds=30, min_responses=10, min_nxdomain=8, ratio=0.6
        )
        for i in range(5):
            result = rule.process(
                _response("8.8.8.8", "10.0.0.1", f"bad{i}.example", 3, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)

    def test_below_min_nxdomain_does_not_fire(self):
        rule = DnsNxdomainRule(
            window_seconds=30, min_responses=10, min_nxdomain=8, ratio=0.6
        )
        for i in range(10):
            # Only 5 NXDOMAINs out of 10.
            rcode = 3 if i < 5 else 0
            result = rule.process(
                _response("8.8.8.8", "10.0.0.1", f"host{i}.example", rcode, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
            self.assertIsNone(result)

    def test_excessive_nxdomain_fires(self):
        rule = DnsNxdomainRule(
            window_seconds=30, min_responses=10, min_nxdomain=8, ratio=0.6
        )
        alert = None
        for i in range(10):
            alert = rule.process(
                _response("8.8.8.8", "10.0.0.1", f"bad{i}.example", 3, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.rule_id, "DNS-002")
        self.assertGreaterEqual(alert.evidence["nxdomain_responses"], 8)
        self.assertGreaterEqual(alert.evidence["observed_ratio"], 0.6)
        self.assertIn("note", alert.evidence)

    def test_alert_description_does_not_claim_malware(self):
        rule = DnsNxdomainRule(
            window_seconds=30, min_responses=10, min_nxdomain=8, ratio=0.6
        )
        alert = None
        for i in range(10):
            alert = rule.process(
                _response("8.8.8.8", "10.0.0.1", f"bad{i}.example", 3, EPOCH + i * 0.1),
                EPOCH + i * 0.1,
            )
        assert alert is not None
        lowered = alert.description.lower()
        self.assertNotIn("malware", lowered)
        self.assertNotIn("confirmed", lowered)
        self.assertNotIn("dga", lowered)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()