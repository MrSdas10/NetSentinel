"""
test_dns_detection.py — Tests for DNS-001 (query rate) and DNS-002 (NXDOMAIN).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR

from config_loader import Config, DnsConfig
from alert_manager import DnsQueryRateRule, DnsNxdomainRule
from parsers import parse_packet, DNS_RCODE_NXDOMAIN


def _make_dns_query(src="10.0.0.1", dst="8.8.8.8", name="example.com"):
    return parse_packet(
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=12345, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=name, qtype="A"))
    )


def _make_dns_response(src="8.8.8.8", dst="10.0.0.1",
                       name="example.com", rcode=0):
    return parse_packet(
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=53, dport=12345)
        / DNS(qr=1, rd=1, ra=1, rcode=rcode,
              qd=DNSQR(qname=name, qtype="A"))
    )


def _make_nxdomain(src="8.8.8.8", dst="10.0.0.1", name="notexist.test"):
    return _make_dns_response(src=src, dst=dst, name=name,
                               rcode=DNS_RCODE_NXDOMAIN)


def _make_dns_config(q_threshold=10, q_window=60,
                     nx_threshold=5, nx_window=60, excluded=None):
    config = Config()
    config.dns = DnsConfig(
        enabled=True,
        query_rate_threshold=q_threshold,
        observation_window_seconds=q_window,
        nxdomain_threshold=nx_threshold,
        nxdomain_window_seconds=nx_window,
        excluded_sources=excluded or [],
    )
    return config


# ---------------------------------------------------------------------------
# DNS-001 tests
# ---------------------------------------------------------------------------

class TestDnsQueryRateAboveThreshold(unittest.TestCase):
    def test_triggers_at_threshold(self):
        config = _make_dns_config(q_threshold=5)
        rule = DnsQueryRateRule(config, time_fn=lambda: 0.0)
        evidence = None
        for i in range(5):
            evidence = rule.process(_make_dns_query(name=f"host{i}.example.com"))
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["rule_id"], "DNS-001")
        self.assertGreaterEqual(evidence["query_count"], 5)

    def test_evidence_has_required_fields(self):
        config = _make_dns_config(q_threshold=3)
        rule = DnsQueryRateRule(config, time_fn=lambda: 0.0)
        evidence = None
        for i in range(3):
            evidence = rule.process(_make_dns_query(name=f"x{i}.test"))
        self.assertIsNotNone(evidence)
        for field in ("query_count", "threshold", "observation_window_seconds",
                      "source_ip"):
            self.assertIn(field, evidence)


class TestDnsQueryRateBelowThreshold(unittest.TestCase):
    def test_no_alert_below_threshold(self):
        config = _make_dns_config(q_threshold=10)
        rule = DnsQueryRateRule(config, time_fn=lambda: 0.0)
        for i in range(9):
            evidence = rule.process(_make_dns_query(name=f"y{i}.test"))
            self.assertIsNone(evidence)


class TestDnsResponsesNotCountedAsQueries(unittest.TestCase):
    """DNS responses must NOT count toward the query rate threshold."""

    def test_responses_do_not_trigger_query_rule(self):
        config = _make_dns_config(q_threshold=5)
        rule = DnsQueryRateRule(config, time_fn=lambda: 0.0)
        for _ in range(100):
            # Responses have qr=1; these come from 8.8.8.8 → 10.0.0.1
            evidence = rule.process(_make_dns_response())
            self.assertIsNone(evidence)

    def test_only_queries_counted(self):
        """Mix of queries and responses: only queries should count."""
        config = _make_dns_config(q_threshold=5)
        rule = DnsQueryRateRule(config, time_fn=lambda: 0.0)

        # 4 responses + 4 queries; 4 queries should not trigger threshold of 5.
        for i in range(4):
            rule.process(_make_dns_response())  # should not count
            evidence = rule.process(_make_dns_query(name=f"z{i}.test"))
        self.assertIsNone(evidence)


class TestDnsQueryRateWindow(unittest.TestCase):
    def test_old_queries_expire(self):
        current_time = [0.0]
        config = _make_dns_config(q_threshold=5, q_window=30)
        rule = DnsQueryRateRule(config, time_fn=lambda: current_time[0])

        for i in range(4):
            rule.process(_make_dns_query(name=f"a{i}.test"))

        current_time[0] = 35.0
        evidence = rule.process(_make_dns_query(name="new.test"))
        self.assertIsNone(evidence)


class TestDnsQueryRateExcluded(unittest.TestCase):
    def test_excluded_source_never_alerts(self):
        config = _make_dns_config(q_threshold=2, excluded=["10.0.0.1"])
        rule = DnsQueryRateRule(config, time_fn=lambda: 0.0)
        for i in range(100):
            evidence = rule.process(
                _make_dns_query(src="10.0.0.1", name=f"b{i}.test")
            )
            self.assertIsNone(evidence)


# ---------------------------------------------------------------------------
# DNS-002 tests
# ---------------------------------------------------------------------------

class TestNxdomainAboveThreshold(unittest.TestCase):
    def test_triggers_at_threshold(self):
        config = _make_dns_config(nx_threshold=5, nx_window=60)
        rule = DnsNxdomainRule(config, time_fn=lambda: 0.0)
        evidence = None
        for i in range(5):
            evidence = rule.process(
                _make_nxdomain(name=f"fail{i}.notexist")
            )
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["rule_id"], "DNS-002")
        self.assertGreaterEqual(evidence["nxdomain_count"], 5)

    def test_evidence_has_required_fields(self):
        config = _make_dns_config(nx_threshold=3)
        rule = DnsNxdomainRule(config, time_fn=lambda: 0.0)
        evidence = None
        for i in range(3):
            evidence = rule.process(_make_nxdomain(name=f"bad{i}.test"))
        self.assertIsNotNone(evidence)
        for field in ("nxdomain_count", "threshold",
                      "observation_window_seconds", "source_ip"):
            self.assertIn(field, evidence)


class TestNxdomainBelowThreshold(unittest.TestCase):
    def test_no_alert_below_threshold(self):
        config = _make_dns_config(nx_threshold=10)
        rule = DnsNxdomainRule(config, time_fn=lambda: 0.0)
        for i in range(9):
            evidence = rule.process(_make_nxdomain(name=f"bad{i}.test"))
            self.assertIsNone(evidence)


class TestNxdomainOkResponseNotCounted(unittest.TestCase):
    """Successful (rcode=0) responses must NOT count as NXDOMAINs."""

    def test_ok_responses_do_not_trigger(self):
        config = _make_dns_config(nx_threshold=5)
        rule = DnsNxdomainRule(config, time_fn=lambda: 0.0)
        for i in range(100):
            evidence = rule.process(
                _make_dns_response(name=f"ok{i}.test", rcode=0)
            )
            self.assertIsNone(evidence)


class TestNxdomainWindow(unittest.TestCase):
    def test_old_nxdomains_expire(self):
        current_time = [0.0]
        config = _make_dns_config(nx_threshold=5, nx_window=30)
        rule = DnsNxdomainRule(config, time_fn=lambda: current_time[0])

        for i in range(4):
            rule.process(_make_nxdomain(name=f"old{i}.test"))

        current_time[0] = 35.0
        evidence = rule.process(_make_nxdomain(name="new.test"))
        self.assertIsNone(evidence)


class TestNxdomainDisabledRule(unittest.TestCase):
    def test_disabled_never_triggers(self):
        config = _make_dns_config(nx_threshold=1)
        config.dns.enabled = False
        rule = DnsNxdomainRule(config, time_fn=lambda: 0.0)
        for i in range(100):
            self.assertIsNone(rule.process(_make_nxdomain(name=f"x{i}.test")))


if __name__ == "__main__":
    unittest.main()
