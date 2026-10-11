"""
test_arp_detection.py — Tests for ARP-001 (mapping change detection).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.layers.l2 import Ether, ARP

from config_loader import Config, ArpConfig
from alert_manager import ArpSpoofingRule
from parsers import parse_packet, ARP_REPLY, ARP_REQUEST


def _make_arp(src_ip, src_mac, op=ARP_REPLY, dst_ip="10.0.0.1"):
    return parse_packet(
        Ether(src=src_mac)
        / ARP(op=op, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip)
    )


def _make_config(expiry=300, trusted=None, max_size=1024):
    config = Config()
    config.arp = ArpConfig(
        enabled=True,
        mapping_expiry_seconds=expiry,
        trusted_mappings=trusted or {},
        max_table_size=max_size,
    )
    return config


class TestArpNewMapping(unittest.TestCase):
    """First time we see an IP→MAC should not trigger."""

    def test_first_seen_no_alert(self):
        config = _make_config()
        rule = ArpSpoofingRule(config, time_fn=lambda: 0.0)
        evidence = rule.process(_make_arp("10.0.0.2", "aa:bb:cc:dd:ee:02"))
        self.assertIsNone(evidence)


class TestArpMappingChange(unittest.TestCase):
    """A MAC change for an existing IP must produce evidence."""

    def test_mac_change_triggers(self):
        config = _make_config()
        rule = ArpSpoofingRule(config, time_fn=lambda: 0.0)

        # First packet: establish mapping.
        rule.process(_make_arp("10.0.0.2", "aa:bb:cc:dd:ee:02"))

        # Second packet: different MAC for same IP.
        evidence = rule.process(_make_arp("10.0.0.2", "ff:ee:dd:cc:bb:aa"))

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["rule_id"], "ARP-001")
        self.assertEqual(evidence["source_ip"], "10.0.0.2")
        self.assertEqual(evidence["previous_mac"], "aa:bb:cc:dd:ee:02")
        self.assertEqual(evidence["new_mac"], "ff:ee:dd:cc:bb:aa")

    def test_evidence_contains_required_fields(self):
        config = _make_config()
        rule = ArpSpoofingRule(config, time_fn=lambda: 0.0)
        rule.process(_make_arp("10.0.0.5", "11:22:33:44:55:66"))
        evidence = rule.process(_make_arp("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
        self.assertIsNotNone(evidence)
        for field in ("previous_mac", "new_mac", "source_ip", "rule_id"):
            self.assertIn(field, evidence)


class TestArpSameMacNoAlert(unittest.TestCase):
    """Same MAC seen repeatedly must not trigger."""

    def test_repeated_same_mac_no_alert(self):
        config = _make_config()
        rule = ArpSpoofingRule(config, time_fn=lambda: 0.0)
        for _ in range(10):
            evidence = rule.process(_make_arp("10.0.0.2", "aa:bb:cc:dd:ee:02"))
            self.assertIsNone(evidence)


class TestArpTrustedMapping(unittest.TestCase):
    """Trusted IP→MAC pairs must never trigger an alert."""

    def test_trusted_mac_no_alert(self):
        trusted = {"10.0.0.2": "aa:bb:cc:dd:ee:02"}
        config = _make_config(trusted=trusted)
        rule = ArpSpoofingRule(config, time_fn=lambda: 0.0)

        # Send the trusted mapping many times — no alert.
        for _ in range(5):
            evidence = rule.process(_make_arp("10.0.0.2", "aa:bb:cc:dd:ee:02"))
            self.assertIsNone(evidence)


class TestArpMappingExpiry(unittest.TestCase):
    """Stale entries should be expired; a new mapping after expiry is not an alert."""

    def test_expired_mapping_no_alert(self):
        current_time = [0.0]

        def clock():
            return current_time[0]

        config = _make_config(expiry=60)
        rule = ArpSpoofingRule(config, time_fn=clock)

        rule.process(_make_arp("10.0.0.2", "aa:bb:cc:dd:ee:02"))

        # Advance time past expiry.
        current_time[0] = 65.0

        # Different MAC after expiry — should not alert (old entry is gone).
        evidence = rule.process(_make_arp("10.0.0.2", "ff:ee:dd:cc:bb:aa"))
        self.assertIsNone(evidence)


class TestArpDisabledRule(unittest.TestCase):
    def test_disabled_never_triggers(self):
        config = _make_config()
        config.arp.enabled = False
        rule = ArpSpoofingRule(config, time_fn=lambda: 0.0)
        rule.process(_make_arp("10.0.0.2", "aa:bb:cc:dd:ee:01"))
        evidence = rule.process(_make_arp("10.0.0.2", "ff:ff:ff:ff:ff:ff"))
        self.assertIsNone(evidence)


class TestArpTableSizeBound(unittest.TestCase):
    """Table must not grow beyond max_table_size."""

    def test_table_does_not_exceed_max(self):
        config = _make_config(max_size=10)
        rule = ArpSpoofingRule(config, time_fn=lambda: 0.0)
        for i in range(20):
            ip = f"10.0.0.{i + 1}"
            mac = f"aa:bb:cc:dd:ee:{i:02x}"
            rule.process(_make_arp(ip, mac))
        self.assertLessEqual(rule.table_size, 10)


if __name__ == "__main__":
    unittest.main()
