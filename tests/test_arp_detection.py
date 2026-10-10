"""Tests for the ARP-001 mapping-change rule."""

from __future__ import annotations

import unittest

from alert_manager import ArpMappingChangeRule
from parsers import ParsedPacket
from utils import to_utc_iso

EPOCH = 1_700_000_000.0


def _arp(sender_ip: str, sender_mac: str, target_ip: str, epoch: float) -> ParsedPacket:
    return ParsedPacket(
        timestamp_utc=to_utc_iso(epoch),
        timestamp_epoch=epoch,
        arp_op=2,  # ARP reply
        arp_sender_ip=sender_ip,
        arp_sender_mac=sender_mac,
        arp_target_ip=target_ip,
        arp_target_mac="00:00:00:00:00:00",
        protocol="ARP",
    )


class ArpMappingChangeRuleTests(unittest.TestCase):

    def test_first_observation_never_fires(self):
        rule = ArpMappingChangeRule(mapping_ttl_seconds=600)
        result = rule.process(
            _arp("10.0.0.1", "aa:bb:cc:dd:ee:ff", "10.0.0.2", EPOCH), EPOCH
        )
        self.assertIsNone(result)

    def test_repeated_same_mapping_does_not_fire(self):
        rule = ArpMappingChangeRule(mapping_ttl_seconds=600)
        for i in range(5):
            result = rule.process(
                _arp("10.0.0.1", "aa:bb:cc:dd:ee:ff", "10.0.0.2", EPOCH + i),
                EPOCH + i,
            )
            self.assertIsNone(result)

    def test_mapping_change_fires_with_evidence(self):
        rule = ArpMappingChangeRule(mapping_ttl_seconds=600)
        rule.process(_arp("10.0.0.1", "aa:bb:cc:dd:ee:ff", "10.0.0.2", EPOCH), EPOCH)
        alert = rule.process(
            _arp("10.0.0.1", "11:22:33:44:55:66", "10.0.0.2", EPOCH + 5),
            EPOCH + 5,
        )
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert.rule_id, "ARP-001")
        self.assertEqual(alert.evidence["ip_address"], "10.0.0.1")
        self.assertEqual(alert.evidence["previous_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(alert.evidence["new_mac"], "11:22:33:44:55:66")
        self.assertIn("note", alert.evidence)

    def test_change_is_not_claimed_as_confirmed_attack(self):
        rule = ArpMappingChangeRule(mapping_ttl_seconds=600)
        rule.process(_arp("10.0.0.1", "aa:bb:cc:dd:ee:ff", "10.0.0.2", EPOCH), EPOCH)
        alert = rule.process(
            _arp("10.0.0.1", "11:22:33:44:55:66", "10.0.0.2", EPOCH + 5),
            EPOCH + 5,
        )
        assert alert is not None
        # Description must be descriptive, not definitive.
        self.assertIn("changed", alert.description)
        self.assertNotIn("attack", alert.description.lower())
        self.assertNotIn("spoofing confirmed", alert.description.lower())

    def test_stale_entry_expires(self):
        rule = ArpMappingChangeRule(mapping_ttl_seconds=10)
        rule.process(_arp("10.0.0.1", "aa:bb:cc:dd:ee:ff", "10.0.0.2", EPOCH), EPOCH)
        # 100 seconds later: the old entry is stale, so a "changed" MAC does
        # not produce an alert; it is treated as a fresh observation.
        alert = rule.process(
            _arp("10.0.0.1", "11:22:33:44:55:66", "10.0.0.2", EPOCH + 100),
            EPOCH + 100,
        )
        self.assertIsNone(alert)

    def test_trusted_mapping_ignores_first_observation(self):
        rule = ArpMappingChangeRule(
            mapping_ttl_seconds=600,
            trusted_mappings={"10.0.0.5": "aa:bb:cc:dd:ee:ff"},
        )
        for _ in range(3):
            result = rule.process(
                _arp("10.0.0.5", "aa:bb:cc:dd:ee:ff", "10.0.0.1", EPOCH),
                EPOCH,
            )
            self.assertIsNone(result)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()