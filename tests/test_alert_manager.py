"""Tests for the AlertManager deduplication and rule wiring."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from alert_manager import (
    Alert,
    AlertManager,
    AlertStore,
    ArpMappingChangeRule,
    DetectionRule,
    TcpPortScanRule,
    build_rules_from_config,
)
from parsers import ParsedPacket
from utils import to_utc_iso

EPOCH = 1_700_000_000.0


class _AlwaysFires(DetectionRule):
    rule_id = "TEST-001"
    rule_name = "Test Rule"
    default_severity = "medium"

    def process(self, packet, now):
        return self._make_alert(
            packet,
            now,
            description="synthetic test alert",
            evidence={"k": 1},
            source_ip=packet.src_ip,
            destination_ip=packet.dst_ip,
        )


def _pkt(src: str, dst: str, epoch: float) -> ParsedPacket:
    return ParsedPacket(
        timestamp_utc=to_utc_iso(epoch),
        timestamp_epoch=epoch,
        src_ip=src,
        dst_ip=dst,
        protocol="TCP",
    )


class AlertManagerTests(unittest.TestCase):

    def test_unique_rule_returns_alert(self):
        mgr = AlertManager(rules=[_AlwaysFires()], suppression_window_seconds=60)
        alerts = mgr.process(_pkt("10.0.0.1", "10.0.0.2", EPOCH))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "TEST-001")
        self.assertEqual(alerts[0].severity, "medium")

    def test_duplicate_alerts_are_suppressed_within_window(self):
        mgr = AlertManager(rules=[_AlwaysFires()], suppression_window_seconds=60)
        first = mgr.process(_pkt("10.0.0.1", "10.0.0.2", EPOCH))
        second = mgr.process(_pkt("10.0.0.1", "10.0.0.2", EPOCH + 10))
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 0)
        self.assertEqual(mgr.total_alerts, 1)
        self.assertEqual(mgr.suppressed_alerts, 1)
        # The cached alert's occurrence count should have grown.
        cached = mgr.alerts()[0]
        self.assertGreaterEqual(cached.occurrence_count, 2)

    def test_duplicate_alerts_allowed_after_window_expires(self):
        mgr = AlertManager(rules=[_AlwaysFires()], suppression_window_seconds=10)
        mgr.process(_pkt("10.0.0.1", "10.0.0.2", EPOCH))
        result = mgr.process(_pkt("10.0.0.1", "10.0.0.2", EPOCH + 100))
        self.assertEqual(len(result), 1)
        self.assertEqual(mgr.total_alerts, 2)

    def test_different_sources_are_not_deduplicated(self):
        mgr = AlertManager(rules=[_AlwaysFires()], suppression_window_seconds=60)
        a = mgr.process(_pkt("10.0.0.1", "10.0.0.2", EPOCH))
        b = mgr.process(_pkt("10.0.0.3", "10.0.0.2", EPOCH))
        self.assertEqual(len(a), 1)
        self.assertEqual(len(b), 1)
        self.assertEqual(mgr.total_alerts, 2)

    def test_network_scope_filter(self):
        mgr = AlertManager(
            rules=[_AlwaysFires()],
            network_scope_enabled=True,
            local_networks=["192.168.1.0/24"],
        )
        # Both endpoints outside the scope → filtered.
        result = mgr.process(_pkt("203.0.113.5", "203.0.113.6", EPOCH))
        self.assertEqual(result, [])
        # Source inside the scope → allowed.
        result = mgr.process(_pkt("192.168.1.10", "203.0.113.6", EPOCH + 1))
        self.assertEqual(len(result), 1)

    def test_in_memory_alert_list_is_bounded(self):
        mgr = AlertManager(
            rules=[_AlwaysFires()],
            suppression_window_seconds=0,
            max_in_memory_alerts=3,
        )
        for i in range(10):
            mgr.process(_pkt(f"10.0.0.{i}", "10.0.0.254", EPOCH + i))
        self.assertLessEqual(len(mgr.alerts()), 3)

    def test_rule_exception_does_not_stop_other_rules(self):
        class _Broken(DetectionRule):
            rule_id = "BROKEN-1"
            rule_name = "Broken"

            def process(self, packet, now):
                raise RuntimeError("boom")

        mgr = AlertManager(rules=[_Broken(), _AlwaysFires()], suppression_window_seconds=0)
        result = mgr.process(_pkt("10.0.0.1", "10.0.0.2", EPOCH))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].rule_id, "TEST-001")

    def test_store_writes_jsonl_and_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = AlertStore(
                jsonl_path=Path(tmp) / "alerts.jsonl",
                log_path=Path(tmp) / "alerts.log",
            )
            mgr = AlertManager(
                rules=[_AlwaysFires()], store=store, suppression_window_seconds=0
            )
            mgr.process(_pkt("10.0.0.1", "10.0.0.2", EPOCH))
            self.assertTrue((Path(tmp) / "alerts.jsonl").is_file())
            self.assertTrue((Path(tmp) / "alerts.log").is_file())
            jsonl_line = (Path(tmp) / "alerts.jsonl").read_text(encoding="utf-8").strip()
            self.assertIn("TEST-001", jsonl_line)

    def test_alert_to_dict_round_trip(self):
        alert = Alert(
            alert_id="a-1",
            timestamp_utc="2025-01-01T00:00:00Z",
            rule_id="TCP-001",
            rule_name="Test",
            severity="medium",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            protocol="TCP",
            description="d",
            evidence={"x": 1},
            recommended_action="r",
            confidence="medium",
        )
        data = alert.to_dict()
        for key in ("alert_id", "timestamp_utc", "rule_id", "rule_name",
                    "severity", "source_ip", "destination_ip", "protocol",
                    "description", "evidence", "recommended_action", "confidence"):
            self.assertIn(key, data)


class BuildRulesFromConfigTests(unittest.TestCase):

    def _config(self) -> dict:
        return {
            "severity": {
                "TCP-001": "medium", "UDP-001": "medium", "ICMP-001": "low",
                "ARP-001": "high", "DNS-001": "medium", "DNS-002": "high",
            },
            "trusted_hosts": [],
            "detection": {
                "tcp": {"enabled": True, "window_seconds": 10,
                        "distinct_destination_ports": 15,
                        "excluded_destination_ports": [], "max_tracked_sources": 100},
                "udp": {"enabled": True, "window_seconds": 10,
                        "distinct_destination_ports": 20, "max_tracked_sources": 100},
                "icmp": {"enabled": True, "window_seconds": 5,
                         "echo_requests": 30, "max_tracked_sources": 100},
                "arp": {"enabled": True, "mapping_ttl_seconds": 900,
                        "max_tracked_mappings": 100, "trusted_mappings": {}},
                "dns": {"enabled": True, "query_window_seconds": 10,
                        "queries_per_source": 50, "max_tracked_sources": 100,
                        "nxdomain_window_seconds": 30, "nxdomain_min_responses": 10,
                        "nxdomain_min_count": 8, "nxdomain_ratio": 0.6},
            },
        }

    def test_all_enabled_yields_six_rules(self):
        rules = build_rules_from_config(self._config())
        self.assertEqual(len(rules), 6)
        ids = {r.rule_id for r in rules}
        self.assertEqual(ids, {"TCP-001", "UDP-001", "ICMP-001", "ARP-001",
                               "DNS-001", "DNS-002"})

    def test_disabling_a_rule_removes_it(self):
        cfg = self._config()
        cfg["detection"]["tcp"]["enabled"] = False
        rules = build_rules_from_config(cfg)
        self.assertNotIn("TCP-001", {r.rule_id for r in rules})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()