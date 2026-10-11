"""
test_alert_manager.py — Tests for AlertManager (orchestration and deduplication).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, ICMP

from config_loader import Config, TcpConfig, IcmpConfig, OutputConfig
from alert_manager import AlertManager, Alert
from parsers import parse_packet, ICMP_ECHO_REQUEST


def _make_syn(src="10.0.0.1", dst="10.0.0.2", dport=80):
    return parse_packet(
        Ether() / IP(src=src, dst=dst) / TCP(sport=50000, dport=dport, flags="S")
    )


def _make_icmp_req(src="10.0.0.1"):
    return parse_packet(
        Ether() / IP(src=src, dst="10.0.0.2") / ICMP(type=ICMP_ECHO_REQUEST)
    )


def _make_config(
    tcp_threshold=5,
    icmp_threshold=5,
    suppression_window=60,
    max_alerts=1000,
):
    config = Config()
    config.tcp = TcpConfig(
        enabled=True,
        syn_port_threshold=tcp_threshold,
        observation_window_seconds=60,
    )
    config.icmp = IcmpConfig(
        enabled=True,
        echo_request_threshold=icmp_threshold,
        observation_window_seconds=30,
    )
    config.output = OutputConfig(
        alert_suppression_window_seconds=suppression_window,
        max_alerts_in_memory=max_alerts,
    )
    return config


class TestAlertManagerProducesAlerts(unittest.TestCase):
    def test_produces_alerts_above_tcp_threshold(self):
        current_time = [0.0]
        config = _make_config(tcp_threshold=5, suppression_window=60)
        manager = AlertManager(config, time_fn=lambda: current_time[0])

        all_alerts = []
        for port in range(80, 90):
            alerts = manager.process_packet(_make_syn(dport=port))
            all_alerts.extend(alerts)

        self.assertGreater(len(all_alerts), 0)
        self.assertEqual(all_alerts[0].rule_id, "TCP-001")

    def test_alert_has_required_fields(self):
        current_time = [0.0]
        config = _make_config(tcp_threshold=5, suppression_window=60)
        manager = AlertManager(config, time_fn=lambda: current_time[0])

        all_alerts = []
        for port in range(80, 90):
            alerts = manager.process_packet(_make_syn(dport=port))
            all_alerts.extend(alerts)

        alert = all_alerts[0]
        self.assertIsInstance(alert.alert_id, str)
        self.assertGreater(len(alert.alert_id), 0)
        self.assertIsNotNone(alert.timestamp_utc)
        self.assertIsNotNone(alert.rule_id)
        self.assertIsNotNone(alert.severity)
        self.assertIsNotNone(alert.description)
        self.assertIsNotNone(alert.evidence)
        self.assertIsNotNone(alert.recommended_action)
        self.assertIsNotNone(alert.confidence)

    def test_alert_dict_serializable(self):
        import json
        current_time = [0.0]
        config = _make_config(tcp_threshold=5, suppression_window=60)
        manager = AlertManager(config, time_fn=lambda: current_time[0])
        for port in range(80, 90):
            manager.process_packet(_make_syn(dport=port))
        for alert in manager.alerts:
            # Should not raise.
            json.dumps(alert.to_dict())


class TestAlertDeduplication(unittest.TestCase):
    """Repeated alerts for the same rule+source within the window are suppressed."""

    def test_duplicate_suppressed_within_window(self):
        current_time = [0.0]
        config = _make_config(tcp_threshold=5, suppression_window=60)
        manager = AlertManager(config, time_fn=lambda: current_time[0])

        # Trigger the first alert.
        for port in range(80, 90):
            manager.process_packet(_make_syn(dport=port))

        first_alert_count = manager.total_alerts

        # Continue sending packets (same source); should be suppressed.
        for port in range(100, 200):
            manager.process_packet(_make_syn(dport=port))

        # Alert count should not have doubled; suppression should be active.
        self.assertEqual(manager.total_alerts, first_alert_count)
        self.assertGreater(manager.suppressed_alerts, 0)

    def test_alert_allowed_after_suppression_window(self):
        current_time = [0.0]
        config = _make_config(tcp_threshold=5, suppression_window=30)
        manager = AlertManager(config, time_fn=lambda: current_time[0])

        # Trigger first alert.
        for port in range(80, 90):
            manager.process_packet(_make_syn(dport=port))
        first_count = manager.total_alerts

        # Advance time past the suppression window.
        current_time[0] = 35.0

        # Should be allowed to alert again.
        for port in range(200, 210):
            manager.process_packet(_make_syn(dport=port))

        self.assertGreater(manager.total_alerts, first_count)


class TestAlertManagerBoundedStorage(unittest.TestCase):
    """In-memory alert list must not exceed max_alerts_in_memory."""

    def test_bounded_alert_list(self):
        max_alerts = 10
        current_time = [0.0]
        # Use a tiny suppression window so each alert group is not suppressed.
        config = _make_config(
            tcp_threshold=5, suppression_window=0, max_alerts=max_alerts
        )
        manager = AlertManager(config, time_fn=lambda: current_time[0])

        # Generate many alerts from different source IPs.
        for i in range(50):
            current_time[0] = float(i)
            src = f"10.0.{i // 256}.{i % 256}"
            for port in range(80, 90):
                manager.process_packet(_make_syn(src=src, dport=port))

        self.assertLessEqual(len(manager.alerts), max_alerts)


class TestAlertManagerClear(unittest.TestCase):
    def test_clear_resets_state(self):
        current_time = [0.0]
        config = _make_config(tcp_threshold=5, suppression_window=0)
        manager = AlertManager(config, time_fn=lambda: current_time[0])

        for port in range(80, 90):
            manager.process_packet(_make_syn(dport=port))

        self.assertGreater(manager.total_alerts, 0)
        manager.clear()
        self.assertEqual(manager.total_alerts, 0)
        self.assertEqual(len(manager.alerts), 0)


class TestAlertCountsByCategory(unittest.TestCase):
    def test_count_by_severity(self):
        current_time = [0.0]
        config = _make_config(tcp_threshold=5, suppression_window=0)
        manager = AlertManager(config, time_fn=lambda: current_time[0])

        for port in range(80, 90):
            manager.process_packet(_make_syn(dport=port))

        by_sev = manager.alert_count_by_severity()
        self.assertIsInstance(by_sev, dict)

    def test_count_by_rule(self):
        current_time = [0.0]
        config = _make_config(tcp_threshold=5, suppression_window=0)
        manager = AlertManager(config, time_fn=lambda: current_time[0])

        for port in range(80, 90):
            manager.process_packet(_make_syn(dport=port))

        by_rule = manager.alert_count_by_rule()
        self.assertIn("TCP-001", by_rule)


if __name__ == "__main__":
    unittest.main()
