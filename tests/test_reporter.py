"""Tests for :mod:`reporter`."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from alert_manager import Alert
from capture import CaptureStats
from reporter import ReportGenerator


def _stats() -> CaptureStats:
    return CaptureStats(
        mode="offline",
        source="sample.pcap",
        started_utc="2025-01-01T00:00:00Z",
        finished_utc="2025-01-01T00:01:00Z",
        duration_seconds=60.0,
        total_packets=120,
        parsed_packets=118,
        parse_errors=2,
        protocol_counts={"TCP": 80, "UDP": 30, "ICMP": 8},
    )


def _alert(desc: str = "ok description") -> Alert:
    return Alert(
        alert_id="alert-test-1",
        timestamp_utc="2025-01-01T00:00:30Z",
        rule_id="TCP-001",
        rule_name="Possible TCP Port Scan",
        severity="medium",
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        protocol="TCP",
        description=desc,
        evidence={"distinct_destination_ports": 20, "sample_ports": [80, 443]},
        recommended_action="Review the source host.",
        confidence="medium",
    )


class ReporterTests(unittest.TestCase):

    def test_writes_three_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                output_dir=tmp,
                capture_stats=_stats(),
                alerts=[_alert()],
                session_label="sample",
            )
            paths = gen.write_all()
            for p in (paths.json_path, paths.csv_path, paths.html_path):
                self.assertTrue(p.is_file(), f"missing {p}")
                self.assertGreater(p.stat().st_size, 0)

    def test_json_report_contains_alert_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                output_dir=tmp, capture_stats=_stats(), alerts=[_alert()],
                session_label="sample",
            )
            paths = gen.write_all()
            payload = json.loads(paths.json_path.read_text(encoding="utf-8"))
            self.assertIn("summary", payload)
            self.assertIn("alerts", payload)
            self.assertEqual(payload["summary"]["total_packets"], 120)
            self.assertEqual(payload["summary"]["total_alerts"], 1)
            self.assertEqual(payload["alerts"][0]["rule_id"], "TCP-001")

    def test_csv_report_has_expected_header_and_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                output_dir=tmp, capture_stats=_stats(), alerts=[_alert()],
                session_label="sample",
            )
            paths = gen.write_all()
            text = paths.csv_path.read_text(encoding="utf-8")
            reader = csv.DictReader(io.StringIO(text))
            rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertIn("rule_id", reader.fieldnames or [])
            self.assertEqual(rows[0]["rule_id"], "TCP-001")

    def test_html_escapes_untrusted_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                output_dir=tmp,
                capture_stats=_stats(),
                alerts=[_alert("<script>alert(1)</script>")],
                session_label="sample",
            )
            paths = gen.write_all()
            html_text = paths.html_path.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", html_text)
            self.assertIn("&lt;script&gt;", html_text)

    def test_empty_alert_list_is_handled_gracefully(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                output_dir=tmp, capture_stats=_stats(), alerts=[],
                session_label="empty",
            )
            paths = gen.write_all()
            payload = json.loads(paths.json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["alerts"], [])
            self.assertEqual(payload["summary"]["total_alerts"], 0)
            html_text = paths.html_path.read_text(encoding="utf-8")
            self.assertIn("No alerts", html_text)

    def test_parse_errors_are_reflected_in_limitations(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(
                output_dir=tmp, capture_stats=_stats(), alerts=[],
                session_label="errors",
            )
            paths = gen.write_all()
            payload = json.loads(paths.json_path.read_text(encoding="utf-8"))
            notes = " ".join(payload["summary"]["limitations"])
            self.assertIn("parse", notes.lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()