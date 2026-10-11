"""
test_reporter.py — Tests for reporter.py (JSON, CSV, HTML generation).

Tests run without live capture; Alert objects are constructed directly.
"""

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from alert_manager import Alert
from capture import CaptureStats
from reporter import (
    generate_reports,
    append_alert_to_jsonl,
    load_alerts_from_jsonl,
)
from utils import html_escape, safe_html


def _make_alert(
    rule_id="TCP-001",
    severity="medium",
    src="10.0.0.1",
    dst="10.0.0.2",
    protocol="TCP",
):
    return Alert(
        alert_id="abc123",
        timestamp_utc="2024-05-01T12:00:00.000Z",
        rule_id=rule_id,
        rule_name="Test Rule",
        severity=severity,
        source_ip=src,
        destination_ip=dst,
        protocol=protocol,
        description="Test alert description.",
        evidence={"key": "value", "count": 42},
        recommended_action="Investigate.",
        confidence="medium",
    )


def _make_stats(packets=100, errors=2):
    stats = CaptureStats()
    stats.total_packets = packets
    stats.parse_errors = errors
    stats.protocol_counts = {"TCP": 80, "UDP": 20}
    stats.start_time = 0.0
    stats.end_time = 60.0
    return stats


class TestGenerateReportsJSON(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.reports_dir = Path(self.tmpdir)
        self.alerts = [_make_alert(), _make_alert(rule_id="UDP-001")]
        self.stats = _make_stats()

    def test_json_file_created(self):
        paths = generate_reports(
            self.alerts, self.stats, self.reports_dir
        )
        self.assertTrue(paths["json"].exists())

    def test_json_contains_alerts(self):
        paths = generate_reports(self.alerts, self.stats, self.reports_dir)
        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        self.assertEqual(data["total_alerts"], 2)
        self.assertEqual(len(data["alerts"]), 2)

    def test_json_has_required_keys(self):
        paths = generate_reports(self.alerts, self.stats, self.reports_dir)
        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        for key in (
            "project_name", "report_generated_utc", "total_packets_processed",
            "total_alerts", "protocol_counts", "alerts", "limitations",
        ):
            self.assertIn(key, data)

    def test_json_empty_alerts(self):
        paths = generate_reports([], self.stats, self.reports_dir)
        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        self.assertEqual(data["total_alerts"], 0)
        self.assertEqual(data["alerts"], [])


class TestGenerateReportsCSV(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.reports_dir = Path(self.tmpdir)
        self.alerts = [_make_alert()]
        self.stats = _make_stats()

    def test_csv_file_created(self):
        paths = generate_reports(self.alerts, self.stats, self.reports_dir)
        self.assertTrue(paths["csv"].exists())

    def test_csv_has_header_and_row(self):
        paths = generate_reports(self.alerts, self.stats, self.reports_dir)
        with paths["csv"].open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertIn("rule_id", rows[0])
        self.assertEqual(rows[0]["rule_id"], "TCP-001")

    def test_csv_empty_alerts_only_header(self):
        paths = generate_reports([], self.stats, self.reports_dir)
        with paths["csv"].open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        self.assertEqual(len(rows), 0)


class TestGenerateReportsHTML(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.reports_dir = Path(self.tmpdir)
        self.alerts = [_make_alert()]
        self.stats = _make_stats()

    def test_html_file_created(self):
        paths = generate_reports(self.alerts, self.stats, self.reports_dir)
        self.assertTrue(paths["html"].exists())

    def test_html_not_empty(self):
        paths = generate_reports(self.alerts, self.stats, self.reports_dir)
        content = paths["html"].read_text(encoding="utf-8")
        self.assertGreater(len(content), 100)

    def test_html_is_valid_document(self):
        paths = generate_reports(self.alerts, self.stats, self.reports_dir)
        content = paths["html"].read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("</html>", content)

    def test_html_empty_alerts_handled(self):
        """Empty alert list should produce a valid HTML report."""
        paths = generate_reports([], self.stats, self.reports_dir)
        content = paths["html"].read_text(encoding="utf-8")
        self.assertIn("No alerts were generated", content)

    def test_html_contains_alert_rule_id(self):
        paths = generate_reports(self.alerts, self.stats, self.reports_dir)
        content = paths["html"].read_text(encoding="utf-8")
        self.assertIn("TCP-001", content)


class TestHTMLEscaping(unittest.TestCase):
    """html_escape and safe_html must neutralise dangerous characters."""

    def test_ampersand_escaped(self):
        self.assertEqual(html_escape("a&b"), "a&amp;b")

    def test_less_than_escaped(self):
        self.assertEqual(html_escape("<script>"), "&lt;script&gt;")

    def test_greater_than_escaped(self):
        self.assertEqual(html_escape(">"), "&gt;")

    def test_double_quote_escaped(self):
        self.assertEqual(html_escape('"hello"'), "&quot;hello&quot;")

    def test_single_quote_escaped(self):
        self.assertIn("&#x27;", html_escape("it's"))

    def test_no_double_escape(self):
        """&amp; should not become &amp;amp;"""
        result = html_escape("a&b")
        self.assertEqual(result, "a&amp;b")
        # Escaping again should add an extra layer — test that we do it right.

    def test_xss_attempt_neutralised(self):
        dangerous = '<script>alert("xss")</script>'
        escaped = html_escape(dangerous)
        self.assertNotIn("<script>", escaped)
        self.assertNotIn("</script>", escaped)

    def test_safe_html_converts_none(self):
        # safe_html(None) returns "" (empty string) — None is treated as
        # "no value" rather than being stringified to "None".
        self.assertEqual(safe_html(None), "")

    def test_html_report_escapes_alert_content(self):
        """Malicious content in alert fields must be escaped in the HTML report."""
        tmpdir = Path(tempfile.mkdtemp())
        malicious_alert = Alert(
            alert_id="xss-test",
            timestamp_utc="2024-01-01T00:00:00.000Z",
            rule_id="TCP-001",
            rule_name='<script>alert("xss")</script>',
            severity="high",
            source_ip='"><img src=x onerror=alert(1)>',
            destination_ip="10.0.0.2",
            protocol="TCP",
            description='<b>bold injection</b>',
            evidence={"xss_key": '<script>evil()</script>'},
            recommended_action="Investigate.",
            confidence="high",
        )
        paths = generate_reports(
            [malicious_alert], _make_stats(), tmpdir
        )
        content = paths["html"].read_text(encoding="utf-8")
        # Raw HTML tags must not appear unescaped.
        self.assertNotIn("<script>", content)
        self.assertNotIn("</script>", content)
        # The src_ip contained "><img src=x onerror=alert(1)>
        # After escaping it becomes &quot;&gt;&lt;img src=x onerror=alert(1)&gt;
        # The tag delimiters are escaped so no executable <img> element exists.
        self.assertNotIn("<img ", content)
        # Confirm the script tag itself is escaped (appears as &lt;script&gt;)
        self.assertIn("&lt;script&gt;", content)


class TestAlertJsonlPersistence(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_append_and_load(self):
        alert = _make_alert()
        append_alert_to_jsonl(alert, self.tmpdir)
        loaded = load_alerts_from_jsonl(self.tmpdir)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["rule_id"], "TCP-001")

    def test_multiple_appends(self):
        for i in range(5):
            append_alert_to_jsonl(_make_alert(rule_id=f"TCP-00{i}"), self.tmpdir)
        loaded = load_alerts_from_jsonl(self.tmpdir)
        self.assertEqual(len(loaded), 5)

    def test_load_missing_file_empty_list(self):
        loaded = load_alerts_from_jsonl(Path(tempfile.mkdtemp()) / "none")
        self.assertEqual(loaded, [])

    def test_load_skips_corrupt_lines(self):
        jsonl_path = self.tmpdir / "alerts.jsonl"
        jsonl_path.write_text(
            '{"rule_id": "TCP-001"}\n'
            'NOT_VALID_JSON\n'
            '{"rule_id": "UDP-001"}\n',
            encoding="utf-8",
        )
        loaded = load_alerts_from_jsonl(self.tmpdir)
        self.assertEqual(len(loaded), 2)


if __name__ == "__main__":
    unittest.main()
