"""
reporter.py — Report and alert export for NetSentinel.

Generates three output formats from the alert list:
  1. JSON  — machine-readable structured alerts
  2. CSV   — tabular alert records for spreadsheets / SIEMs
  3. HTML  — human-readable report openable in any browser

Design notes
------------
* All untrusted string values written to HTML are escaped via utils.safe_html().
* Output directories are created automatically.
* Reports use unique timestamped filenames to avoid overwriting previous runs.
* Report generation does not modify the alert list or interrupt capture.
* Empty alert lists are handled gracefully (reports are generated and note
  that no alerts were produced).
* File-write failures are logged and raised so main.py can report them.
"""

import csv
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from alert_manager import Alert
from capture import CaptureStats
from utils import ensure_directory, safe_html, utc_now_iso

logger = logging.getLogger(__name__)

# Columns written to the CSV report (in order).
_CSV_COLUMNS = [
    "alert_id",
    "timestamp_utc",
    "rule_id",
    "rule_name",
    "severity",
    "source_ip",
    "destination_ip",
    "protocol",
    "description",
    "confidence",
    "recommended_action",
]


# ---------------------------------------------------------------------------
# Public report-generation function
# ---------------------------------------------------------------------------

def generate_reports(
    alerts: List[Alert],
    stats: CaptureStats,
    reports_dir: Path,
    analysis_mode: str = "live",            # "live" | "offline"
    pcap_file: Optional[str] = None,
    project_name: str = "NetSentinel",
    baseline_summary: Optional[dict] = None,
) -> Dict[str, Path]:
    """
    Generate JSON, CSV, and HTML reports from *alerts*.

    Parameters
    ----------
    alerts        : List of Alert objects to include in the report.
    stats         : CaptureStats from the capture engine.
    reports_dir   : Directory where report files are written.
    analysis_mode : "live" for live capture, "offline" for PCAP analysis.
    pcap_file     : Path to the PCAP file (offline mode only).
    project_name  : Display name written in report headers.
    baseline_summary : Optional dict of baseline comparison results.

    Returns
    -------
    dict mapping format name ("json", "csv", "html") to the file Path.
    Raises OSError if a file cannot be written.
    """
    ensure_directory(reports_dir)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    stem = f"netsentinel_report_{ts}"

    json_path = reports_dir / f"{stem}.json"
    csv_path  = reports_dir / f"{stem}.csv"
    html_path = reports_dir / f"{stem}.html"

    # Build the shared report context.
    context = _build_context(
        alerts, stats, analysis_mode, pcap_file, project_name, baseline_summary
    )

    _write_json(context, json_path)
    _write_csv(alerts, csv_path)
    _write_html(context, alerts, html_path)

    logger.info(
        "Reports written: JSON=%s, CSV=%s, HTML=%s",
        json_path.name, csv_path.name, html_path.name,
    )
    return {"json": json_path, "csv": csv_path, "html": html_path}


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_context(
    alerts: List[Alert],
    stats: CaptureStats,
    analysis_mode: str,
    pcap_file: Optional[str],
    project_name: str,
    baseline_summary: Optional[dict],
) -> dict:
    """Build the shared report data structure."""
    severity_counts: Dict[str, int] = {}
    rule_counts: Dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
        rule_counts[alert.rule_id] = rule_counts.get(alert.rule_id, 0) + 1

    return {
        "project_name": project_name,
        "report_generated_utc": utc_now_iso(),
        "analysis_mode": analysis_mode,
        "pcap_file": pcap_file,
        "capture_duration_seconds": round(stats.elapsed_seconds, 1),
        "total_packets_processed": stats.total_packets,
        "parse_errors": stats.parse_errors,
        "protocol_counts": dict(stats.protocol_counts),
        "total_alerts": len(alerts),
        "alert_counts_by_severity": severity_counts,
        "alert_counts_by_rule": rule_counts,
        "baseline_summary": baseline_summary or {},
        "alerts": [a.to_dict() for a in alerts],
        "limitations": [
            "Passive NIDS only sees traffic that reaches the capture interface.",
            "Encrypted payloads are not inspected; only metadata is analysed.",
            "On switched networks, only traffic to/from the host or "
            "mirrored ports is visible.",
            "All detections are indicators requiring further investigation, "
            "not confirmed security incidents.",
            "High ICMP or DNS counts may have legitimate explanations "
            "(network diagnostics, misconfiguration).",
            "ARP mapping changes may result from DHCP renewals, failover, "
            "or hardware replacement.",
            "Packet loss, hardware offloading, and interface configuration "
            "can affect completeness.",
        ],
    }


# ---------------------------------------------------------------------------
# JSON writer
# ---------------------------------------------------------------------------

def _write_json(context: dict, path: Path) -> None:
    try:
        text = json.dumps(context, indent=2, default=str, ensure_ascii=False)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        logger.error("Failed to write JSON report: %s", exc)
        raise


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

def _write_csv(alerts: List[Alert], path: Path) -> None:
    try:
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=_CSV_COLUMNS,
                extrasaction="ignore",
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()
            for alert in alerts:
                row = {col: getattr(alert, col, "") or "" for col in _CSV_COLUMNS}
                writer.writerow(row)
    except OSError as exc:
        logger.error("Failed to write CSV report: %s", exc)
        raise


# ---------------------------------------------------------------------------
# HTML writer
# ---------------------------------------------------------------------------

def _write_html(context: dict, alerts: List[Alert], path: Path) -> None:
    try:
        html = _render_html(context, alerts)
        path.write_text(html, encoding="utf-8")
    except OSError as exc:
        logger.error("Failed to write HTML report: %s", exc)
        raise


def _render_html(context: dict, alerts: List[Alert]) -> str:
    """
    Render a self-contained HTML report string.

    All untrusted string values are passed through safe_html() before
    being embedded in the document.  No external CSS or JS is loaded.
    """

    def _sev_color(sev: str) -> str:
        return {
            "critical": "#c0392b",
            "high":     "#e67e22",
            "medium":   "#f1c40f",
            "low":      "#27ae60",
        }.get(sev.lower(), "#95a5a6")

    def _sev_badge(sev: str) -> str:
        color = _sev_color(sev)
        return (
            f'<span style="background:{color};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:0.85em;font-weight:bold;">'
            f'{safe_html(sev.upper())}</span>'
        )

    # --- Summary table rows ---
    def _kv(label: str, value: str) -> str:
        return (
            f"<tr><th>{safe_html(label)}</th>"
            f"<td>{safe_html(value)}</td></tr>\n"
        )

    summary_rows = (
        _kv("Project", context["project_name"])
        + _kv("Report generated (UTC)", context["report_generated_utc"])
        + _kv("Analysis mode", context["analysis_mode"])
    )
    if context.get("pcap_file"):
        summary_rows += _kv("PCAP file", str(context["pcap_file"]))
    summary_rows += (
        _kv("Capture duration", f"{context['capture_duration_seconds']} s")
        + _kv("Total packets processed", str(context["total_packets_processed"]))
        + _kv("Parse errors", str(context["parse_errors"]))
        + _kv("Total alerts", str(context["total_alerts"]))
    )

    # --- Protocol counts ---
    proto_rows = "".join(
        f"<tr><td>{safe_html(k)}</td><td>{safe_html(str(v))}</td></tr>\n"
        for k, v in sorted(context["protocol_counts"].items())
    ) or "<tr><td colspan='2'>No traffic observed.</td></tr>\n"

    # --- Alert severity counts ---
    sev_rows = "".join(
        f"<tr><td>{_sev_badge(k)}</td><td>{safe_html(str(v))}</td></tr>\n"
        for k, v in sorted(context["alert_counts_by_severity"].items())
    ) or "<tr><td colspan='2'>No alerts.</td></tr>\n"

    # --- Rule counts ---
    rule_rows = "".join(
        f"<tr><td>{safe_html(k)}</td><td>{safe_html(str(v))}</td></tr>\n"
        for k, v in sorted(context["alert_counts_by_rule"].items())
    ) or "<tr><td colspan='2'>No alerts.</td></tr>\n"

    # --- Individual alert cards ---
    alert_cards = ""
    for i, alert in enumerate(alerts, start=1):
        ev_rows = "".join(
            f"<tr><td style='font-family:monospace;font-size:0.85em;'>"
            f"{safe_html(str(k))}</td>"
            f"<td style='font-family:monospace;font-size:0.85em;'>"
            f"{safe_html(str(v))}</td></tr>\n"
            for k, v in alert.evidence.items()
            if k != "rule_id"  # Already shown in header.
        )
        alert_cards += f"""
<div class="alert-card" style="border-left:4px solid {_sev_color(alert.severity)};
     margin:12px 0;padding:12px 16px;background:#fafafa;border-radius:4px;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
    <strong>#{i}</strong>
    {_sev_badge(alert.severity)}
    <code style="font-size:0.9em;">{safe_html(alert.rule_id)}</code>
    <span style="color:#555;">{safe_html(alert.rule_name)}</span>
  </div>
  <table style="width:100%;font-size:0.9em;">
    <tr><th>Alert ID</th><td><code>{safe_html(alert.alert_id)}</code></td></tr>
    <tr><th>Timestamp (UTC)</th><td>{safe_html(alert.timestamp_utc)}</td></tr>
    <tr><th>Source IP</th><td>{safe_html(str(alert.source_ip or '—'))}</td></tr>
    <tr><th>Destination IP</th><td>{safe_html(str(alert.destination_ip or '—'))}</td></tr>
    <tr><th>Protocol</th><td>{safe_html(alert.protocol)}</td></tr>
    <tr><th>Description</th><td>{safe_html(alert.description)}</td></tr>
    <tr><th>Confidence</th><td>{safe_html(alert.confidence)}</td></tr>
    <tr><th>Recommended action</th><td>{safe_html(alert.recommended_action)}</td></tr>
  </table>
  {"<details><summary style='cursor:pointer;margin-top:6px;'>Evidence</summary><table style='width:100%;font-size:0.85em;margin-top:4px;'>" + ev_rows + "</table></details>" if ev_rows else ""}
</div>
"""

    if not alert_cards:
        alert_cards = "<p style='color:#555;'>No alerts were generated during this analysis.</p>"

    # --- Limitations ---
    limitations_li = "".join(
        f"<li>{safe_html(lim)}</li>\n"
        for lim in context.get("limitations", [])
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{safe_html(context['project_name'])} Security Report</title>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 24px;
            background: #f0f2f5; color: #222; }}
    h1 {{ color: #1a1a2e; margin-bottom: 4px; }}
    h2 {{ color: #16213e; border-bottom: 2px solid #e0e0e0; padding-bottom: 6px; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 16px; }}
    th, td {{ border: 1px solid #ddd; padding: 7px 12px; text-align: left; }}
    th {{ background: #eef0f4; font-weight: 600; width: 200px; }}
    .card {{ background: #fff; border-radius: 8px; padding: 20px;
             margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
    .alert-card th {{ background: #f4f4f4; }}
    details summary {{ color: #0055a5; }}
    code {{ background: #eee; padding: 2px 5px; border-radius: 3px; }}
    footer {{ font-size: 0.8em; color: #888; margin-top: 32px; text-align: center; }}
  </style>
</head>
<body>
<h1>🛡 {safe_html(context['project_name'])} — Security Report</h1>
<p style="color:#555;font-size:0.95em;">
  Defensive monitoring report. All detections are indicators requiring
  investigation — not confirmed security incidents.
</p>

<div class="card">
  <h2>Summary</h2>
  <table>{summary_rows}</table>
</div>

<div class="card">
  <h2>Protocol Breakdown</h2>
  <table>
    <tr><th>Protocol</th><th>Packets</th></tr>
    {proto_rows}
  </table>
</div>

<div class="card">
  <h2>Alert Summary</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    {sev_rows}
  </table>
  <table style="margin-top:12px;">
    <tr><th>Rule ID</th><th>Count</th></tr>
    {rule_rows}
  </table>
</div>

<div class="card">
  <h2>Detection Details ({safe_html(str(len(alerts)))} alert{"s" if len(alerts) != 1 else ""})</h2>
  {alert_cards}
</div>

<div class="card">
  <h2>Known Limitations</h2>
  <ul>{limitations_li}</ul>
</div>

<footer>
  Generated by {safe_html(context['project_name'])} &mdash;
  {safe_html(context['report_generated_utc'])}
  &mdash; For authorized use on networks you own or have permission to monitor.
</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Alert file helpers (append-only event log)
# ---------------------------------------------------------------------------

def append_alert_to_jsonl(alert: Alert, alerts_dir: Path) -> None:
    """
    Append a single alert as a JSON line to alerts/alerts.jsonl.

    JSONL (one JSON object per line) is easy to process with standard tools
    (jq, grep, Python) and survives application restarts cleanly.
    File-write failures are logged but do not propagate to the caller.
    """
    ensure_directory(alerts_dir)
    jsonl_path = alerts_dir / "alerts.jsonl"
    try:
        line = json.dumps(alert.to_dict(), default=str, ensure_ascii=False)
        with jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        logger.error("Failed to append alert to %s: %s", jsonl_path, exc)


def load_alerts_from_jsonl(alerts_dir: Path) -> List[dict]:
    """
    Read all previously persisted alerts from alerts/alerts.jsonl.

    Returns a list of dicts.  Lines that cannot be parsed are skipped
    with a warning.  Returns an empty list if the file does not exist.
    """
    jsonl_path = alerts_dir / "alerts.jsonl"
    if not jsonl_path.exists():
        return []
    alerts = []
    try:
        with jsonl_path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Skipping malformed alert line %d in %s: %s",
                        lineno, jsonl_path, exc,
                    )
    except OSError as exc:
        logger.error("Cannot read %s: %s", jsonl_path, exc)
    return alerts
