"""Report generation for NetSentinel.

Produces three artefacts per session, all timestamped and placed in the
configured ``reports/`` directory:

  * ``report_<UTC>_<session>.json``  - machine readable, full alert records.
  * ``report_<UTC>_<session>.csv``   - one row per alert, for spreadsheets.
  * ``report_<UTC>_<session>.html``  - a self-contained page for a browser.

All untrusted values (host names, MAC addresses, DNS qnames, descriptions)
are HTML-escaped before insertion.  The reporter never invents packet
counts: everything it prints comes from the supplied ``CaptureStats`` and
the alert list.
"""

from __future__ import annotations

import csv
import html
import io
import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from alert_manager import Alert
from capture import CaptureStats
from utils import atomic_write_text, dumps_json, ensure_dir, utc_now_iso

LOGGER = logging.getLogger(__name__)

PROJECT_NAME = "NetSentinel"
PROJECT_TAGLINE = "Real-Time Network Threat Detection and Anomaly Monitoring"
SCHEMA_VERSION = "1.0"

CSV_COLUMNS = (
    "alert_id",
    "timestamp_utc",
    "rule_id",
    "rule_name",
    "severity",
    "confidence",
    "source_ip",
    "destination_ip",
    "protocol",
    "occurrence_count",
    "description",
)


class ReportError(Exception):
    """Raised when a report cannot be written."""


@dataclass
class ReportPaths:
    json_path: Path
    csv_path: Path
    html_path: Path

    def to_dict(self) -> Dict[str, str]:
        return {
            "json": str(self.json_path),
            "csv": str(self.csv_path),
            "html": str(self.html_path),
        }


class ReportGenerator:
    """Build and write JSON/CSV/HTML reports from a session's data."""

    def __init__(
        self,
        output_dir: Path | str,
        capture_stats: CaptureStats,
        alerts: Sequence[Alert],
        baseline_summary: Optional[Mapping[str, Any]] = None,
        config: Optional[Mapping[str, Any]] = None,
        session_label: Optional[str] = None,
    ) -> None:
        self.output_dir = ensure_dir(output_dir)
        self.stats = capture_stats
        self.alerts = list(alerts)
        self.baseline_summary = dict(baseline_summary or {})
        self.config = dict(config or {})
        self.generated_utc = utc_now_iso()
        self.session_label = session_label or _slugify(self.stats.source) or "session"

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def write_all(self) -> ReportPaths:
        """Write JSON, CSV and HTML reports and return their paths."""
        stem = _report_stem(self.generated_utc, self.session_label)
        json_path = self.output_dir / f"{stem}.json"
        csv_path = self.output_dir / f"{stem}.csv"
        html_path = self.output_dir / f"{stem}.html"

        try:
            atomic_write_text(json_path, self._render_json())
            atomic_write_text(csv_path, self._render_csv())
            atomic_write_text(html_path, self._render_html())
        except OSError as exc:
            raise ReportError(f"Failed to write report: {exc}") from exc

        LOGGER.info("Reports written: %s, %s, %s", json_path, csv_path, html_path)
        return ReportPaths(json_path=json_path, csv_path=csv_path, html_path=html_path)

    # ------------------------------------------------------------------
    # Data assembly
    # ------------------------------------------------------------------

    def _alert_counts_by_rule(self) -> Dict[str, int]:
        counter: Counter[str] = Counter()
        for alert in self.alerts:
            counter[alert.rule_id] += 1
        return dict(counter)

    def _alert_counts_by_severity(self) -> Dict[str, int]:
        counter: Counter[str] = Counter()
        for alert in self.alerts:
            counter[alert.severity] += 1
        return dict(counter)

    def _top_sources(self, limit: int = 10) -> List[Dict[str, Any]]:
        counter: Counter[str] = Counter()
        for alert in self.alerts:
            if alert.source_ip:
                counter[alert.source_ip] += 1
        return [
            {"source_ip": ip, "alert_count": count}
            for ip, count in counter.most_common(limit)
        ]

    def _top_destinations(self, limit: int = 10) -> List[Dict[str, Any]]:
        counter: Counter[str] = Counter()
        for alert in self.alerts:
            if alert.destination_ip:
                counter[alert.destination_ip] += 1
        return [
            {"destination_ip": ip, "alert_count": count}
            for ip, count in counter.most_common(limit)
        ]

    def _recommended_actions(self) -> List[str]:
        seen: List[str] = []
        for alert in self.alerts:
            if alert.recommended_action and alert.recommended_action not in seen:
                seen.append(alert.recommended_action)
        return seen

    def _limitations(self) -> List[str]:
        notes: List[str] = [
            "NetSentinel is a passive monitor: it cannot observe traffic that "
            "never reaches its capture interface.",
            "Encrypted payloads are analysed only through their observable "
            "metadata (addresses, ports, timing, flags).",
            "Switched networks, VLAN configuration, capture permissions and "
            "packet loss can all reduce what is visible.",
            "Every detection is an indicator requiring investigation, not a "
            "confirmed security incident.",
        ]
        if self.stats.parse_errors:
            notes.append(
                f"{self.stats.parse_errors} packet(s) could not be fully parsed; "
                "detection coverage may be incomplete."
            )
        if self.stats.filtered_packets:
            notes.append(
                f"{self.stats.filtered_packets} packet(s) were dropped by the "
                "network-scope filter."
            )
        if self.stats.interrupted:
            notes.append(
                "Capture was interrupted before the intended duration elapsed."
            )
        if self.stats.error_message:
            notes.append(f"Capture reported an error: {self.stats.error_message}")
        if not self.alerts:
            notes.append(
                "No alerts were generated during this session; this does not "
                "prove the network was free of malicious activity."
            )
        return notes

    def _summary(self) -> Dict[str, Any]:
        return {
            "project": PROJECT_NAME,
            "tagline": PROJECT_TAGLINE,
            "schema_version": SCHEMA_VERSION,
            "generated_utc": self.generated_utc,
            "mode": self.stats.mode,
            "source": self.stats.source,
            "started_utc": self.stats.started_utc,
            "finished_utc": self.stats.finished_utc,
            "duration_seconds": round(self.stats.duration_seconds, 3),
            "total_packets": self.stats.total_packets,
            "parsed_packets": self.stats.parsed_packets,
            "parse_errors": self.stats.parse_errors,
            "filtered_packets": self.stats.filtered_packets,
            "protocol_counts": dict(self.stats.protocol_counts),
            "total_alerts": len(self.alerts),
            "alerts_by_severity": self._alert_counts_by_severity(),
            "alerts_by_rule": self._alert_counts_by_rule(),
            "top_sources": self._top_sources(),
            "top_destinations": self._top_destinations(),
            "baseline": self.baseline_summary,
            "limitations": self._limitations(),
            "recommended_actions": self._recommended_actions(),
        }

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _render_json(self) -> str:
        payload = {
            "summary": self._summary(),
            "alerts": [alert.to_dict() for alert in self.alerts],
        }
        return dumps_json(payload, indent=2)

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def _render_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for alert in self.alerts:
            row = alert.to_dict()
            writer.writerow({key: row.get(key, "") for key in CSV_COLUMNS})
        return buffer.getvalue()

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def _render_html(self) -> str:
        summary = self._summary()
        esc = html.escape

        def render_alert(alert: Alert) -> str:
            evidence_rows = "".join(
                f"<tr><th>{esc(str(k))}</th><td>{esc(_stringify(v))}</td></tr>"
                for k, v in sorted(alert.evidence.items())
            )
            return f"""
            <article class="alert severity-{esc(alert.severity)}">
              <header>
                <h3>{esc(alert.rule_id)} &mdash; {esc(alert.rule_name)}</h3>
                <p class="meta">
                  <span class="sev">{esc(alert.severity.upper())}</span>
                  <span>confidence: {esc(alert.confidence)}</span>
                  <span>{esc(alert.timestamp_utc)}</span>
                  <span>id: {esc(alert.alert_id)}</span>
                </p>
              </header>
              <p><strong>From:</strong> {esc(alert.source_ip or "-")}
                 &nbsp; <strong>To:</strong> {esc(alert.destination_ip or "-")}
                 &nbsp; <strong>Protocol:</strong> {esc(alert.protocol)}</p>
              <p>{esc(alert.description)}</p>
              <details open>
                <summary>Evidence</summary>
                <table class="evidence">
                  <tbody>{evidence_rows}</tbody>
                </table>
              </details>
              <p class="action"><strong>Recommended action:</strong>
                 {esc(alert.recommended_action)}</p>
              <p class="occurrences">Occurrences: {int(alert.occurrence_count)}</p>
            </article>
            """

        alerts_html = "\n".join(render_alert(a) for a in self.alerts) or (
            "<p class='empty'>No alerts were generated during this session.</p>"
        )

        severity_rows = "".join(
            f"<tr><th>{esc(k)}</th><td>{v}</td></tr>"
            for k, v in sorted(summary["alerts_by_severity"].items())
        ) or "<tr><td colspan='2'>No alerts</td></tr>"

        rule_rows = "".join(
            f"<tr><th>{esc(k)}</th><td>{v}</td></tr>"
            for k, v in sorted(summary["alerts_by_rule"].items())
        ) or "<tr><td colspan='2'>No alerts</td></tr>"

        protocol_rows = "".join(
            f"<tr><th>{esc(k)}</th><td>{v}</td></tr>"
            for k, v in sorted(summary["protocol_counts"].items())
        ) or "<tr><td colspan='2'>No packets</td></tr>"

        limitation_items = "".join(
            f"<li>{esc(item)}</li>" for item in summary["limitations"]
        )
        action_items = "".join(
            f"<li>{esc(item)}</li>" for item in summary["recommended_actions"]
        ) or "<li>No specific actions were recommended.</li>"

        baseline_html = _render_baseline_section(summary.get("baseline") or {})

        return _HTML_TEMPLATE.format(
            project=esc(PROJECT_NAME),
            tagline=esc(PROJECT_TAGLINE),
            generated=esc(summary["generated_utc"]),
            mode=esc(summary["mode"]),
            source=esc(summary["source"]),
            started=esc(summary["started_utc"]),
            finished=esc(summary["finished_utc"]),
            duration=f"{summary['duration_seconds']:.2f}",
            total_packets=summary["total_packets"],
            parsed_packets=summary["parsed_packets"],
            parse_errors=summary["parse_errors"],
            filtered_packets=summary["filtered_packets"],
            total_alerts=summary["total_alerts"],
            protocol_rows=protocol_rows,
            severity_rows=severity_rows,
            rule_rows=rule_rows,
            baseline_section=baseline_html,
            limitations=limitation_items,
            actions=action_items,
            alerts=alerts_html,
        )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _slugify(value: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(value))
    return safe.strip("_")[:40]


def _report_stem(generated_utc: str, label: str) -> str:
    stamp = generated_utc.replace(":", "").replace("-", "")
    if stamp.endswith("Z"):
        stamp = stamp[:-1]
    return f"report_{stamp}_{label}"


def _stringify(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def _render_baseline_section(baseline: Mapping[str, Any]) -> str:
    if not baseline:
        return "<p class='empty'>No baseline information available.</p>"
    esc = html.escape
    rows = "".join(
        f"<tr><th>{esc(str(k))}</th><td>{esc(_stringify(v))}</td></tr>"
        for k, v in sorted(baseline.items())
    )
    return f"<table class='evidence'><tbody>{rows}</tbody></table>"


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{project} report &mdash; {generated}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; line-height: 1.4; }}
  h1, h2, h3 {{ margin: 0 0 0.5rem; }}
  .tagline {{ color: #666; margin-top: 0; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin: 1rem 0 2rem; }}
  .card {{ border: 1px solid #ccc; border-radius: 6px; padding: 0.75rem 1rem; }}
  .card h3 {{ font-size: 0.85rem; text-transform: uppercase; color: #555; }}
  .card p {{ margin: 0; font-size: 1.4rem; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }}
  th {{ background: #f4f4f4; width: 40%; }}
  article.alert {{ border-left: 6px solid #888; background: #fafafa; padding: 0.8rem 1rem; margin: 1rem 0; border-radius: 4px; }}
  article.alert.severity-low {{ border-color: #2c7; }}
  article.alert.severity-medium {{ border-color: #fa0; }}
  article.alert.severity-high {{ border-color: #d43; }}
  article.alert.severity-critical {{ border-color: #800; }}
  .meta span {{ display: inline-block; margin-right: 1rem; font-size: 0.85rem; color: #444; }}
  .meta .sev {{ font-weight: 700; }}
  .empty {{ color: #666; font-style: italic; }}
  details > summary {{ cursor: pointer; font-weight: 600; }}
  .action {{ font-size: 0.9rem; }}
  .occurrences {{ font-size: 0.85rem; color: #555; }}
  footer {{ margin-top: 3rem; color: #666; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>{project} report</h1>
<p class="tagline">{tagline}</p>
<p><strong>Generated (UTC):</strong> {generated}</p>

<section class="summary">
  <div class="card"><h3>Mode</h3><p>{mode}</p></div>
  <div class="card"><h3>Source</h3><p>{source}</p></div>
  <div class="card"><h3>Duration (s)</h3><p>{duration}</p></div>
  <div class="card"><h3>Total packets</h3><p>{total_packets}</p></div>
  <div class="card"><h3>Parsed</h3><p>{parsed_packets}</p></div>
  <div class="card"><h3>Parse errors</h3><p>{parse_errors}</p></div>
  <div class="card"><h3>Filtered</h3><p>{filtered_packets}</p></div>
  <div class="card"><h3>Alerts</h3><p>{total_alerts}</p></div>
</section>

<section>
  <h2>Session</h2>
  <table><tbody>
    <tr><th>Started (UTC)</th><td>{started}</td></tr>
    <tr><th>Finished (UTC)</th><td>{finished}</td></tr>
  </tbody></table>
</section>

<section>
  <h2>Protocol counts</h2>
  <table><tbody>{protocol_rows}</tbody></table>
</section>

<section>
  <h2>Alerts by severity</h2>
  <table><tbody>{severity_rows}</tbody></table>
</section>

<section>
  <h2>Alerts by rule</h2>
  <table><tbody>{rule_rows}</tbody></table>
</section>

<section>
  <h2>Baseline</h2>
  {baseline_section}
</section>

<section>
  <h2>Recommended investigation steps</h2>
  <ul>{actions}</ul>
</section>

<section>
  <h2>Known limitations</h2>
  <ul>{limitations}</ul>
</section>

<section>
  <h2>Alerts</h2>
  {alerts}
</section>

<footer>
  <p>This report was generated by {project}. Detections are indicators that
  require investigation; they are not proof of an attack.</p>
</footer>
</body>
</html>
"""