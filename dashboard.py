import json
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _parse_iso(value: Any) -> datetime:
    if not value:
        return datetime.min
    try:
        if isinstance(value, str):
            cleaned = value.replace("Z", "+00:00")
            return datetime.fromisoformat(cleaned)
    except ValueError:
        pass
    return datetime.min


def _collect_sessions(project_root: Path) -> List[Dict[str, Any]]:
    reports_dir = Path(project_root) / "reports"
    if not reports_dir.exists():
        return []

    sessions: List[Dict[str, Any]] = []
    for path in sorted(reports_dir.glob("*.json"), key=lambda p: p.name.lower()):
        if "dashboard" in path.name.lower():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue

        alerts = payload.get("alerts") or []
        if not isinstance(alerts, list):
            alerts = []
        report_ts = payload.get("report_generated_utc") or payload.get("capture_end_utc")
        session = {
            "session_id": path.stem,
            "file": str(path),
            "analysis_mode": payload.get("analysis_mode", "unknown"),
            "pcap_file": payload.get("pcap_file") or "N/A",
            "report_generated_utc": report_ts,
            "capture_duration_seconds": payload.get("capture_duration_seconds", 0),
            "total_packets_processed": int(payload.get("total_packets_processed", 0) or 0),
            "total_alerts": int(payload.get("total_alerts", len(alerts)) or 0),
            "protocol_counts": payload.get("protocol_counts") or {},
            "alert_counts_by_severity": payload.get("alert_counts_by_severity") or {},
            "alert_counts_by_rule": payload.get("alert_counts_by_rule") or {},
            "alerts": alerts,
        }
        sessions.append(session)

    alert_path = Path(project_root) / "alerts" / "alerts.jsonl"
    if alert_path.exists():
        try:
            with alert_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(alert, dict):
                        continue
                    session = {
                        "session_id": f"alert-{alert.get('alert_id', 'unknown')}",
                        "file": str(alert_path),
                        "analysis_mode": "alerts-jsonl",
                        "pcap_file": "N/A",
                        "report_generated_utc": alert.get("timestamp_utc"),
                        "capture_duration_seconds": 0,
                        "total_packets_processed": 0,
                        "total_alerts": 1,
                        "protocol_counts": {},
                        "alert_counts_by_severity": {alert.get("severity", "unknown"): 1},
                        "alert_counts_by_rule": {alert.get("rule_id", "unknown"): 1},
                        "alerts": [alert],
                    }
                    sessions.append(session)
        except OSError:
            pass

    sessions.sort(key=lambda s: _parse_iso(s.get("report_generated_utc") or "1970-01-01T00:00:00Z"))
    return sessions


def _summarize_sessions(sessions: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    sessions = list(sessions)
    if not sessions:
        return {
            "total_sessions": 0,
            "total_packets": 0,
            "total_alerts": 0,
            "severity_counts": {},
            "rules": {},
            "protocol_totals": {},
            "source_ip_counts": {},
            "most_recent": "N/A",
            "days_with_data": 0,
            "top_protocol": "N/A",
            "distinct_sources": 0,
        }

    total_packets = sum(int(s.get("total_packets_processed", 0) or 0) for s in sessions)
    total_alerts = sum(int(s.get("total_alerts", 0) or 0) for s in sessions)
    severity_counts: Counter[str] = Counter()
    rule_counts: Counter[str] = Counter()
    protocol_totals: Counter[str] = Counter()
    source_ip_counts: Counter[str] = Counter()

    for session in sessions:
        for proto, count in (session.get("protocol_counts") or {}).items():
            protocol_totals[str(proto)] += int(count or 0)
        for severity, count in (session.get("alert_counts_by_severity") or {}).items():
            severity_counts[str(severity)] += int(count or 0)
        for rule_id, count in (session.get("alert_counts_by_rule") or {}).items():
            rule_counts[str(rule_id)] += int(count or 0)
        for alert in session.get("alerts") or []:
            if isinstance(alert, dict):
                source_ip = alert.get("source_ip")
                if source_ip:
                    source_ip_counts[str(source_ip)] += 1

    recent_iso = max(
        (s.get("report_generated_utc") for s in sessions if s.get("report_generated_utc")),
        default="N/A",
    )
    recent_dt = _parse_iso(recent_iso)
    days_with_data = len({
        recent_dt.strftime("%Y-%m-%d") if recent_dt != datetime.min else "unknown"
        for recent_dt in [_parse_iso(s.get("report_generated_utc")) for s in sessions if s.get("report_generated_utc")]
    })
    top_protocol = "N/A"
    if protocol_totals:
        top_protocol = max(protocol_totals.items(), key=lambda item: item[1])[0]

    return {
        "total_sessions": len(sessions),
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "severity_counts": dict(severity_counts),
        "rules": dict(rule_counts),
        "protocol_totals": dict(protocol_totals),
        "source_ip_counts": dict(source_ip_counts),
        "most_recent": recent_iso,
        "days_with_data": days_with_data,
        "top_protocol": top_protocol,
        "distinct_sources": len(source_ip_counts),
    }


def generate_dashboard(project_root: Path, output_dir: Optional[Path] = None, open_browser: bool = False) -> Path:
    """Generate a self-contained HTML dashboard using historical NetSentinel reports."""
    project_root = Path(project_root).resolve()
    report_dir = output_dir if output_dir is not None else project_root / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    sessions = _collect_sessions(project_root)
    summary = _summarize_sessions(sessions)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = report_dir / f"netsentinel_dashboard_{timestamp}.html"

    session_rows = []
    for session in sessions:
        session_rows.append(
            {
                "session_id": session.get("session_id", "unknown"),
                "report_generated_utc": session.get("report_generated_utc") or "N/A",
                "analysis_mode": session.get("analysis_mode", "unknown"),
                "pcap_file": session.get("pcap_file", "N/A"),
                "total_packets_processed": session.get("total_packets_processed", 0),
                "total_alerts": session.get("total_alerts", 0),
                "protocol_counts": session.get("protocol_counts") or {},
            }
        )

    session_json = json.dumps(session_rows, ensure_ascii=False)
    summary_json = json.dumps(summary, ensure_ascii=False)
    protocol_json = json.dumps(summary.get("protocol_totals", {}), ensure_ascii=False)
    rule_json = json.dumps(summary.get("rules", {}), ensure_ascii=False)
    severity_json = json.dumps(summary.get("severity_counts", {}), ensure_ascii=False)

    html = f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>NetSentinel Historical Dashboard</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #111c2d;
      --panel-alt: #16253a;
      --text: #eaf3ff;
      --muted: #9fb7d6;
      --accent: #4ecdc4;
      --warn: #f9a94a;
      --danger: #ff6b6b;
      --success: #67d376;
      --border: #2b3a52;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--text);
    }}
    .shell {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    .header {{ margin-bottom: 22px; }}
    .subtitle {{ color: var(--muted); }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin: 22px 0; }}
    .card {{ background: linear-gradient(180deg, var(--panel), var(--panel-alt)); border: 1px solid var(--border); border-radius: 12px; padding: 18px; box-shadow: 0 8px 20px rgba(0,0,0,0.2); }}
    .card .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
    .card .value {{ font-size: clamp(1.4rem, 2vw, 2.1rem); margin-top: 8px; font-weight: bold; }}
    .grid {{ display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 18px; margin: 20px 0; }}
    .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }}
    .bars {{ display: flex; flex-direction: column; gap: 10px; }}
    .bar-row {{ display: grid; grid-template-columns: 110px 1fr 60px; align-items: center; gap: 8px; }}
    .bar-track {{ background: rgba(255,255,255,0.08); height: 12px; border-radius: 9px; overflow: hidden; }}
    .bar-fill {{ background: linear-gradient(90deg, var(--accent), #80d8ff); height: 100%; }}
    .chart-wrap {{ min-height: 260px; position: relative; }}
    .chart-wrap svg {{ width: 100%; height: 260px; display: block; }}
    .chart-axis {{ stroke: var(--border); stroke-width: 1; }}
    .chart-grid {{ stroke: rgba(159,183,214,0.16); stroke-width: 1; }}
    .chart-label {{ fill: var(--muted); font-size: 11px; }}
    .chart-line {{ fill: none; stroke: var(--accent); stroke-width: 3; stroke-linecap: round; stroke-linejoin: round; }}
    .chart-line.alerts {{ stroke: var(--danger); }}
    .chart-point {{ fill: var(--panel); stroke: var(--accent); stroke-width: 2; }}
    .chart-point.alerts {{ stroke: var(--danger); }}
    .chart-legend {{ display: flex; gap: 16px; flex-wrap: wrap; color: var(--muted); font-size: 12px; margin-top: 8px; }}
    .legend-swatch {{ width: 10px; height: 10px; display: inline-block; border-radius: 50%; margin-right: 5px; }}
    .donut-layout {{ display: flex; align-items: center; gap: 22px; min-height: 230px; }}
    .donut {{ width: 170px; height: 170px; border-radius: 50%; flex: 0 0 auto; position: relative; }}
    .donut::after {{ content: ''; position: absolute; inset: 32px; background: var(--panel); border-radius: 50%; }}
    .donut-total {{ position: absolute; inset: 0; z-index: 1; display: grid; place-items: center; text-align: center; font-weight: bold; font-size: 20px; }}
    .donut-total span {{ display: block; color: var(--muted); font-size: 11px; font-weight: normal; text-transform: uppercase; letter-spacing: .08em; }}
    .donut-legend {{ display: flex; flex-direction: column; gap: 8px; }}
    .donut-legend-row {{ display: flex; align-items: center; gap: 7px; color: var(--muted); font-size: 13px; }}
    .donut-legend-row strong {{ color: var(--text); margin-left: auto; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ padding: 10px 8px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }}
    .muted {{ color: var(--muted); }}
    .empty {{ padding: 18px 0; color: var(--muted); }}
    .legend {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 10px 0; }}
    .dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 6px; }}
    @media (max-width: 840px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class=\"shell\">
    <div class=\"header\">
      <h1>NetSentinel Historical Dashboard</h1>
      <div class=\"subtitle\">Generated from persisted NetSentinel JSON reports and alert data.</div>
    </div>

    <div class=\"cards\" id=\"cards\"></div>

    <div class=\"grid\">
      <div class=\"panel\">
        <h2>Protocol distribution</h2>
        <div id=\"protocolBreakdown\"></div>
      </div>
      <div class=\"panel\">
        <h2>Alert severity</h2>
        <div id=\"severityBreakdown\"></div>
      </div>
    </div>

    <div class=\"grid\">
      <div class=\"panel\">
        <h2>Security rule activity</h2>
        <div id=\"ruleBreakdown\"></div>
      </div>
      <div class=\"panel\">
        <h2>Historical comparison</h2>
        <div id=\"comparison\"></div>
      </div>
    </div>

    <div class=\"grid\">
      <div class=\"panel\">
        <h2>Session trend</h2>
        <div class=\"subtitle\">Packets and alerts across stored sessions</div>
        <div class=\"chart-wrap\" id=\"trendChart\"></div>
        <div class=\"chart-legend\">
          <span><i class=\"legend-swatch\" style=\"background:var(--accent)\"></i>Packets</span>
          <span><i class=\"legend-swatch\" style=\"background:var(--danger)\"></i>Alerts</span>
        </div>
      </div>
      <div class=\"panel\">
        <h2>Severity distribution</h2>
        <div class=\"subtitle\">Share of recorded alert severity levels</div>
        <div class=\"donut-layout\" id=\"severityChart\"></div>
      </div>
    </div>

    <div class=\"panel\" style=\"margin-top: 18px;\">
      <h2>Session history</h2>
      <table>
        <thead>
          <tr>
            <th>Session</th>
            <th>Captured</th>
            <th>Mode</th>
            <th>Packets</th>
            <th>Alerts</th>
            <th>Protocols</th>
          </tr>
        </thead>
        <tbody id=\"sessionTableBody\"></tbody>
      </table>
    </div>
  </div>

  <script>
    const summary = {summary_json};
    const sessions = {session_json};

    function renderCards() {{
      const cards = [
        ['Total capture sessions', summary.total_sessions],
        ['Total packets processed', summary.total_packets],
        ['Total security alerts', summary.total_alerts],
        ['High-severity alerts', summary.severity_counts.high || 0],
        ['Medium-severity alerts', summary.severity_counts.medium || 0],
        ['Low-severity alerts', summary.severity_counts.low || 0],
        ['Most frequent protocol', summary.top_protocol || 'N/A'],
        ['Distinct source IPs', summary.distinct_sources || 'N/A'],
        ['Most recent capture', summary.most_recent || 'N/A'],
        ['Historical days with data', summary.days_with_data || 'N/A'],
      ];
      const container = document.getElementById('cards');
      container.innerHTML = cards.map(([label, value]) => `
        <div class=\"card\">
          <div class=\"label\">${{label}}</div>
          <div class=\"value\">${{value}}</div>
        </div>
      `).join('');
    }}

    function renderBars(targetId, map) {{
      const container = document.getElementById(targetId);
      const entries = Object.entries(map || {{}}).sort((a, b) => b[1] - a[1]);
      if (!entries.length) {{
        container.innerHTML = '<div class=\"empty\">No recorded data available for this section.</div>';
        return;
      }}
      const max = Math.max(...entries.map(([, value]) => Number(value) || 0), 1);
      container.innerHTML = entries.map(([label, value]) => `
        <div class=\"bar-row\">
          <div>${{label}}</div>
          <div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:${{((Number(value) || 0) / max) * 100}}%\"></div></div>
          <div>${{Number(value) || 0}}</div>
        </div>
      `).join('');
    }}

    function renderComparison() {{
      const comparison = document.getElementById('comparison');
      if (!sessions.length) {{
        comparison.innerHTML = '<div class=\"empty\">No historical data available for comparison.</div>';
        return;
      }}
      const latest = sessions[sessions.length - 1];
      const previous = sessions[sessions.length - 2] || null;
      if (!previous) {{
        comparison.innerHTML = '<div class=\"empty\">Insufficient historical data for a meaningful comparison; only one session is stored.</div>';
        return;
      }}
      const currentPackets = Number(latest.total_packets_processed || 0);
      const prevPackets = Number(previous.total_packets_processed || 0);
      const currentAlerts = Number(latest.total_alerts || 0);
      const prevAlerts = Number(previous.total_alerts || 0);
      const packetDelta = currentPackets - prevPackets;
      const alertDelta = currentAlerts - prevAlerts;
      const packetPct = prevPackets ? (packetDelta / prevPackets) * 100 : 0;
      const alertPct = prevAlerts ? (alertDelta / prevAlerts) * 100 : 0;
      comparison.innerHTML = `
        <div class=\"muted\">Latest session: ${{latest.session_id}}</div>
        <div style=\"margin-top: 12px; line-height: 1.8;\">
          <div>Current packets: <strong>${{currentPackets}}</strong> vs previous <strong>${{prevPackets}}</strong></div>
          <div>Packet delta: <strong>${{packetDelta >= 0 ? '+' : ''}}${{packetDelta}}</strong> (${{packetPct >= 0 ? '+' : ''}}${{packetPct.toFixed(1)}}%)</div>
          <div>Alert delta: <strong>${{alertDelta >= 0 ? '+' : ''}}${{alertDelta}}</strong> (${{alertPct >= 0 ? '+' : ''}}${{alertPct.toFixed(1)}}%)</div>
          <div class=\"muted\">This comparison is based on the latest and previous completed captures in the stored history.</div>
        </div>
      `;
    }}

    function renderTrendChart() {{
      const container = document.getElementById('trendChart');
      if (!sessions.length) {{
        container.innerHTML = '<div class="empty">No session data available for the trend chart.</div>';
        return;
      }}
      const width = 720;
      const height = 260;
      const pad = {{ left: 46, right: 18, top: 18, bottom: 38 }};
      const plotWidth = width - pad.left - pad.right;
      const plotHeight = height - pad.top - pad.bottom;
      const packetValues = sessions.map(session => Number(session.total_packets_processed || 0));
      const alertValues = sessions.map(session => Number(session.total_alerts || 0));
      const maximum = Math.max(...packetValues, ...alertValues, 1);
      const x = index => sessions.length === 1
        ? pad.left + plotWidth / 2
        : pad.left + (index / (sessions.length - 1)) * plotWidth;
      const y = value => pad.top + plotHeight - (value / maximum) * plotHeight;
      const points = values => values.map((value, index) => `${{x(index).toFixed(1)}},${{y(value).toFixed(1)}}`).join(' ');
      const grid = [0, 0.25, 0.5, 0.75, 1].map(ratio => {{
        const yPos = pad.top + plotHeight - ratio * plotHeight;
        const label = Math.round(maximum * ratio);
        return `<line class="chart-grid" x1="${{pad.left}}" y1="${{yPos}}" x2="${{width - pad.right}}" y2="${{yPos}}"></line>
          <text class="chart-label" x="${{pad.left - 8}}" y="${{yPos + 4}}" text-anchor="end">${{label}}</text>`;
      }}).join('');
      const labels = sessions.map((session, index) => {{
        if (sessions.length > 8 && index % Math.ceil(sessions.length / 6) !== 0 && index !== sessions.length - 1) return '';
        const date = (session.report_generated_utc || '').slice(0, 10) || 'N/A';
        return `<text class="chart-label" x="${{x(index)}}" y="${{height - 12}}" text-anchor="middle">${{date}}</text>`;
      }}).join('');
      const circles = (values, className) => values.map((value, index) =>
        `<circle class="chart-point ${{className}}" cx="${{x(index)}}" cy="${{y(value)}}" r="4"><title>${{value}}</title></circle>`
      ).join('');
      container.innerHTML = `<svg viewBox="0 0 ${{width}} ${{height}}" role="img" aria-label="Session packets and alerts trend">
        ${{grid}}
        <line class="chart-axis" x1="${{pad.left}}" y1="${{pad.top + plotHeight}}" x2="${{width - pad.right}}" y2="${{pad.top + plotHeight}}"></line>
        <polyline class="chart-line" points="${{points(packetValues)}}"></polyline>
        <polyline class="chart-line alerts" points="${{points(alertValues)}}"></polyline>
        ${{circles(packetValues, '')}}
        ${{circles(alertValues, 'alerts')}}
        ${{labels}}
      </svg>`;
    }}

    function renderSeverityChart() {{
      const container = document.getElementById('severityChart');
      const entries = Object.entries(summary.severity_counts || {{}})
        .map(([label, value]) => [label, Number(value) || 0])
        .filter(([, value]) => value > 0)
        .sort((a, b) => b[1] - a[1]);
      if (!entries.length) {{
        container.innerHTML = '<div class="empty">No severity data available for the chart.</div>';
        return;
      }}
      const colors = {{ high: '#ff6b6b', medium: '#f9a94a', low: '#67d376', critical: '#d94bff', unknown: '#80d8ff' }};
      const total = entries.reduce((sum, [, value]) => sum + value, 0);
      let cursor = 0;
      const segments = entries.map(([label, value]) => {{
        const start = cursor;
        cursor += (value / total) * 360;
        return `${{colors[label.toLowerCase()] || colors.unknown}} ${{start}}deg ${{cursor}}deg`;
      }}).join(', ');
      const legend = entries.map(([label, value]) => `<div class="donut-legend-row">
        <i class="legend-swatch" style="background:${{colors[label.toLowerCase()] || colors.unknown}}"></i>
        <span>${{label}}</span><strong>${{value}}</strong>
      </div>`).join('');
      container.innerHTML = `<div class="donut" style="background: conic-gradient(${{segments}})">
        <div class="donut-total">${{total}}<span>alerts</span></div>
      </div><div class="donut-legend">${{legend}}</div>`;
    }}

    function renderSessionTable() {{
      const body = document.getElementById('sessionTableBody');
      if (!sessions.length) {{
        body.innerHTML = '<tr><td colspan=\"6\" class=\"empty\">No historical sessions are available.</td></tr>';
        return;
      }}
      body.innerHTML = sessions.map(session => `
        <tr>
          <td>${{session.session_id}}</td>
          <td>${{session.report_generated_utc || 'N/A'}}</td>
          <td>${{session.analysis_mode || 'N/A'}}</td>
          <td>${{session.total_packets_processed || 0}}</td>
          <td>${{session.total_alerts || 0}}</td>
          <td>${{Object.entries(session.protocol_counts || {{}}).map(([proto, count]) => `${{proto}}:${{count}}`).join(', ') || 'N/A'}}</td>
        </tr>
      `).join('');
    }}

    renderCards();
    renderBars('protocolBreakdown', summary.protocol_totals || {{}});
    renderBars('severityBreakdown', summary.severity_counts || {{}});
    renderBars('ruleBreakdown', summary.rules || {{}});
    renderComparison();
    renderTrendChart();
    renderSeverityChart();
    renderSessionTable();
  </script>
</body>
</html>
"""

    html = html.replace("{summary_json}", summary_json)
    html = html.replace("{session_json}", session_json)
    html = html.replace("{protocol_json}", protocol_json)
    html = html.replace("{rule_json}", rule_json)
    html = html.replace("{severity_json}", severity_json)

    output_path.write_text(html, encoding="utf-8")

    if open_browser:
        try:
            webbrowser.open(output_path.as_uri())
        except Exception:
            pass

    return output_path
