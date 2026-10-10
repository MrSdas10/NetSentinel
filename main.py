"""NetSentinel command-line entry point.

Wires together configuration, capture, parsing, baseline, detection and
reporting.  All heavy lifting lives in the other modules; this file is
responsible for argument parsing, orchestration, console output and exit
codes.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from alert_manager import AlertManager, AlertStore, build_rules_from_config
from baseline import BaselineError, BaselineManager
from capture import CaptureEngine, CaptureError, CaptureStats, SCAPY_AVAILABLE
from config_loader import ConfigError, load_config, output_path
from parsers import describe_packet
from reporter import ReportError, ReportGenerator
from utils import ensure_dir, utc_now_iso

LOGGER = logging.getLogger("netsentinel")

# Exit codes: 0 success, 1 runtime error, 2 invalid CLI usage.
EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE_ERROR = 2


# --------------------------------------------------------------------------
# Logging setup
# --------------------------------------------------------------------------

def _configure_logging(level: str, log_dir: Path) -> None:
    """Send INFO+ to the console and DEBUG+ to a rotating file."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    console = logging.StreamHandler(stream=sys.stderr)
    console.setLevel(numeric)
    console.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(console)

    try:
        ensure_dir(log_dir)
        file_handler = logging.FileHandler(
            log_dir / "netsentinel.log", encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        ))
        root.addHandler(file_handler)
    except OSError as exc:
        # A failed log file must not stop the tool from running; the console
        # handler still works and the user sees the warning.
        LOGGER.warning("Could not open log file in %s: %s", log_dir, exc)


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description=(
            "NetSentinel - real-time network threat detection and anomaly "
            "monitoring. Defensive monitoring only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --list-interfaces\n"
            "  python main.py --show-config\n"
            "  python main.py --offline capture.pcap --report\n"
            "  sudo python main.py --interface eth0 --duration 60 --report\n"
        ),
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--interface", "-i", metavar="IFACE",
        help="Capture live packets on IFACE (requires elevated privileges on most systems).",
    )
    mode.add_argument(
        "--offline", metavar="PCAP",
        help="Analyse packets from an existing PCAP file (no privileges required).",
    )

    parser.add_argument(
        "--duration", "-d", type=float, default=None,
        help="Live capture duration in seconds. Ignored with --offline.",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Generate JSON, CSV and HTML reports in the configured reports directory.",
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List capture interfaces visible to this process and exit.",
    )
    parser.add_argument(
        "--show-config", action="store_true",
        help="Print the loaded configuration and exit.",
    )
    parser.add_argument(
        "--config", metavar="PATH", default=None,
        help="Path to config.json (default: ./config.json).",
    )
    parser.add_argument(
        "--log-level", metavar="LEVEL", default=None,
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Override the configured log level.",
    )
    parser.add_argument(
        "--baseline-learn", action="store_true",
        help="Run in baseline-learning mode and overwrite the baseline file on exit.",
    )
    parser.add_argument(
        "--baseline-reset", action="store_true",
        help="Delete the stored baseline before running.",
    )
    parser.add_argument(
        "--verbose-packets", action="store_true",
        help="Print a one-line summary for each parsed packet (noisy; for lab use only).",
    )
    return parser


# --------------------------------------------------------------------------
# Sub-command implementations
# --------------------------------------------------------------------------

def _cmd_list_interfaces() -> int:
    if not SCAPY_AVAILABLE:
        print(
            "Scapy is not installed, so interfaces cannot be enumerated.\n"
            "Install dependencies with: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR

    interfaces = CaptureEngine.list_interfaces()
    if not interfaces:
        print("No capture interfaces were reported by Scapy.", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    print("Available capture interfaces:")
    for name in interfaces:
        print(f"  - {name}")
    print(
        "\nLive capture typically requires root on Linux. "
        "See README.md for details."
    )
    return EXIT_OK


def _cmd_show_config(config: Dict[str, Any]) -> int:
    import json
    print(json.dumps(config, indent=2, sort_keys=True, default=str))
    return EXIT_OK


# --------------------------------------------------------------------------
# Session orchestration
# --------------------------------------------------------------------------

class Session:
    """Holds per-run state so shutdown can flush cleanly."""

    def __init__(
        self,
        config: Dict[str, Any],
        baseline: BaselineManager,
        alert_manager: AlertManager,
        verbose_packets: bool = False,
    ) -> None:
        self.config = config
        self.baseline = baseline
        self.alert_manager = alert_manager
        self.verbose_packets = verbose_packets
        self.packets_seen = 0

    # Called by CaptureEngine for every parsed packet.
    def handle(self, parsed) -> None:
        self.packets_seen += 1
        self.baseline.observe(parsed)
        new_alerts = self.alert_manager.process(parsed)
        if self.verbose_packets:
            print(f"  pkt: {describe_packet(parsed)}")
        for alert in new_alerts:
            src = alert.source_ip or "-"
            dst = alert.destination_ip or "-"
            print(
                f"[{alert.severity.upper()}] {alert.rule_id} {alert.rule_name} "
                f"({src} -> {dst}): {alert.description}"
            )


def _build_session(
    config: Dict[str, Any],
    learn_mode: bool,
    verbose_packets: bool,
) -> Session:
    baseline_path = Path(config["baseline"]["baseline_file"])
    baseline = BaselineManager(
        baseline_path=baseline_path,
        observation_seconds=config["baseline"]["observation_seconds"],
        learning_mode=learn_mode or config["baseline"]["learning_mode"],
    )

    alerts_dir = Path(config["output_dirs"]["alerts"])
    store = AlertStore(
        jsonl_path=alerts_dir / "alerts.jsonl",
        log_path=alerts_dir / "alerts.log",
    )
    rules = build_rules_from_config(config)
    manager = AlertManager(
        rules=rules,
        store=store,
        suppression_window_seconds=config["deduplication"]["suppression_window_seconds"],
        max_in_memory_alerts=config["retention"]["max_in_memory_alerts"],
        local_networks=config["network_scope"]["local_networks"],
        network_scope_enabled=config["network_scope"]["enabled"],
    )
    return Session(
        config=config,
        baseline=baseline,
        alert_manager=manager,
        verbose_packets=verbose_packets,
    )


def _summarise(stats: CaptureStats, alert_manager: AlertManager) -> None:
    print()
    print("=" * 68)
    print("NetSentinel session summary")
    print("=" * 68)
    print(f"  Mode               : {stats.mode}")
    print(f"  Source             : {stats.source}")
    print(f"  Started (UTC)      : {stats.started_utc}")
    print(f"  Finished (UTC)     : {stats.finished_utc}")
    print(f"  Duration (s)       : {stats.duration_seconds:.2f}")
    print(f"  Total packets      : {stats.total_packets}")
    print(f"  Parsed packets     : {stats.parsed_packets}")
    print(f"  Parse errors       : {stats.parse_errors}")
    print(f"  Filtered packets   : {stats.filtered_packets}")
    print(f"  Alerts (new)       : {alert_manager.total_alerts}")
    print(f"  Alerts (suppressed): {alert_manager.suppressed_alerts}")

    if stats.protocol_counts:
        print("  Protocol counts    :")
        for proto, count in sorted(stats.protocol_counts.items()):
            print(f"      {proto:<6} {count}")

    if alert_manager.total_alerts:
        print("  Alerts by rule     :")
        for rule, count in sorted(alert_manager.counts_by_rule().items()):
            print(f"      {rule:<8} {count}")
        print("  Alerts by severity :")
        for sev, count in sorted(alert_manager.counts_by_severity().items()):
            print(f"      {sev:<8} {count}")
    print("=" * 68)


# --------------------------------------------------------------------------
# Run paths
# --------------------------------------------------------------------------

def _run_offline(
    args: argparse.Namespace,
    config: Dict[str, Any],
    session: Session,
) -> int:
    engine = CaptureEngine(
        packet_handler=session.handle,
        local_networks=config["network_scope"]["local_networks"],
        network_scope_enabled=config["network_scope"]["enabled"],
    )
    try:
        stats = engine.run_offline(args.offline)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR
    return _finalise(args, config, session, stats, mode="offline")


def _run_live(
    args: argparse.Namespace,
    config: Dict[str, Any],
    session: Session,
) -> int:
    engine = CaptureEngine(
        packet_handler=session.handle,
        local_networks=config["network_scope"]["local_networks"],
        network_scope_enabled=config["network_scope"]["enabled"],
    )

    # Translate SIGINT into a graceful engine stop so the summary and any
    # requested reports are still produced.
    def _handle_sigint(signum, frame):  # noqa: ARG001 - signature fixed by signal
        print("\nInterrupt received - stopping capture...", file=sys.stderr)
        engine.stop()
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGINT, _handle_sigint)
    except ValueError:
        # Not on the main thread; fall back to default handling.
        pass

    try:
        stats = engine.run_live(
            interface=args.interface,
            duration=args.duration,
        )
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR
    except KeyboardInterrupt:
        # The engine has already flushed stats when it caught the signal.
        stats = engine.stats

    return _finalise(args, config, session, stats, mode="live")


def _finalise(
    args: argparse.Namespace,
    config: Dict[str, Any],
    session: Session,
    stats: CaptureStats,
    mode: str,
) -> int:
    # Persist the baseline if we were learning.
    if session.baseline.learning_mode_active:
        try:
            session.baseline.save()
        except BaselineError as exc:
            print(f"warning: {exc}", file=sys.stderr)

    _summarise(stats, session.alert_manager)

    if args.report:
        generator = ReportGenerator(
            output_dir=Path(config["output_dirs"]["reports"]),
            capture_stats=stats,
            alerts=session.alert_manager.alerts(),
            baseline_summary=session.baseline.summary(),
            config=config,
            session_label=stats.source,
        )
        try:
            paths = generator.write_all()
        except ReportError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_RUNTIME_ERROR
        print("Reports written:")
        print(f"  JSON: {paths.json_path}")
        print(f"  CSV : {paths.csv_path}")
        print(f"  HTML: {paths.html_path}")

    return EXIT_OK


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Handle trivial commands before loading configuration so that
    # --list-interfaces and --help work even with a broken config file.
    if args.list_interfaces:
        return _cmd_list_interfaces()

    # Load and validate configuration.
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    # Apply CLI overrides.
    if args.log_level:
        config["log_level"] = args.log_level.upper()

    log_dir = Path(config["output_dirs"]["logs"])
    _configure_logging(config["log_level"], log_dir)
    LOGGER.debug("Effective configuration: %s", config)

    if args.show_config:
        return _cmd_show_config(config)

    # Require a mode for anything that actually runs the pipeline.
    if not args.interface and not args.offline:
        parser.print_help(sys.stderr)
        print(
            "\nerror: one of --interface or --offline is required for monitoring.",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    # Reject incompatible combinations explicitly.
    if args.offline and args.duration is not None:
        print(
            "error: --duration only applies to live capture; remove it or "
            "drop --offline.",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR
    if args.offline and args.baseline_learn:
        # Allowed: learning from a PCAP is a valid workflow. Nothing to reject.

    # Optional baseline reset before the session starts.
    baseline_path = Path(config["baseline"]["baseline_file"])
    if args.baseline_reset and baseline_path.exists():
        try:
            baseline_path.unlink()
            print(f"Baseline reset: removed {baseline_path}")
        except OSError as exc:
            print(f"error: could not remove baseline {baseline_path}: {exc}",
                  file=sys.stderr)
            return EXIT_RUNTIME_ERROR

    # Build the per-run session.
    try:
        session = _build_session(
            config,
            learn_mode=args.baseline_learn or config["baseline"]["learning_mode"],
            verbose_packets=args.verbose_packets,
        )
    except (ValueError, KeyError) as exc:
        print(f"error: could not build session: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    print(f"NetSentinel starting at {utc_now_iso()}")
    if session.baseline.learning_mode_active:
        print("Running in baseline LEARNING mode - detections are still active.")
    elif session.baseline.has_baseline:
        print(f"Loaded baseline from {baseline_path}")
    else:
        print("No baseline loaded; first-run mode.")

    if args.offline:
        return _run_offline(args, config, session)
    return _run_live(args, config, session)


if __name__ == "__main__":
    sys.exit(main())