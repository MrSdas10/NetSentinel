"""
main.py — NetSentinel application entry point.

Implements the command-line interface and wires together all modules.

Usage examples
--------------
    python main.py --help
    python main.py --list-interfaces
    python main.py --show-config
    python main.py --interface eth0
    python main.py --interface eth0 --duration 60
    python main.py --interface eth0 --duration 60 --report
    python main.py --offline captures/lab.pcap
    python main.py --offline captures/lab.pcap --report

Exit codes
----------
    0  Successful execution.
    1  Invalid arguments or incompatible options.
    2  Configuration error.
    3  Capture or I/O error.
    4  Permission denied (live capture).
"""

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Project root — all relative paths are resolved from here.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.resolve()
CONFIG_PATH = PROJECT_ROOT / "config.json"

# Exit codes
EXIT_OK          = 0
EXIT_ARG_ERROR   = 1
EXIT_CONFIG_ERROR = 2
EXIT_IO_ERROR    = 3
EXIT_PERMISSION  = 4


# ---------------------------------------------------------------------------
# Logging bootstrap (before config is loaded)
# ---------------------------------------------------------------------------

def _bootstrap_logging(level: str = "INFO") -> None:
    """Configure console logging before the config file is read."""
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description=(
            "NetSentinel — Real-Time Network Threat Detection and Anomaly "
            "Monitoring System.\n\n"
            "A defensive passive NIDS for authorized networks. "
            "Do not use on networks you do not own or have written permission "
            "to monitor."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --list-interfaces\n"
            "  python main.py --interface eth0 --duration 60 --report\n"
            "  python main.py --offline captures/lab.pcap --report\n"
        ),
    )

    # Mode selection (mutually exclusive)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--interface", "-i",
        metavar="IFACE",
        help="Network interface for live capture (requires elevated privileges).",
    )
    mode.add_argument(
        "--offline", "-o",
        metavar="PCAP_FILE",
        help="Analyse an existing PCAP file instead of live capture.",
    )
    mode.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    mode.add_argument(
        "--show-config",
        action="store_true",
        help="Display the loaded configuration and exit.",
    )

    # Capture options
    parser.add_argument(
        "--duration", "-d",
        metavar="SECONDS",
        type=_positive_float,
        default=None,
        help="Live capture duration in seconds (default: unlimited).",
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Generate JSON, CSV, and HTML reports after analysis.",
    )
    parser.add_argument(
        "--config", "-c",
        metavar="FILE",
        default=str(CONFIG_PATH),
        help=f"Path to the configuration file (default: {CONFIG_PATH}).",
    )
    parser.add_argument(
        "--bpf",
        metavar="FILTER",
        default="",
        help='Optional BPF capture filter expression (e.g. "tcp port 80").',
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Override the log level from the configuration file.",
    )

    return parser


def _positive_float(value: str) -> float:
    """argparse type: a positive float value."""
    try:
        fval = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number.")
    if fval <= 0:
        raise argparse.ArgumentTypeError(f"Duration must be > 0, got {fval}.")
    return fval


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _configure_file_logging(config) -> None:
    """Add a rotating file handler based on the loaded config."""
    from config_loader import LoggingConfig
    lc: LoggingConfig = config.logging
    if not lc.log_to_file:
        return
    log_path = PROJECT_ROOT / lc.log_filename
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(str(log_path), encoding="utf-8")
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    logging.getLogger().addHandler(handler)


def _print_separator(char: str = "-", width: int = 60) -> None:
    print(char * width)


def _print_summary(processor, alert_manager) -> None:
    """Print a concise post-capture summary to stdout."""
    stats = processor.stats
    _print_separator()
    print("  NetSentinel — Capture Summary")
    _print_separator()
    print(f"  Total packets processed : {stats.total_packets}")
    print(f"  Parse errors            : {stats.parse_errors}")
    print(f"  Elapsed time            : {stats.elapsed_seconds:.1f} s")
    print()
    print("  Protocol breakdown:")
    for proto, count in sorted(stats.protocol_counts.items()):
        print(f"    {proto:<12} {count}")
    print()
    print(f"  Total alerts            : {alert_manager.total_alerts}")
    print(f"  Suppressed (dedup)      : {alert_manager.suppressed_alerts}")
    by_sev = alert_manager.alert_count_by_severity()
    if by_sev:
        print("  Alerts by severity:")
        for sev, count in sorted(by_sev.items()):
            print(f"    {sev:<12} {count}")
    by_rule = alert_manager.alert_count_by_rule()
    if by_rule:
        print("  Alerts by rule:")
        for rule, count in sorted(by_rule.items()):
            print(f"    {rule:<12} {count}")
    _print_separator()


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_list_interfaces() -> int:
    from capture import list_interfaces
    interfaces = list_interfaces()
    if not interfaces:
        print("No interfaces found (Scapy may need elevated privileges).")
        return EXIT_IO_ERROR
    print("Available network interfaces:")
    for iface in interfaces:
        print(f"  {iface}")
    return EXIT_OK


def cmd_show_config(config_path: Path) -> int:
    from config_loader import load_config_or_defaults, ConfigError
    import json, dataclasses
    try:
        config = load_config_or_defaults(config_path)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    def _to_dict(obj):
        if dataclasses.is_dataclass(obj):
            return {k: _to_dict(v) for k, v in dataclasses.asdict(obj).items()}
        return obj

    print(json.dumps(_to_dict(config), indent=2))
    return EXIT_OK


def cmd_live_capture(
    args: argparse.Namespace,
    config,
) -> int:
    from capture import LiveCapture, PacketProcessor, validate_interface
    from alert_manager import AlertManager
    from baseline import Baseline
    from parsers import parse_packet
    from reporter import generate_reports, append_alert_to_jsonl

    interface = args.interface

    # Validate interface.
    if not validate_interface(interface):
        print(
            f"Error: Interface {interface!r} not found.\n"
            "Run --list-interfaces to see available interfaces.",
            file=sys.stderr,
        )
        return EXIT_ARG_ERROR

    alerts_dir = PROJECT_ROOT / config.output.alerts_dir
    reports_dir = PROJECT_ROOT / config.output.reports_dir
    data_dir = PROJECT_ROOT / config.output.data_dir

    alert_manager = AlertManager(config)
    baseline = Baseline(
        baseline_file=PROJECT_ROOT / config.baseline.baseline_file,
        learning_duration_seconds=config.baseline.learning_duration_seconds,
        anomaly_multiplier=config.baseline.anomaly_multiplier,
    )
    baseline.load()

    def on_alerts(new_alerts):
        for alert in new_alerts:
            append_alert_to_jsonl(alert, alerts_dir)

    processor = PacketProcessor(
        parser_fn=parse_packet,
        alert_manager=alert_manager,
        baseline=baseline,
        alert_callback=on_alerts,
    )

    capture = LiveCapture(
        interface=interface,
        processor=processor,
        bpf_filter=args.bpf,
    )

    # Graceful Ctrl+C shutdown.
    def _sigint_handler(signum, frame):
        print("\n[*] Interrupt received — stopping capture...")
        capture.stop()

    signal.signal(signal.SIGINT, _sigint_handler)

    print(f"[*] Starting live capture on {interface!r}...")
    if args.duration:
        print(f"[*] Duration: {args.duration} seconds.")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        capture.start(duration=args.duration)
    except PermissionError:
        print(
            "Error: Permission denied.\n"
            "Run with sudo, or grant CAP_NET_RAW to the Python interpreter:\n"
            "  sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)",
            file=sys.stderr,
        )
        return EXIT_PERMISSION
    except OSError as exc:
        print(f"Capture error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    _print_summary(processor, alert_manager)

    if args.report:
        try:
            paths = generate_reports(
                alerts=alert_manager.alerts,
                stats=processor.stats,
                reports_dir=reports_dir,
                analysis_mode="live",
                project_name="NetSentinel",
            )
            print("\n[*] Reports generated:")
            for fmt, p in paths.items():
                print(f"    {fmt.upper():<6} {p}")
        except OSError as exc:
            print(f"Report generation failed: {exc}", file=sys.stderr)

    return EXIT_OK


def cmd_offline(
    args: argparse.Namespace,
    config,
) -> int:
    from capture import OfflineCapture, PacketProcessor
    from alert_manager import AlertManager
    from baseline import Baseline
    from parsers import parse_packet
    from reporter import generate_reports, append_alert_to_jsonl

    pcap_path = Path(args.offline).expanduser().resolve()
    if not pcap_path.exists():
        print(f"Error: PCAP file not found: {pcap_path}", file=sys.stderr)
        return EXIT_ARG_ERROR
    if not pcap_path.is_file():
        print(f"Error: {pcap_path} is not a file.", file=sys.stderr)
        return EXIT_ARG_ERROR

    alerts_dir = PROJECT_ROOT / config.output.alerts_dir
    reports_dir = PROJECT_ROOT / config.output.reports_dir

    alert_manager = AlertManager(config)
    baseline = Baseline(
        baseline_file=PROJECT_ROOT / config.baseline.baseline_file,
        learning_duration_seconds=config.baseline.learning_duration_seconds,
        anomaly_multiplier=config.baseline.anomaly_multiplier,
    )
    baseline.load()

    def on_alerts(new_alerts):
        for alert in new_alerts:
            append_alert_to_jsonl(alert, alerts_dir)

    processor = PacketProcessor(
        parser_fn=parse_packet,
        alert_manager=alert_manager,
        baseline=baseline,
        alert_callback=on_alerts,
    )

    print(f"[*] Analysing offline PCAP: {pcap_path}\n")

    try:
        cap = OfflineCapture(pcap_path=pcap_path, processor=processor)
        cap.run()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ARG_ERROR
    except RuntimeError as exc:
        print(f"Capture error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    _print_summary(processor, alert_manager)

    if args.report:
        try:
            paths = generate_reports(
                alerts=alert_manager.alerts,
                stats=processor.stats,
                reports_dir=reports_dir,
                analysis_mode="offline",
                pcap_file=str(pcap_path),
                project_name="NetSentinel",
            )
            print("\n[*] Reports generated:")
            for fmt, p in paths.items():
                print(f"    {fmt.upper():<6} {p}")
        except OSError as exc:
            print(f"Report generation failed: {exc}", file=sys.stderr)

    return EXIT_OK


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    # Bootstrap console logging early.
    _bootstrap_logging(args.log_level or "INFO")

    logger = logging.getLogger("main")

    # Load configuration.
    config_path = Path(args.config).expanduser().resolve()

    # Commands that don't need a full valid config.
    if args.list_interfaces:
        return cmd_list_interfaces()

    if args.show_config:
        return cmd_show_config(config_path)

    # All other commands require a valid config.
    from config_loader import load_config, ConfigError
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    # Override log level from CLI if provided.
    if args.log_level:
        config.logging.level = args.log_level
    _bootstrap_logging(config.logging.level)
    _configure_file_logging(config)

    # Validate: --duration only makes sense with --interface.
    if args.duration and not args.interface:
        print(
            "Error: --duration is only valid with --interface (live capture).",
            file=sys.stderr,
        )
        return EXIT_ARG_ERROR

    # Validate: --bpf only makes sense with --interface.
    if args.bpf and not args.interface:
        print(
            "Error: --bpf filter is only valid with --interface (live capture).",
            file=sys.stderr,
        )
        return EXIT_ARG_ERROR

    if args.interface:
        return cmd_live_capture(args, config)

    if args.offline:
        return cmd_offline(args, config)

    # No mode selected.
    parser.print_help()
    print(
        "\nError: Specify --interface <IFACE>, --offline <FILE>, "
        "--list-interfaces, or --show-config.",
        file=sys.stderr,
    )
    return EXIT_ARG_ERROR


if __name__ == "__main__":
    sys.exit(main())
