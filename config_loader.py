"""
config_loader.py — Configuration loading and validation for NetSentinel.

Reads config.json, validates every field, and returns a typed Config
dataclass.  Raises ConfigError with an actionable message for any invalid
setting so that main.py can report the problem and exit cleanly.

Key names and default values must match the generated config.json exactly.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ConfigError(ValueError):
    """Raised when the configuration file is missing, unreadable, or invalid."""


# ---------------------------------------------------------------------------
# Sub-configuration dataclasses (one per logical group)
# ---------------------------------------------------------------------------

@dataclass
class TcpConfig:
    enabled: bool = True
    syn_port_threshold: int = 20        # Distinct destination ports in window
    observation_window_seconds: int = 60
    excluded_sources: List[str] = field(default_factory=list)


@dataclass
class UdpConfig:
    enabled: bool = True
    port_diversity_threshold: int = 15  # Distinct destination ports in window
    observation_window_seconds: int = 60
    excluded_sources: List[str] = field(default_factory=list)


@dataclass
class IcmpConfig:
    enabled: bool = True
    echo_request_threshold: int = 50    # Echo requests per window
    observation_window_seconds: int = 30
    excluded_sources: List[str] = field(default_factory=list)


@dataclass
class ArpConfig:
    enabled: bool = True
    # How long (seconds) before a seen mapping is considered stale.
    mapping_expiry_seconds: int = 300
    # Static trusted IP→MAC mappings that should never trigger an alert.
    trusted_mappings: Dict[str, str] = field(default_factory=dict)
    # Maximum number of IP→MAC mappings to retain in memory.
    max_table_size: int = 1024


@dataclass
class DnsConfig:
    enabled: bool = True
    query_rate_threshold: int = 100     # Queries per source per window
    observation_window_seconds: int = 60
    nxdomain_threshold: int = 20        # NXDOMAINs per source per window
    nxdomain_window_seconds: int = 60
    excluded_sources: List[str] = field(default_factory=list)


@dataclass
class BaselineConfig:
    enabled: bool = True
    learning_duration_seconds: int = 300   # Time to collect baseline data
    baseline_file: str = "data/baseline.json"
    # Multiplier applied to baseline average to set the anomaly threshold.
    # e.g. 2.0 means "alert if current value > 2x baseline average".
    anomaly_multiplier: float = 2.0


@dataclass
class OutputConfig:
    alerts_dir: str = "alerts"
    reports_dir: str = "reports"
    logs_dir: str = "logs"
    data_dir: str = "data"
    # Maximum alerts held in memory.
    max_alerts_in_memory: int = 10000
    # Seconds during which an identical alert (same rule+source) is suppressed.
    alert_suppression_window_seconds: int = 60
    generate_report_on_exit: bool = True


@dataclass
class LoggingConfig:
    level: str = "INFO"          # DEBUG | INFO | WARNING | ERROR
    log_to_file: bool = True
    log_filename: str = "logs/netsentinel.log"


@dataclass
class Config:
    tcp: TcpConfig = field(default_factory=TcpConfig)
    udp: UdpConfig = field(default_factory=UdpConfig)
    icmp: IcmpConfig = field(default_factory=IcmpConfig)
    arp: ArpConfig = field(default_factory=ArpConfig)
    dns: DnsConfig = field(default_factory=DnsConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    # Optional: restrict analysis to packets from/to these CIDR networks.
    # Empty list means "monitor all observed traffic".
    local_networks: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _require_bool(d: Dict, key: str, section: str) -> bool:
    val = d.get(key)
    if not isinstance(val, bool):
        raise ConfigError(
            f"[{section}] '{key}' must be true or false, got {val!r}"
        )
    return val


def _require_positive_int(d: Dict, key: str, section: str) -> int:
    val = d.get(key)
    if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
        raise ConfigError(
            f"[{section}] '{key}' must be a positive integer, got {val!r}"
        )
    return int(val)


def _require_positive_float(d: Dict, key: str, section: str) -> float:
    val = d.get(key)
    if not isinstance(val, (int, float)) or isinstance(val, bool) or val <= 0:
        raise ConfigError(
            f"[{section}] '{key}' must be a positive number, got {val!r}"
        )
    return float(val)


def _require_string(d: Dict, key: str, section: str) -> str:
    val = d.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ConfigError(
            f"[{section}] '{key}' must be a non-empty string, got {val!r}"
        )
    return val


def _optional_string_list(d: Dict, key: str, section: str) -> List[str]:
    val = d.get(key, [])
    if not isinstance(val, list):
        raise ConfigError(f"[{section}] '{key}' must be a list of strings")
    for item in val:
        if not isinstance(item, str):
            raise ConfigError(
                f"[{section}] '{key}' must contain only strings, found {item!r}"
            )
    return val


def _optional_string_dict(d: Dict, key: str, section: str) -> Dict[str, str]:
    val = d.get(key, {})
    if not isinstance(val, dict):
        raise ConfigError(f"[{section}] '{key}' must be an object (dict)")
    for k, v in val.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ConfigError(
                f"[{section}] '{key}' must map strings to strings"
            )
    return val


# ---------------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------------

def _parse_tcp(d: Dict) -> TcpConfig:
    s = "tcp"
    return TcpConfig(
        enabled=_require_bool(d, "enabled", s),
        syn_port_threshold=_require_positive_int(d, "syn_port_threshold", s),
        observation_window_seconds=_require_positive_int(
            d, "observation_window_seconds", s
        ),
        excluded_sources=_optional_string_list(d, "excluded_sources", s),
    )


def _parse_udp(d: Dict) -> UdpConfig:
    s = "udp"
    return UdpConfig(
        enabled=_require_bool(d, "enabled", s),
        port_diversity_threshold=_require_positive_int(
            d, "port_diversity_threshold", s
        ),
        observation_window_seconds=_require_positive_int(
            d, "observation_window_seconds", s
        ),
        excluded_sources=_optional_string_list(d, "excluded_sources", s),
    )


def _parse_icmp(d: Dict) -> IcmpConfig:
    s = "icmp"
    return IcmpConfig(
        enabled=_require_bool(d, "enabled", s),
        echo_request_threshold=_require_positive_int(
            d, "echo_request_threshold", s
        ),
        observation_window_seconds=_require_positive_int(
            d, "observation_window_seconds", s
        ),
        excluded_sources=_optional_string_list(d, "excluded_sources", s),
    )


def _parse_arp(d: Dict) -> ArpConfig:
    s = "arp"
    return ArpConfig(
        enabled=_require_bool(d, "enabled", s),
        mapping_expiry_seconds=_require_positive_int(
            d, "mapping_expiry_seconds", s
        ),
        trusted_mappings=_optional_string_dict(d, "trusted_mappings", s),
        max_table_size=_require_positive_int(d, "max_table_size", s),
    )


def _parse_dns(d: Dict) -> DnsConfig:
    s = "dns"
    return DnsConfig(
        enabled=_require_bool(d, "enabled", s),
        query_rate_threshold=_require_positive_int(
            d, "query_rate_threshold", s
        ),
        observation_window_seconds=_require_positive_int(
            d, "observation_window_seconds", s
        ),
        nxdomain_threshold=_require_positive_int(d, "nxdomain_threshold", s),
        nxdomain_window_seconds=_require_positive_int(
            d, "nxdomain_window_seconds", s
        ),
        excluded_sources=_optional_string_list(d, "excluded_sources", s),
    )


def _parse_baseline(d: Dict) -> BaselineConfig:
    s = "baseline"
    return BaselineConfig(
        enabled=_require_bool(d, "enabled", s),
        learning_duration_seconds=_require_positive_int(
            d, "learning_duration_seconds", s
        ),
        baseline_file=_require_string(d, "baseline_file", s),
        anomaly_multiplier=_require_positive_float(d, "anomaly_multiplier", s),
    )


def _parse_output(d: Dict) -> OutputConfig:
    s = "output"
    return OutputConfig(
        alerts_dir=_require_string(d, "alerts_dir", s),
        reports_dir=_require_string(d, "reports_dir", s),
        logs_dir=_require_string(d, "logs_dir", s),
        data_dir=_require_string(d, "data_dir", s),
        max_alerts_in_memory=_require_positive_int(
            d, "max_alerts_in_memory", s
        ),
        alert_suppression_window_seconds=_require_positive_int(
            d, "alert_suppression_window_seconds", s
        ),
        generate_report_on_exit=_require_bool(d, "generate_report_on_exit", s),
    )


_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}


def _parse_logging(d: Dict) -> LoggingConfig:
    s = "logging"
    level = _require_string(d, "level", s).upper()
    if level not in _VALID_LOG_LEVELS:
        raise ConfigError(
            f"[logging] 'level' must be one of {sorted(_VALID_LOG_LEVELS)}, "
            f"got {level!r}"
        )
    return LoggingConfig(
        level=level,
        log_to_file=_require_bool(d, "log_to_file", s),
        log_filename=_require_string(d, "log_filename", s),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config(path: Path) -> Config:
    """
    Load and validate the configuration file at *path*.

    Returns a populated Config dataclass on success.
    Raises ConfigError with an actionable message on failure.
    """
    if not path.exists():
        raise ConfigError(
            f"Configuration file not found: {path}\n"
            "Create or restore config.json from the project template."
        )

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration file: {exc}") from exc

    try:
        data: Any = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"Configuration file is not valid JSON: {exc}\n"
            f"Check {path} for syntax errors (trailing commas, missing quotes)."
        ) from exc

    if not isinstance(data, dict):
        raise ConfigError("Configuration file must contain a JSON object at the top level.")

    # Validate and parse each section.  Missing sections use defaults.
    required_sections = {
        "tcp": _parse_tcp,
        "udp": _parse_udp,
        "icmp": _parse_icmp,
        "arp": _parse_arp,
        "dns": _parse_dns,
        "baseline": _parse_baseline,
        "output": _parse_output,
        "logging": _parse_logging,
    }

    parsed: Dict[str, Any] = {}
    for section, parser in required_sections.items():
        section_data = data.get(section)
        if section_data is None:
            raise ConfigError(
                f"Required configuration section '{section}' is missing.\n"
                f"Add a '{section}' block to {path}."
            )
        if not isinstance(section_data, dict):
            raise ConfigError(
                f"Configuration section '{section}' must be a JSON object, "
                f"got {type(section_data).__name__!r}"
            )
        try:
            parsed[section] = parser(section_data)
        except ConfigError:
            raise  # Re-raise with the message already set by the helper.

    # Optional: local_networks
    local_networks: List[str] = []
    raw_nets = data.get("local_networks", [])
    if not isinstance(raw_nets, list):
        raise ConfigError("'local_networks' must be a list of CIDR strings.")
    for net in raw_nets:
        if not isinstance(net, str):
            raise ConfigError(f"'local_networks' entries must be strings, got {net!r}")
        # Basic sanity check — full CIDR validation happens in the caller.
        if "/" not in net:
            raise ConfigError(
                f"'local_networks' entry {net!r} does not look like a CIDR "
                "(e.g. '192.168.1.0/24')."
            )
        local_networks.append(net)

    config = Config(
        tcp=parsed["tcp"],
        udp=parsed["udp"],
        icmp=parsed["icmp"],
        arp=parsed["arp"],
        dns=parsed["dns"],
        baseline=parsed["baseline"],
        output=parsed["output"],
        logging=parsed["logging"],
        local_networks=local_networks,
    )

    logger.debug("Configuration loaded successfully from %s", path)
    return config


def load_config_or_defaults(path: Path) -> Config:
    """
    Attempt to load the configuration file.  If it cannot be read or parsed,
    log a warning and return the built-in defaults.

    Use this only in contexts where continuing with defaults is explicitly
    acceptable (e.g. --show-config before a configuration file exists).
    """
    try:
        return load_config(path)
    except ConfigError as exc:
        logger.warning("Using built-in defaults because config failed to load: %s", exc)
        return Config()
