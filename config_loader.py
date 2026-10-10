"""Configuration loading and validation for NetSentinel.

``config.json`` is the single source of truth for every tunable value.  This
module guarantees that, once :func:`load_config` returns, every key the rest of
the application indexes is present and of the expected type.  A missing or
invalid value is always an error - a detection rule is never silently disabled
because a key was absent.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from utils import NetSentinelError

DEFAULT_CONFIG_FILENAME = "config.json"

SEVERITY_LEVELS = ("low", "medium", "high", "critical")
KNOWN_RULES = ("TCP-001", "UDP-001", "ICMP-001", "ARP-001", "DNS-001", "DNS-002")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
OUTPUT_DIR_KEYS = ("alerts", "reports", "logs", "data")


class ConfigError(NetSentinelError):
    """Raised when configuration is missing, unreadable or invalid."""


# --------------------------------------------------------------------------
# Primitive validators
# --------------------------------------------------------------------------

def _expect_mapping(value: Any, dotted: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(
            f"'{dotted}' must be a JSON object, got {type(value).__name__}"
        )
    return value


def _expect_bool(value: Any, dotted: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"'{dotted}' must be true or false, got {value!r}")
    return value


def _expect_int(value: Any, dotted: str, minimum: Optional[int] = None,
                maximum: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"'{dotted}' must be an integer, got {value!r}")
    if minimum is not None and value < minimum:
        raise ConfigError(f"'{dotted}' must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"'{dotted}' must be <= {maximum}, got {value}")
    return value


def _expect_number(value: Any, dotted: str, minimum: Optional[float] = None,
                   maximum: Optional[float] = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"'{dotted}' must be a number, got {value!r}")
    number = float(value)
    if minimum is not None and number < minimum:
        raise ConfigError(f"'{dotted}' must be >= {minimum}, got {number}")
    if maximum is not None and number > maximum:
        raise ConfigError(f"'{dotted}' must be <= {maximum}, got {number}")
    return number


def _expect_str(value: Any, dotted: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"'{dotted}' must be a non-empty string, got {value!r}")
    return value.strip()


def _expect_list(value: Any, dotted: str) -> List[Any]:
    if not isinstance(value, list):
        raise ConfigError(f"'{dotted}' must be a JSON array, got {type(value).__name__}")
    return value


def _expect_ip_list(value: Any, dotted: str) -> List[str]:
    items = _expect_list(value, dotted)
    result: List[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ConfigError(f"'{dotted}' must contain strings, got {item!r}")
        try:
            result.append(str(ipaddress.ip_address(item.strip())))
        except ValueError as exc:
            raise ConfigError(
                f"'{dotted}' contains an invalid IP address {item!r}: {exc}"
            ) from exc
    return result


def _expect_network_list(value: Any, dotted: str) -> List[str]:
    items = _expect_list(value, dotted)
    result: List[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ConfigError(f"'{dotted}' must contain strings, got {item!r}")
        try:
            result.append(str(ipaddress.ip_network(item.strip(), strict=False)))
        except ValueError as exc:
            raise ConfigError(
                f"'{dotted}' contains an invalid network {item!r}: {exc}"
            ) from exc
    return result


def _expect_port_list(value: Any, dotted: str) -> List[int]:
    items = _expect_list(value, dotted)
    for item in items:
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 65535:
            raise ConfigError(
                f"'{dotted}' must contain integers between 0 and 65535, got {item!r}"
            )
    return items


def _expect_str_map(value: Any, dotted: str) -> Dict[str, str]:
    mapping = _expect_mapping(value, dotted)
    result: Dict[str, str] = {}
    for key, item in mapping.items():
        if not isinstance(item, str):
            raise ConfigError(f"'{dotted}.{key}' must be a string, got {item!r}")
        result[str(key)] = item.strip()
    return result


# --------------------------------------------------------------------------
# Section validators
# --------------------------------------------------------------------------

def _validate_output_dirs(cfg: Dict[str, Any]) -> None:
    dirs = _expect_mapping(cfg.get("output_dirs"), "output_dirs")
    for key in OUTPUT_DIR_KEYS:
        _expect_str(dirs.get(key), f"output_dirs.{key}")


def _validate_retention(cfg: Dict[str, Any]) -> None:
    retention = _expect_mapping(cfg.get("retention"), "retention")
    _expect_int(retention.get("max_in_memory_alerts"),
                "retention.max_in_memory_alerts", minimum=1)


def _validate_deduplication(cfg: Dict[str, Any]) -> None:
    dedup = _expect_mapping(cfg.get("deduplication"), "deduplication")
    _expect_number(dedup.get("suppression_window_seconds"),
                   "deduplication.suppression_window_seconds", minimum=0.0)


def _validate_network_scope(cfg: Dict[str, Any]) -> None:
    scope = _expect_mapping(cfg.get("network_scope"), "network_scope")
    enabled = _expect_bool(scope.get("enabled"), "network_scope.enabled")
    networks = _expect_network_list(scope.get("local_networks"),
                                    "network_scope.local_networks")
    if enabled and not networks:
        raise ConfigError(
            "network_scope.enabled is true but network_scope.local_networks is "
            "empty; provide at least one CIDR range or disable the scope filter"
        )


def _validate_severity(cfg: Dict[str, Any]) -> None:
    severity = _expect_str_map(cfg.get("severity"), "severity")
    missing = [rule for rule in KNOWN_RULES if rule not in severity]
    if missing:
        raise ConfigError(
            f"'severity' is missing an entry for rule(s): {', '.join(missing)}"
        )
    unknown = [rule for rule in severity if rule not in KNOWN_RULES]
    if unknown:
        raise ConfigError(
            f"'severity' contains unknown rule id(s): {', '.join(sorted(unknown))}"
        )
    for rule, level in severity.items():
        if level.lower() not in SEVERITY_LEVELS:
            raise ConfigError(
                f"'severity.{rule}' must be one of {SEVERITY_LEVELS}, got {level!r}"
            )


def _validate_trusted_hosts(cfg: Dict[str, Any]) -> None:
    _expect_ip_list(cfg.get("trusted_hosts"), "trusted_hosts")


def _validate_detection_tcp(section: Dict[str, Any]) -> None:
    tcp = _expect_mapping(section.get("tcp"), "detection.tcp")
    _expect_bool(tcp.get("enabled"), "detection.tcp.enabled")
    _expect_number(tcp.get("window_seconds"),
                   "detection.tcp.window_seconds", minimum=0.001)
    _expect_int(tcp.get("distinct_destination_ports"),
                "detection.tcp.distinct_destination_ports", minimum=2)
    _expect_port_list(tcp.get("excluded_destination_ports"),
                      "detection.tcp.excluded_destination_ports")
    _expect_int(tcp.get("max_tracked_sources"),
                "detection.tcp.max_tracked_sources", minimum=1)


def _validate_detection_udp(section: Dict[str, Any]) -> None:
    udp = _expect_mapping(section.get("udp"), "detection.udp")
    _expect_bool(udp.get("enabled"), "detection.udp.enabled")
    _expect_number(udp.get("window_seconds"),
                   "detection.udp.window_seconds", minimum=0.001)
    _expect_int(udp.get("distinct_destination_ports"),
                "detection.udp.distinct_destination_ports", minimum=2)
    _expect_int(udp.get("max_tracked_sources"),
                "detection.udp.max_tracked_sources", minimum=1)


def _validate_detection_icmp(section: Dict[str, Any]) -> None:
    icmp = _expect_mapping(section.get("icmp"), "detection.icmp")
    _expect_bool(icmp.get("enabled"), "detection.icmp.enabled")
    _expect_number(icmp.get("window_seconds"),
                   "detection.icmp.window_seconds", minimum=0.001)
    _expect_int(icmp.get("echo_requests"),
                "detection.icmp.echo_requests", minimum=2)
    _expect_int(icmp.get("max_tracked_sources"),
                "detection.icmp.max_tracked_sources", minimum=1)


def _validate_detection_arp(section: Dict[str, Any]) -> None:
    arp = _expect_mapping(section.get("arp"), "detection.arp")
    _expect_bool(arp.get("enabled"), "detection.arp.enabled")
    _expect_number(arp.get("mapping_ttl_seconds"),
                   "detection.arp.mapping_ttl_seconds", minimum=1.0)
    _expect_int(arp.get("max_tracked_mappings"),
                "detection.arp.max_tracked_mappings", minimum=1)

    trusted = _expect_str_map(arp.get("trusted_mappings"),
                              "detection.arp.trusted_mappings")
    for key, value in trusted.items():
        try:
            ipaddress.ip_address(key)
        except ValueError as exc:
            raise ConfigError(
                f"'detection.arp.trusted_mappings' key {key!r} is not a valid IP: {exc}"
            ) from exc
        normalised = value.lower().replace("-", ":")
        if len(normalised.replace(":", "")) != 12:
            raise ConfigError(
                f"'detection.arp.trusted_mappings.{key}' is not a valid MAC: {value!r}"
            )


def _validate_detection_dns(section: Dict[str, Any]) -> None:
    dns = _expect_mapping(section.get("dns"), "detection.dns")
    _expect_bool(dns.get("enabled"), "detection.dns.enabled")
    _expect_number(dns.get("query_window_seconds"),
                   "detection.dns.query_window_seconds", minimum=0.001)
    _expect_int(dns.get("queries_per_source"),
                "detection.dns.queries_per_source", minimum=2)
    _expect_int(dns.get("max_tracked_sources"),
                "detection.dns.max_tracked_sources", minimum=1)
    _expect_number(dns.get("nxdomain_window_seconds"),
                   "detection.dns.nxdomain_window_seconds", minimum=0.001)
    _expect_int(dns.get("nxdomain_min_responses"),
                "detection.dns.nxdomain_min_responses", minimum=1)
    _expect_int(dns.get("nxdomain_min_count"),
                "detection.dns.nxdomain_min_count", minimum=1)
    ratio = _expect_number(dns.get("nxdomain_ratio"),
                           "detection.dns.nxdomain_ratio",
                           minimum=0.0, maximum=1.0)

    min_responses = int(dns["nxdomain_min_responses"])
    min_count = int(dns["nxdomain_min_count"])
    if min_count > min_responses:
        raise ConfigError(
            "detection.dns.nxdomain_min_count "
            f"({min_count}) cannot exceed "
            f"detection.dns.nxdomain_min_responses ({min_responses})"
        )
    if ratio == 0.0 and min_count > 0:
        raise ConfigError(
            "detection.dns.nxdomain_ratio of 0.0 would make DNS-002 fire on "
            "every response; set a value greater than 0.0"
        )


def _validate_detection(cfg: Dict[str, Any]) -> None:
    detection = _expect_mapping(cfg.get("detection"), "detection")
    _validate_detection_tcp(detection)
    _validate_detection_udp(detection)
    _validate_detection_icmp(detection)
    _validate_detection_arp(detection)
    _validate_detection_dns(detection)


def _validate_baseline(cfg: Dict[str, Any]) -> None:
    baseline = _expect_mapping(cfg.get("baseline"), "baseline")
    _expect_bool(baseline.get("enabled"), "baseline.enabled")
    _expect_bool(baseline.get("learning_mode"), "baseline.learning_mode")
    _expect_number(baseline.get("observation_seconds"),
                   "baseline.observation_seconds", minimum=1.0)
    _expect_str(baseline.get("baseline_file"), "baseline.baseline_file")


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def validate_config(config: Any) -> Dict[str, Any]:
    """Validate ``config`` in place and return it.

    Raises :class:`ConfigError` with an actionable message on the first
    problem found.
    """
    cfg = _expect_mapping(config, "<root>")

    log_level = _expect_str(cfg.get("log_level"), "log_level").upper()
    if log_level not in LOG_LEVELS:
        raise ConfigError(
            f"'log_level' must be one of {LOG_LEVELS}, got {log_level!r}"
        )
    cfg["log_level"] = log_level

    _validate_output_dirs(cfg)
    _validate_retention(cfg)
    _validate_deduplication(cfg)
    _validate_network_scope(cfg)
    _validate_severity(cfg)
    _validate_trusted_hosts(cfg)
    _validate_detection(cfg)
    _validate_baseline(cfg)
    return cfg


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load, validate and return ``config.json``.

    ``path`` defaults to ``config.json`` in the current working directory.
    """
    config_path = Path(path) if path else Path(DEFAULT_CONFIG_FILENAME)

    if not config_path.is_file():
        raise ConfigError(f"Configuration file not found: {config_path}")

    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Unable to read configuration {config_path}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"{config_path} is not valid JSON (line {exc.lineno}, column "
            f"{exc.colno}): {exc.msg}"
        ) from exc

    cfg = validate_config(data)
    cfg["_config_path"] = str(config_path)
    return cfg


def output_path(config: Mapping[str, Any], key: str, filename: str) -> Path:
    """Return ``<output_dirs[key]>/<filename>`` as a :class:`Path`.

    ``key`` must be one of :data:`OUTPUT_DIR_KEYS`; anything else is a
    programming error and raises :class:`ConfigError`.
    """
    if key not in OUTPUT_DIR_KEYS:
        raise ConfigError(
            f"Unknown output directory key {key!r}; expected one of {OUTPUT_DIR_KEYS}"
        )
    return Path(config["output_dirs"][key]) / filename