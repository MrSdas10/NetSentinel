"""Packet capture engine for NetSentinel.

This module is deliberately *dumb*: it knows how to obtain Scapy packets
(live or from a PCAP file), hand each one to a handler, and keep counters.
It has no knowledge of detection rules.  That separation is what makes the
detection engine testable without a live socket.

The handler receives a :class:`parsers.ParsedPacket`, never a raw Scapy
object, so downstream code cannot accidentally depend on Scapy internals.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from parsers import ParsedPacket, parse_packet
from utils import NetSentinelError, ip_in_networks, utc_now_iso

try:
    from scapy.sendrecv import sniff as _scapy_sniff
    from scapy.utils import PcapReader as _ScapyPcapReader
    from scapy.interfaces import get_if_list as _scapy_get_if_list
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - only on broken installs
    SCAPY_AVAILABLE = False
    _scapy_sniff = None
    _ScapyPcapReader = None
    _scapy_get_if_list = None

LOGGER = logging.getLogger(__name__)

PacketHandler = Callable[[ParsedPacket], None]


class CaptureError(NetSentinelError):
    """Raised for unrecoverable capture problems."""


@dataclass
class CaptureStats:
    """Counters describing a capture session.

    These are facts about what the engine saw - they must never be
    fabricated by the reporter.
    """

    mode: str = "idle"                    # "live", "offline", or "idle"
    source: str = ""                      # interface name or PCAP path
    started_utc: str = ""
    finished_utc: str = ""
    duration_seconds: float = 0.0
    total_packets: int = 0
    parsed_packets: int = 0
    parse_errors: int = 0
    filtered_packets: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    interrupted: bool = False
    error_message: Optional[str] = None

    def note_packet(self, parsed: Optional[ParsedPacket]) -> None:
        self.total_packets += 1
        if parsed is None:
            self.parse_errors += 1
            return
        self.parsed_packets += 1
        proto = parsed.protocol or "OTHER"
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "source": self.source,
            "started_utc": self.started_utc,
            "finished_utc": self.finished_utc,
            "duration_seconds": round(self.duration_seconds, 3),
            "total_packets": self.total_packets,
            "parsed_packets": self.parsed_packets,
            "parse_errors": self.parse_errors,
            "filtered_packets": self.filtered_packets,
            "protocol_counts": dict(self.protocol_counts),
            "interrupted": self.interrupted,
            "error_message": self.error_message,
        }


class CaptureEngine:
    """Live or offline packet capture feeding a single handler.

    Construction is cheap; call :meth:`run_live` or :meth:`run_offline`.
    The engine can be reused across runs, but counters reset each time.
    """

    def __init__(
        self,
        packet_handler: PacketHandler,
        bpf_filter: Optional[str] = None,
        local_networks: Optional[Iterable[str]] = None,
        network_scope_enabled: bool = False,
    ) -> None:
        self.packet_handler = packet_handler
        self.bpf_filter = bpf_filter
        self.local_networks = list(local_networks or ())
        self.network_scope_enabled = bool(network_scope_enabled)

        self._stop_event = threading.Event()
        self._stats = CaptureStats()
        # A re-entrancy guard prevents a mis-behaving handler from recursively
        # feeding packets back into the engine.
        self._handler_lock = threading.Lock()
        self._handler_busy = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def stats(self) -> CaptureStats:
        return self._stats

    def stop(self) -> None:
        """Ask a running capture to stop at the next packet boundary."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Interface discovery
    # ------------------------------------------------------------------

    @staticmethod
    def list_interfaces() -> List[str]:
        """Return the interface names Scapy can see, or an empty list."""
        if not SCAPY_AVAILABLE:
            return []
        try:
            return list(_scapy_get_if_list() or [])
        except Exception as exc:  # noqa: BLE001 - interface enumeration varies by OS
            LOGGER.warning("Could not enumerate interfaces: %s", exc)
            return []

    @staticmethod
    def interface_exists(name: str) -> bool:
        return name in CaptureEngine.list_interfaces()

    # ------------------------------------------------------------------
    # Live capture
    # ------------------------------------------------------------------

    def run_live(
        self,
        interface: str,
        duration: Optional[float] = None,
        packet_limit: Optional[int] = None,
    ) -> CaptureStats:
        """Capture packets on ``interface`` until stopped.

        ``duration`` is a soft limit in seconds; ``None`` runs until the
        user interrupts (Ctrl+C) or :meth:`stop` is called.  ``packet_limit``
        is mainly useful in tests.
        """
        if not SCAPY_AVAILABLE:
            raise CaptureError(
                "Scapy is not installed or could not be imported; "
                "install it with 'pip install -r requirements.txt'"
            )
        if not interface:
            raise CaptureError("A capture interface must be specified")
        if not self.interface_exists(interface):
            raise CaptureError(
                f"Interface {interface!r} does not exist. Use --list-interfaces "
                f"to see the interfaces visible to this process."
            )
        if duration is not None and duration <= 0:
            raise CaptureError("Capture duration must be greater than 0 seconds")

        self._reset_stats(mode="live", source=interface)
        self._stop_event.clear()

        kwargs: Dict[str, Any] = {
            "iface": interface,
            "prn": self._on_packet,
            "store": False,
            "stop_filter": self._stop_filter,
        }
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        if duration is not None:
            kwargs["timeout"] = float(duration)
        if packet_limit is not None:
            kwargs["count"] = int(packet_limit)

        LOGGER.info(
            "Starting live capture on %s%s%s",
            interface,
            f" for up to {duration:.0f}s" if duration else "",
            f" (filter: {self.bpf_filter})" if self.bpf_filter else "",
        )

        try:
            _scapy_sniff(**kwargs)
        except PermissionError as exc:
            message = (
                f"Permission denied opening {interface!r}. Live capture "
                "typically requires root or CAP_NET_RAW on Linux."
            )
            self._stats.error_message = message
            raise CaptureError(message) from exc
        except OSError as exc:
            message = f"Operating-system error during capture: {exc}"
            self._stats.error_message = message
            raise CaptureError(message) from exc
        except KeyboardInterrupt:
            LOGGER.info("Live capture interrupted by user")
            self._stats.interrupted = True

        self._finish()
        LOGGER.info(
            "Live capture finished: %d packets (%d parsed, %d errors)",
            self._stats.total_packets,
            self._stats.parsed_packets,
            self._stats.parse_errors,
        )
        return self._stats

    # ------------------------------------------------------------------
    # Offline capture
    # ------------------------------------------------------------------

    def run_offline(self, pcap_path: str) -> CaptureStats:
        """Replay packets from ``pcap_path`` through the same pipeline."""
        if not SCAPY_AVAILABLE:
            raise CaptureError(
                "Scapy is not installed; offline analysis requires Scapy."
            )
        path = Path(pcap_path)
        if not path.is_file():
            raise CaptureError(f"PCAP file not found: {path}")
        if path.stat().st_size == 0:
            raise CaptureError(f"PCAP file is empty: {path}")

        self._reset_stats(mode="offline", source=str(path))
        self._stop_event.clear()

        LOGGER.info("Starting offline analysis of %s", path)

        try:
            with _ScapyPcapReader(str(path)) as reader:
                for pkt in reader:
                    if self._stop_event.is_set():
                        self._stats.interrupted = True
                        break
                    self._on_packet(pkt)
        except PermissionError as exc:
            message = f"Permission denied reading {path}"
            self._stats.error_message = message
            raise CaptureError(message) from exc
        except OSError as exc:
            message = f"Could not read PCAP file {path}: {exc}"
            self._stats.error_message = message
            raise CaptureError(message) from exc
        except Exception as exc:  # noqa: BLE001 - Scapy can raise many types
            message = f"Failed to parse PCAP file {path}: {exc}"
            self._stats.error_message = message
            raise CaptureError(message) from exc

        self._finish()
        LOGGER.info(
            "Offline analysis finished: %d packets (%d parsed, %d errors)",
            self._stats.total_packets,
            self._stats.parsed_packets,
            self._stats.parse_errors,
        )
        return self._stats

    # ------------------------------------------------------------------
    # Internal machinery
    # ------------------------------------------------------------------

    def _reset_stats(self, mode: str, source: str) -> None:
        self._stats = CaptureStats(
            mode=mode,
            source=source,
            started_utc=utc_now_iso(),
        )

    def _finish(self) -> None:
        self._stats.finished_utc = utc_now_iso()

    def _stop_filter(self, _pkt: Any) -> bool:
        return self._stop_event.is_set()

    def _on_packet(self, pkt: Any) -> None:
        """Parse one packet, apply scope, then invoke the handler."""
        parsed = parse_packet(pkt)

        # Scope filter: drop packets whose *only* identifiable endpoints are
        # outside the configured local networks.  Packets with no usable
        # addresses are always kept.
        if (
            parsed is not None
            and self.network_scope_enabled
            and self.local_networks
            and not self._scope_allows(parsed)
        ):
            self._stats.total_packets += 1
            self._stats.filtered_packets += 1
            return

        self._stats.note_packet(parsed)

        if parsed is None:
            return

        # Prevent recursive re-entry if a handler somehow raises while
        # partially updating state.
        with self._handler_lock:
            if self._handler_busy:
                LOGGER.debug("Skipping packet: handler already in progress")
                return
            self._handler_busy = True
        try:
            self.packet_handler(parsed)
        except Exception as exc:  # noqa: BLE001 - handler faults must not kill capture
            LOGGER.exception("Packet handler raised: %s", exc)
        finally:
            with self._handler_lock:
                self._handler_busy = False

    def _scope_allows(self, parsed: ParsedPacket) -> bool:
        candidates = [
            parsed.src_ip, parsed.dst_ip,
            parsed.arp_sender_ip, parsed.arp_target_ip,
        ]
        present = [ip for ip in candidates if ip]
        if not present:
            return True
        return any(ip_in_networks(ip, self.local_networks) for ip in present)