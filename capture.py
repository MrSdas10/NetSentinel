"""
capture.py — Packet capture engine for NetSentinel.

Supports live interface capture and offline PCAP analysis.
Feeds each packet through parsers.py and alert_manager.py.

Operating system requirements
------------------------------
Linux:  Run with sudo or grant CAP_NET_RAW / CAP_NET_ADMIN to the
        Python interpreter for live capture.
        Example:  sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

macOS:  Run with sudo for live capture.  BPF device permissions may
        vary by macOS version.

Windows: Install Npcap (https://npcap.com).  Run the terminal as
         Administrator for live capture.

Scapy caveats
--------------
* Scapy's sniff() is not perfectly thread-safe on all platforms.
  We use a threading.Event for shutdown and rely on Scapy's
  stop_filter mechanism.
* Packet timestamps come from the OS/PCAP layer and are in POSIX
  seconds.  Accuracy depends on the capture driver and OS.
* On switched networks, only traffic to/from the capture host or
  that arrives via port mirroring is visible.
* Traffic subject to hardware offloading (TSO, LRO, checksumming)
  may not appear as individual packets.
* Packet loss is possible under high traffic load.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Type alias for the per-packet callback used by the pipeline.
PacketCallback = Callable[[object], None]


# ---------------------------------------------------------------------------
# Capture statistics
# ---------------------------------------------------------------------------

@dataclass
class CaptureStats:
    """Counters maintained by the capture engine."""
    total_packets: int = 0
    parse_errors: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    def record_protocol(self, protocol: Optional[str]) -> None:
        key = protocol or "UNKNOWN"
        self.protocol_counts[key] = self.protocol_counts.get(key, 0) + 1

    @property
    def elapsed_seconds(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time if self.end_time is not None else time.time()
        return max(0.0, end - self.start_time)


# ---------------------------------------------------------------------------
# Packet processor: ties capture to parsing and detection
# ---------------------------------------------------------------------------

class PacketProcessor:
    """
    Receives raw Scapy packets, parses them, updates the baseline,
    and forwards to the alert manager.

    Keeps the capture engine decoupled from parsing and detection so
    that detection rules can be tested without live packet capture.
    """

    def __init__(
        self,
        parser_fn: Callable,       # parsers.parse_packet
        alert_manager: object,     # AlertManager instance
        baseline: Optional[object] = None,  # Baseline instance or None
        alert_callback: Optional[Callable] = None,  # called with new alerts
    ) -> None:
        self._parse = parser_fn
        self._alert_manager = alert_manager
        self._baseline = baseline
        self._alert_callback = alert_callback
        self.stats = CaptureStats()

    def handle_packet(self, raw_pkt: object) -> None:
        """
        Process one raw Scapy packet.

        This method is called from the Scapy capture callback.
        It must not raise exceptions — all errors are logged and counted.
        """
        try:
            parsed = self._parse(raw_pkt)
        except Exception as exc:
            logger.debug("Parse exception: %s", exc)
            self.stats.parse_errors += 1
            self.stats.total_packets += 1
            return

        if parsed is None:
            return

        self.stats.total_packets += 1
        self.stats.record_protocol(parsed.protocol)

        if parsed.parse_error:
            self.stats.parse_errors += 1

        # Update baseline counters regardless of learning/detection mode.
        if self._baseline is not None:
            try:
                self._baseline.update(parsed)
            except Exception as exc:
                logger.debug("Baseline update error: %s", exc)

        # Run detection rules.
        try:
            new_alerts = self._alert_manager.process_packet(parsed)
        except Exception as exc:
            logger.error("Alert manager error: %s", exc, exc_info=True)
            new_alerts = []

        if new_alerts and self._alert_callback is not None:
            try:
                self._alert_callback(new_alerts)
            except Exception as exc:
                logger.debug("Alert callback error: %s", exc)


# ---------------------------------------------------------------------------
# Live capture engine
# ---------------------------------------------------------------------------

class LiveCapture:
    """
    Captures packets from a live network interface using Scapy.

    Usage
    -----
        cap = LiveCapture(interface="eth0", processor=processor)
        cap.start(duration=60)   # blocks until done or Ctrl+C
    """

    def __init__(
        self,
        interface: str,
        processor: PacketProcessor,
        bpf_filter: str = "",
    ) -> None:
        self.interface = interface
        self._processor = processor
        self._bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self._running = False

    def start(self, duration: Optional[float] = None) -> None:
        """
        Begin capturing packets.  Blocks until *duration* seconds have
        elapsed, the stop event is set (e.g. by Ctrl+C), or Scapy raises
        a fatal exception.
        """
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is not installed.  Run: pip install scapy"
            ) from exc

        self._running = True
        self._stop_event.clear()
        self._processor.stats.start_time = time.time()
        logger.info(
            "Starting live capture on interface %r (duration=%s s, filter=%r).",
            self.interface,
            duration if duration else "unlimited",
            self._bpf_filter or "none",
        )

        timeout = float(duration) if duration else None

        def _stop_filter(_pkt: object) -> bool:
            """Return True to ask Scapy to stop sniffing."""
            return self._stop_event.is_set()

        try:
            sniff(
                iface=self.interface,
                prn=self._processor.handle_packet,
                stop_filter=_stop_filter,
                timeout=timeout,
                store=False,    # Do not accumulate packets in memory.
                filter=self._bpf_filter if self._bpf_filter else None,
            )
        except PermissionError as exc:
            logger.error(
                "Permission denied on interface %r: %s\n"
                "Try running with sudo or granting CAP_NET_RAW.",
                self.interface, exc,
            )
            raise
        except OSError as exc:
            logger.error(
                "OS error on interface %r: %s\n"
                "Check that the interface exists and is up.",
                self.interface, exc,
            )
            raise
        finally:
            self._running = False
            self._processor.stats.end_time = time.time()
            logger.info(
                "Capture on %r stopped. Packets: %d, Parse errors: %d, "
                "Elapsed: %.1fs.",
                self.interface,
                self._processor.stats.total_packets,
                self._processor.stats.parse_errors,
                self._processor.stats.elapsed_seconds,
            )

    def stop(self) -> None:
        """Signal the capture loop to stop after the next packet."""
        logger.info("Capture stop requested.")
        self._stop_event.set()

    @property
    def is_running(self) -> bool:
        return self._running


# ---------------------------------------------------------------------------
# Offline PCAP analysis engine
# ---------------------------------------------------------------------------

class OfflineCapture:
    """
    Reads packets from a PCAP file using Scapy and feeds them through
    the processing pipeline.

    Offline analysis does not require elevated privileges when the file
    permissions allow it (OS-dependent).
    """

    def __init__(self, pcap_path: Path, processor: PacketProcessor) -> None:
        self.pcap_path = pcap_path
        self._processor = processor

    def run(self) -> None:
        """
        Process all packets in the PCAP file.

        Raises FileNotFoundError if the file does not exist.
        Raises RuntimeError if Scapy cannot read the file.
        """
        try:
            from scapy.all import rdpcap, PcapReader
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is not installed.  Run: pip install scapy"
            ) from exc

        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        logger.info("Starting offline analysis of %s.", self.pcap_path)
        self._processor.stats.start_time = time.time()

        # Use PcapReader for streaming to avoid loading the entire file
        # into memory at once.
        try:
            with PcapReader(str(self.pcap_path)) as reader:
                for pkt in reader:
                    self._processor.handle_packet(pkt)
        except Exception as exc:
            logger.error(
                "Error reading PCAP file %s: %s", self.pcap_path, exc
            )
            raise RuntimeError(
                f"Failed to read PCAP file {self.pcap_path}"
            ) from exc
        finally:
            self._processor.stats.end_time = time.time()
            logger.info(
                "Offline analysis complete. Packets: %d, Parse errors: %d, "
                "Elapsed: %.1fs.",
                self._processor.stats.total_packets,
                self._processor.stats.parse_errors,
                self._processor.stats.elapsed_seconds,
            )


# ---------------------------------------------------------------------------
# Interface listing helper
# ---------------------------------------------------------------------------

def list_interfaces() -> List[str]:
    """
    Return a list of available network interfaces as reported by Scapy.

    On Linux and macOS, this typically requires no privileges.
    On Windows, requires Npcap to be installed.
    Returns an empty list (with a logged warning) if Scapy is unavailable.
    """
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except ImportError:
        logger.warning("Scapy is not installed; cannot list interfaces.")
        return []
    except Exception as exc:
        logger.warning("Could not list interfaces: %s", exc)
        return []


def validate_interface(interface: str) -> bool:
    """
    Return True if *interface* appears in the Scapy interface list.

    Note: Scapy's interface list may not include all valid interfaces
    on all operating systems (e.g. some virtual or alias interfaces).
    This check is a best-effort validation.
    """
    available = list_interfaces()
    if not available:
        # Cannot enumerate interfaces (e.g. Scapy unavailable or no privileges).
        # Allow the caller to proceed and let Scapy fail with a clear error.
        logger.warning(
            "Cannot validate interface %r: interface list is empty.", interface
        )
        return True
    return interface in available
