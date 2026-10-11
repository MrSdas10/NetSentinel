"""
utils.py — Shared utility functions for NetSentinel.

Provides: UTC timestamps, IP/MAC normalization, UUID generation,
safe JSON serialization, directory creation, and input validation.

No detection logic lives here.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Return the current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string ending in 'Z'."""
    return utc_now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def timestamp_to_iso(dt: datetime) -> str:
    """
    Convert a datetime object to an ISO-8601 UTC string.

    If *dt* is naive (no tzinfo), it is assumed to be UTC.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def epoch_to_iso(epoch: float) -> str:
    """Convert a POSIX timestamp (float seconds) to an ISO-8601 UTC string."""
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------

def new_alert_id() -> str:
    """Return a new unique alert identifier (UUID4 hex string)."""
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# IP / MAC normalization
# ---------------------------------------------------------------------------

# Matches a 6-group colon-separated MAC address (case-insensitive)
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def normalize_ip(address: Optional[str]) -> Optional[str]:
    """
    Return the IP address string in a canonical lower-case form,
    or None if *address* is empty, None, or clearly invalid.

    Does not validate whether the address is routable or assigned.
    """
    if not address:
        return None
    address = address.strip()
    if not address:
        return None
    return address  # Scapy already returns dotted-decimal strings.


def normalize_mac(address: Optional[str]) -> Optional[str]:
    """
    Return the MAC address in lower-case colon-separated form,
    or None if *address* is None, empty, or does not match the expected format.
    """
    if not address:
        return None
    address = address.strip().lower()
    # Scapy uses colon-separated form; accept it directly.
    if _MAC_RE.match(address):
        return address
    # Try converting dash-separated (Windows) to colon form.
    if "-" in address:
        parts = address.split("-")
        if len(parts) == 6:
            converted = ":".join(parts)
            if _MAC_RE.match(converted):
                return converted
    return None


# ---------------------------------------------------------------------------
# Safe JSON serialization
# ---------------------------------------------------------------------------

class _SafeEncoder(json.JSONEncoder):
    """
    JSON encoder that handles datetime objects and falls back to str()
    for types that the standard encoder cannot handle.
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return timestamp_to_iso(obj)
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


def safe_json_dumps(obj: Any, indent: Optional[int] = None) -> str:
    """
    Serialize *obj* to a JSON string, handling datetimes and unknown types.
    Raises ValueError if the result cannot be serialized after fallback.
    """
    return json.dumps(obj, cls=_SafeEncoder, indent=indent, ensure_ascii=False)


def safe_json_loads(text: str) -> Any:
    """
    Deserialize a JSON string, returning None on parse errors rather than
    propagating an exception — callers must check for None.
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.debug("JSON parse error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------

def ensure_directory(path: Path) -> Path:
    """
    Create *path* and all intermediate directories if they do not exist.
    Return *path* on success.  Raise OSError on failure.
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("Cannot create directory %s: %s", path, exc)
        raise
    return path


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def is_positive_int(value: Any) -> bool:
    """Return True if *value* is an integer greater than zero."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def is_non_negative_number(value: Any) -> bool:
    """Return True if *value* is a non-negative int or float."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0


def is_non_empty_string(value: Any) -> bool:
    """Return True if *value* is a non-empty string."""
    return isinstance(value, str) and bool(value.strip())


def clamp(value: float, lo: float, hi: float) -> float:
    """Return *value* clamped to the inclusive range [lo, hi]."""
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# HTML escaping (used by reporter.py)
# ---------------------------------------------------------------------------

def html_escape(text: str) -> str:
    """
    Escape characters that have special meaning in HTML.

    This is a minimal implementation that does not depend on html.escape
    but behaves identically.  We avoid importing the html module solely
    to keep this function self-contained and clearly auditable.
    """
    replacements = [
        ("&", "&amp;"),   # Must be first to avoid double-escaping.
        ("<", "&lt;"),
        (">", "&gt;"),
        ('"', "&quot;"),
        ("'", "&#x27;"),
    ]
    for char, entity in replacements:
        text = text.replace(char, entity)
    return text


def safe_html(value: Any) -> str:
    """
    Convert *value* to a safe HTML string.

    None is treated as "no value" and returns an empty string.
    All other values are converted with str() and then HTML-escaped.
    """
    if value is None:
        return ""
    return html_escape(str(value))
