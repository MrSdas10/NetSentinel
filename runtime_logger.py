import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def generate_runtime_log_path(project_root: Path) -> Path:
    """Return a unique timestamped runtime log path in the logs directory."""
    project_root = Path(project_root).resolve()
    logs_dir = project_root / "logs"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    base_name = f"NetSentinel_Log_{timestamp}.txt"
    candidate = logs_dir / base_name
    index = 1
    while candidate.exists():
        candidate = logs_dir / f"NetSentinel_Log_{timestamp}_{index}.txt"
        index += 1
    return candidate


def configure_runtime_logging(project_root: Path, *, verbose: bool = False) -> Path:
    """Attach a dedicated file handler for the runtime session log."""
    root_logger = logging.getLogger()
    project_root = Path(project_root).resolve()

    for handler in root_logger.handlers:
        if getattr(handler, "_netsentinel_runtime_handler", False):
            if hasattr(handler, "baseFilename"):
                return Path(handler.baseFilename)

    log_path = generate_runtime_log_path(project_root)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)sZ [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler._netsentinel_runtime_handler = True
    file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    file_handler.setFormatter(formatter)

    root_logger.addHandler(file_handler)
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    try:
        root_logger.info("Runtime log created at %s (timezone UTC).", log_path)
    except Exception:
        pass

    return log_path


def attach_runtime_log_summary(root_logger: Optional[logging.Logger] = None) -> None:
    """Emit a short startup summary to the runtime log without duplicates."""
    logger = root_logger or logging.getLogger("netsentinel.runtime")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.info("Runtime logging configured for NetSentinel.")
