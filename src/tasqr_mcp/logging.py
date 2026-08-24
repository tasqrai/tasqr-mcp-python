import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

# Levels, coarsest first. "off" silences the log entirely, and is the default:
# nothing touches disk unless the user opts in.
OFF, INFO, DEBUG = 0, 1, 2
_LEVELS = {"off": OFF, "info": INFO, "debug": DEBUG}

# What each event costs you. Lifecycle events fire about once per session; the
# per-call ones fire on every tool call, so they only appear at debug.
_EVENT_LEVEL = {
    "dek_loaded": INFO,
    "kms_decrypt": INFO,
    "encrypt": DEBUG,
    "decrypt": DEBUG,
}
_DEFAULT_EVENT_LEVEL = INFO  # an unmapped event stays visible rather than vanishing


def _config() -> dict:
    # Imported lazily: credentials.py logs, so a module-level import would be circular.
    try:
        from .credentials import read_config

        return read_config()
    except Exception:
        return {}


def _level() -> int:
    """Resolved log level. Precedence: env var → credentials file → default (off).

    Logging is opt-in: unset means off, so nothing is written to disk unless asked for.
    But a value that is *set* and unrecognised (a typo like "debbug") falls back to info
    rather than off — the user plainly wanted logging, and silently giving them none
    would hide the mistake.
    """
    raw = os.environ.get("TASQR_LOG_LEVEL") or _config().get("log_level")
    if not raw:
        return OFF
    return _LEVELS.get(raw.strip().lower(), INFO)


def _log_path() -> Path:
    """Resolved log path. Precedence: env var → credentials file → default.

    Both user-supplied forms are expanduser'd: neither an INI value nor an env
    var set from an MCP client's config passes through a shell, so a literal
    `~/...` (the README's own example) would otherwise create a `./~/` directory.
    """
    if "TASQR_LOG" in os.environ:
        return Path(os.environ["TASQR_LOG"]).expanduser()
    configured = _config().get("log_path")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        appdata = os.environ.get("APPDATA") or str(Path.home())
        return Path(appdata) / "tasqr" / "tasqr-mcp.log"
    return Path.home() / ".config" / "tasqr" / "tasqr-mcp.log"


def log_event(event: str, **fields) -> None:
    """Write one JSON line to the log file. Never log plaintext DEK or task content."""
    level = _level()
    if level == OFF or _EVENT_LEVEL.get(event, _DEFAULT_EVENT_LEVEL) > level:
        return

    path = _log_path()
    # 0700 like credentials' writes — the default path shares the credential dir.
    # Applies only when this call creates the directory; an existing dir is kept as-is.
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = {"event": event, "ts": datetime.now(UTC).isoformat(), **fields}
    try:
        if os.name == "nt":
            with open(path, "a") as f:
                f.write(json.dumps(record) + "\n")
        else:
            # Create the log 0600 — it shares the credential directory, and a future
            # log_event mistake shouldn't be world-readable.
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(record) + "\n")
    except OSError:
        pass  # Never crash the proxy because of logging
