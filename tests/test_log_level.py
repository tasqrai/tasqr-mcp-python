"""log_level / log_path are configurable from the credentials file."""

import json
import os
from unittest.mock import patch


def _lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _events(path):
    return [r["event"] for r in _lines(path)]


def _with_cfg(cfg):
    """Patch the credentials file that logging consults."""
    return patch("tasqr_mcp.credentials.read_config", return_value=cfg)


def test_off_writes_nothing(tmp_path):
    log = tmp_path / "x.log"
    from tasqr_mcp.logging import log_event

    with (
        patch.dict(os.environ, {"TASQR_LOG": str(log)}, clear=False),
        _with_cfg({"log_level": "off"}),
    ):
        log_event("dek_loaded", source="api")
        log_event("encrypt", tool="create_tasks", fields=["title"])

    assert _events(log) == []


def test_off_is_the_default_when_unset(tmp_path):
    """Logging is opt-in: with no log_level configured, nothing touches disk."""
    log = tmp_path / "x.log"
    from tasqr_mcp.logging import log_event

    env = {k: v for k, v in os.environ.items() if k != "TASQR_LOG_LEVEL"}
    env["TASQR_LOG"] = str(log)
    with (
        patch.dict(os.environ, env, clear=True),
        _with_cfg({}),
    ):  # no log_level configured -> default
        log_event("dek_loaded", source="api")
        log_event("kms_decrypt", profile="p")
        log_event("encrypt", tool="create_tasks", fields=["title"])

    assert _events(log) == []
    assert not log.exists(), "no file should be created at all when logging is off"


def test_info_logs_lifecycle_but_omits_per_call_events(tmp_path):
    log = tmp_path / "x.log"
    from tasqr_mcp.logging import log_event

    with (
        patch.dict(os.environ, {"TASQR_LOG": str(log)}, clear=False),
        _with_cfg({"log_level": "info"}),
    ):
        log_event("dek_loaded", source="api")
        log_event("kms_decrypt", profile="p")
        log_event("encrypt", tool="create_tasks", fields=["title"])
        log_event("decrypt", tool="get_tasks", fields=["title"])

    assert _events(log) == ["dek_loaded", "kms_decrypt"]


def test_debug_includes_per_call_events(tmp_path):
    log = tmp_path / "x.log"
    from tasqr_mcp.logging import log_event

    with (
        patch.dict(os.environ, {"TASQR_LOG": str(log)}, clear=False),
        _with_cfg({"log_level": "debug"}),
    ):
        log_event("dek_loaded", source="api")
        log_event("encrypt", tool="create_tasks", fields=["title"])

    assert _events(log) == ["dek_loaded", "encrypt"]


def test_log_path_from_credentials_file(tmp_path):
    log = tmp_path / "from-config.log"
    from tasqr_mcp.logging import log_event

    env = {k: v for k, v in os.environ.items() if k != "TASQR_LOG"}
    with (
        patch.dict(os.environ, env, clear=True),
        _with_cfg({"log_path": str(log), "log_level": "debug"}),
    ):
        log_event("dek_loaded", source="api")

    assert _events(log) == ["dek_loaded"]


def test_env_log_level_overrides_credentials_file(tmp_path):
    log = tmp_path / "x.log"
    from tasqr_mcp.logging import log_event

    with (
        patch.dict(os.environ, {"TASQR_LOG": str(log), "TASQR_LOG_LEVEL": "off"}, clear=False),
        _with_cfg({"log_level": "debug"}),
    ):  # file says debug, env says off -> env wins
        log_event("dek_loaded", source="api")

    assert _events(log) == []


def test_unknown_level_falls_back_to_info_not_silence(tmp_path):
    """A typo must not silently disable the audit trail."""
    log = tmp_path / "x.log"
    from tasqr_mcp.logging import log_event

    with (
        patch.dict(os.environ, {"TASQR_LOG": str(log)}, clear=False),
        _with_cfg({"log_level": "verbose"}),
    ):  # not a real level
        log_event("dek_loaded", source="api")
        log_event("encrypt", tool="create_tasks", fields=["title"])

    assert _events(log) == ["dek_loaded"]
