"""Logging output: JSON format, no plaintext leakage, kms_decrypt fires once."""

import json
import os
from unittest.mock import patch

import pytest


def read_log_lines(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def test_log_event_writes_json_line(tmp_path):
    log_file = str(tmp_path / "test.log")
    # Logging is off by default, so these tests opt in explicitly.
    with patch.dict(os.environ, {"TASQR_LOG": log_file, "TASQR_LOG_LEVEL": "info"}):
        from tasqr_mcp.logging import log_event

        log_event("dek_loaded", source="config")
    lines = read_log_lines(log_file)
    assert len(lines) == 1
    assert lines[0]["event"] == "dek_loaded"
    assert lines[0]["source"] == "config"
    assert "ts" in lines[0]


def test_no_plaintext_in_logs(tmp_path):
    """Log output must not contain plaintext task content.

    Pinned to debug — the most verbose setting is where a leak would surface, and
    `encrypt`/`decrypt` are debug-level events so they are silent at the info default.
    """
    log_file = str(tmp_path / "test.log")
    DEK = os.urandom(32)

    with patch.dict(os.environ, {"TASQR_LOG": log_file, "TASQR_LOG_LEVEL": "debug"}):
        from tasqr_mcp.crypto import ClientCrypto

        c = ClientCrypto(dek=DEK, org_id="org-log-test")
        c.encrypt_args(
            "create_tasks",
            {"tasks": [{"title": "SECRET_CONTENT_XYZ", "description": "PRIVATE_DATA_ABC"}]},
        )

    with open(log_file) as f:
        log_content = f.read()

    # The event itself must have been written, or "no plaintext" is trivially true.
    assert '"event": "encrypt"' in log_content
    assert "SECRET_CONTENT_XYZ" not in log_content
    assert "PRIVATE_DATA_ABC" not in log_content


@pytest.mark.anyio
async def test_kms_decrypt_fires_once_in_full_session(tmp_path):
    """Full session log: exactly one kms_decrypt line, rest are encrypt/decrypt."""
    import base64
    from unittest.mock import AsyncMock, MagicMock, patch

    log_file = str(tmp_path / "session.log")
    DEK = os.urandom(32)
    WRAPPED = base64.b64encode(b"fake-wrapped").decode()

    mock_kms = MagicMock()
    mock_kms.decrypt.return_value = {"Plaintext": DEK, "KeyId": "arn:test"}

    cfg = {
        "api_key": "tasqr_test",
        "kms_key_id": "arn:test",
        "aws_profile": "test",
        "wrapped_dek": WRAPPED,
    }

    # init now probes GET /org/dek to confirm the org is client_byok before encrypting.
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "wrapped_dek": WRAPPED,
        "key_provider": "client_byok",
        "org_id": "org-log-test",
    }
    mock_http = MagicMock()
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__ = AsyncMock(return_value=False)
    mock_http.get = AsyncMock(return_value=mock_resp)

    with (
        patch.dict(os.environ, {"TASQR_LOG": log_file, "TASQR_LOG_LEVEL": "debug"}),
        patch("boto3.session.Session") as mock_session_cls,
        patch("httpx2.AsyncClient", return_value=mock_http),
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
    ):
        mock_session_cls.return_value.client.return_value = mock_kms

        from mcp.types import CallToolResult, TextContent

        from tasqr_mcp.crypto import ClientCrypto

        c = await ClientCrypto.init(cfg)

        for i in range(5):
            c.encrypt_args(
                "create_tasks", {"tasks": [{"title": f"task {i}", "description": "desc"}]}
            )
            enc_envelope = json.dumps(
                {
                    "tasks": [
                        {
                            "task_id": "t1",
                            "title": "plain",
                            "description": "desc",
                            "metadata": None,
                            "output": None,
                            "status": "p",
                            "history": [],
                        }
                    ],
                    "count": 1,
                    "not_found": [],
                }
            )
            result = CallToolResult(content=[TextContent(type="text", text=enc_envelope)])
            c.decrypt_result("get_tasks", result)

    lines = read_log_lines(log_file)
    kms_lines = [r for r in lines if r["event"] == "kms_decrypt"]
    assert len(kms_lines) == 1

    non_startup = [r for r in lines if r["event"] not in ("dek_loaded", "kms_decrypt")]
    assert all(r["event"] in ("encrypt", "decrypt") for r in non_startup)


def test_configured_log_path_expands_tilde(tmp_path):
    """The README's own example is `log_path = ~/.config/tasqr/tasqr-mcp.log` — an
    INI value gets no shell expansion, so an unexpanded `~` would silently create a
    literal `./~/` directory relative to wherever the proxy happened to start."""
    from tasqr_mcp.logging import _log_path

    env = {"HOME": str(tmp_path)}
    with (
        patch.dict(os.environ, env, clear=False),
        patch("tasqr_mcp.logging._config", return_value={"log_path": "~/logs/tasqr.log"}),
    ):
        os.environ.pop("TASQR_LOG", None)
        assert _log_path() == tmp_path / "logs" / "tasqr.log"


def test_env_log_path_expands_tilde(tmp_path):
    """TASQR_LOG can arrive without a shell too (an MCP client's env block), so the
    env var gets the same expansion as the credentials-file value."""
    from tasqr_mcp.logging import _log_path

    with patch.dict(os.environ, {"HOME": str(tmp_path), "TASQR_LOG": "~/elogs/tasqr.log"}):
        assert _log_path() == tmp_path / "elogs" / "tasqr.log"


def test_log_dir_created_owner_only(tmp_path):
    """The log shares the credential directory’s sensitivity; when log_event has to
    create the directory itself, it must be 0700 like credentials’ writes."""
    log_file = tmp_path / "logdir" / "tasqr.log"
    with patch.dict(os.environ, {"TASQR_LOG": str(log_file), "TASQR_LOG_LEVEL": "info"}):
        from tasqr_mcp.logging import log_event

        log_event("dek_loaded", source="config")
    assert log_file.exists()
    assert (log_file.parent.stat().st_mode & 0o777) == 0o700
