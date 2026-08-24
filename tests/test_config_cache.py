"""Config cache behaviour: wrapped_dek read/write lifecycle."""

import base64
import configparser
import os
import pathlib
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

DEK = os.urandom(32)
WRAPPED = base64.b64encode(b"fake-wrapped").decode()
NEW_WRAPPED = base64.b64encode(b"new-wrapped").decode()


@pytest.mark.anyio
async def test_wrapped_dek_written_after_api_fetch():
    """When no wrapped_dek in config, API fetch result is written to config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        creds_path = pathlib.Path(tmpdir) / "credentials"

        mock_kms = MagicMock()
        mock_kms.decrypt.return_value = {"Plaintext": DEK, "KeyId": "arn:test"}

        # Write a minimal config (no wrapped_dek)
        config = configparser.ConfigParser()
        config["default"] = {"api_key": "tasqr_test", "kms_key_id": "arn:test"}
        with open(creds_path, "w") as f:
            config.write(f)

        cfg = {
            "api_key": "tasqr_test",
            "kms_key_id": "arn:test",
            "aws_profile": "test",
        }

        # boto3 imported locally inside fetch_or_generate_dek — patch at module level
        with (
            patch("boto3.session.Session") as mock_session_cls,
            patch("tasqr_mcp.credentials._credentials_path", return_value=creds_path),
            patch("tasqr_mcp.logging.log_event"),
        ):
            mock_session_cls.return_value.client.return_value = mock_kms

            mock_client = MagicMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "wrapped_dek": WRAPPED,
                "kms_key_id": "arn:test",
                "org_id": "org-cache",
            }
            mock_client.get = AsyncMock(return_value=mock_resp)

            with patch("httpx2.AsyncClient", return_value=mock_client):
                from tasqr_mcp.credentials import fetch_or_generate_dek

                dek, source, org_id = await fetch_or_generate_dek(cfg)

        assert source == "api"
        # Check config now has wrapped_dek
        config2 = configparser.ConfigParser()
        config2.read(creds_path)
        assert config2.get("default", "wrapped_dek", fallback=None) == WRAPPED


@pytest.mark.anyio
async def test_cached_wrapped_dek_still_confirms_org_is_byok():
    """Second session: the cached wrapped_dek spares a KMS unwrap, not the server probe.

    The server is always consulted; the cache is honoured only once the org is
    confirmed client_byok.
    """
    mock_kms = MagicMock()
    mock_kms.decrypt.return_value = {"Plaintext": DEK, "KeyId": "arn:test"}

    cfg = {
        "api_key": "tasqr_test",
        "kms_key_id": "arn:test",
        "aws_profile": "test",
        "wrapped_dek": WRAPPED,
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "wrapped_dek": WRAPPED,
        "kms_key_id": "arn:test",
        "key_provider": "client_byok",
        "org_id": "org-cache",
    }
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_resp)

    with (
        patch("boto3.session.Session") as mock_session_cls,
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
        patch("tasqr_mcp.logging.log_event"),
    ):
        mock_session_cls.return_value.client.return_value = mock_kms

        with patch("httpx2.AsyncClient", return_value=mock_client):
            from tasqr_mcp.credentials import fetch_or_generate_dek

            dek, source, org_id = await fetch_or_generate_dek(cfg)

    assert source == "config"  # cached DEK was used...
    assert mock_client.get.await_count == 1  # ...but only after asking the server
    assert mock_kms.decrypt.call_count == 1


@pytest.mark.anyio
async def test_stale_dek_retry():
    """If KMS Decrypt raises on stale wrapped_dek, delete from config, retry via GET /org/dek."""
    from botocore.exceptions import ClientError as BotoClientError

    call_count = 0

    def decrypt_side_effect(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            error = {"Error": {"Code": "InvalidCiphertextException", "Message": "stale"}}
            raise BotoClientError(error, "Decrypt")
        return {"Plaintext": DEK, "KeyId": "arn:test"}

    mock_kms = MagicMock()
    mock_kms.decrypt.side_effect = decrypt_side_effect

    cfg = {
        "api_key": "tasqr_test",
        "kms_key_id": "arn:test",
        "aws_profile": "test",
        "wrapped_dek": WRAPPED,  # stale
    }

    deleted = []

    def mock_delete(key):
        deleted.append(key)

    with (
        patch("boto3.session.Session") as mock_session_cls,
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
        patch("tasqr_mcp.credentials._delete_config_value", side_effect=mock_delete),
        patch("tasqr_mcp.credentials.write_config_value"),
        patch("tasqr_mcp.logging.log_event"),
    ):
        mock_session_cls.return_value.client.return_value = mock_kms

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "wrapped_dek": NEW_WRAPPED,
            "kms_key_id": "arn:test",
            "org_id": "org-cache",
        }
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx2.AsyncClient", return_value=mock_client):
            from tasqr_mcp.credentials import fetch_or_generate_dek

            dek, source, org_id = await fetch_or_generate_dek(cfg)

    assert "wrapped_dek" in deleted
    assert source == "api"
    assert mock_kms.decrypt.call_count == 2
    assert dek == DEK
