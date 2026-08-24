"""§10.4 First-time DEK setup — GenerateDataKey path and concurrent loser race."""

import base64
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

DEK = os.urandom(32)
WRAPPED = base64.b64encode(b"kms-generated-wrapped").decode()
WINNER_WRAPPED = base64.b64encode(b"winner-wrapped").decode()


@pytest.mark.anyio
async def test_first_time_generates_and_stores_dek():
    """GET 404 → GenerateDataKey → PUT 201 → wrapped_dek written to config."""
    mock_kms = MagicMock()
    mock_kms.generate_data_key.return_value = {
        "Plaintext": DEK,
        "CiphertextBlob": b"kms-generated-wrapped",
        "KeyId": "arn:test",
    }

    cfg = {"api_key": "tasqr_test", "kms_key_id": "arn:test", "aws_profile": "test"}

    written = {}

    def mock_write(key, value):
        written[key] = value

    with (
        patch("boto3.session.Session") as mock_session_cls,
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
        patch("tasqr_mcp.credentials.write_config_value", side_effect=mock_write),
        patch("tasqr_mcp.logging.log_event"),
    ):
        mock_session_cls.return_value.client.return_value = mock_kms

        get_resp = MagicMock()
        get_resp.status_code = 404
        put_resp = MagicMock()
        put_resp.status_code = 201
        put_resp.json.return_value = {"status": "created", "org_id": "org-first"}

        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.put = AsyncMock(return_value=put_resp)

        with patch("httpx2.AsyncClient", return_value=mock_client):
            from tasqr_mcp.credentials import fetch_or_generate_dek

            dek, source, org_id = await fetch_or_generate_dek(cfg)

    assert source == "api"
    assert org_id == "org-first"
    assert mock_kms.generate_data_key.call_count == 1
    assert "wrapped_dek" in written


@pytest.mark.anyio
async def test_first_time_concurrent_loser():
    """PUT 409 → retry GET → fetch winner's blob → succeed."""
    mock_kms = MagicMock()
    mock_kms.generate_data_key.return_value = {
        "Plaintext": DEK,
        "CiphertextBlob": b"my-wrapped",
        "KeyId": "arn:test",
    }
    mock_kms.decrypt.return_value = {"Plaintext": DEK, "KeyId": "arn:test"}

    cfg = {"api_key": "tasqr_test", "kms_key_id": "arn:test", "aws_profile": "test"}

    get_call_count = 0

    async def mock_get(*args, **kwargs):
        nonlocal get_call_count
        get_call_count += 1
        resp = MagicMock()
        resp.status_code = 404 if get_call_count == 1 else 200
        if get_call_count > 1:
            resp.json.return_value = {
                "wrapped_dek": WINNER_WRAPPED,
                "kms_key_id": "arn:test",
                "org_id": "org-win",
            }
        return resp

    put_resp = MagicMock()
    put_resp.status_code = 409

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get
    mock_client.put = AsyncMock(return_value=put_resp)

    with (
        patch("boto3.session.Session") as mock_session_cls,
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
        patch("tasqr_mcp.credentials.write_config_value"),
        patch("tasqr_mcp.logging.log_event"),
    ):
        mock_session_cls.return_value.client.return_value = mock_kms

        with patch("httpx2.AsyncClient", return_value=mock_client):
            from tasqr_mcp.credentials import fetch_or_generate_dek

            dek, source, org_id = await fetch_or_generate_dek(cfg)

    assert org_id == "org-win"
    assert get_call_count == 2  # first 404, second 200 (winner's blob)
    assert mock_kms.decrypt.call_count == 1
    assert dek == DEK
