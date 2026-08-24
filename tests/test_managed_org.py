"""A managed org must never be client-encrypted, even if the profile is set up for BYOK.

The server is authoritative: GET /org/dek returns 200 (client_byok), 409 (server-managed),
or 404 (BYOK-eligible but unenrolled).
"""

import base64
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

DEK = os.urandom(32)
WRAPPED = base64.b64encode(b"fake-wrapped").decode()


def _mock_http(status_code: int, json_body: dict | None = None):
    """An httpx2.AsyncClient whose GET returns the given status."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.get = AsyncMock(return_value=resp)
    client.put = AsyncMock(return_value=resp)
    return client


MANAGED_BODY = {
    "error": "org uses server-managed encryption; do not client-encrypt",
    "key_provider": "managed",
}


@pytest.mark.anyio
async def test_managed_org_refuses_to_encrypt():
    """GET /org/dek -> 409: refuse, even though kms_key_id is configured."""
    from tasqr_mcp.credentials import ManagedOrgError, fetch_or_generate_dek

    cfg = {"api_key": "k", "kms_key_id": "arn:test", "aws_profile": "test"}

    mock_kms = MagicMock()
    with (
        patch("boto3.session.Session") as sess,
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
        patch("tasqr_mcp.logging.log_event"),
    ):
        sess.return_value.client.return_value = mock_kms
        with patch("httpx2.AsyncClient", return_value=_mock_http(409, MANAGED_BODY)):
            with pytest.raises(ManagedOrgError) as exc:
                await fetch_or_generate_dek(cfg)

    # The message must tell the user how to fix it.
    assert "server-managed" in str(exc.value)
    assert "kms_key_id" in str(exc.value)
    # And we must not have touched KMS at all.
    assert mock_kms.decrypt.call_count == 0
    assert mock_kms.generate_data_key.call_count == 0


@pytest.mark.anyio
async def test_managed_org_refuses_even_with_cached_wrapped_dek():
    """A cached wrapped_dek must never win over the server's answer."""
    from tasqr_mcp.credentials import ManagedOrgError, fetch_or_generate_dek

    cfg = {
        "api_key": "k",
        "kms_key_id": "arn:test",
        "aws_profile": "test",
        "wrapped_dek": WRAPPED,  # the short-circuit that produced the double wrap
    }

    mock_kms = MagicMock()
    mock_kms.decrypt.return_value = {"Plaintext": DEK, "KeyId": "arn:test"}

    http = _mock_http(409, MANAGED_BODY)
    with (
        patch("boto3.session.Session") as sess,
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
        patch("tasqr_mcp.logging.log_event"),
    ):
        sess.return_value.client.return_value = mock_kms
        with patch("httpx2.AsyncClient", return_value=http), pytest.raises(ManagedOrgError):
            await fetch_or_generate_dek(cfg)

    # The server MUST have been consulted despite the local cache.
    assert http.get.await_count == 1
    # And the cached DEK must never have been unwrapped.
    assert mock_kms.decrypt.call_count == 0


@pytest.mark.anyio
async def test_managed_org_refuses_even_when_aws_is_unusable():
    """The refusal must not depend on AWS being installed or configured.

    A bad aws_profile must not mask the 409 — the KMS client is built only after the probe.
    """
    from tasqr_mcp.credentials import ManagedOrgError, fetch_or_generate_dek

    cfg = {"api_key": "k", "kms_key_id": "arn:test", "aws_profile": "does-not-exist"}

    def explode(*a, **k):
        raise Exception("ProfileNotFound: the AWS profile does not exist")

    with (
        patch("boto3.session.Session", side_effect=explode),
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
        patch("tasqr_mcp.logging.log_event"),
    ):
        with patch("httpx2.AsyncClient", return_value=_mock_http(409, MANAGED_BODY)):
            with pytest.raises(ManagedOrgError):
                await fetch_or_generate_dek(cfg)


@pytest.mark.anyio
async def test_byok_org_still_encrypts():
    """GET /org/dek -> 200: the BYOK path is unchanged."""
    from tasqr_mcp.credentials import fetch_or_generate_dek

    cfg = {"api_key": "k", "kms_key_id": "arn:test", "aws_profile": "test"}

    mock_kms = MagicMock()
    mock_kms.decrypt.return_value = {"Plaintext": DEK, "KeyId": "arn:test"}

    body = {
        "wrapped_dek": WRAPPED,
        "kms_key_id": "arn:test",
        "key_provider": "client_byok",
        "org_id": "org-managed-test",
    }
    with (
        patch("boto3.session.Session") as sess,
        patch("tasqr_mcp.credentials.read_config", return_value=cfg),
        patch("tasqr_mcp.credentials.write_config_value"),
        patch("tasqr_mcp.logging.log_event"),
    ):
        sess.return_value.client.return_value = mock_kms
        with patch("httpx2.AsyncClient", return_value=_mock_http(200, body)):
            dek, source, org_id = await fetch_or_generate_dek(cfg)

    assert dek == DEK
    assert source == "api"
    assert org_id == "org-managed-test"


def test_run_reports_grouped_errors_on_every_supported_python(capsys):
    """anyio raises errors wrapped in an ExceptionGroup; run() must report them cleanly."""
    from tasqr_mcp import proxy

    def boom(*_a, **_k):
        raise BaseExceptionGroup("grouped", [ValueError("inner failure")])

    with patch.object(proxy.anyio, "run", side_effect=boom), pytest.raises(SystemExit) as exc:
        proxy.run("api-key")

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "inner failure" in err
    assert "NameError" not in err


def test_cli_prints_clean_message_and_exits(capsys):
    """A managed-org refusal must reach the user as a message, not a traceback."""
    import tasqr_mcp.__main__ as m
    from tasqr_mcp.credentials import ManagedOrgError

    def boom(_key):
        raise ManagedOrgError("org uses server-managed encryption; remove kms_key_id")

    with (
        patch.object(m, "read_api_key", return_value="k"),
        patch.object(m, "run", side_effect=boom),
        pytest.raises(SystemExit) as exc,
    ):
        m.main()

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "server-managed encryption" in err
    assert "Traceback" not in err


@pytest.mark.anyio
async def test_proxy_does_not_build_crypto_for_managed_org():
    """proxy._run must surface the refusal, not silently double-encrypt."""
    from tasqr_mcp.credentials import ManagedOrgError

    cfg = {"api_key": "k", "kms_key_id": "arn:test", "aws_profile": "test"}

    async def boom(_cfg):
        raise ManagedOrgError("org uses server-managed encryption; remove kms_key_id")

    with (
        patch("tasqr_mcp.proxy.read_config", return_value=cfg),
        patch("tasqr_mcp.crypto.ClientCrypto.init", side_effect=boom),
    ):
        from tasqr_mcp.proxy import _run

        with pytest.raises(ManagedOrgError):
            await _run("api-key")
