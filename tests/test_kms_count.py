"""KMS call-count invariant: exactly one Decrypt at init, zero thereafter."""

import base64
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

DEK = os.urandom(32)
WRAPPED = base64.b64encode(b"fake-wrapped-dek").decode()


class StrictKMSMock:
    """Raises if Decrypt is called more than the allowed number of times."""

    def __init__(self, allowed_calls=1):
        self._allowed = allowed_calls
        self._count = 0

    def decrypt(self, **kwargs):
        self._count += 1
        if self._count > self._allowed:
            raise AssertionError(f"kms.Decrypt called {self._count} times (max {self._allowed})")
        return {"Plaintext": DEK, "KeyId": "arn:aws:kms:us-east-1:123:key/test"}

    @property
    def call_count(self):
        return self._count


def _byok_http():
    """httpx2.AsyncClient stub: GET /org/dek -> 200, org is client_byok."""
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "wrapped_dek": WRAPPED,
        "kms_key_id": "arn:aws:kms:us-east-1:123:key/test",
        "key_provider": "client_byok",
        "org_id": "org-kms",
    }
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.get = AsyncMock(return_value=resp)
    return client


@pytest.mark.anyio
async def test_kms_called_once_at_init():
    """ClientCrypto.init() results in exactly 1 KMS Decrypt call.

    The org-state probe (GET /org/dek) is an HTTP call, not a KMS call, so the
    one-Decrypt-per-session invariant is unchanged by it. A cached wrapped_dek still
    spares us a second unwrap — it just no longer lets us skip asking the server.
    """
    strict_kms = StrictKMSMock(allowed_calls=1)

    cfg = {
        "kms_key_id": "arn:aws:kms:us-east-1:123:key/test",
        "aws_profile": "test",
        "api_key": "tasqr_test",
    }

    # boto3 is imported locally inside fetch_or_generate_dek — patch at the boto3 module level
    with patch("boto3.session.Session") as mock_session_cls, patch("tasqr_mcp.logging.log_event"):
        mock_session_cls.return_value.client.return_value = strict_kms

        with (
            patch(
                "tasqr_mcp.credentials.read_config", return_value={**cfg, "wrapped_dek": WRAPPED}
            ),
            patch("httpx2.AsyncClient", return_value=_byok_http()),
        ):
            from tasqr_mcp.crypto import ClientCrypto

            await ClientCrypto.init(cfg)

    assert strict_kms.call_count == 1


@pytest.mark.anyio
async def test_kms_not_called_on_encrypt_decrypt():
    """After init, 50 encrypt+decrypt calls use zero KMS calls (pure AES in memory)."""
    from mcp.types import CallToolResult, TextContent

    from tasqr_mcp.crypto import ClientCrypto

    strict_kms = StrictKMSMock(allowed_calls=0)

    # Build ClientCrypto directly — bypasses KMS entirely
    crypto = ClientCrypto(dek=DEK, org_id="org-kms-test")

    with patch("tasqr_mcp.logging.log_event"), patch("boto3.session.Session") as mock_session_cls:
        mock_session_cls.return_value.client.return_value = strict_kms
        for _ in range(50):
            args = crypto.encrypt_args(
                "create_tasks", {"tasks": [{"title": "hello", "description": "world"}]}
            )
            item = args["tasks"][0]
            enc_envelope = json.dumps(
                {
                    "tasks": [
                        {
                            "task_id": item["task_id"],
                            "title": item.get("title", "hello"),
                            "description": item.get("description", "world"),
                            "metadata": None,
                            "output": None,
                            "status": "pending",
                            "history": [],
                        }
                    ],
                    "count": 1,
                    "not_found": [],
                }
            )
            result = CallToolResult(content=[TextContent(type="text", text=enc_envelope)])
            crypto.decrypt_result("get_tasks", result)

    assert strict_kms.call_count == 0
