"""§10.1 Crypto correctness — AES-256-GCM logic, no KMS needed.

Wire format v2: every ciphertext carries GCM associated data binding it to
`v2|{org_id}|{task_id}|{field}`. A blob only decrypts in the exact slot it was
sealed for — relocation across fields, tasks, or orgs is a hard failure.
There is no v1 read path: v1 was a dead pre-release format; any non-v2 marker
raises the typed UnsupportedCiphertextError, never a bare GCM tag error.
"""

import json
import os
import uuid
from unittest.mock import patch

import pytest

# Build a ClientCrypto directly (bypass init/KMS)
DEK = os.urandom(32)
ORG = "11111111-0000-4000-8000-000000000001"
TID = "22222222-0000-4000-8000-000000000002"
TID2 = "33333333-0000-4000-8000-000000000003"


def make_crypto(org_id=ORG):
    from tasqr_mcp.crypto import ClientCrypto

    return ClientCrypto(dek=DEK, org_id=org_id)


def test_encrypt_decrypt_roundtrip():
    c = make_crypto()
    for plaintext in ["hello world", "unicode: café", '{"nested": true}']:
        encrypted = c._encrypt_str(plaintext, TID, "title")
        assert c._decrypt_str(encrypted, TID, "title") == plaintext


def test_marker_format_is_v2():
    """Encrypted output must be a JSON string with __tasqr_enc__ == 2, n, ct keys."""
    from tasqr_mcp.crypto import ENC_MARKER, ENC_VERSION

    assert ENC_VERSION == 2
    c = make_crypto()
    enc = c._encrypt_str("test", TID, "title")
    obj = json.loads(enc)
    assert obj[ENC_MARKER] == 2
    assert "n" in obj and "ct" in obj


def test_marker_detected():
    from tasqr_mcp.crypto import _is_enc_marker

    c = make_crypto()
    enc = c._encrypt_str("hello", TID, "title")
    assert _is_enc_marker(enc) is True
    assert _is_enc_marker("plain string") is False
    assert _is_enc_marker(None) is False
    assert _is_enc_marker(42) is False


# ── AAD binding: relocation must fail ─────────────────────────────────────────
# These are the tests that prove the AAD is actually wired in — a round-trip
# alone passes even if no AAD is sent on either side.


# A raw InvalidTag has an EMPTY str() — surfacing it unwrapped gives the user a
# blank MCP error. The typed ClientCryptoError names the field and task instead.


def test_relocated_to_other_field_fails():
    from tasqr_mcp.crypto import ClientCryptoError

    c = make_crypto()
    blob = c._encrypt_str("secret", TID, "title")
    with pytest.raises(ClientCryptoError, match="description"):
        c._decrypt_str(blob, TID, "description")


def test_relocated_to_other_task_fails():
    from tasqr_mcp.crypto import ClientCryptoError

    c = make_crypto()
    blob = c._encrypt_str("secret", TID, "title")
    with pytest.raises(ClientCryptoError, match=TID2):
        c._decrypt_str(blob, TID2, "title")


def test_relocated_to_other_org_fails():
    from tasqr_mcp.crypto import ClientCryptoError

    c_a = make_crypto("org-a")
    c_b = make_crypto("org-b")  # same DEK, different org
    blob = c_a._encrypt_str("secret", TID, "title")
    with pytest.raises(ClientCryptoError, match="moved|tampered"):
        c_b._decrypt_str(blob, TID, "title")


# ── version handling ──────────────────────────────────────────────────────────


def _marker(version, c):
    """A syntactically valid marker claiming the given version."""
    obj = json.loads(c._encrypt_str("x", TID, "title"))
    obj["__tasqr_enc__"] = version
    return json.dumps(obj)


def test_unknown_version_raises_typed_error():
    from tasqr_mcp.crypto import UnsupportedCiphertextError

    c = make_crypto()
    with pytest.raises(UnsupportedCiphertextError, match="99"):
        c._decrypt_str(_marker(99, c), TID, "title")


def test_v1_is_a_dead_format():
    """v1 (pre-release, no AAD) is not read — it must fail with the typed error
    naming the version, not an opaque GCM tag failure."""
    from tasqr_mcp.crypto import UnsupportedCiphertextError

    c = make_crypto()
    with pytest.raises(UnsupportedCiphertextError, match="1"):
        c._decrypt_str(_marker(1, c), TID, "title")


# ── encrypt_args ──────────────────────────────────────────────────────────────


def test_create_tasks_mints_task_id():
    """The proxy mints each new task's id so the AAD can bind it at encrypt time;
    the id rides along to the server, which stores it as the primary key."""
    c = make_crypto()
    args = {"tasks": [{"title": "t", "description": "d"}]}
    with patch("tasqr_mcp.logging.log_event"):
        result = c.encrypt_args("create_tasks", args)
    item = result["tasks"][0]
    tid = item["task_id"]
    assert str(uuid.UUID(tid)) == tid  # canonical form
    assert c._decrypt_str(item["title"], tid, "title") == "t"
    assert c._decrypt_str(item["description"], tid, "description") == "d"
    # original args not mutated
    assert "task_id" not in args["tasks"][0]


def test_create_tasks_keeps_caller_supplied_task_id():
    c = make_crypto()
    args = {"tasks": [{"title": "t", "description": "d", "task_id": TID}]}
    with patch("tasqr_mcp.logging.log_event"):
        result = c.encrypt_args("create_tasks", args)
    item = result["tasks"][0]
    assert item["task_id"] == TID
    assert c._decrypt_str(item["title"], TID, "title") == "t"


def test_passthrough_fields_unchanged():
    """Fields not in the create_tasks encrypt list pass through encrypt_args unmodified."""
    c = make_crypto()
    args = {
        "tasks": [
            {
                "title": "t",
                "status": "pending",
                "priority": 2,
                "assignee": "a@b.com",
                "tags": ["x"],
            },
        ]
    }
    with patch("tasqr_mcp.logging.log_event"):
        result = c.encrypt_args("create_tasks", args)
    item = result["tasks"][0]
    assert item["status"] == "pending"
    assert item["priority"] == 2
    assert item["assignee"] == "a@b.com"
    assert item["tags"] == ["x"]


def test_metadata_roundtrip():
    """metadata dict is JSON-serialised before encrypting and deserialised after."""
    c = make_crypto()
    meta = {"key": "value", "count": 42}
    with patch("tasqr_mcp.logging.log_event"):
        args = c.encrypt_args(
            "create_tasks", {"tasks": [{"title": "t", "description": "d", "metadata": meta}]}
        )
    from tasqr_mcp.crypto import _is_enc_marker

    item = args["tasks"][0]
    # metadata is now a dict marker (not a string) so pydantic accepts dict | None
    assert isinstance(item["metadata"], dict)
    assert _is_enc_marker(item["metadata"])
    # decrypt it back through the task path (rebuilds AAD from the task's own id)
    task = {"task_id": item["task_id"], "metadata": item["metadata"]}
    result = c._decrypt_task(task)
    assert result["metadata"] == meta


def test_submit_feedback_not_encrypted():
    """submit_feedback args pass through unmodified (not in the crypto tables)."""
    c = make_crypto()
    args = {"message": "please add feature X", "type": "feature"}
    with patch("tasqr_mcp.logging.log_event"):
        result = c.encrypt_args("submit_feedback", args)
    assert result["message"] == "please add feature X"


def test_create_tasks_items_encrypted():
    """Each item in a create_tasks call gets field encryption (a single task is a list of one)."""
    from tasqr_mcp.crypto import _is_enc_marker

    c = make_crypto()
    args = {
        "tasks": [
            {"ref": "a", "title": "first", "description": "d1", "metadata": {"k": 1}},
            {"title": "second", "description": "d2", "blocked_by": ["ref:a"], "priority": 2},
        ]
    }
    with patch("tasqr_mcp.logging.log_event"):
        result = c.encrypt_args("create_tasks", args)
    for item in result["tasks"]:
        assert _is_enc_marker(item["title"])
        assert _is_enc_marker(item["description"])
    # non-sensitive fields pass through untouched
    assert result["tasks"][0]["ref"] == "a"
    assert result["tasks"][1]["blocked_by"] == ["ref:a"]
    assert result["tasks"][1]["priority"] == 2
    # metadata marker stays a dict for pydantic validation server-side
    assert isinstance(result["tasks"][0]["metadata"], dict)
    assert _is_enc_marker(result["tasks"][0]["metadata"])
    # each item decrypts under its own minted id
    t0 = result["tasks"][0]
    assert c._decrypt_str(t0["title"], t0["task_id"], "title") == "first"
    # original args not mutated
    assert args["tasks"][0]["title"] == "first"


def test_create_tags_not_encrypted():
    """Tag names/descriptions are plaintext server-side, so no tag tool is in the
    crypto sets — create_tags must pass through untouched."""
    c = make_crypto()
    args = {"tags": [{"name": "backend", "strict": True}]}
    result = c.encrypt_args("create_tags", args)
    assert result == args


def test_update_tasks_items_encrypted():
    """Each item in update_tasks binds its ciphertext to the item's own task_id."""
    from tasqr_mcp.crypto import _is_enc_marker

    c = make_crypto()
    args = {
        "updates": [
            {"task_id": TID, "title": "new title", "note": "done", "status": "completed"},
            {"task_id": TID2, "output": {"ok": True}, "metadata": {"k": 1}},
        ]
    }
    with patch("tasqr_mcp.logging.log_event"):
        result = c.encrypt_args("update_tasks", args)
    assert _is_enc_marker(result["updates"][0]["title"])
    assert _is_enc_marker(result["updates"][0]["note"])
    # passthrough fields untouched
    assert result["updates"][0]["task_id"] == TID
    assert result["updates"][0]["status"] == "completed"
    # dict fields stay dicts (pydantic dict | None on the server)
    assert isinstance(result["updates"][1]["output"], dict)
    assert _is_enc_marker(result["updates"][1]["output"])
    assert isinstance(result["updates"][1]["metadata"], dict)
    # bound to each update's own task id
    assert c._decrypt_str(result["updates"][0]["title"], TID, "title") == "new title"
    assert json.loads(
        c._decrypt_str(json.dumps(result["updates"][1]["output"]), TID2, "output")
    ) == {"ok": True}
    # original args not mutated
    assert args["updates"][0]["title"] == "new title"


def test_update_tasks_item_without_task_id_raises():
    """An update item with encryptable fields but no task_id cannot build an AAD;
    the server would reject the update anyway, so fail loudly instead of leaking
    plaintext upstream."""
    from tasqr_mcp.crypto import ClientCryptoError

    c = make_crypto()
    with pytest.raises(ClientCryptoError, match="task_id"):
        c.encrypt_args("update_tasks", {"updates": [{"title": "no id"}]})


# ── decrypt paths ─────────────────────────────────────────────────────────────


def test_decrypt_passthrough_non_marker():
    """_decrypt_task passes plain string fields through unchanged (not markers)."""
    c = make_crypto()
    plaintext = "just a plain string"
    task = {"task_id": TID, "title": plaintext, "description": "also plain"}
    result = c._decrypt_task(task)
    assert result["title"] == plaintext
    assert result["description"] == "also plain"


def test_decrypt_passthrough_missing_field():
    """_decrypt_task on dict without encrypted fields doesn't raise."""
    c = make_crypto()
    task = {"task_id": "123", "status": "pending"}
    with patch("tasqr_mcp.logging.log_event"):
        result = c._decrypt_task(task)
    assert result["task_id"] == "123"


def test_decrypt_task_uses_own_task_id():
    c = make_crypto()
    task = {"task_id": TID, "title": c._encrypt_str("secret", TID, "title")}
    result = c._decrypt_task(task)
    assert result["title"] == "secret"


def test_decrypt_task_history_notes_bound_to_task():
    c = make_crypto()
    task = {
        "task_id": TID,
        "title": "plain",
        "history": [{"to_status": "completed", "note": c._encrypt_str("done", TID, "note")}],
    }
    result = c._decrypt_task(task)
    assert result["history"][0]["note"] == "done"


def test_decrypt_task_decrypts_dependency_titles_with_blocker_id():
    """get_tasks embeds a `dependencies` list of blocker summaries
    ({task_id, title, status}). The blob is the *blocker's* title ciphertext,
    sealed under the blocker's id — the AAD must be rebuilt from dep["task_id"],
    not the enclosing task's id."""
    c = make_crypto()
    enc_title = c._encrypt_str("blocker's secret title", TID2, "title")
    task = {
        "task_id": TID,
        "title": "plain dependent title",
        "dependencies": [
            {"task_id": TID2, "title": enc_title, "status": "pending"},
        ],
    }
    result = c._decrypt_task(task)
    assert result["dependencies"][0]["title"] == "blocker's secret title"


def test_get_tasks_response_decrypted():
    """get_tasks {tasks:[...]} responses are decrypted like list_tasks."""
    from mcp.types import CallToolResult, TextContent

    c = make_crypto()
    enc_title = c._encrypt_str("secret title", TID, "title")
    payload = {"tasks": [{"task_id": TID, "title": enc_title}], "count": 1, "not_found": []}
    result = CallToolResult(content=[TextContent(type="text", text=json.dumps(payload))])
    out = c.decrypt_result("get_tasks", result)
    data = json.loads(out.content[0].text)
    assert data["tasks"][0]["title"] == "secret title"


def test_get_tasks_decrypts_structured_content():
    """A tool with an outputSchema returns the payload twice — as serialized JSON in
    `content` and as an object in `structuredContent`. The proxy must decrypt BOTH and
    leave them in agreement; dropping structuredContent makes the result malformed
    (clients raise -32600), and passing it through untouched leaks ciphertext."""
    from mcp.types import CallToolResult, TextContent

    from tasqr_mcp.crypto import _is_enc_marker

    c = make_crypto()
    enc_title = c._encrypt_str("secret title", TID, "title")
    payload = {"tasks": [{"task_id": TID, "title": enc_title}], "count": 1, "not_found": []}
    result = CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        structured_content=payload,
    )
    out = c.decrypt_result("get_tasks", result)

    # structuredContent must survive AND be decrypted
    assert out.structured_content is not None, "structuredContent was dropped"
    assert out.structured_content["tasks"][0]["title"] == "secret title"
    assert not _is_enc_marker(out.structured_content["tasks"][0]["title"])

    # and it must agree with the text channel
    text_data = json.loads(out.content[0].text)
    assert text_data["tasks"][0]["title"] == out.structured_content["tasks"][0]["title"]


def test_decrypt_result_preserves_is_error():
    """Rebuilding the result must not silently drop isError."""
    from mcp.types import CallToolResult, TextContent

    c = make_crypto()
    payload = {"tasks": [], "count": 0, "not_found": []}
    result = CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload))],
        structured_content=payload,
        is_error=True,
    )
    out = c.decrypt_result("get_tasks", result)
    assert out.is_error is True


def test_rejects_non_256_bit_dek():
    """AES-256-GCM is the wire contract. `cryptography`'s AESGCM would happily run
    AES-128 with a 16-byte key, producing ciphertext no other client (including the
    Node port, which hard-requires 32 bytes) can read — fail at construction instead."""
    from tasqr_mcp.crypto import ClientCrypto, ClientCryptoError

    with pytest.raises(ClientCryptoError, match="32"):
        ClientCrypto(os.urandom(16), ORG)
