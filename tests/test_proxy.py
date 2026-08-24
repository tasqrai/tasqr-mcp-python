"""§10.6 Tool interception — encrypt_args and decrypt_result field coverage."""

import json
import os
from unittest.mock import patch

DEK = os.urandom(32)
ORG = "org-proxy-test"


def make_crypto():
    from tasqr_mcp.crypto import ClientCrypto

    return ClientCrypto(dek=DEK, org_id=ORG)


def make_call_tool_result(data):
    from mcp.types import CallToolResult, TextContent

    return CallToolResult(content=[TextContent(type="text", text=json.dumps(data))])


def test_create_tasks_encrypts_title():
    c = make_crypto()
    with patch("tasqr_mcp.logging.log_event"):
        args = c.encrypt_args(
            "create_tasks", {"tasks": [{"title": "my plaintext title", "description": "desc"}]}
        )
    from tasqr_mcp.crypto import _is_enc_marker

    item = args["tasks"][0]
    assert _is_enc_marker(item["title"])
    assert "my plaintext title" not in str(item["title"])


def test_create_tasks_encrypts_description_and_metadata():
    c = make_crypto()
    meta = {"priority_reason": "urgent customer escalation"}
    with patch("tasqr_mcp.logging.log_event"):
        args = c.encrypt_args(
            "create_tasks",
            {"tasks": [{"title": "t", "description": "secret instructions", "metadata": meta}]},
        )
    from tasqr_mcp.crypto import _is_enc_marker

    item = args["tasks"][0]
    assert _is_enc_marker(item["description"])
    assert _is_enc_marker(item["metadata"])


def test_update_tasks_encrypts_output_and_note():
    c = make_crypto()
    with patch("tasqr_mcp.logging.log_event"):
        args = c.encrypt_args(
            "update_tasks",
            {
                "updates": [
                    {
                        "task_id": "t1",
                        "output": {"result": "done"},
                        "note": "Completed successfully",
                    }
                ]
            },
        )
    from tasqr_mcp.crypto import _is_enc_marker

    item = args["updates"][0]
    assert _is_enc_marker(item["note"])
    assert _is_enc_marker(item["output"])


def test_get_tasks_decrypts_response():
    c = make_crypto()
    with patch("tasqr_mcp.logging.log_event"):
        encrypted_title = c._encrypt_str("secret task title", "t1", "title")

    task = {
        "task_id": "t1",
        "title": encrypted_title,
        "description": "plain",
        "metadata": None,
        "output": None,
        "status": "pending",
        "history": [],
    }
    envelope = {"tasks": [task], "count": 1, "not_found": []}
    result = make_call_tool_result(envelope)

    with patch("tasqr_mcp.logging.log_event"):
        decrypted_result = c.decrypt_result("get_tasks", result)

    data = json.loads(decrypted_result.content[0].text)
    assert data["tasks"][0]["title"] == "secret task title"


def test_list_tasks_decrypts_all_items():
    c = make_crypto()
    with patch("tasqr_mcp.logging.log_event"):
        tasks = [
            {
                "task_id": f"t{i}",
                "title": c._encrypt_str(f"task {i}", f"t{i}", "title"),
                "description": "d",
                "metadata": None,
                "output": None,
                "status": "pending",
                "history": [],
            }
            for i in range(5)
        ]
    # Real server returns {"tasks": [...], "count": N, "cursor": null}
    envelope = {"tasks": tasks, "count": 5, "cursor": None}
    result = make_call_tool_result(envelope)
    with patch("tasqr_mcp.logging.log_event"):
        decrypted = c.decrypt_result("list_tasks", result)

    data = json.loads(decrypted.content[0].text)
    assert "tasks" in data
    assert data["count"] == 5
    for i, t in enumerate(data["tasks"]):
        assert t["title"] == f"task {i}"


def test_submit_feedback_not_encrypted():
    c = make_crypto()
    with patch("tasqr_mcp.logging.log_event"):
        args = c.encrypt_args("submit_feedback", {"message": "great product!", "type": "feature"})
    assert args["message"] == "great product!"


def test_output_dict_roundtrip():
    """output dict survives encrypt→decrypt without corruption."""
    c = make_crypto()
    output_data = {"result": "done", "score": 42, "nested": {"key": "val"}}
    with patch("tasqr_mcp.logging.log_event"):
        args = c.encrypt_args(
            "update_tasks", {"updates": [{"task_id": "t1", "output": output_data}]}
        )
    item = args["updates"][0]
    # encrypted output should be a dict marker
    from tasqr_mcp.crypto import _is_enc_marker

    assert isinstance(item["output"], dict)
    assert _is_enc_marker(item["output"])
    # decrypt it back via _decrypt_task (AAD rebuilt from the task's own id)
    task = {"task_id": "t1", "output": item["output"]}
    result = c._decrypt_task(task)
    assert result["output"] == output_data


def test_claim_next_task_nested_shape():
    """claim_next_task returns {"claimed": true, "task": {...}} — decrypt nested task."""
    c = make_crypto()
    with patch("tasqr_mcp.logging.log_event"):
        enc_title = c._encrypt_str("claimed task title", "c1", "title")
        payload = {
            "claimed": True,
            "task": {
                "task_id": "c1",
                "title": enc_title,
                "description": "d",
                "metadata": None,
                "output": None,
                "status": "in_progress",
                "history": [],
            },
        }
        result = make_call_tool_result(payload)
        decrypted = c.decrypt_result("claim_next_task", result)
    data = json.loads(decrypted.content[0].text)
    assert data["claimed"] is True
    assert data["task"]["title"] == "claimed task title"


def test_status_priority_assignee_tags_not_encrypted():
    c = make_crypto()
    with patch("tasqr_mcp.logging.log_event"):
        args = c.encrypt_args(
            "create_tasks",
            {
                "tasks": [
                    {
                        "title": "t",
                        "description": "d",
                        "status": "pending",
                        "priority": 2,
                        "assignee": "alice@example.com",
                        "tags": ["bug"],
                    }
                ]
            },
        )
    item = args["tasks"][0]
    assert item["status"] == "pending"
    assert item["priority"] == 2
    assert item["assignee"] == "alice@example.com"
    assert item["tags"] == ["bug"]


def test_version_matches_installed_metadata():
    """__version__ duplicates pyproject's version and only pyproject is checked by the
    release workflow's tag guard — this is the guard for the other copy."""
    import importlib.metadata

    from tasqr_mcp import __version__

    assert __version__ == importlib.metadata.version("tasqr-mcp")
