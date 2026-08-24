"""The two request handlers the proxy serves (proxy._handlers).

The SDK takes handlers as constructor callables rather than decorators, so these
are ordinary functions and can be driven directly with a stub upstream session —
which is the only way this wiring gets covered: everything above it needs a live
streamable-HTTP connection.
"""

import json
import os
from unittest.mock import AsyncMock, patch

import pytest
from mcp import types

DEK = os.urandom(32)
ORG = "org-handler-test"
TID = "11111111-1111-4111-8111-111111111111"


def _upstream(list_result=None, call_result=None):
    session = AsyncMock()
    session.list_tools = AsyncMock(return_value=list_result)
    session.call_tool = AsyncMock(return_value=call_result)
    return session


def _tool(name):
    return types.Tool(name=name, inputSchema={"type": "object"})


def _result(payload):
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(payload))])


@pytest.mark.anyio
async def test_list_tools_passes_the_upstream_listing_through():
    from tasqr_mcp.proxy import _handlers

    listing = types.ListToolsResult(tools=[_tool("create_tasks"), _tool("get_tasks")])
    on_list_tools, _ = _handlers(_upstream(list_result=listing), None)

    out = await on_list_tools(None, None)

    assert [t.name for t in out.tools] == ["create_tasks", "get_tasks"]


@pytest.mark.anyio
async def test_list_tools_forwards_the_cursor():
    """Pagination is the client's to drive — we must not swallow its cursor."""
    from tasqr_mcp.proxy import _handlers

    upstream = _upstream(list_result=types.ListToolsResult(tools=[]))
    on_list_tools, _ = _handlers(upstream, None)

    await on_list_tools(None, types.PaginatedRequestParams(cursor="page-2"))

    # Client takes the cursor as a keyword: it owns the response-cache lookup,
    # which a pre-built params object would bypass.
    assert upstream.list_tools.await_args.kwargs["cursor"] == "page-2"


@pytest.mark.anyio
async def test_list_tools_without_params_asks_for_the_first_page():
    """The downstream client may send no params at all; that is page one, not a
    crash on `None.cursor`."""
    from tasqr_mcp.proxy import _handlers

    upstream = _upstream(list_result=types.ListToolsResult(tools=[]))
    on_list_tools, _ = _handlers(upstream, None)

    await on_list_tools(None, None)

    assert upstream.list_tools.await_args.kwargs["cursor"] is None


@pytest.mark.anyio
async def test_call_tool_passes_args_and_result_through_unencrypted():
    from tasqr_mcp.proxy import _handlers

    upstream = _upstream(call_result=_result({"ok": True}))
    _, on_call_tool = _handlers(upstream, None)

    params = types.CallToolRequestParams(name="get_quota", arguments={"a": 1})
    out = await on_call_tool(None, params)

    assert upstream.call_tool.await_args.args == ("get_quota", {"a": 1})
    assert json.loads(out.content[0].text) == {"ok": True}


@pytest.mark.anyio
async def test_call_tool_with_no_arguments_sends_an_empty_dict():
    from tasqr_mcp.proxy import _handlers

    upstream = _upstream(call_result=_result({"ok": True}))
    _, on_call_tool = _handlers(upstream, None)

    await on_call_tool(None, types.CallToolRequestParams(name="get_quota"))

    assert upstream.call_tool.await_args.args == ("get_quota", {})


@pytest.mark.anyio
async def test_call_tool_encrypts_outbound_args():
    """BYOK: plaintext must not leave the process. Asserted on the ciphertext marker,
    not on the absence of plaintext — a broken tool table encrypts nothing, which makes
    'no plaintext in the payload' trivially false."""
    from tasqr_mcp.crypto import ClientCrypto, _is_enc_marker
    from tasqr_mcp.proxy import _handlers

    crypto = ClientCrypto(dek=DEK, org_id=ORG)
    upstream = _upstream(call_result=_result({"results": [{"task_id": TID}]}))
    _, on_call_tool = _handlers(upstream, crypto)

    with patch("tasqr_mcp.logging.log_event"):
        await on_call_tool(
            None,
            types.CallToolRequestParams(
                name="create_tasks",
                arguments={"tasks": [{"title": "my plaintext title", "description": "d"}]},
            ),
        )

    sent = upstream.call_tool.await_args.args[1]["tasks"][0]
    assert _is_enc_marker(sent["title"])
    assert _is_enc_marker(sent["description"])


@pytest.mark.anyio
async def test_call_tool_decrypts_inbound_result():
    """BYOK: ciphertext must not reach the client."""
    from tasqr_mcp.crypto import ClientCrypto
    from tasqr_mcp.proxy import _handlers

    crypto = ClientCrypto(dek=DEK, org_id=ORG)
    with patch("tasqr_mcp.logging.log_event"):
        sealed = crypto._encrypt_str("secret title", TID, "title")

    upstream = _upstream(
        call_result=_result({"tasks": [{"task_id": TID, "title": sealed}], "count": 1})
    )
    _, on_call_tool = _handlers(upstream, crypto)

    with patch("tasqr_mcp.logging.log_event"):
        out = await on_call_tool(
            None, types.CallToolRequestParams(name="get_tasks", arguments={"task_ids": [TID]})
        )

    assert json.loads(out.content[0].text)["tasks"][0]["title"] == "secret title"


@pytest.mark.anyio
async def test_call_tool_leaves_untabled_tools_alone():
    """submit_feedback is in neither crypto table — args and result pass through."""
    from tasqr_mcp.crypto import ClientCrypto
    from tasqr_mcp.proxy import _handlers

    crypto = ClientCrypto(dek=DEK, org_id=ORG)
    upstream = _upstream(call_result=_result({"task_id": "t1"}))
    _, on_call_tool = _handlers(upstream, crypto)

    with patch("tasqr_mcp.logging.log_event"):
        out = await on_call_tool(
            None,
            types.CallToolRequestParams(
                name="submit_feedback", arguments={"message": "great product!"}
            ),
        )

    assert upstream.call_tool.await_args.args[1] == {"message": "great product!"}
    assert json.loads(out.content[0].text) == {"task_id": "t1"}
