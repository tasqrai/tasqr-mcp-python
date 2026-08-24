import os
import sys

import anyio
import httpx2
from mcp import types
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .credentials import read_config

_DEFAULT_MCP_URL = "https://mcp.tasqr.ai/mcp"

# The SDK's own client defaults, restated because we build the HTTP client
# ourselves (see _run): a short budget for connect/write/pool, a long one for
# reads, because the streamable-HTTP transport holds a GET open between calls and
# a 30s read timeout would tear the session down while the agent is thinking.
_TIMEOUT = httpx2.Timeout(30.0, read=300.0)


def _mcp_url() -> str:
    return os.environ.get("TASQR_MCP_URL") or read_config().get("mcp_url") or _DEFAULT_MCP_URL


def _upstream_client(http_client: httpx2.AsyncClient) -> Client:
    """The upstream connection to mcp.tasqr.ai, era-negotiated.

    `mode="auto"` is the whole point. MCP 2026-07-28 deletes the `initialize`
    handshake, and a legacy client meeting a modern server does not degrade — it
    fails at process startup, so the symptom is "the MCP server won't start".
    Auto sends a `server/discover` probe and falls back to the handshake on
    anything that is not positive modern evidence, which means one proxy build
    works against both eras and the server can flip without a flag day.

    We do NOT hand-write that negotiation: `mcp.client._probe` owns it, including
    the awkward cases (a `-32022` answer to the fallback handshake re-probes at a
    mutual version). This is §7.2's "the proxy is our dual-era shim" — supplied by
    the SDK rather than maintained here.

    The trap this replaces: migrating to the mcp 2.x SDK gave the proxy the
    capability but not the behavior. `ClientSession(...)` + `.initialize()` sends
    at LATEST_HANDSHAKE_VERSION and raises on any non-handshake reply — an
    explicitly legacy path that never probes. Being on a modern SDK is not the
    same as speaking the modern protocol.

    `server` is the transport instance, not a URL string: auth rides on an httpx
    client we build, and passing a string would have the SDK build its own,
    unauthenticated one. The default `CacheConfig` is kept so a modern server's
    `ttlMs`/`cacheScope` on tools/list are honored.
    """
    return Client(
        server=streamable_http_client(_mcp_url(), http_client=http_client),
        mode="auto",
    )


def _handlers(upstream: Client, crypto):
    """The two request handlers this proxy serves, bound to an upstream client.

    Built apart from the Server so tests can drive them directly: the SDK takes
    handlers as constructor callables, so there is no decorator to reach for.
    """

    async def on_list_tools(_ctx, params: types.PaginatedRequestParams | None):
        # Straight pass-through, pagination included — whatever the server
        # offers, and whichever page of it was asked for. Client takes the cursor
        # as a keyword (it owns the cache lookup that a params object would skip).
        return await upstream.list_tools(cursor=params.cursor if params else None)

    async def on_call_tool(_ctx, params: types.CallToolRequestParams):
        args = params.arguments or {}
        if crypto:
            args = crypto.encrypt_args(params.name, args)
        result = await upstream.call_tool(params.name, args)
        if crypto:
            result = crypto.decrypt_result(params.name, result)
        return result

    return on_list_tools, on_call_tool


async def _run(api_key: str) -> None:
    cfg = read_config()
    crypto = None
    if cfg.get("kms_key_id"):
        from .crypto import ClientCrypto

        crypto = await ClientCrypto.init(cfg)

    # The transport takes no headers of its own — auth rides on a client we build,
    # and building it means we close it (the transport only manages the lifecycle
    # of a client it created itself).
    http_client = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=_TIMEOUT,
        follow_redirects=True,
    )

    # Client owns the connect: it enters the transport, builds the session, and
    # negotiates era (see _upstream_client). There is no explicit initialize()
    # here on purpose — calling one would force the legacy handshake and undo it.
    async with (
        http_client,
        _upstream_client(http_client) as upstream,
    ):
        on_list_tools, on_call_tool = _handlers(upstream, crypto)
        server = Server(
            "tasqr-mcp",
            on_list_tools=on_list_tools,
            on_call_tool=on_call_tool,
        )

        async with stdio_server() as (reader, writer):
            await server.run(
                reader,
                writer,
                server.create_initialization_options(),
            )


def run(api_key: str) -> None:
    try:
        anyio.run(_run, api_key)
    except KeyboardInterrupt:
        pass
    except BaseExceptionGroup as eg:
        cause = eg.exceptions[0]
        print(f"tasqr-mcp: {cause}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"tasqr-mcp: {exc}", file=sys.stderr)
        sys.exit(1)
