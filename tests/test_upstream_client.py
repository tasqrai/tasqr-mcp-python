"""How the proxy connects UPSTREAM to mcp.tasqr.ai.

This is the half of MCP 2026-07-28 adoption the proxy owns. The revision deletes
the `initialize` handshake, and the spec's own compatibility matrix scores a
legacy client against a modern server as "Fails" — at PROCESS STARTUP, so the
symptom is "the MCP server won't start", with no partial degradation. The proxy
is therefore UPSTREAM of any server flip, not downstream of it: this must be
right before the server can move.

We do not hand-write era negotiation. mcp 2.x owns it (`mcp.client._probe`), and
what these tests pin is that we actually opted into it rather than taking the
SDK's explicitly-legacy path — which is exactly the trap the proxy was in:
migrating to the mcp 2.x SDK gave it the capability, but `ClientSession(...)` +
`.initialize()` is hard-wired to the handshake and never probes.
"""

import httpx2
import pytest


@pytest.fixture
def http_client():
    return httpx2.AsyncClient(headers={"Authorization": "Bearer test"})


def test_upstream_is_era_negotiated_not_forced_legacy(http_client):
    """mode='auto' probes server/discover and falls back to the handshake on
    anything that is not positive modern evidence. mode='legacy' would be
    byte-identical pre-2026 behavior — correct against today's server and broken
    against tomorrow's, with no signal in between."""
    from tasqr_mcp.proxy import _upstream_client

    assert _upstream_client(http_client).mode == "auto"


def test_upstream_honors_server_cache_hints(http_client):
    """A modern server may return ttlMs/cacheScope on tools/list. The SDK's
    default CacheConfig honors them; disabling the cache would mean paying for
    every tools/list forever, which is the cost this revision exists to remove."""
    from tasqr_mcp.proxy import _upstream_client

    assert _upstream_client(http_client).cache is not None


def test_upstream_carries_our_authenticated_http_client(http_client):
    """Auth rides on an httpx client we build, so `server` must be a transport we
    constructed. Handing Client a URL string instead makes it build its own
    transport with no Authorization header — every call would 401, and the
    credentials plumbing above this would look like the broken thing."""
    from tasqr_mcp.proxy import _upstream_client

    server = _upstream_client(http_client).server
    assert not isinstance(server, str)
    assert hasattr(server, "__aenter__")
