"""The local server the proxy serves (proxy._server).

What matters is what a connecting client receives, so these connect a real
in-process Client to the server rather than inspecting constructor arguments —
over both eras, since Claude Code and other clients may still use the legacy
initialize handshake.
"""

from unittest.mock import AsyncMock

import pytest
from mcp import Client

UPSTREAM_TEXT = "Tasqr is a shared, durable task tracker.\n\nCore loop: create_tasks, update_tasks."


def _upstream(instructions):
    session = AsyncMock()
    session.instructions = instructions
    return session


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_relays_upstream_instructions_verbatim(mode):
    from tasqr_mcp.proxy import _server

    async with Client(_server(_upstream(UPSTREAM_TEXT), None), mode=mode) as client:
        assert client.instructions == UPSTREAM_TEXT


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_no_upstream_instructions_advertises_none(mode):
    """Absent upstream means absent here — never an empty string standing in for it."""
    from tasqr_mcp.proxy import _server

    async with Client(_server(_upstream(None), None), mode=mode) as client:
        assert client.instructions is None
