"""Canary for the fail-open crypto tables.

ENCRYPT_LIST_TOOLS / DECRYPT_TOOLS are keyed by server tool name and encrypt or
decrypt NOTHING for an unrecognized name — no error, no log. A server-side tool
rename that isn't mirrored here therefore ships plaintext while every behavioral
test still passes (it already happened once: the plural-forms rename left the Node
port silently unencrypted until it was synced). This test pins the exact table
contents against a fixture that is checked into BOTH repos byte-for-byte, so a
rename can't land in one port without failing the other's CI too.
"""

import json
import pathlib

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "crypto_tool_tables.json").read_text()
)


def test_encrypt_list_tools_pin_exact_tools_and_fields():
    from tasqr_mcp.crypto import ENCRYPT_LIST_TOOLS

    actual = {
        tool: {"list_key": list_key, "fields": list(fields)}
        for tool, (list_key, fields) in ENCRYPT_LIST_TOOLS.items()
    }
    assert actual == FIXTURE["encrypt_list_tools"]


def test_decrypt_tools_and_fields_pin_exact_names():
    from tasqr_mcp.crypto import DECRYPT_TOOLS, TASK_DEC_FIELDS

    assert sorted(DECRYPT_TOOLS) == FIXTURE["decrypt_tools"]
    assert list(TASK_DEC_FIELDS) == FIXTURE["task_dec_fields"]
