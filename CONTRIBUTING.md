# Contributing

Thanks for your interest in `tasqr-mcp`. This is the Python proxy; a line-for-line Node port lives in [tasqr-mcp-node](https://github.com/tasqrai/tasqr-mcp-node).

## Getting set up

Requires Python 3.11 or newer.

```bash
pip install -e ".[dev]"
pytest                                  # full suite, runs offline
pytest tests/test_crypto.py::test_name  # a single test
ruff check .                            # lint
ruff format .                           # format
```

The suite is fast, dependency-light, and needs no network or AWS account — KMS is mocked with `moto`. Lint and formatting are handled by [ruff](https://docs.astral.sh/ruff/), configured in `pyproject.toml`; CI fails on violations.

Tests use `anyio`, so any test marked `@pytest.mark.anyio` runs twice — once under `asyncio`, once under `trio`. Seeing each test name appear twice is expected.

To run against a local Tasqr server instead of production:

```bash
TASQR_MCP_URL=http://localhost:8000/mcp uvx tasqr-mcp
```

## Two things to know before you change crypto

**Keep the two ports in sync.** The Node proxy is a port of this one: same module names, same behavior, same wire format. A task encrypted by one client must decrypt in the other. Any change to the protocol, the tool tables, or the crypto logic has to land in both repos, or clients silently disagree.

**The crypto tables fail open.** `ENCRYPT_LIST_TOOLS` / `DECRYPT_TOOLS` in `crypto.py` are keyed by server tool name, and an unrecognised name encrypts nothing, decrypts nothing, and raises no error. That makes a tool rename a silent-plaintext bug rather than a crash. Tests won't catch it on their own — a suite written against a stale tool name still passes, because "no plaintext" is trivially true when nothing was encrypted. Assert on the ciphertext (`_is_enc_marker`), not on the absence of plaintext. The exact table contents are pinned by `tests/test_tool_tables.py` against `tests/fixtures/crypto_tool_tables.json`, which is checked into both repos byte-for-byte — a rename must update the fixture and the tables in both repos in the same change.

## Pull requests

- Include a test. For a bug fix, write the failing test first.
- Run the full suite and the linter before pushing; CI runs the tests on Python 3.11–3.14 and lint on the newest of those.
- Keep commits focused, and explain *why* in the message rather than restating the diff.

## Security

Please don't open a public issue for a security problem. Use GitHub's private vulnerability reporting instead: **Security** tab → **Report a vulnerability**.
