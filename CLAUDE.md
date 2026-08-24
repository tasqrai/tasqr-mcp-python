# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tasqr-mcp` is a thin local MCP proxy. It runs as a stdio process, authenticates with a Tasqr API key, and forwards every `list_tools`/`call_tool` request to the remote Tasqr Lambda MCP server over streamable HTTP (`https://mcp.tasqr.ai/mcp` by default). The actual task-management logic (task storage, claiming, tags, etc.) lives server-side — this repo does not implement it. The only substantial local logic is credential/auth bootstrapping and optional client-side (BYOK) encryption of task fields before they leave the process.

## Commands

```bash
# Install for local dev (editable + dev deps)
pip install -e ".[dev]"

# Run the full test suite
uv run pytest        # or: pytest

# Run a single test file / test
uv run pytest tests/test_crypto.py
uv run pytest tests/test_crypto.py::test_create_task_encrypts_title

# Lint / format
uv run ruff check .
uv run ruff format .

# Run against a local dev server instead of production
TASQR_MCP_URL=http://localhost:8000/mcp uvx tasqr-mcp

# Check version / run the CLI directly
tasqr-mcp --version
```

Lint and format with `ruff check .` and `ruff format .` (configured in `pyproject.toml`, line length 100). CI fails on either. There is no type checker configured.

Tests use `pytest-anyio` (`pytest_plugins = ('anyio',)` in `tests/conftest.py`), so any `@pytest.mark.anyio` test runs once under `asyncio` and once under `trio` — expect `[asyncio]`/`[trio]` variants in test output.

## Architecture

**Entry point** (`__main__.py`): reads the API key via `credentials.read_api_key()`. If missing and stdin is a TTY, runs the GitHub Device Flow signup (`device_flow.py`) and persists the resulting key; otherwise exits with an error telling the user to run `uvx tasqr-mcp` interactively first. Then hands off to `proxy.run(api_key)`.

**Proxy loop** (`proxy.py`): opens a `streamable_http_client` session to the upstream Tasqr MCP server, then starts a local `mcp.server.Server` over stdio that mirrors it — `on_list_tools` passes the upstream listing through directly (cursor included), `on_call_tool` optionally encrypts args before forwarding and decrypts the result after. Both handlers come from `_handlers(upstream, crypto)` and are passed to the `Server` constructor: the SDK registers handlers as constructor callables, not decorators, and building them apart from the server is what makes them testable (`tests/test_handlers.py`) without a live connection. The transport takes no `headers=` of its own — auth rides on an `httpx2.AsyncClient` the proxy builds and therefore closes (the transport only manages a client it created itself). A `kms_key_id` in the credentials config is *necessary but not sufficient* to encrypt: it only makes the proxy ask. The server has the final say (see BYOK below) and can refuse, in which case `ClientCrypto` is never constructed and the proxy exits with a `ManagedOrgError`. With no `kms_key_id`, calls pass straight through.

**Dependency ceilings** (`pyproject.toml`): every runtime dep is capped at its next major, and `tests/test_dependency_bounds.py` fails if a new one is added uncapped. `uvx --from git+…` ignores `uv.lock` and resolves fresh on every launch, so an uncapped floor ships the next major to every user the day it lands — which is how mcp 2.0 (renamed `streamablehttp_client`) broke every launch at once. Lifting a cap belongs in the same commit as the migration it needs. The JS proxy gets this free from `^1.0.0`.

**Credentials/config** (`credentials.py`): all local state lives in one INI file — `~/.config/tasqr/credentials` (or `%APPDATA%\tasqr\credentials` on Windows), keyed by profile (`[default]`, overridable via `TASQR_PROFILE`). Holds `api_key`, and optionally `kms_key_id`, `aws_profile`, `mcp_url`, `auth_url`, `api_url`, and a cached `wrapped_dek`. Config precedence throughout the codebase is: env var → credentials file → hardcoded default (see `_mcp_url()` in `proxy.py` and `_auth_url()` in `device_flow.py` for the pattern).

**Client-side encryption / BYOK** (`crypto.py` + `fetch_or_generate_dek` in `credentials.py`): when a `kms_key_id` is configured, `ClientCrypto.init()` runs once at proxy startup and resolves a single AES-256 data encryption key (DEK).

**The server decides whether we may encrypt at all — never local config.** `GET /org/dek` is consulted *first*, before any local state is touched:
1. **409** → the org is server-managed. Raise `ManagedOrgError`; do **not** construct `ClientCrypto`, even though `kms_key_id` is set. Client-encrypting here would corrupt the data for every other reader (dashboard, REST, other agents) and make it unrecoverable if the client key is lost.
2. **200** → the org is `client_byok`. Only now is the cached `wrapped_dek` safe to use: KMS `Decrypt` it (saving a round trip). If that fails (stale ciphertext), delete the cached value and fall back to the server's blob.
3. **404** → BYOK-eligible but unenrolled. Generate a DEK via KMS `GenerateDataKey`, `PUT /org/dek` to register it (racing PUTs resolve via a 409 → re-fetch-the-winner path), then cache the wrapped form locally.

This ordering is load-bearing. Never unwrap the cached `wrapped_dek` without first confirming with the server that the org is `client_byok` — a local short-circuit would client-encrypt against a managed org, and the server would then wrap that ciphertext again with the org DEK, leaving the data readable only by a key it has no record of.

This is a hard invariant covered by `tests/test_kms_count.py`: exactly one KMS `Decrypt` call happens per proxy session (at init), and zero further KMS calls occur no matter how many tool calls follow — all subsequent encrypt/decrypt is pure in-memory AES-256-GCM using the resolved DEK. Don't add code paths that call KMS outside of `fetch_or_generate_dek`.

Field-level encryption is declarative, driven by lookup tables in `crypto.py` that are **keyed by server tool name**. The server's task tools are all array-taking (`create_tasks`, `update_tasks`, `get_tasks`, plus `list_tasks` / `claim_next_task`) — a single task is just a list of one — so:
- `ENCRYPT_LIST_TOOLS` — outbound args holding a list of task-like objects, each item encrypted per the field list (`create_tasks`'s `tasks[]`, `update_tasks`'s `updates[]`). There is no single-object encrypt table — every task tool the server exposes is array-taking.
- `DECRYPT_TOOLS` / `TASK_DEC_FIELDS` — which inbound tool responses get decrypted, including nested shapes (`claim_next_task`'s `{"task": {...}}`, and the `{"tasks": [...]}` envelope returned by both `list_tasks` and `get_tasks`, which also carries `history[].note` entries).

Both lookups **fail open**: an unrecognized tool name encrypts/decrypts nothing and raises no error. So if the server renames a tool and these tables aren't updated, BYOK silently ships plaintext. A rename server-side is a breaking change here — grep the tables for the old name and sync both this repo and `tasqr-mcp-node` in the same change. Tests don't catch this on their own: a suite written against a stale tool name still passes, because "no plaintext in logs" is trivially true when nothing is encrypted. Assert on the ciphertext (`_is_enc_marker`), not on the absence of plaintext.

Encrypted values are JSON "marker" objects: `{"__tasqr_enc__": 2, "n": <base64 nonce>, "ct": <base64 ciphertext+tag>}`. Dict-typed fields (`metadata`, `output`) are JSON-serialized before encryption and the marker is embedded as a dict (not a string) so the field still validates against the server's `dict | None` pydantic schema. When adding a new tool that should be encrypted, add it to the appropriate table rather than special-casing it in `encrypt_args`/`decrypt_result`.

**AAD binding (format v2 — the only format).** Every ciphertext carries GCM associated data `v2|{org_id}|{task_id}|{field}`, so a blob only decrypts in the exact slot it was sealed for — relocating it across fields, tasks, or orgs is a hard `InvalidTag` failure. The pieces of that string are byte-exact contracts:
- `org_id` comes verbatim from `/org/dek` (the server added it to the 200 and PUT-201 bodies for exactly this purpose); `fetch_or_generate_dek` returns `(dek, source, org_id)` and refuses to run against a server that doesn't send it.
- `task_id`: on `create_tasks` the proxy **mints** each item's id (canonical lowercase `uuid4`) before encrypting and sends it with the call — the server stores it as the primary key and rejects (never overwrites) an existing id. On `update_tasks` the item's own `task_id` is used; an update item with encryptable fields but no `task_id` raises `ClientCryptoError` rather than sending plaintext.
- Decrypt-side reconstruction: a task's fields and its `history[].note` were sealed under the task's own id; a `dependencies[].title` is the **blocker's** ciphertext, sealed under the blocker's id — rebuild from `dep["task_id"]`, never the enclosing task's.

Version handling: `_decrypt_str` reads the marker's `__tasqr_enc__` value and raises the typed `UnsupportedCiphertextError` (naming the version) for anything ≠ 2. **There is no v1 read path** — v1 was a dead pre-release format (no AAD) that no released client ever wrote; do not add compatibility for it. The relocation-must-fail tests in `tests/test_crypto.py` are what prove the AAD is actually wired in on both sides — a round-trip test alone passes even when no AAD is sent at all; keep them.

**The server uses this same binding.** Tasqr-managed (non-BYOK) orgs are encrypted server-side under the identical `v2|{org_id}|{task_id}|{field}` AAD (`services/shared/src/tasqr/crypto.py` in the `llm_task_tracker` repo), and the server likewise has no v1 reader. The two never decrypt each other's blobs — a managed org's data never passes through this proxy's crypto, and a BYOK org's never passes through the server's — so the formats can't break each other at runtime. Keep them identical anyway: one format, one mental model, and one thing to reason about when auditing.

**Device flow** (`device_flow.py`): GitHub OAuth Device Flow used only for first-time signup. Polls GitHub for a token, then exchanges it with the Tasqr auth service (`POST {auth_url}/device`), which may prompt the user to pick a workspace (`_prompt_choice`) if their GitHub account belongs to multiple.

**Logging** (`logging.py`): append-only JSON-lines event log. Only structured event metadata is ever logged (e.g. `kms_decrypt`, `dek_loaded`, `encrypt`/`decrypt` with field *names*, never values) — never log plaintext DEK material or task content.

Level and path are configurable, both following the usual env var → credentials file → default precedence: `log_level` (`TASQR_LOG_LEVEL`) and `log_path` (`TASQR_LOG`, default `~/.config/tasqr/tasqr-mcp.log`). Levels are `off` (**default** — logging is opt-in; nothing touches disk unless asked for) / `info` / `debug`, and each event is assigned a level in `_EVENT_LEVEL`: lifecycle events (`dek_loaded`, `kms_decrypt`, ~once per session) are `info`; per-tool-call events (`encrypt`, `decrypt`) are `debug`. An event missing from the table defaults to `info` so a new event stays visible rather than silently vanishing. An *absent* level means `off`, but a level that is set-but-unrecognised (`debbug`) falls back to `info` rather than `off` — the user plainly wanted logging, so a typo must not silently give them none.

When adding an event, add it to `_EVENT_LEVEL` (in **both** ports). Note that any test asserting "no plaintext in the log" must pin `TASQR_LOG_LEVEL=debug` **and** assert the event was actually written — otherwise the assertion is trivially true when nothing is logged, which is the same fail-open trap as the crypto tables.
