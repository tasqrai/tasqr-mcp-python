# tasqr-mcp (Python)

[![ci](https://github.com/tasqrai/tasqr-mcp-python/actions/workflows/ci.yml/badge.svg)](https://github.com/tasqrai/tasqr-mcp-python/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tasqr-mcp)](https://pypi.org/project/tasqr-mcp/)

Tasqr MCP server — task state management for AI agents.

Runs as a local stdio process that reads your API key from `~/.config/tasqr/credentials` and proxies tool calls to the Tasqr Lambda MCP server. Your MCP client config holds no secrets — the API key lives only in the credentials file (written `0600` on Mac/Linux; on Windows it relies on your profile directory's ACLs).

## Install

Requires Python 3.11 or newer.

```bash
uvx tasqr-mcp        # run once without installing
# or
pip install tasqr-mcp
```

On a Mac, Homebrew is a third option, and the requirement above doesn't apply to
it — the formula wraps this same sdist in its own virtualenv with its own Python,
so it shares nothing with any Python you have installed:

```bash
brew tap tasqrai/tasqr
brew trust --tap tasqrai/tasqr
brew install tasqr-mcp
```

Installed this way the command is plain `tasqr-mcp`, so use that in place of
`uvx` in the client config below. Full install notes are in the tap,
[tasqrai/homebrew-tasqr](https://github.com/tasqrai/homebrew-tasqr).

## MCP client config

The entry is the same in every client; only where it lives differs. Most clients accept it per project or for every project, and a per-project entry wins where both exist.

```json
{
  "mcpServers": {
    "tasqr": { "command": "uvx", "args": ["tasqr-mcp"] }
  }
}
```

### Claude Code

The [Tasqr plugin](https://github.com/tasqrai/tasqr-claude-code-plugin) adds this for you (`/plugin marketplace add tasqrai/tasqr-claude-code-plugin`, then `/plugin install tasqr@tasqr`). To add it by hand:

```bash
claude mcp add --scope project tasqr -- uvx tasqr-mcp   # .mcp.json in the project, shareable via git
claude mcp add --scope user tasqr -- uvx tasqr-mcp      # ~/.claude.json, every project
```

### Cursor

`.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for every project. Cursor › Settings › MCP shows the servers it loaded.

```json
{
  "mcpServers": {
    "tasqr": { "command": "uvx", "args": ["tasqr-mcp"] }
  }
}
```

### Claude Desktop

Settings › Developer › Edit Config opens `claude_desktop_config.json` (`~/Library/Application Support/Claude/` on macOS, `%APPDATA%\Claude\` on Windows). Global only; restart Claude Desktop after saving.

```json
{
  "mcpServers": {
    "tasqr": { "command": "uvx", "args": ["tasqr-mcp"] }
  }
}
```

### Google Antigravity

`.agents/mcp_config.json` in the workspace, or `~/.gemini/config/mcp_config.json` for every workspace (shared by the IDE and the CLI). The agent panel's MCP Servers › Manage MCP Servers › View raw config opens the global file.

```json
{
  "mcpServers": {
    "tasqr": { "command": "uvx", "args": ["tasqr-mcp"] }
  }
}
```

### Amazon Kiro

`.kiro/settings/mcp.json` in the workspace, or `~/.kiro/settings/mcp.json` for every workspace. The command palette has "Kiro: Open workspace MCP config (JSON)" and "Kiro: Open user MCP config (JSON)".

```json
{
  "mcpServers": {
    "tasqr": { "command": "uvx", "args": ["tasqr-mcp"] }
  }
}
```

### Amazon Quick Desktop

Settings › Capabilities › MCP › Add MCP. Either add a local server with the command and arguments from the entry above, or choose Import and point it at a Kiro or Claude Code config file that already contains the entry.

### Anything else

Any MCP client that can launch a stdio server takes the same entry: a command, no URL, no headers, no key.

## Credentials

**First run — no setup needed.** Run the proxy once in a terminal:

```bash
uvx tasqr-mcp
```

With no API key on disk, it starts GitHub device-flow signup: it opens your browser to GitHub, copies the device code to your clipboard to paste in, and (if your account has more than one workspace) asks which to use. It then writes the credentials file for you. You only need the manual steps below if you'd rather create it yourself.

Your MCP client never sees a secret — it just launches `uvx tasqr-mcp`, and the key is read from:

```
~/.config/tasqr/credentials   (Mac/Linux)
%APPDATA%\tasqr\credentials   (Windows)
```

```ini
[default]
api_key = tasqr_abc123...
```

On Mac/Linux the file is written `0600` (owner read/write only); on Windows it inherits your profile directory's ACLs. Sign up at [tasqr.ai](https://tasqr.ai) if you'd prefer to grab a key from the web instead.

Because the signup is interactive, it only runs when stdin is a TTY. An MCP client launching the proxy headlessly with no key will exit and tell you to run `uvx tasqr-mcp` in a terminal first.

## Logging

**Logging is off by default** — nothing is written to disk unless you turn it on. When enabled, the proxy keeps an append-only JSON-lines event log recording metadata only: tool names and field names, never task content, never key material.

Turn it on in the credentials file:

```ini
[default]
api_key   = tasqr_abc123...
log_level = info                        # off (default) | info | debug
log_path  = ~/.config/tasqr/tasqr-mcp.log
```

| Level | Logs |
|---|---|
| `off` *(default)* | nothing — no file is created |
| `info` | session lifecycle: `dek_loaded`, `kms_decrypt` — roughly one line per session |
| `debug` | the above plus one `encrypt`/`decrypt` line per tool call |

There is no rotation or size cap, so `debug` is for troubleshooting, not for leaving on.

## Environment variables

Env vars win over the credentials file, which wins over the defaults.

| Variable | Purpose |
|---|---|
| `TASQR_PROFILE` | Which `[section]` of the credentials file to use (default: `default`) |
| `TASQR_MCP_URL` | Point at a different server, e.g. `http://localhost:8000/mcp` |
| `TASQR_LOG` | Override `log_path` |
| `TASQR_LOG_LEVEL` | Override `log_level` |

## Client-side encryption (BYOK)

Encrypt task fields (title, description, metadata, output, note) locally before they reach Tasqr servers. Requires an AWS KMS key you control.

Add `kms_key_id` to your credentials file to turn it on — nothing else to install:

```ini
[default]
api_key      = tasqr_abc123...
kms_key_id   = arn:aws:kms:us-east-1:123456789012:key/your-key-id
aws_profile  = default
```

**Your Tasqr org must be enrolled in client-side BYOK.** At startup the proxy asks the server which mode your org uses. If the org is server-managed, it refuses to start rather than encrypt — the server would otherwise encrypt your ciphertext a second time, leaving the data unreadable to the dashboard, the REST API, and any other agent, and unrecoverable if you lost your KMS key. The error tells you which profile to fix.

Once enrolled, the proxy fetches or generates a data encryption key (DEK), wraps it with KMS, and stores the wrapped key in the Tasqr API. Later runs unwrap the cached DEK with a single KMS call. All AES-256-GCM encryption happens in memory — the plaintext DEK never leaves the process.

Every ciphertext is additionally **bound to its context**: the GCM associated data ties each encrypted value to your org, its task, and the field it was written for. A blob moved to any other slot — a different field, task, or org — fails decryption outright instead of decrypting in the wrong place. To make this possible the proxy mints each new task's id itself and sends it with the create call.

See the [client-side encryption guide](https://tasqr.ai/docs/concepts#client-encryption) for the full setup walkthrough.

## Local development

```bash
pip install -e ".[dev]"
pytest
tasqr-mcp --version
```
