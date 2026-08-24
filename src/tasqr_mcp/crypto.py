import base64
import json
import os
import uuid

from .logging import log_event

ENC_MARKER = "__tasqr_enc__"
ENC_VERSION = 2

# Tools whose args hold a list of task-like dicts; each item is encrypted with the
# given field list. A single task is just a list of one. (Every task tool the server
# exposes is array-taking — there is no single-object encrypt table.)
ENCRYPT_LIST_TOOLS = {
    "create_tasks": ("tasks", ["title", "description", "metadata"]),
    "update_tasks": ("updates", ["title", "description", "metadata", "output", "note"]),
}

# Tools whose responses need decryption. get_tasks and list_tasks both return a
# {tasks:[...]} envelope, handled by the tasks-list branch in decrypt_result (which
# also covers history notes and dependency titles).
DECRYPT_TOOLS = {"get_tasks", "list_tasks", "claim_next_task"}

# Task fields to decrypt in responses (history notes and dependency titles are
# handled structurally in _decrypt_task, not via this list)
TASK_DEC_FIELDS = ["title", "description", "metadata", "output"]


class ClientCryptoError(Exception):
    """A client-side crypto invariant was violated (not a GCM tag failure)."""


class UnsupportedCiphertextError(ClientCryptoError):
    """The marker's version is not the one this client speaks.

    v2 is the only format ever published. v1 was a dead pre-release format;
    nothing reads or writes it.
    """


def _is_enc_marker(value) -> bool:
    """Check if a value is an encrypted marker (string or dict form)."""
    if isinstance(value, dict):
        return ENC_MARKER in value and "n" in value and "ct" in value
    if not isinstance(value, str):
        return False
    try:
        obj = json.loads(value)
        return isinstance(obj, dict) and ENC_MARKER in obj and "n" in obj and "ct" in obj
    except (json.JSONDecodeError, TypeError):
        return False


class ClientCrypto:
    def __init__(self, dek: bytes, org_id: str):
        if not org_id:
            raise ClientCryptoError("org_id is required — the AAD binds every ciphertext to it")
        if len(dek) != 32:
            # AESGCM would silently run AES-128 with a 16-byte key, producing
            # ciphertext no other client can read. AES-256 is the wire contract.
            raise ClientCryptoError(f"DEK must be 32 bytes (AES-256), got {len(dek)}")
        self._dek = dek
        self._org_id = org_id

    @classmethod
    async def init(cls, cfg: dict) -> "ClientCrypto":
        """Fetch or generate the DEK and learn the org_id.

        Called once at proxy startup, and makes exactly one KMS Decrypt call.
        """
        from .credentials import fetch_or_generate_dek

        dek, source, org_id = await fetch_or_generate_dek(cfg)
        log_event("dek_loaded", source=source)
        return cls(dek, org_id)

    def _aad(self, task_id: str, field: str) -> bytes:
        """The associated data that binds a ciphertext to its slot.

        Must be reconstructible byte-for-byte at decrypt time: org_id comes from
        /org/dek verbatim, task_id from the record the blob arrived in (for
        dependency titles, the *blocker's* id), field is the fixed field name.
        """
        return f"v{ENC_VERSION}|{self._org_id}|{task_id}|{field}".encode()

    def _encrypt_str(self, plaintext: str, task_id: str, field: str) -> str:
        """Encrypt a string bound to (org, task, field); returns a marker string."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aes = AESGCM(self._dek)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plaintext.encode(), self._aad(task_id, field))
        marker = {
            ENC_MARKER: ENC_VERSION,
            "n": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode(),
        }
        return json.dumps(marker)

    def _decrypt_str(self, marker, task_id: str, field: str) -> str:
        """Decrypt a marker (JSON string or dict) bound to (org, task, field)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if isinstance(marker, dict):
            marker = json.dumps(marker)
        obj = json.loads(marker)
        version = obj.get(ENC_MARKER)
        if version != ENC_VERSION:
            raise UnsupportedCiphertextError(
                f"This value was encrypted with tasqr-mcp ciphertext format v{version}; "
                f"this client only reads v{ENC_VERSION}. Upgrade tasqr-mcp on every "
                "machine in your org (v1 was a pre-release format that no released "
                "client reads or writes)."
            )
        from cryptography.exceptions import InvalidTag

        aes = AESGCM(self._dek)
        nonce = base64.b64decode(obj["n"])
        ct = base64.b64decode(obj["ct"])
        try:
            return aes.decrypt(nonce, ct, self._aad(task_id, field)).decode()
        except InvalidTag:
            # InvalidTag has an empty str() — surfaced raw it becomes a blank MCP
            # error, and the rejection is meant to be a *signal*.
            raise ClientCryptoError(
                f"Failed to authenticate the encrypted '{field}' of task {task_id} — "
                "the ciphertext was moved, tampered with, or sealed for a different "
                "slot. Refusing to decrypt."
            ) from None

    def _encrypt_fields(self, d: dict, fields: list[str], task_id: str) -> tuple[dict, list[str]]:
        """Return a copy of d with the given fields encrypted, plus the fields touched."""
        d = dict(d)
        encrypted_fields = []
        for field in fields:
            if field not in d or d[field] is None:
                continue
            if field in ("metadata", "output"):
                # dict fields — serialise first, then store marker as dict (not string)
                # so the server's dict | None type annotation passes pydantic validation
                d[field] = json.loads(self._encrypt_str(json.dumps(d[field]), task_id, field))
            else:
                d[field] = self._encrypt_str(str(d[field]), task_id, field)
            encrypted_fields.append(field)
        return d, encrypted_fields

    def encrypt_args(self, tool_name: str, args: dict) -> dict:
        """Return a copy of args with sensitive fields encrypted.

        create_tasks items get a client-minted task_id (canonical UUID) if they
        don't already carry one — the id must exist at encrypt time for the AAD
        to bind it, so the proxy mints it and the server stores it as the task's
        primary key. update_tasks items bind to the task_id they already carry.
        """
        if tool_name in ENCRYPT_LIST_TOOLS:
            list_key, fields = ENCRYPT_LIST_TOOLS[tool_name]
            items = args.get(list_key)
            if not isinstance(items, list):
                return args
            args = dict(args)
            touched = set()
            new_items = []
            for i, item in enumerate(items):
                if isinstance(item, dict):
                    item = dict(item)
                    if tool_name == "create_tasks" and not item.get("task_id"):
                        item["task_id"] = str(uuid.uuid4())
                    task_id = item.get("task_id")
                    if not task_id or not isinstance(task_id, str):
                        raise ClientCryptoError(
                            f"{list_key}[{i}] has no task_id — cannot bind its "
                            "ciphertext. Include the task_id in every update item."
                        )
                    item, enc = self._encrypt_fields(item, fields, task_id)
                    touched.update(enc)
                new_items.append(item)
            args[list_key] = new_items
            if touched:
                log_event("encrypt", tool=tool_name, fields=sorted(touched))
            return args
        return args

    def _decrypt_task(self, task: dict) -> dict:
        """Decrypt encrypted fields in a task dict. Safe to run on any dict.

        AAD reconstruction: the task's own fields and its history notes were
        sealed under the task's id; a dependency summary's title is the
        *blocker's* ciphertext, sealed under the blocker's id (dep["task_id"]).
        """
        task = dict(task)
        task_id = task.get("task_id")
        for field in TASK_DEC_FIELDS:
            val = task.get(field)
            if _is_enc_marker(val):
                plaintext = self._decrypt_str(val, self._require_id(task_id, field), field)
                if field in ("metadata", "output"):
                    task[field] = json.loads(plaintext)
                else:
                    task[field] = plaintext
        # Decrypt history notes (sealed under the enclosing task's id)
        for event in task.get("history", []):
            note = event.get("note")
            if _is_enc_marker(note):
                event["note"] = self._decrypt_str(note, self._require_id(task_id, "note"), "note")
        # Decrypt dependency (blocker) title summaries under the blocker's own id
        for dep in task.get("dependencies", []):
            title = dep.get("title")
            if _is_enc_marker(title):
                dep["title"] = self._decrypt_str(
                    title, self._require_id(dep.get("task_id"), "dependency title"), "title"
                )
        return task

    @staticmethod
    def _require_id(task_id, what: str):
        if not task_id or not isinstance(task_id, str):
            raise ClientCryptoError(
                f"Response carries an encrypted {what} but no task_id to rebuild "
                "its AAD from — refusing to guess."
            )
        return task_id

    def _decrypt_payload(self, data):
        """Decrypt a decoded tool payload, whatever shape it arrives in."""
        if isinstance(data, list):
            return [self._decrypt_task(t) for t in data]
        if isinstance(data, dict):
            if "task" in data and isinstance(data.get("task"), dict):
                # claim_next_task: {"claimed": true, "task": {...}}
                return {**data, "task": self._decrypt_task(data["task"])}
            if "tasks" in data and isinstance(data.get("tasks"), list):
                # list_tasks: {"tasks": [...], "count": N, "cursor": ...} and
                # get_tasks: {"tasks": [...], "count": N, "not_found": [...]}
                # (a single-id get_tasks task carries its history in that dict).
                return {**data, "tasks": [self._decrypt_task(t) for t in data["tasks"]]}
            # Defensive fallback for a bare task dict (no current tool returns one).
            return self._decrypt_task(data)
        return data

    def decrypt_result(self, tool_name: str, result) -> object:
        """Decrypt a CallToolResult.

        Tools that declare an outputSchema return the payload TWICE — serialized JSON in
        `content` and the same object in `structured_content` (MCP spec: a tool returning
        structured content SHOULD also return the serialized JSON in a TextContent block).
        Both carry ciphertext, so both must be decrypted and left in agreement. Dropping
        structured_content violates the tool's own outputSchema and clients reject the
        result with -32600; passing it through untouched leaks ciphertext to any client
        that prefers the structured channel.

        Field names are the SDK's snake_case ones (`structured_content`, `is_error`);
        they serialize to the camelCase wire spelling via their aliases.
        """
        from mcp.types import CallToolResult, TextContent

        if tool_name not in DECRYPT_TOOLS:
            return result

        # Structured channel (an already-decoded object — no JSON parsing needed).
        structured = result.structured_content
        if isinstance(structured, (dict, list)):
            structured = self._decrypt_payload(structured)

        # Text channel (serialized JSON). Leave non-text/unparseable content untouched.
        content = result.content
        if content and isinstance(content[0], TextContent):
            try:
                data = json.loads(content[0].text)
            except (json.JSONDecodeError, TypeError):
                pass
            else:
                decrypted = self._decrypt_payload(data)
                content = [TextContent(type="text", text=json.dumps(decrypted))]

        log_event("decrypt", tool=tool_name, fields=TASK_DEC_FIELDS)
        return CallToolResult(
            content=content,
            structured_content=structured,
            is_error=result.is_error,
            meta=result.meta,
        )
