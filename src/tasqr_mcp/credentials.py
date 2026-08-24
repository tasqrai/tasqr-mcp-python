import configparser
import contextlib
import os
import stat
from pathlib import Path


def _credentials_path() -> Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA") or str(Path.home())
        return Path(appdata) / "tasqr" / "credentials"
    return Path.home() / ".config" / "tasqr" / "credentials"


def _profile() -> str:
    return os.environ.get("TASQR_PROFILE", "default")


def read_config() -> dict[str, str]:
    """Return all key=value pairs for the current profile."""
    path = _credentials_path()
    if not path.exists():
        return {}
    config = configparser.ConfigParser()
    config.read(path)
    profile = _profile()
    return dict(config[profile]) if profile in config else {}


def read_api_key() -> str | None:
    path = _credentials_path()
    if not path.exists():
        return None
    config = configparser.ConfigParser()
    config.read(path)
    return config.get(_profile(), "api_key", fallback=None) or None


def _write_config(path: Path, config: "configparser.ConfigParser") -> None:
    """Persist the credentials file, restricted to the owner.

    Creates the file 0600 *atomically* rather than open()+chmod, which would leave the
    api_key world-readable in the window between creation and chmod (and permanently so
    if interrupted). The trailing chmod also tightens a pre-existing looser file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        with open(path, "w") as f:
            config.write(f)
        return
    with contextlib.suppress(OSError):
        os.chmod(path.parent, stat.S_IRWXU)  # 0700 — don't expose credential filenames
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        config.write(f)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def write_api_key(api_key: str) -> None:
    path = _credentials_path()
    config = configparser.ConfigParser()
    if path.exists():
        config.read(path)
    profile = _profile()
    if profile not in config:
        config[profile] = {}
    config[profile]["api_key"] = api_key
    _write_config(path, config)


def write_config_value(key: str, value: str) -> None:
    """Write a single key=value to the current profile in the credentials file."""
    path = _credentials_path()
    config = configparser.ConfigParser()
    if path.exists():
        config.read(path)
    profile = _profile()
    if profile not in config:
        config[profile] = {}
    config[profile][key] = value
    _write_config(path, config)


def _delete_config_value(key: str) -> None:
    """Remove a key from the current profile (used for stale wrapped_dek cleanup)."""
    path = _credentials_path()
    if not path.exists():
        return
    config = configparser.ConfigParser()
    config.read(path)
    profile = _profile()
    if profile in config and key in config[profile]:
        del config[profile][key]
        _write_config(path, config)


class ConfigurationError(Exception):
    pass


class ManagedOrgError(ConfigurationError):
    """The org is server-managed, so client-side encryption must not run.

    Encrypting anyway would double-wrap: the server would encrypt our ciphertext again
    with the org DEK, leaving data readable only by a key it has no record of.
    """


async def fetch_or_generate_dek(cfg: dict) -> tuple[bytes, str, str]:
    """Fetch or generate the DEK. Returns (plaintext_dek_bytes, source, org_id).

    source is "config" if read from local credentials, "api" if fetched from Tasqr API.
    org_id comes from the server (/org/dek) and is bound verbatim into every
    ciphertext's AAD, so it must be the server's exact string — never derived locally.

    The server is authoritative — GET /org/dek is consulted before any local state:
       - 409: org is server-managed → raise ManagedOrgError. Never encrypt.
       - 200: org is client_byok → use the cached wrapped_dek if present, else the
              server's; KMS Decrypt → return.
       - 404: BYOK-eligible but unenrolled → GenerateDataKey, PUT /org/dek
              (409 → re-fetch the winner), write to config, Decrypt → return ("api").

    Stale key: if KMS Decrypt raises (InvalidCiphertextException etc), delete wrapped_dek
    from config and fall back to the server's blob.
    """
    import base64

    import boto3
    import httpx2
    from botocore.exceptions import ClientError as BotoClientError

    api_key = cfg.get("api_key", "")
    kms_key_id = cfg.get("kms_key_id", "")
    aws_profile = cfg.get("aws_profile", "default")
    api_url = cfg.get("api_url", "https://api.tasqr.ai")

    # The KMS client is built lazily, *after* the org-state probe below. Refusing to
    # encrypt for a managed org must not depend on AWS being configured — a bad
    # aws_profile must not mask the refusal — so don't hoist this.
    _kms = []

    def _kms_client():
        if not _kms:
            _kms.append(boto3.session.Session(profile_name=aws_profile).client("kms"))
        return _kms[0]

    def _kms_decrypt(wrapped_b64: str) -> bytes:
        from .logging import log_event

        blob = base64.b64decode(wrapped_b64)
        resp = _kms_client().decrypt(CiphertextBlob=blob, KeyId=kms_key_id)
        log_event("kms_decrypt", profile=aws_profile)
        return resp["Plaintext"]

    def _org_id_or_raise(body: dict) -> str:
        org_id = body.get("org_id")
        if not org_id:
            raise ConfigurationError(
                "The server's /org/dek response carried no org_id — the proxy needs it "
                "to bind ciphertext AAD. The Tasqr server is older than this client."
            )
        return org_id

    async def _fetch_dek_from_api() -> tuple[str, str | None, str | None]:
        """Ask the server what this org is. Returns (key_provider, wrapped_dek, org_id).

        200 -> ("client_byok", <wrapped>, org_id)  encrypt with it
        409 -> raises ManagedOrgError              server-managed; must not client-encrypt
        404 -> ("unenrolled", None, None)          BYOK-eligible, no DEK yet
        """
        async with httpx2.AsyncClient() as client:
            r = await client.get(
                f"{api_url}/org/dek",
                headers={"X-Api-Key": api_key},
                timeout=10,
            )
            if r.status_code == 409:
                raise ManagedOrgError(
                    "This org uses server-managed encryption, so the proxy must not "
                    "client-encrypt (doing so would double-wrap your data and make it "
                    "unreadable to everything except this machine).\n"
                    f"Remove kms_key_id and wrapped_dek from profile [{_profile()}] in "
                    f"{_credentials_path()}, or enroll the org in client-side BYOK."
                )
            if r.status_code == 404:
                return "unenrolled", None, None
            r.raise_for_status()
            body = r.json()
            return "client_byok", body["wrapped_dek"], _org_id_or_raise(body)

    async def _put_dek_to_api(wrapped_b64: str) -> str | None:
        """PUT wrapped DEK. Returns org_id on 201, None on 409 (already set)."""
        async with httpx2.AsyncClient() as client:
            r = await client.put(
                f"{api_url}/org/dek",
                headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
                json={"wrapped_dek": wrapped_b64, "kms_key_id": kms_key_id},
                timeout=10,
            )
            if r.status_code == 409:
                return None
            r.raise_for_status()
            return _org_id_or_raise(r.json())

    # Step 1: The server is authoritative about whether this org may be client-encrypted.
    # This MUST happen before any use of a locally cached wrapped_dek — a managed org must
    # never be client-encrypted, and only the server knows. Raises ManagedOrgError on 409.
    key_provider, wrapped_b64, org_id = await _fetch_dek_from_api()

    # Step 2: BYOK confirmed — now the local cache is safe to use, and saves a KMS round trip.
    if key_provider == "client_byok":
        cached = read_config().get("wrapped_dek")
        if cached:
            try:
                return _kms_decrypt(cached), "config", org_id
            except BotoClientError:
                # Stale — drop it and fall back to the server's blob.
                _delete_config_value("wrapped_dek")

    if wrapped_b64 is None:
        # Step 3: First-ever session — generate
        resp = _kms_client().generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
        plaintext_dek = resp["Plaintext"]
        wrapped_b64 = base64.b64encode(resp["CiphertextBlob"]).decode()

        org_id = await _put_dek_to_api(wrapped_b64)
        if org_id is None:
            # Lost race — fetch the winner's blob
            _, wrapped_b64, org_id = await _fetch_dek_from_api()
            if wrapped_b64 is None:
                raise ConfigurationError(
                    "Failed to set up encryption key. Check kms_key_id in config."
                )
            dek = _kms_decrypt(wrapped_b64)
        else:
            dek = plaintext_dek
        write_config_value("wrapped_dek", wrapped_b64)
        return dek, "api", org_id

    # Fetched from API — write to config and decrypt
    try:
        dek = _kms_decrypt(wrapped_b64)
    except BotoClientError as e:
        raise ConfigurationError(
            f"KMS Decrypt failed after API fetch. Check aws_profile and kms_key_id. Error: {e}"
        ) from e
    write_config_value("wrapped_dek", wrapped_b64)
    return dek, "api", org_id
