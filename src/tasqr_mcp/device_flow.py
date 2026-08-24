import os
import subprocess
import sys
import time
import webbrowser

import httpx2

from .credentials import read_config

# Public client ID for the Tasqr GitHub OAuth App.
# Find it at: github.com → Settings → Developer settings → OAuth Apps → Tasqr
# Device Flow must be enabled on the app.
GITHUB_CLIENT_ID = os.environ.get("TASQR_GITHUB_CLIENT_ID", "Ov23liHc2GB3yXBniiy1")
_DEFAULT_AUTH_URL = "https://auth.tasqr.ai"


def _auth_url() -> str:
    return os.environ.get("TASQR_AUTH_URL") or read_config().get("auth_url") or _DEFAULT_AUTH_URL


def _copy_to_clipboard(text: str) -> bool:
    try:
        if sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        elif sys.platform == "win32":
            subprocess.run(["clip"], input=text.encode(), check=True, shell=True)
        else:
            subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True)
        return True
    except Exception:
        return False


def run_device_flow() -> str:
    """Run GitHub Device Flow, exchange the token for a Tasqr API key, and return it."""
    print("\nNo Tasqr credentials found. Starting signup...", file=sys.stderr)

    # Step 1: request device + user codes from GitHub
    resp = httpx2.post(
        "https://github.com/login/device/code",
        data={"client_id": GITHUB_CLIENT_ID, "scope": "user:email,read:org"},
        headers={"Accept": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    device_code = data["device_code"]
    user_code = data["user_code"]
    verification_uri = data["verification_uri"]
    interval = data.get("interval", 5)
    expires_in = data.get("expires_in", 900)

    # Step 2: open browser and copy code to clipboard (URL pre-fill doesn't survive
    # GitHub's account-picker redirect added Jan 2024)
    webbrowser.open(verification_uri)
    copied = _copy_to_clipboard(user_code)
    print("\n  Opening browser for GitHub authorization...", file=sys.stderr)
    if copied:
        print(f"  Code copied to clipboard — paste it in the browser: {user_code}", file=sys.stderr)
    else:
        print(f"  Enter code: {user_code}", file=sys.stderr)
    print("Waiting for authorization...", file=sys.stderr)

    # Step 3: poll GitHub until the user authorizes or the code expires
    deadline = time.monotonic() + expires_in
    github_token: str | None = None
    while time.monotonic() < deadline:
        time.sleep(interval)
        poll = httpx2.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            headers={"Accept": "application/json"},
            timeout=15,
        ).json()
        error = poll.get("error")
        if not error:
            github_token = poll.get("access_token")
            break
        elif error == "authorization_pending":
            continue
        elif error == "slow_down":
            interval += 5
        elif error == "expired_token":
            print("\nCode expired. Run tasqr-mcp again.", file=sys.stderr)
            sys.exit(1)
        elif error == "access_denied":
            print("\nAuthorization denied.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"\nGitHub error: {error}", file=sys.stderr)
            sys.exit(1)

    if not github_token:
        print("\nTimed out waiting for authorization.", file=sys.stderr)
        sys.exit(1)

    # Step 4: exchange the GitHub token for a Tasqr API key
    return _exchange(github_token)


def _exchange(github_token: str, choice: str | None = None) -> str:
    payload: dict = {"github_token": github_token}
    if choice:
        payload["choice"] = choice

    try:
        resp = httpx2.post(f"{_auth_url()}/device", json=payload, timeout=15)
    except httpx2.RequestError as exc:
        print(f"\nCould not reach Tasqr: {exc}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    if resp.status_code == 429:
        print(f"\n{data.get('error', 'Capacity limit reached.')}", file=sys.stderr)
        sys.exit(1)
    if not resp.is_success:
        print(f"\nTasqr error: {data.get('error', resp.text)}", file=sys.stderr)
        sys.exit(1)

    if "choose" in data:
        return _prompt_choice(github_token, data["choose"], data.get("email", ""))

    api_key = data.get("api_key")
    if not api_key:
        print(f"\nUnexpected response from Tasqr: {data}", file=sys.stderr)
        sys.exit(1)

    action = "Key reissued" if data.get("reissued") else "Signup complete"
    print(f"\n{action}! Signed in as {data.get('email', '')}.\n", file=sys.stderr)
    return api_key


def _prompt_choice(github_token: str, options: list[dict], email: str) -> str:
    all_options = options + [
        {"value": "personal", "label": "Personal workspace", "action": "create"}
    ]
    print(f"\nSigned in as {email}. Choose a workspace:\n", file=sys.stderr)
    for i, opt in enumerate(all_options, 1):
        action = "Join" if opt.get("action") == "join" else "Create"
        print(f"  {i}. {opt['label']}  ({action})", file=sys.stderr)
    print(file=sys.stderr)

    while True:
        try:
            raw = input("Enter number: ").strip()
            n = int(raw)
            if 1 <= n <= len(all_options):
                return _exchange(github_token, choice=all_options[n - 1]["value"])
        except ValueError:
            pass
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.", file=sys.stderr)
            sys.exit(1)
        print(f"  Please enter a number between 1 and {len(all_options)}.", file=sys.stderr)
