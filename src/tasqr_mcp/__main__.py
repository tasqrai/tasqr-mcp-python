import sys

from .credentials import ConfigurationError, read_api_key, write_api_key
from .device_flow import run_device_flow
from .proxy import run


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        from . import __version__

        print(f"tasqr-mcp {__version__}")
        return

    api_key = read_api_key()
    if not api_key:
        if not sys.stdin.isatty():
            print(
                "tasqr-mcp: No credentials found.\n"
                "Run `uvx tasqr-mcp` in your terminal to sign up, then restart your MCP client.",
                file=sys.stderr,
            )
            sys.exit(1)
        api_key = run_device_flow()
        write_api_key(api_key)

    try:
        run(api_key)
    except ConfigurationError as exc:
        # Misconfiguration is the user's to fix — show the message, not a traceback.
        print(f"tasqr-mcp: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
