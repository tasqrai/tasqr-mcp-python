"""Every runtime dependency must carry an upper bound.

`uvx --from git+…` (how most people run this proxy) ignores uv.lock and resolves
dependencies fresh on every launch. So an uncapped floor like `mcp>=1.1` ships the
next major release to every user the day it lands: that is precisely how mcp 2.0
broke every launch — it renamed `streamablehttp_client`, and the traceback was the
first anyone heard of it.

This test keeps the caps there, since a new dependency is otherwise added uncapped
out of habit. Dev-only deps are exempt: they never reach a user's launch.
"""

import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_every_runtime_dependency_has_an_upper_bound():
    specs = tomllib.loads(PYPROJECT.read_text())["project"]["dependencies"]
    uncapped = [spec for spec in specs if "<" not in spec.split(";")[0]]
    assert not uncapped, (
        "These requirements would let the next major version install itself on every "
        f"`uvx` launch — cap them at the next major: {uncapped}"
    )
