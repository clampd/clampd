"""`clampd` CLI launcher.

    clampd run -- python app.py
    clampd run -- uvicorn main:app

Runs any command with Clampd auto-instrumentation enabled (no code change),
mirroring `ddtrace-run` / `opentelemetry-instrument`: a bootstrap directory is
prepended to PYTHONPATH so its sitecustomize imports `clampd.auto` at
interpreter startup, before the target program runs.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "run":
        argv = argv[1:]
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        sys.exit("usage: clampd run -- <command> [args...]\n  e.g. clampd run -- python app.py")

    bootstrap = str(Path(__file__).parent / "_bootstrap")
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = bootstrap + (os.pathsep + existing if existing else "")

    try:
        completed = subprocess.run(argv, env=env)
    except FileNotFoundError:
        sys.exit(f"clampd run: command not found: {argv[0]}")
    sys.exit(completed.returncode)


if __name__ == "__main__":
    main()
