"""Bootstrap auto-imported by the interpreter when this directory is on
PYTHONPATH (injected by `clampd run`). Enables zero-code instrumentation for
the launched program. Never fatal."""

try:
    import clampd.auto  # noqa: F401
except Exception:
    pass
