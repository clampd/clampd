"""Zero-code auto-instrumentation for Clampd.

Activate either with one line at the top of your entrypoint::

    import clampd.auto   # noqa: F401

…or with the launcher (no code change at all)::

    clampd run -- python app.py
    clampd run -- uvicorn main:app

It does two things:
  1. Auto-initializes Clampd from ``CLAMPD_DSN`` (enrolls; no explicit init()).
  2. Patches OpenAI / Anthropic clients at import time so every client is
     guarded — no ``clampd.openai(...)`` wrapping in your code.

Failures are logged, never fatal: auto-instrumentation must not take down the
host application.
"""

from __future__ import annotations

import importlib.abc
import importlib.util
import logging
import os
import sys
from types import ModuleType

import clampd

logger = logging.getLogger("clampd.auto")


def _wrap_class(module: ModuleType, class_name: str, wrapper) -> None:
    cls = getattr(module, class_name, None)
    if cls is None or getattr(cls, "_clampd_patched", False):
        return
    orig_init = cls.__init__

    def patched_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        orig_init(self, *args, **kwargs)
        try:
            wrapper(self)
        except Exception as e:  # noqa: BLE001 - never break the host app
            logger.warning("clampd auto-instrument(%s) failed: %s", class_name, e)

    cls.__init__ = patched_init
    cls._clampd_patched = True


def _patch_openai(module: ModuleType) -> None:
    _wrap_class(module, "OpenAI", clampd.openai)
    _wrap_class(module, "AsyncOpenAI", clampd.openai)


def _patch_anthropic(module: ModuleType) -> None:
    _wrap_class(module, "Anthropic", clampd.anthropic)
    _wrap_class(module, "AsyncAnthropic", clampd.anthropic)


_TARGETS = {"openai": _patch_openai, "anthropic": _patch_anthropic}


class _PatchingLoader(importlib.abc.Loader):
    """Wraps a real loader, patching the module right after it executes."""

    def __init__(self, name: str, inner: importlib.abc.Loader) -> None:
        self.name = name
        self.inner = inner

    def create_module(self, spec):  # type: ignore[no-untyped-def]
        return self.inner.create_module(spec)

    def exec_module(self, module: ModuleType) -> None:
        self.inner.exec_module(module)
        try:
            _TARGETS[self.name](module)
        except Exception as e:  # noqa: BLE001
            logger.warning("clampd auto-instrument(%s) failed: %s", self.name, e)


class _Finder(importlib.abc.MetaPathFinder):
    """Intercepts imports of target libraries and wraps their loader."""

    _in_progress: set[str] = set()

    def find_spec(self, name, path, target=None):  # type: ignore[no-untyped-def]
        if name not in _TARGETS or name in self._in_progress:
            return None
        # Re-enter to find the *real* spec via the other finders.
        self._in_progress.add(name)
        try:
            spec = importlib.util.find_spec(name)
        except Exception:  # noqa: BLE001
            return None
        finally:
            self._in_progress.discard(name)
        if spec is None or spec.loader is None:
            return None
        spec.loader = _PatchingLoader(name, spec.loader)
        return spec


def install() -> None:
    """Idempotently auto-init Clampd and install the import hooks."""
    # 1. Auto-init from CLAMPD_DSN (enrolls). Never fatal.
    if getattr(clampd, "_default_client", None) is None and os.environ.get("CLAMPD_DSN"):
        try:
            clampd.init()
        except Exception as e:  # noqa: BLE001
            logger.warning("clampd auto-init failed (calls will error until init): %s", e)

    # 2. Install the import hook (once).
    if not any(isinstance(f, _Finder) for f in sys.meta_path):
        sys.meta_path.insert(0, _Finder())

    # 3. Patch libraries already imported before clampd.auto.
    for name, patch in _TARGETS.items():
        mod = sys.modules.get(name)
        if mod is not None:
            try:
                patch(mod)
            except Exception as e:  # noqa: BLE001
                logger.warning("clampd auto-instrument(%s) failed: %s", name, e)


install()
