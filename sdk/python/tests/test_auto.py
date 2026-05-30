"""Tests for clampd.auto (zero-code auto-instrumentation)."""

from __future__ import annotations

import sys
import types

import clampd
import clampd.auto as auto


def test_patch_openai_wraps_constructor(monkeypatch):
    wrapped = []
    monkeypatch.setattr(clampd, "openai", lambda c, **k: (wrapped.append(c), c)[1])

    fake = types.ModuleType("openai")

    class OpenAI:
        def __init__(self, **kw):
            self.inited = True

    fake.OpenAI = OpenAI
    auto._patch_openai(fake)

    inst = fake.OpenAI()
    assert inst.inited                 # original __init__ still runs
    assert wrapped == [inst]           # clampd.openai auto-applied to the instance


def test_patch_is_idempotent(monkeypatch):
    monkeypatch.setattr(clampd, "openai", lambda c, **k: c)
    fake = types.ModuleType("openai")

    class OpenAI:
        def __init__(self):
            pass

    fake.OpenAI = OpenAI
    auto._patch_openai(fake)
    first = fake.OpenAI.__init__
    auto._patch_openai(fake)           # second call must not re-wrap
    assert fake.OpenAI.__init__ is first
    assert fake.OpenAI._clampd_patched is True


def test_install_idempotent_and_auto_inits():
    # conftest sets CLAMPD_DSN + mocks enroll, so install() should auto-init.
    clampd._reset()
    auto.install()
    auto.install()  # idempotent
    finders = [f for f in sys.meta_path if type(f).__name__ == "_Finder"]
    assert len(finders) == 1, "import hook installed exactly once"
    assert clampd._default_client is not None, "auto-init enrolled a default client"
