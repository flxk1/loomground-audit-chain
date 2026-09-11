# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""HOME, USERPROFILE and WORKSPACE_KEY_DIR are redirected to a per-session
directory BEFORE the package is first imported (``signing.DEFAULT_KEY_DIR``
and ``paths.LOG_ROOT_DEFAULT`` are evaluated at import), so nothing in this
suite touches the real ``~/.workspace``. Do not import the package here."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_HOME: Path | None = None


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global _HOME
    factory = getattr(config, "_tmp_path_factory", None)
    if factory is not None:
        home = factory.mktemp("home")
    else:  # pragma: no cover - older pytest without the factory on config
        home = Path(tempfile.mkdtemp(prefix="audit-chain-home-"))
    _HOME = Path(home)
    os.environ["HOME"] = str(_HOME)
    os.environ["USERPROFILE"] = str(_HOME)
    os.environ["WORKSPACE_KEY_DIR"] = str(_HOME / ".workspace" / "keys")


@pytest.fixture(autouse=True)
def _isolated_chain_env(tmp_path, monkeypatch):
    """Each test: its own key dir, unregistered folders allowed, default
    chain profile (pinning off, advisory divergence)."""
    monkeypatch.setenv("WORKSPACE_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("WORKSPACES_ALLOW_UNREGISTERED", "1")
    for var in ("WORKSPACE_KEY_PINNING", "WORKSPACE_STRICT_KEY_PINNING",
                "WORKSPACE_STRICT_HOST_DIVERGENCE", "WORKSPACE_KEY_PASSPHRASE",
                "WORKSPACE_HOST_ID", "WORKSPACE_KEY_PIN_DIR", "RVND_LOG_ROOT",
                "WORKSPACE_L0_LOG_ROOT"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def session_home() -> Path:
    assert _HOME is not None
    return _HOME
