# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""A failed audit write is reported on stderr, in process, and durably."""
from __future__ import annotations

import json

import pytest

from loomground_audit_chain import audit_drop


@pytest.fixture(autouse=True)
def _clean():
    audit_drop.clear()
    yield
    audit_drop.clear()


def test_record_reports_to_stderr_process_register_and_marker(tmp_path, capsys):
    audit_drop.record("unit.test", OSError("disk gone"), log_root=tmp_path, detail="x")
    assert [d["where"] for d in audit_drop.drops()] == ["unit.test"]
    err = capsys.readouterr().err
    assert "AUDIT WRITE DROPPED at unit.test" in err
    assert err.startswith(audit_drop.STDERR_PREFIX)
    marker = tmp_path / audit_drop.MARKER_NAME
    assert marker.exists()
    row = json.loads(marker.read_text().splitlines()[0])
    assert row["where"] == "unit.test" and "disk gone" in row["error"] and row["detail"] == "x"


def test_record_never_raises_even_when_the_marker_cannot_be_written(tmp_path):
    unwritable = tmp_path / "file-not-a-dir"
    unwritable.write_text("x")
    audit_drop.record("unit.test", OSError("x"), log_root=unwritable / "sub")
    assert audit_drop.drops()


def test_durable_drops_reports_corrupt_records_rather_than_skipping(tmp_path):
    (tmp_path / audit_drop.MARKER_NAME).write_text('{"where":"a"}\nnot json\n')
    rows = audit_drop.durable_drops(tmp_path)
    assert len(rows) == 2
    assert rows[1]["error"] == "unparseable drop record"


def test_marker_root_falls_back_to_the_env_var(tmp_path, monkeypatch):
    assert audit_drop.LOG_ROOT_ENV == "WORKSPACE_L0_LOG_ROOT"
    assert audit_drop.durable_drops() == []
    monkeypatch.setenv(audit_drop.LOG_ROOT_ENV, str(tmp_path))
    audit_drop.record("env.test", OSError("x"))
    assert [d["where"] for d in audit_drop.durable_drops()] == ["env.test"]
