# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Disk-full mid-append and malformed lines mid-chain."""
from __future__ import annotations

import errno
from pathlib import Path

import pytest

from loomground_audit_chain.mutation_log import DiskFullError, LogEvent, MutationLog


def test_disk_full_during_append_raises_DiskFullError_and_truncates_log(tmp_path, monkeypatch):
    folder = tmp_path / "workspace"
    folder.mkdir()
    log = MutationLog(folder, log_root=tmp_path / "log_root")
    log.append(LogEvent(event="ingest", folder_path=str(folder), pair_id="pair-1"))
    baseline_size = log.log_file.stat().st_size
    assert baseline_size > 0

    real_open = Path.open

    class _FailingHandle:
        def __init__(self, inner):
            self._inner = inner
            self._tripped = False

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def write(self, data):
            if not self._tripped:
                self._tripped = True
                self._inner.write(data[: max(1, len(data) // 2)])
                self._inner.flush()
                raise OSError(errno.ENOSPC, "No space left on device")
            return self._inner.write(data)

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *exc):
            return self._inner.__exit__(*exc)

    def fake_open(self, *a, **kw):
        h = real_open(self, *a, **kw)
        if str(self).endswith("events.jsonl") and "a" in (a[0] if a else kw.get("mode", "")):
            return _FailingHandle(h)
        return h

    monkeypatch.setattr(Path, "open", fake_open)
    with pytest.raises(DiskFullError) as exc_info:
        log.append(LogEvent(event="ingest", folder_path=str(folder), pair_id="pair-2"))
    assert exc_info.value.errno == errno.ENOSPC
    assert log.log_file.stat().st_size == baseline_size

    monkeypatch.setattr(Path, "open", real_open)
    result = log.verify_chain()
    assert result.ok, result
    assert result.total_events == 1


def test_malformed_unicode_line_does_not_block_subsequent_append(tmp_path):
    folder = tmp_path / "workspace"
    folder.mkdir()
    log = MutationLog(folder, log_root=tmp_path / "log_root")
    log.append(LogEvent(event="ingest", folder_path=str(folder), pair_id="pair-1"))
    log.append(LogEvent(event="ingest", folder_path=str(folder), pair_id="pair-2"))
    with open(log.log_file, "ab") as fh:
        fh.write(b"\xff\xfe not utf-8 \x80\x81\n")
    assert log.append(LogEvent(event="ingest", folder_path=str(folder), pair_id="pair-3"))
    result = log.verify_chain()
    assert result.malformed_lines >= 1
    assert result.total_events == 3
    assert [e.pair_id for e in log.replay()] == ["pair-1", "pair-2", "pair-3"]


def test_malformed_json_line_counted_as_malformed_not_broken_link(tmp_path):
    folder = tmp_path / "workspace"
    folder.mkdir()
    log = MutationLog(folder, log_root=tmp_path / "log_root")
    log.append(LogEvent(event="ingest", folder_path=str(folder), pair_id="p1"))
    with open(log.log_file, "a", encoding="utf-8") as fh:
        fh.write("{not valid json\n")
    log.append(LogEvent(event="ingest", folder_path=str(folder), pair_id="p2"))
    result = log.verify_chain()
    assert result.malformed_lines >= 1
    assert result.total_events == 2
