# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""A dropped audit write must never read as a successful operation.

The caller stays up (availability is kept); the silence is removed on three
channels: stderr (works when the failure IS the filesystem), an in-process
register, and a durable marker under the log root for another process to
read. The marker write is itself best-effort and never raises.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

MARKER_NAME = "audit-drops.jsonl"
#: Compatibility surface (docs/seam.md): env var naming the log root the
#: marker lands under when ``log_root`` is not passed.
LOG_ROOT_ENV = "WORKSPACE_L0_LOG_ROOT"
#: Prefix of the stderr line; a host may rebind it.
STDERR_PREFIX = "[audit-chain]"

_DROPS: list[dict[str, Any]] = []


def _marker_path(log_root: str | Path | None) -> Path | None:
    root = log_root if log_root is not None else os.environ.get(LOG_ROOT_ENV)
    return Path(root) / MARKER_NAME if root else None


def record(where: str, exc: BaseException, *,
           log_root: str | Path | None = None, **context: Any) -> dict[str, Any]:
    """Report an audit write that did not happen. Never raises."""
    entry: dict[str, Any] = {
        "where": where,
        "error": f"{type(exc).__name__}: {exc}",
        "ts": time.time(),
        **context,
    }
    _DROPS.append(entry)
    try:
        print(f"{STDERR_PREFIX} AUDIT WRITE DROPPED at {where}: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001 — stderr itself is gone
        pass
    path = _marker_path(log_root)
    if path is not None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        except OSError:
            pass  # the disk is usually why we are here; stderr already carried it
    return entry


def drops() -> list[dict[str, Any]]:
    """Drops in this process, oldest first."""
    return list(_DROPS)


def clear() -> None:
    _DROPS.clear()


def durable_drops(log_root: str | Path | None = None) -> list[dict[str, Any]]:
    """Drops by ANY process against this log root. Unreadable or malformed
    lines are reported as entries, never skipped: a corrupt drop record is
    still evidence of a drop."""
    path = _marker_path(log_root)
    if path is None or not path.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [{"where": "audit_drop.durable_drops",
                 "error": f"{type(exc).__name__}: {exc}", "unreadable": True}]
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append({"where": "unknown", "error": "unparseable drop record",
                        "raw": line[:200]})
    return out
