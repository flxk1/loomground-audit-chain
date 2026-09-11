# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Witness escape — an out-of-territory touch, on the record.

A witness (a run, an invocation, an agent's declared working set) is scoped
to a folder. When its own trace shows it touched a path OUTSIDE that folder,
:func:`record_witness_escape` appends exactly one event to the folder's
signed chain through ``MutationLog.append`` (never hand-rolled signing),
with ``extra["kind"] == WITNESS_ESCAPE_KIND``, verifies the chain, and then
hands the actor to the host's ``quarantine`` port when one is wired.

Every failure raises a typed error; nothing here silently no-ops:

- a malformed call raises BEFORE anything is written;
- a failed append, or a chain that no longer verifies afterward, raises
  BEFORE the quarantine port is called — an unverifiable record is never
  grounds to suspend anyone;
- a quarantine port that fails AFTER a clean, verified append raises an
  error naming the event's ``audit_id``: the record landed, the actor is
  not yet capped.

This module exposes no clear/release path; only the host does.
"""

from __future__ import annotations

import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .mutation_log import ChainVerificationResult, LogEvent, MutationLog

__all__ = [
    "WITNESS_ESCAPE_KIND",
    "WitnessEscapeError",
    "WitnessEscapeInputError",
    "WitnessEscapeRecordError",
    "WitnessEscapeVerificationError",
    "WitnessEscapeQuarantineError",
    "record_witness_escape",
    "recent_witness_escapes",
    "main",
    "quarantine",
]

#: ``extra["kind"]`` of a witness-escape event; ``event`` stays ``"system"``.
WITNESS_ESCAPE_KIND = "witness-escape"

#: Actor attributed to the automatic quarantine: a system response, never the
#: suspended actor, never a human's later explicit clear.
_QUARANTINE_ACTOR = "system"

#: Host port. Called as
#: ``quarantine(folder_context, actor, "suspended", reason=..., actor="system", log_root=...)``.
#: ``None`` (default) records the escape and applies no quarantine.
quarantine: Optional[Callable[..., Any]] = None


class WitnessEscapeError(Exception):
    """Base of every typed failure here."""


class WitnessEscapeInputError(WitnessEscapeError, ValueError):
    """Malformed call (no actor, no paths); nothing written."""


class WitnessEscapeRecordError(WitnessEscapeError):
    """The append itself failed; nothing quarantined."""


class WitnessEscapeVerificationError(WitnessEscapeError):
    """Appended, but the chain no longer verifies; nothing quarantined."""


class WitnessEscapeQuarantineError(WitnessEscapeError):
    """Appended and verified, but the quarantine port raised. The event is
    permanent (its ``audit_id`` is in the message); the actor is NOT capped."""


def _relpath(path: Any, folder_context: str | Path) -> str:
    """Relative form of an escaped path when both are absolute (leading
    ``../`` shows how far outside); else the string stripped of leading
    separators. Never raises."""
    p = str(path)
    if not p:
        return p
    try:
        base = Path(folder_context).expanduser()
        pp = Path(p).expanduser()
        if pp.is_absolute() and base.is_absolute():
            import os
            return os.path.relpath(pp, base)
    except Exception:
        pass
    return p.lstrip("/\\")


def record_witness_escape(
    folder_context: str | Path,
    unauthorised_paths: Iterable[Any],
    actor: str,
    *,
    run_since: Optional[float] = None,
    log_root: Optional[str | Path] = None,
) -> dict[str, Any]:
    """Append ONE witness-escape event, verify the chain, then quarantine.

    Returns ``{"audit_id": str, "event": dict}`` — the appended event
    (``prev_hash``/``signature``/``host_id`` filled) as a plain dict. The
    event carries ``extra = {"kind", "actor", "paths", "run_since", "count"}``.
    """
    actor = (actor or "").strip()
    if not actor:
        raise WitnessEscapeInputError("actor is required")
    paths = [_relpath(p, folder_context) for p in (unauthorised_paths or []) if str(p).strip()]
    if not paths:
        raise WitnessEscapeInputError("unauthorised_paths must be non-empty")

    extra = {
        "kind": WITNESS_ESCAPE_KIND,
        "actor": actor,
        "paths": paths,
        "run_since": run_since,
        "count": len(paths),
    }
    event = LogEvent(
        event="system",
        folder_path=str(folder_context),
        pair_id=WITNESS_ESCAPE_KIND,
        channel="system",
        actor=actor,
        extra=extra,
    )

    log = MutationLog(folder_context, log_root=log_root)
    try:
        audit_id = log.append(event)
    except WitnessEscapeError:
        raise
    except Exception as exc:
        raise WitnessEscapeRecordError(
            f"failed to record witness escape for actor {actor!r} in "
            f"{folder_context!r}: {type(exc).__name__}: {exc}"
        ) from exc

    verification: ChainVerificationResult = log.verify_chain()
    if not verification.ok:
        raise WitnessEscapeVerificationError(
            "witness-escape event was appended but the chain no longer "
            f"verifies afterward (audit_id={audit_id}): "
            f"broken_links={len(verification.broken_links)} "
            f"signature_failures={len(verification.signature_failures)} "
            f"malformed_lines={verification.malformed_lines}"
        )

    port = globals()["quarantine"]
    if port is not None:
        try:
            port(
                folder_context,
                actor,
                "suspended",
                reason=f"witness-escape audit_id={audit_id}",
                actor=_QUARANTINE_ACTOR,
                log_root=log_root,
            )
        except Exception as exc:  # noqa: BLE001 — surface, never swallow
            raise WitnessEscapeQuarantineError(
                f"witness-escape event {audit_id} for actor {actor!r} was "
                "recorded and the chain verifies, but quarantining the actor "
                f"failed: {type(exc).__name__}: {exc}. The event is permanent on "
                "the chain; the actor is NOT yet capped."
            ) from exc

    return {"audit_id": audit_id, "event": asdict(event)}


def recent_witness_escapes(
    folder_context: str | Path,
    actor: str,
    *,
    since: Optional[float] = None,
    log_root: Optional[str | Path] = None,
) -> list[dict[str, Any]]:
    """Read-only: witness-escape events for ``actor`` in this folder at or
    after ``since`` (unix seconds; ``None`` = all). Each dict is the event's
    ``extra`` plus ``ts`` and ``audit_id``. ``[]`` is an answer, not a failure."""
    log = MutationLog(folder_context, log_root=log_root)
    hits: list[dict[str, Any]] = []
    for evt in log.replay():
        if evt.actor != actor:
            continue
        extra = evt.extra or {}
        if extra.get("kind") != WITNESS_ESCAPE_KIND:
            continue
        if since is not None and evt.ts < since:
            continue
        hits.append({**extra, "ts": evt.ts, "audit_id": evt.audit_id})
    return hits


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m loomground_audit_chain.witness_escape",
        description="Record a witness-escape event on a folder's signed chain "
                    "and hand the actor to the quarantine port.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record", help="record a witness-escape event")
    rec.add_argument("--folder", required=True, help="folder (folder_context)")
    rec.add_argument("--actor", required=True, help="the actor whose run escaped")
    rec.add_argument("--paths", required=True,
                     help="comma-separated list of unauthorised paths")
    rec.add_argument("--since", type=float, default=None, dest="run_since",
                     help="unix timestamp the run started (optional)")
    rec.add_argument("--log-root", default=None, dest="log_root",
                     help="override the log root (optional)")

    args = parser.parse_args(argv)

    if args.command == "record":
        paths = [p.strip() for p in args.paths.split(",") if p.strip()]
        try:
            result = record_witness_escape(
                args.folder, paths, args.actor,
                run_since=args.run_since, log_root=args.log_root,
            )
        except WitnessEscapeError as exc:
            print(f"witness-escape record failed: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            print(f"witness-escape record failed: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            return 1
        print(result["audit_id"])
        return 0

    parser.error(f"unknown command {args.command!r}")
    return 2  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
