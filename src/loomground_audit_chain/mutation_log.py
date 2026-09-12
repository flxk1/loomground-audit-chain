# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Per-folder append-only, hash-chained, Ed25519-signed JSONL log.

One log directory per folder under a log root; the directory is keyed by
``loomground_workspace.identity.folder_hash``. Each line is one event::

    {"ts": ..., "event": ..., "channel": ..., "folder_path": ..., "pair_id": ...,
     "problem_id": ..., "source_hash": ..., "lifecycle_state": ..., "actor": ...,
     "audit_id": ..., "extra": {...}, "prev_hash": ..., "signature": ..., "host_id": ...}

Invariants: files are append-only (``purge`` is the one authorised rewrite and
leaves a signed tombstone); malformed lines are skipped on replay and counted
on verification; ``audit_id`` is unique per event; ``prev_hash`` links each
event to the canonical hash of its predecessor (``GENESIS_HASH`` first);
``signature`` binds content and chain position; a signed head anchor beside
the log makes tail truncation visible.

Host ports (module globals a host may rebind, see docs/seam.md):
``purged_pair_ref``, ``content_signature``, ``register_workspace``.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from loomground_workspace.folder_context import resolve_folder_context
from loomground_workspace.identity import (  # noqa: F401  (re-exported)
    _filesystem_is_case_insensitive,
    folder_hash,
    legacy_folder_hash,
)
from loomground_workspace.paths import LOG_ROOT_DEFAULT  # noqa: F401  (re-exported)
from loomground_workspace.workspace_registry import add_known_workspace as _add_known_workspace

#: Public surface (docs/seam.md): env var redirecting every log root.
#: Precedence everywhere: explicit ``log_root=`` > this variable > ``LOG_ROOT_DEFAULT``.
LOG_ROOT_ENV = "LOOMGROUND_LOG_ROOT"
#: Opt-in: NEW chains record their signing identity in a genesis
#: ``key_registration`` event. Enforcement of an already-registered chain is
#: NOT gated on this — unsetting it cannot downgrade a pinned chain.
KEY_PINNING_ENV = "WORKSPACE_KEY_PINNING"
#: Opt-in: an unregistered chain fails verification.
STRICT_KEY_PINNING_ENV = "WORKSPACE_STRICT_KEY_PINNING"
#: Relocate the TOFU pin file off the log tree (a read-only mount) so a
#: filesystem adversary who rewrites the log cannot also rewrite the pin.
KEY_PIN_DIR_ENV = "WORKSPACE_KEY_PIN_DIR"
#: Opt-in: a host_id shift without a ``key_rotation`` marker fails the chain.
STRICT_HOST_DIVERGENCE_ENV = "WORKSPACE_STRICT_HOST_DIVERGENCE"
#: Value of ``backend`` in :func:`seal`'s result; a host may rebind it.
SEAL_BACKEND = "audit-chain"


def resolve_log_root(explicit: "str | Path | None" = None) -> Path:
    if explicit:
        return Path(explicit)
    env_value = os.environ.get(LOG_ROOT_ENV)
    if env_value:
        return Path(env_value).expanduser()
    return LOG_ROOT_DEFAULT


_log = logging.getLogger(__name__)


class DiskFullError(OSError):
    """ENOSPC during append or purge rewrite. The partial write is truncated
    (append) or the temp shard removed (purge) before this is raised."""


GENESIS_HASH = "GENESIS"

#: Erasure grounds a ``purge`` must name (Art. 17(1)(a)-(f) codes).
VALID_LEGAL_BASES = frozenset({
    "art_17_1_a", "art_17_1_b", "art_17_1_c",
    "art_17_1_d", "art_17_1_e", "art_17_1_f",
})


# ---------------------------------------------------------------------------
# Cross-process file lock
# ---------------------------------------------------------------------------

_IS_WINDOWS = os.name == "nt"


def _file_lock_backend():
    """The platform OS-lock module; refuse to run unlocked."""
    if _IS_WINDOWS:
        try:
            import msvcrt
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Windows mutation-log locking requires msvcrt; refusing "
                "to access the log without an OS lock"
            ) from exc
        return "msvcrt", msvcrt
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "mutation-log locking requires fcntl on this platform; refusing "
            "to access the log without an OS lock"
        ) from exc
    return "fcntl", fcntl


@contextlib.contextmanager
def _file_lock(fh, *, exclusive: bool):
    """Advisory lock: ``fcntl.flock`` on POSIX, ``msvcrt.locking`` over the
    first byte on Windows (exclusive only; shared degrades to exclusive).
    Acquisition and release fail closed."""
    backend, lock_module = _file_lock_backend()
    locked = False
    try:
        if backend == "fcntl":
            mode = lock_module.LOCK_EX if exclusive else lock_module.LOCK_SH
            lock_module.flock(fh.fileno(), mode)
            locked = True
        else:
            fh.seek(0)
            lock_module.locking(fh.fileno(), lock_module.LK_LOCK, 1)
            locked = True
        yield
    finally:
        if locked and backend == "fcntl":
            lock_module.flock(fh.fileno(), lock_module.LOCK_UN)
        elif locked:
            fh.seek(0)
            lock_module.locking(fh.fileno(), lock_module.LK_UNLCK, 1)


def _canonical_event_hash(event_dict: dict) -> str:
    """SHA-256 of canonical JSON EXCLUDING ``prev_hash`` and ``signature``
    (both are derived from content; including them would be circular)."""
    d = {k: v for k, v in event_dict.items() if k not in ("prev_hash", "signature")}
    canonical = json.dumps(
        d, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _signed_bytes(event_dict: dict) -> bytes:
    """What Ed25519 signs: canonical hash + prev_hash, so a signature is bound
    to its chain position and cannot be lifted onto another event."""
    canonical_hash = _canonical_event_hash(event_dict)
    prev_hash = event_dict.get("prev_hash", "")
    return f"{canonical_hash}|{prev_hash}".encode("utf-8")


@dataclass
class ChainVerificationResult:
    """Outcome of :meth:`MutationLog.verify_chain`.

    ``ok`` iff every link resolves and every signature verifies.
    ``legacy_events`` have no ``prev_hash``; ``unsigned_events`` have no
    ``signature`` — both accepted, neither validated. ``purged_with_tombstone``
    counts re-links explained by a purge tombstone. ``host_divergence_warning``
    lists host_id shifts without a ``key_rotation`` marker (advisory unless
    ``STRICT_HOST_DIVERGENCE_ENV`` is ``1``). ``key_pin`` is ``None`` on an
    unregistered chain, else ``{"registered", "fingerprint", "pin_file"}``.
    """

    ok: bool
    total_events: int
    legacy_events: int
    broken_links: list[dict]
    malformed_lines: int
    unsigned_events: int = 0
    signature_failures: list[dict] = field(default_factory=list)
    purged_with_tombstone: int = 0
    host_divergence_warning: list[dict] = field(default_factory=list)
    key_pin: "dict | None" = None

    def __bool__(self) -> bool:
        return self.ok


VALID_EVENTS = frozenset({
    "ingest", "classify", "extract", "admit", "hold", "reject", "live",
    "supersede", "stale", "delete", "purge", "system",
    "validator_rejected", "air_gap_refused",
    "key_rotation",       # deliberate signing-identity move across hosts
    "key_registration",   # genesis pin of the identity key
})

VALID_CHANNELS = frozenset({
    "document", "websearch", "llm_answer", "system", "reasoning", "fact",
})


# ---------------------------------------------------------------------------
# Host ports
# ---------------------------------------------------------------------------

def purged_pair_ref(folder: "str | Path", pair_id: str) -> str:
    """On-chain stand-in for a purged pair id: the tombstone outlives the
    events it erases, so the raw id (which may carry the subject) never lands
    in it. Default: folder-keyed, unsalted. A host with a per-folder secret
    salt rebinds this name."""
    digest = hashlib.sha256(
        ("pair-ref\x1f" + folder_hash(folder) + "\x1f" + pair_id).encode("utf-8")
    ).hexdigest()
    return "pair-ref:" + digest[:16]


_WS = re.compile(r"\s+")


def content_signature(text: str) -> str:
    """Case- and whitespace-normalised SHA-256 used by :func:`seal` for
    ``source_hash``. A host may rebind it to its own fingerprint."""
    norm = _WS.sub(" ", (text or "").strip().lower())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


#: Called by :func:`seal` as ``register_workspace(folder, log_root=...)``.
register_workspace: Callable[..., Any] = _add_known_workspace


__all__ = [
    "_filesystem_is_case_insensitive", "folder_hash", "legacy_folder_hash",
    "LOG_ROOT_DEFAULT", "DiskFullError", "ChainVerificationResult", "LogEvent",
    "SealedWriteError", "MutationLog", "seal", "events_from_bytes",
    "append_event", "read_chain", "resolve_log_root",
]


@dataclass
class LogEvent:
    """One entry in a folder's log."""

    event: str
    folder_path: str
    pair_id: str
    lifecycle_state: str = ""
    channel: str = "system"
    problem_id: str = ""
    source_hash: str = ""
    actor: str = "system"
    audit_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts: float = field(default_factory=time.time)
    extra: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""   # set by MutationLog.append()
    signature: str = ""   # set by MutationLog.append()
    host_id: str = ""     # set by MutationLog.append()

    def __post_init__(self) -> None:
        if self.event not in VALID_EVENTS:
            raise ValueError(
                f"unknown event '{self.event}'. Valid: {sorted(VALID_EVENTS)}"
            )
        if self.channel not in VALID_CHANNELS:
            raise ValueError(
                f"unknown channel '{self.channel}'. Valid: {sorted(VALID_CHANNELS)}"
            )
        if not self.pair_id:
            raise ValueError("pair_id is required")
        # folder_path is overwritten on append() to the log's own folder.

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict) -> "LogEvent":
        return cls(
            event=str(d.get("event", "")),
            folder_path=str(d.get("folder_path", "")),
            pair_id=str(d.get("pair_id", "")),
            lifecycle_state=str(d.get("lifecycle_state", "")),
            channel=str(d.get("channel", "system")),
            problem_id=str(d.get("problem_id", "")),
            source_hash=str(d.get("source_hash", "")),
            actor=str(d.get("actor", "system")),
            audit_id=str(d.get("audit_id", "")),
            ts=float(d.get("ts", 0.0)),
            extra=dict(d.get("extra") or {}),
            prev_hash=str(d.get("prev_hash", "")),
            signature=str(d.get("signature", "")),
            host_id=str(d.get("host_id", "")),
        )


class SealedWriteError(RuntimeError):
    """A write (append/purge) against a sealed store; a sealed store is read-only."""


def _iter_json_lines(fh) -> Iterator[dict]:
    """Decode a binary handle line by line, skipping undecodable and
    unparseable lines so one corrupt line never blocks the rest."""
    for raw in fh:
        try:
            line = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            continue
        if not line:
            continue
        try:
            yield json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue


class MutationLog:
    """One folder's append-only log."""

    def __init__(
        self,
        folder_path: str | Path,
        *,
        log_root: str | Path | None = None,
    ):
        # Persistence is a trust boundary of its own: the folder is resolved
        # and allowlist-checked here, against the same log root this log uses.
        eff_log_root = resolve_log_root(log_root)
        self.folder_path = resolve_folder_context(folder_path, log_root=eff_log_root)
        self._folder_id = folder_hash(self.folder_path)
        root = eff_log_root
        self._log_dir = root / self._folder_id
        self._log_file = self._log_dir / "events.jsonl"
        self._root = root
        # A sealed store must not get an empty plaintext dir beside the ciphertext.
        if not self._is_sealed():
            self._log_dir.mkdir(parents=True, exist_ok=True)

    @property
    def folder_id(self) -> str:
        return self._folder_id

    @property
    def log_dir(self) -> Path:
        return self._log_dir

    @property
    def log_file(self) -> Path:
        return self._log_file

    def head_hash(self) -> str:
        """Current head hash from the signed anchor; ``GENESIS_HASH`` when the
        chain is empty or unanchored. ``verify_chain`` re-derives the
        authoritative head, so this fast read may swallow anchor errors."""
        af = self._anchor_file()
        try:
            if af.exists():
                head = str(json.loads(af.read_text(encoding="utf-8")).get("head_hash", ""))
                if head:
                    return head
        except Exception:
            pass
        return GENESIS_HASH

    def _is_sealed(self) -> bool:
        """A ``.sealed`` blob exists for the primary or legacy folder hash."""
        try:
            if (self._root / (self._folder_id + ".sealed")).exists():
                return True
            return (self._root / (legacy_folder_hash(self.folder_path) + ".sealed")).exists()
        except Exception:
            return False

    # ----- genesis key pin -------------------------------------------------

    def _pin_file(self) -> Path:
        pin_dir = os.environ.get(KEY_PIN_DIR_ENV)
        base = Path(pin_dir).expanduser() / self._folder_id if pin_dir else self._log_dir
        return base / "identity.pin"

    def _read_pin_fingerprint(self) -> "str | None":
        try:
            data = json.loads(self._pin_file().read_text(encoding="utf-8"))
            fp = str(data.get("fingerprint", ""))
            return fp or None
        except Exception:
            return None

    def _write_pin(self, fingerprint: str) -> None:
        """Write the TOFU pin once; never overwrite (a changed pin is a signal)."""
        pf = self._pin_file()
        if pf.exists():
            return
        try:
            pf.parent.mkdir(parents=True, exist_ok=True)
            tmp = pf.with_name(pf.name + ".tmp")
            tmp.write_text(json.dumps({"folder_id": self._folder_id,
                                       "fingerprint": fingerprint}),
                           encoding="utf-8")
            os.replace(tmp, pf)
        except Exception as e:  # noqa: BLE001 — never fail append
            _log.warning("mutation_log: pin write failed on %s (%s)", pf, e)

    def _build_registration_event(self) -> "LogEvent | None":
        try:
            from . import signing
            fp, pem = signing.register_identity()
            if not fp or not pem:
                return None
        except Exception:
            return None
        return LogEvent(
            event="key_registration",
            folder_path=self.folder_path,
            pair_id=f"key_registration:{self._folder_id}",
            actor="system",
            extra={"kind": "key_registration",
                   "identity_fingerprint": fp,
                   "identity_pub": pem},
        )

    def _ensure_registered(self) -> None:
        """With pinning on, a fresh chain gets a genesis ``key_registration``
        before its first event and the pin is written. Registration is a
        genesis act, never injected mid-chain."""
        if os.environ.get(KEY_PINNING_ENV) != "1":
            return
        try:
            if self._log_file.exists() and self._log_file.stat().st_size > 0:
                return
        except OSError:
            return
        reg = self._build_registration_event()
        if reg is None:
            return
        self.append(reg)
        self._write_pin(reg.extra["identity_fingerprint"])

    # ----- writes ------------------------------------------------------------

    def append(self, event: LogEvent) -> str:
        """Append one event under an exclusive OS lock; returns its ``audit_id``.

        ``folder_path`` and ``host_id`` are stamped before hashing so the
        signature binds them. A signing failure leaves ``signature`` empty
        (the chain keeps hash-link protection). ENOSPC truncates the partial
        line and raises :class:`DiskFullError`. Refuses while sealed.
        """
        if self._is_sealed():
            raise SealedWriteError(
                "store is sealed — unseal it before writing; a sealed store is "
                "read-only. Writing would leak plaintext.")
        if event.event != "key_registration":
            self._ensure_registered()
        event.folder_path = self.folder_path
        if not event.host_id:
            try:
                from . import signing
                event.host_id = signing._host_id()
            except Exception:
                event.host_id = ""

        try:
            fh_ctx = self._log_file.open("a+", encoding="utf-8")
        except FileNotFoundError:
            # The plaintext dir was sealed away between the check above and this open.
            if self._is_sealed():
                raise SealedWriteError(
                    "store was sealed while this append was in flight — "
                    "the event was not written; unseal before writing.")
            raise
        with fh_ctx as fh:
            with _file_lock(fh, exclusive=True):
                # seal_folder holds this same lock across snapshot -> blob ->
                # plaintext removal, so re-check under the lock.
                if self._is_sealed():
                    raise SealedWriteError(
                        "store was sealed while this append awaited the "
                        "log lock — the event was not written; unseal before "
                        "writing.")
                if not event.prev_hash:
                    event.prev_hash = self._tail_hash_cached(fh) or GENESIS_HASH
                if not event.signature:
                    try:
                        from .signing import sign_bytes
                        signed = _signed_bytes({**asdict(event), "signature": ""})
                        event.signature = sign_bytes(signed)
                    except Exception:
                        event.signature = ""
                line = event.to_jsonl() + "\n"
                try:
                    pre_write_size = fh.tell()
                except OSError:
                    pre_write_size = None
                try:
                    fh.write(line)
                    fh.flush()
                except OSError as e:
                    if e.errno == errno.ENOSPC:
                        rollback_ok = False
                        if pre_write_size is not None:
                            try:
                                fh.flush()
                            except OSError as fe:
                                _log.debug("flush during ENOSPC rollback failed: %s", fe)
                            try:
                                os.ftruncate(fh.fileno(), pre_write_size)
                                rollback_ok = True
                            except OSError as te:
                                _log.warning(
                                    "ENOSPC rollback truncate failed on %s: "
                                    "%s — the log tail may carry a partial "
                                    "line; verify_chain will surface it",
                                    self._log_file, te,
                                )
                        if rollback_ok:
                            _log.error(
                                "mutation_log: disk full during append to "
                                "%s; truncated partial write back to %s "
                                "bytes", self._log_file, pre_write_size,
                            )
                        else:
                            _log.error(
                                "mutation_log: disk full during append to "
                                "%s; a partial line may remain on the log "
                                "tail", self._log_file,
                            )
                        raise DiskFullError(
                            errno.ENOSPC,
                            "no space left on device while appending mutation_log event",
                            str(self._log_file),
                        ) from e
                    raise
                try:
                    os.fsync(fh.fileno())
                except OSError as e:
                    _log.warning(
                        "fsync after append to %s failed (%s); the event is "
                        "written but durability across power loss is not "
                        "guaranteed", self._log_file, e,
                    )
                head = _canonical_event_hash(json.loads(event.to_jsonl()))
                try:
                    self._tail_cache = (head, os.fstat(fh.fileno()).st_size)
                except OSError:
                    self._tail_cache = None
        self._write_anchor(head=head)
        return event.audit_id

    def _last_event_canonical_hash(self) -> str:
        if not self._log_file.exists():
            return ""
        last_obj: dict | None = None
        with self._log_file.open("rb") as fh:
            with _file_lock(fh, exclusive=False):
                for obj in _iter_json_lines(fh):
                    last_obj = obj
        if last_obj is None:
            return ""
        return _canonical_event_hash(last_obj)

    # ----- signed head anchor (tail-truncation evidence) --------------------

    def _anchor_file(self):
        """Sidecar holding the SIGNED head hash. Without it, dropping the last
        N events still validates (each remaining link resolves)."""
        return self._log_dir / "events.anchor"

    def _write_anchor(self, head: str = "") -> None:
        """Best-effort: the event is already durable; verify tolerates a
        missing anchor as unanchored."""
        try:
            head = head or self._last_event_canonical_hash()
            if not head:
                return
            from .signing import sign_bytes
            sig = sign_bytes(f"head|{head}".encode("utf-8"))
            af = self._anchor_file()
            tmp = af.with_name(af.name + ".tmp")
            tmp.write_text(json.dumps({"head_hash": head, "signature": sig}),
                           encoding="utf-8")
            os.replace(tmp, af)
        except Exception as e:  # noqa: BLE001 — never fail append
            _log.warning("mutation_log: head-anchor update failed on %s (%s)",
                         self._log_file, e)

    def _verify_anchor(self, chain_hashes: set, public_key) -> "dict | None":
        """The anchored head must still be PRESENT in the chain (growth is
        fine: it becomes an interior ancestor). Absent, unreadable, or
        wrongly signed => a broken link. No anchor => ``None``."""
        af = self._anchor_file()
        if not af.exists():
            return None
        try:
            data = json.loads(af.read_text(encoding="utf-8"))
            head = str(data.get("head_hash", ""))
            sig = str(data.get("signature", ""))
        except Exception:
            return {"position": -1, "audit_id": None, "reason": "anchor_unreadable"}
        if not head or not sig:
            return {"position": -1, "audit_id": None, "reason": "anchor_malformed"}
        if public_key is not None:
            try:
                from .signing import verify_signature
                if not verify_signature(f"head|{head}".encode("utf-8"), sig, public_key):
                    return {"position": -1, "audit_id": None,
                            "reason": "anchor_signature_invalid"}
            except Exception:
                return {"position": -1, "audit_id": None, "reason": "anchor_verify_error"}
        if head not in chain_hashes:
            return {"position": -1, "audit_id": None,
                    "reason": "tail_truncation_anchored_head_missing"}
        return None

    def _tail_hash_cached(self, fh) -> str:
        """Tail hash under the held exclusive lock. A (head, file size) pair
        cached after this instance's last append is valid until another writer
        changes the size; integrity never rests on it (verify re-derives)."""
        cached = getattr(self, "_tail_cache", None)
        if cached:
            try:
                if os.fstat(fh.fileno()).st_size == cached[1]:
                    return cached[0]
            except OSError:
                pass
        return self._last_event_canonical_hash_locked(fh)

    def _last_event_canonical_hash_locked(self, fh) -> str:
        """Scan variant for use INSIDE an already-locked ``a+`` handle: a
        separate binary handle does the scan, the text handle is restored."""
        try:
            saved_pos = fh.tell()
        except OSError:
            saved_pos = None
        last_obj: dict | None = None
        try:
            with open(self._log_file, "rb") as bin_fh:
                for obj in _iter_json_lines(bin_fh):
                    last_obj = obj
        except OSError:
            return ""
        try:
            if saved_pos is not None:
                fh.seek(saved_pos)
            else:
                fh.seek(0, os.SEEK_END)
        except OSError as e:
            _log.debug("seek restore after tail-scan failed: %s", e)
        if last_obj is None:
            return ""
        return _canonical_event_hash(last_obj)

    def append_raw(self, **kwargs: Any) -> str:
        """Build a :class:`LogEvent` from kwargs and append it."""
        kwargs.setdefault("folder_path", self.folder_path)
        return self.append(LogEvent(**kwargs))

    # ----- reads -------------------------------------------------------------

    def replay(self) -> Iterator[LogEvent]:
        """Every event in append order; malformed lines skipped silently."""
        if not self._log_file.exists():
            return
        with self._log_file.open("rb") as fh:
            for obj in _iter_json_lines(fh):
                try:
                    yield LogEvent.from_dict(obj)
                except (ValueError, TypeError):
                    continue

    def replay_filtered(
        self,
        predicate: Callable[[LogEvent], bool],
    ) -> Iterator[LogEvent]:
        for evt in self.replay():
            if predicate(evt):
                yield evt

    def latest_state(self, pair_id: str) -> str | None:
        """Most-recent non-empty ``lifecycle_state`` for ``pair_id``, or ``None``."""
        latest: str | None = None
        for evt in self.replay():
            if evt.pair_id == pair_id and evt.lifecycle_state:
                latest = evt.lifecycle_state
        return latest

    def pair_ids(self, *, exclude_states: tuple[str, ...] = ("deleted", "purged")) -> set[str]:
        seen: dict[str, str] = {}
        for evt in self.replay():
            if evt.lifecycle_state:
                seen[evt.pair_id] = evt.lifecycle_state
        return {pid for pid, state in seen.items() if state not in exclude_states}

    def count(self) -> int:
        """Line count, malformed lines included."""
        if not self._log_file.exists():
            return 0
        with self._log_file.open("r", encoding="utf-8") as fh:
            return sum(1 for _ in fh)

    def verify_chain(self) -> ChainVerificationResult:
        """Walk the log: hash links, Ed25519 signatures, tombstone
        co-signatures, the head anchor, host divergence, the key pin."""
        broken: list[dict] = []
        signature_failures: list[dict] = []
        malformed = 0
        total = 0
        legacy = 0
        unsigned = 0
        purged_with_tombstone = 0
        chain_hashes: set[str] = set()
        expected_prev = GENESIS_HASH
        # A purge tombstone is inserted into a previously complete chain, so
        # the event after it re-links once; that single break is authorised.
        prev_was_purge = False
        # Once the chain carries a signature, a later unsigned event is a
        # stripped signature, never legacy.
        seen_signed = False
        host_divergence: list[dict] = []
        prev_host_id: str | None = None
        registered_fp: str | None = None

        # identity.pub first: verification must not need the private key.
        public_key = None
        try:
            from .signing import ensure_keypair, identity_public_key_or_none
            public_key = identity_public_key_or_none()
            if public_key is None:
                _, public_key = ensure_keypair()
        except Exception:
            public_key = None

        if not self._log_file.exists():
            # A surviving anchor commits to a head that no longer exists:
            # deleting the log is tail truncation taken to the limit.
            anchor_break = self._verify_anchor(set(), public_key)
            return ChainVerificationResult(
                ok=anchor_break is None, total_events=0, legacy_events=0,
                broken_links=[] if anchor_break is None else [anchor_break],
                malformed_lines=0,
                unsigned_events=0, signature_failures=[],
                purged_with_tombstone=0,
            )

        with self._log_file.open("rb") as fh:
            with _file_lock(fh, exclusive=False):
                for position, raw in enumerate(fh):
                    try:
                        line = raw.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        # Accidental damage, counted but never a broken link.
                        malformed += 1
                        continue
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        malformed += 1
                        broken.append({
                            "position": position,
                            "audit_id": None,
                            "reason": "malformed_json",
                            "expected": expected_prev,
                            "found": None,
                        })
                        continue
                    total += 1
                    stored_prev = obj.get("prev_hash", "")
                    if not stored_prev:
                        legacy += 1
                    else:
                        if stored_prev != expected_prev:
                            if prev_was_purge:
                                purged_with_tombstone += 1
                            else:
                                broken.append({
                                    "position": position,
                                    "audit_id": obj.get("audit_id"),
                                    "reason": "prev_hash_mismatch",
                                    "expected": expected_prev,
                                    "found": stored_prev,
                                })
                    stored_sig = obj.get("signature", "")
                    if not stored_sig:
                        unsigned += 1
                        if seen_signed:
                            signature_failures.append({
                                "position": position,
                                "audit_id": obj.get("audit_id"),
                                "reason": "unsigned_event_after_signing_epoch",
                            })
                    else:
                        seen_signed = True
                        if public_key is not None:
                            try:
                                from .signing import verify_signature
                                signed_data = _signed_bytes({**obj, "signature": ""})
                                if not verify_signature(signed_data, stored_sig, public_key):
                                    signature_failures.append({
                                        "position": position,
                                        "audit_id": obj.get("audit_id"),
                                        "reason": "ed25519_signature_invalid",
                                    })
                            except Exception as e:
                                signature_failures.append({
                                    "position": position,
                                    "audit_id": obj.get("audit_id"),
                                    "reason": f"signature_verify_error: {type(e).__name__}",
                                })
                    # A tombstone that CLAIMS controller co-signature must
                    # validate against the registered controller pubkey.
                    _extra = obj.get("extra", {}) or {}
                    if _extra.get("kind") == "purge_tombstone":
                        _csig = _extra.get("controller_sig", "") or ""
                        _ckeyid = _extra.get("controller_keyid")
                        _mode = _extra.get("erasure_mode", "")
                        _claims_two_key = bool(_ckeyid) or _mode == "two-key" or bool(_csig)
                        if _claims_two_key:
                            try:
                                from .signing import verify_controller_signature_strict
                                import copy as _copy
                                _probe = _copy.deepcopy(obj)
                                _probe.get("extra", {}).pop("controller_sig", None)
                                _probe["signature"] = ""
                                _payload = _signed_bytes(_probe)
                                if not verify_controller_signature_strict(_payload, _csig):
                                    signature_failures.append({
                                        "position": position,
                                        "audit_id": obj.get("audit_id"),
                                        "reason": "controller_cosignature_invalid_or_unverifiable",
                                    })
                            except Exception as e:
                                signature_failures.append({
                                    "position": position,
                                    "audit_id": obj.get("audit_id"),
                                    "reason": f"controller_verify_error: {type(e).__name__}",
                                })

                    if (registered_fp is None
                            and obj.get("event") == "key_registration"):
                        registered_fp = str(_extra.get("identity_fingerprint", "")) or None

                    # A stolen identity key can re-sign a rewritten chain on a
                    # different host; the residual signal is a host_id shift
                    # without a key_rotation marker.
                    _this_host = obj.get("host_id") or ""
                    _is_rotation = (
                        obj.get("event") == "key_rotation"
                        or (obj.get("extra", {}) or {}).get("kind") == "key_rotation"
                    )
                    if _this_host:
                        if (prev_host_id is not None
                                and _this_host != prev_host_id
                                and not _is_rotation):
                            host_divergence.append({
                                "position": position,
                                "audit_id": obj.get("audit_id"),
                                "prev_host_id": prev_host_id,
                                "host_id": _this_host,
                            })
                        prev_host_id = _this_host

                    if obj.get("event") == "purge":
                        purged_with_tombstone += 1
                        prev_was_purge = True
                    else:
                        prev_was_purge = False
                    expected_prev = _canonical_event_hash(obj)
                    chain_hashes.add(expected_prev)

        anchor_break = self._verify_anchor(chain_hashes, public_key)
        if anchor_break is not None:
            broken.append(anchor_break)

        key_pin = self._check_key_pin(registered_fp, public_key, signature_failures)

        strict_host = os.environ.get(STRICT_HOST_DIVERGENCE_ENV) == "1"
        ok = (len(broken) == 0 and len(signature_failures) == 0
              and not (strict_host and host_divergence))
        return ChainVerificationResult(
            ok=ok,
            total_events=total,
            legacy_events=legacy,
            broken_links=broken,
            malformed_lines=malformed,
            unsigned_events=unsigned,
            signature_failures=signature_failures,
            purged_with_tombstone=purged_with_tombstone,
            host_divergence_warning=host_divergence,
            key_pin=key_pin,
        )

    def _check_key_pin(self, registered_fp, public_key,
                       signature_failures) -> "dict | None":
        """Genesis key pin. Enforcement is not env-gated once a chain carries
        a registration: the verifying key must match the registered
        fingerprint, and the pin file (when present) must match too — a full
        re-key rewrites the embedded registration but cannot rewrite a pin
        relocated off the log tree."""
        strict = os.environ.get(STRICT_KEY_PINNING_ENV) == "1"
        if registered_fp is None:
            if strict:
                signature_failures.append({"position": None, "audit_id": None,
                                           "reason": "chain_unregistered"})
            return None

        pin_file_fp = self._read_pin_fingerprint()
        pin_state = ("absent" if pin_file_fp is None
                     else "match" if pin_file_fp == registered_fp else "mismatch")

        if public_key is not None:
            try:
                from . import signing
                ondisk_fp = signing.fingerprint_of(public_key)
                if ondisk_fp != registered_fp:
                    signature_failures.append({
                        "position": None, "audit_id": None,
                        "reason": "key_pin_mismatch"})
            except Exception as e:
                signature_failures.append({
                    "position": None, "audit_id": None,
                    "reason": f"key_pin_check_error: {type(e).__name__}"})

        if pin_state == "mismatch":
            signature_failures.append({"position": None, "audit_id": None,
                                       "reason": "key_pin_tampered"})

        return {"registered": True, "fingerprint": registered_fp,
                "pin_file": pin_state}

    # ----- maintenance -------------------------------------------------------

    def purge(
        self,
        pair_id: str,
        *,
        legal_basis: str = "",
        requester_ref: str = "",
        reason: str = "",
    ) -> int:
        """Physically erase every event for ``pair_id``; IRREVERSIBLE.

        Survivors whose predecessor was removed are re-linked and re-signed
        with the operator key; a single ``purge`` tombstone is appended naming
        the pair only through :func:`purged_pair_ref`. With a controller
        keypair present the tombstone is co-signed (``erasure_mode``
        ``"two-key"``), else ``"single-key"``. ``legal_basis`` must be in
        ``VALID_LEGAL_BASES``; ``requester_ref`` and ``reason`` are required.
        Returns the number of events purged (0 leaves the log untouched).
        """
        if self._is_sealed():
            raise SealedWriteError(
                "store is sealed — unseal it before purging; a sealed store is "
                "read-only.")
        if not legal_basis:
            raise ValueError(
                "purge requires legal_basis (one of "
                f"{sorted(VALID_LEGAL_BASES)})"
            )
        if legal_basis not in VALID_LEGAL_BASES:
            raise ValueError(
                f"unknown legal_basis '{legal_basis}'. Valid: "
                f"{sorted(VALID_LEGAL_BASES)}"
            )
        if not requester_ref:
            raise ValueError("purge requires requester_ref")
        if not reason:
            raise ValueError("purge requires reason")

        from . import signing
        _has_controller = signing.public_controller_key_fingerprint() is not None

        if not self._log_file.exists():
            return 0

        with self._log_file.open("a+", encoding="utf-8") as fh:
            with _file_lock(fh, exclusive=True):
                fh.seek(0)
                raw_lines = fh.readlines()

        parsed: list[tuple[str, dict | None]] = []
        purged_audit_ids: list[str] = []
        for line in raw_lines:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parsed.append((line, None))
                continue
            if obj.get("pair_id") == pair_id:
                purged_audit_ids.append(str(obj.get("audit_id", "")))
                continue
            parsed.append((line, obj))

        purged_count = len(purged_audit_ids)
        if purged_count == 0:
            return 0

        prev_canon = GENESIS_HASH
        rewritten_lines: list[str] = []
        for line, obj in parsed:
            if obj is None:
                rewritten_lines.append(line)  # malformed lines preserved verbatim
                continue
            stored_prev = obj.get("prev_hash", "")
            if stored_prev and stored_prev != prev_canon:
                obj["prev_hash"] = prev_canon
                try:
                    signed = _signed_bytes({**obj, "signature": ""})
                    obj["signature"] = signing.sign_bytes(signed)
                except Exception as e:
                    # An unsigned re-linked survivor would read as a stripped
                    # signature. Nothing is written yet, so abort loudly.
                    raise RuntimeError(
                        f"purge aborted: could not re-sign re-linked survivor "
                        f"{obj.get('audit_id')!r} ({type(e).__name__}: {e}). "
                        f"The log is unchanged; restore signing capability and retry."
                    ) from e
                rewritten_lines.append(json.dumps(obj, ensure_ascii=False) + "\n")
            else:
                rewritten_lines.append(line if line.endswith("\n") else line + "\n")
            prev_canon = _canonical_event_hash(obj)

        _pair_ref = globals()["purged_pair_ref"]
        tombstone: dict[str, Any] = {
            "ts": time.time(),
            "event": "purge",
            "folder_path": self.folder_path,
            "pair_id": _pair_ref(self.folder_path, pair_id),
            "channel": "system",
            "actor": "system:purge",
            "audit_id": str(uuid.uuid4()),
            "lifecycle_state": "purged",
            "problem_id": "",
            "source_hash": "",
            "extra": {
                "kind": "purge_tombstone",
                "purged_event_audit_ids": purged_audit_ids,
                "purged_event_count": purged_count,
                "legal_basis": legal_basis,
                "requester_ref": requester_ref,
                "reason": reason,
                "operator_keyid": signing.public_key_fingerprint(),
                "controller_keyid": signing.public_controller_key_fingerprint() if _has_controller else None,
                "erasure_mode": "two-key" if _has_controller else "single-key",
            },
            "prev_hash": prev_canon,
            "signature": "",
            "host_id": "",
        }
        try:
            tombstone["host_id"] = signing._host_id()
        except Exception:
            tombstone["host_id"] = ""

        # Controller co-signature first (only when deliberately initialised),
        # then the operator signature LAST so it binds everything in extra.
        if _has_controller:
            try:
                controller_sig = signing.sign_with_controller(
                    _signed_bytes({**tombstone, "signature": ""})
                )
            except Exception:
                controller_sig = ""
        else:
            controller_sig = ""
        tombstone["extra"]["controller_sig"] = controller_sig
        try:
            op_signed = _signed_bytes({**tombstone, "signature": ""})
            tombstone["signature"] = signing.sign_bytes(op_signed)
        except Exception:
            tombstone["signature"] = ""

        rewritten_lines.append(json.dumps(tombstone, ensure_ascii=False) + "\n")

        tmp = self._log_file.with_suffix(".jsonl.tmp")
        with self._log_file.open("a+", encoding="utf-8") as fh:
            with _file_lock(fh, exclusive=True):
                try:
                    with tmp.open("w", encoding="utf-8") as wfh:
                        wfh.writelines(rewritten_lines)
                        wfh.flush()
                        try:
                            os.fsync(wfh.fileno())
                        except OSError as fe:
                            _log.warning("fsync of purge rewrite shard %s "
                                         "failed (%s); shard durability not "
                                         "guaranteed", tmp, fe)
                except OSError as e:
                    if e.errno == errno.ENOSPC:
                        try:
                            tmp.unlink()
                        except OSError as ue:
                            _log.warning("could not remove temp shard %s "
                                         "after ENOSPC (%s); stale .tmp may "
                                         "remain beside the log", tmp, ue)
                        _log.error(
                            "mutation_log: disk full during purge rewrite of %s; "
                            "original log left intact, purge did not apply",
                            self._log_file,
                        )
                        raise DiskFullError(
                            errno.ENOSPC,
                            "no space left on device while rewriting mutation_log during purge",
                            str(self._log_file),
                        ) from e
                    raise
                os.replace(tmp, self._log_file)
        self._write_anchor()
        return purged_count


def seal(
    folder: "str | Path",
    *,
    pair_id: str,
    payload: Any,
    event: str = "system",
    actor: str = "",
    extra: "dict[str, Any] | None" = None,
    log_root: "str | Path | None" = None,
) -> dict:
    """One-call consumer entry: register ``folder``, fingerprint ``payload``
    (canonical JSON through :func:`content_signature`) into ``source_hash``,
    append, and report ``{"backend", "audit_id", "head_hash", "verified"}``.
    The payload is bound, never stored; only ``extra`` is written."""
    _register = globals()["register_workspace"]
    _sig = globals()["content_signature"]
    _register(folder, log_root=log_root)
    src_hash = _sig(json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False))
    log = MutationLog(folder, log_root=log_root)
    audit_id = log.append(LogEvent(
        event=event,
        folder_path=str(folder),
        pair_id=pair_id,
        source_hash=src_hash,
        actor=actor or "system",
        extra=extra or {},
    ))
    return {
        "backend": SEAL_BACKEND,
        "audit_id": audit_id,
        "head_hash": log.head_hash(),
        "verified": bool(log.verify_chain().ok),
    }


def events_from_bytes(data: bytes) -> "Iterator[LogEvent]":
    """Parse newline-delimited event JSON with :meth:`MutationLog.replay`'s
    tolerance. Pure: no IO. Lets a sealed store be read from served bytes."""
    for raw in data.splitlines():
        try:
            line = raw.decode("utf-8").strip() if isinstance(raw, (bytes, bytearray)) else str(raw).strip()
        except UnicodeDecodeError:
            continue
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        try:
            yield LogEvent.from_dict(obj)
        except (ValueError, TypeError):
            continue


# ---------------------------------------------------------------------------
# Directory-addressed raw-dict chain (a log with no folder identity, e.g. a
# host's global "unscoped" chain). Same hash link and signature scheme.
# ---------------------------------------------------------------------------

def append_event(log_dir: "str | Path", event: dict) -> str:
    """Append a raw dict event to ``<log_dir>/events.jsonl``, hash-linked and
    signed like :meth:`MutationLog.append`. ``audit_id`` and ``ts`` are
    stamped when absent. Returns the ``audit_id``."""
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "events.jsonl"
    obj = dict(event)
    obj.setdefault("audit_id", str(uuid.uuid4()))
    obj.setdefault("ts", time.time())
    with log_file.open("a+", encoding="utf-8") as fh:
        with _file_lock(fh, exclusive=True):
            last: dict | None = None
            try:
                with open(log_file, "rb") as bin_fh:
                    for prev in _iter_json_lines(bin_fh):
                        last = prev
            except OSError:
                last = None
            obj["prev_hash"] = _canonical_event_hash(last) if last else GENESIS_HASH
            obj["signature"] = ""
            try:
                from .signing import sign_bytes
                obj["signature"] = sign_bytes(_signed_bytes(obj))
            except Exception:
                obj["signature"] = ""
            fh.seek(0, os.SEEK_END)
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError as e:
                _log.warning("fsync after append_event to %s failed (%s)", log_file, e)
    return str(obj["audit_id"])


def read_chain(log_dir: "str | Path | None" = None) -> Iterator[dict]:
    """Raw dict events from ``<log_dir>/events.jsonl`` (default
    ``resolve_log_root() / "unscoped"``), malformed lines skipped."""
    log_file = (Path(log_dir) if log_dir else resolve_log_root() / "unscoped") / "events.jsonl"
    if not log_file.exists():
        return
    with log_file.open("rb") as fh:
        yield from _iter_json_lines(fh)
