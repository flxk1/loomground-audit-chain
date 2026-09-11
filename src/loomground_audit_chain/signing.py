# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Ed25519 keys for the audit chain.

The hash chain in :mod:`.mutation_log` catches casual edits. Signatures close
the rewrite gap: an adversary with filesystem write access can delete an event
and recompute every downstream ``prev_hash``, but cannot re-sign without the
private key.

Key layout under the key root (``KEY_DIR_ENV`` overrides ``DEFAULT_KEY_DIR``)::

    <root>/<host_id>/identity.priv   operator key, per host
    <root>/<host_id>/identity.pub
    <root>/controller.priv           controller key, flat, shared across hosts
    <root>/controller.pub
    <root>/host-id                   pinned host_id

``host_id`` is the first 12 hex chars of ``sha256(hostname + "|" + machine_id)``,
pinned on first derivation so a hostname change does not re-key the host.
The controller key co-signs high-stakes records (purge tombstones); it is
created only by an explicit ``ensure_controller_keypair()`` call.

Events written before signing existed carry no signature; verification
accepts them and counts them as ``unsigned_events``. A flat-root keypair from
before per-host namespacing is moved into the host subdir by
:func:`migrate_legacy_keypair_to_host_subdir` (or silently by
:func:`ensure_keypair`).
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import stat
import subprocess
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_log = logging.getLogger(__name__)

#: Compatibility surface (see docs/seam.md): env var naming the key root.
KEY_DIR_ENV = "WORKSPACE_KEY_DIR"
#: Compatibility surface: default key root when ``KEY_DIR_ENV`` is unset.
DEFAULT_KEY_DIR = Path.home() / ".workspace" / "keys"
#: Passphrase for private keys at rest. Set: new private keys are written
#: PKCS8-encrypted and encrypted keys load with it. Unset: cleartext, 0600.
#: Verification reads ``.pub`` files and never needs it.
KEY_PASSPHRASE_ENV = "WORKSPACE_KEY_PASSPHRASE"
#: Explicit host_id override — the recovery path when a chain was signed under
#: a host_id this machine no longer derives.
HOST_ID_ENV = "WORKSPACE_HOST_ID"


def _key_root_dir() -> Path:
    override = os.environ.get(KEY_DIR_ENV)
    return Path(override).expanduser() if override else DEFAULT_KEY_DIR


def _key_encryption() -> serialization.KeySerializationEncryption:
    pw = os.environ.get(KEY_PASSPHRASE_ENV)
    return (serialization.BestAvailableEncryption(pw.encode())
            if pw else serialization.NoEncryption())


def _load_private_key(pem: bytes, path: Path) -> object:
    """Load a PEM private key in either at-rest mode. An encrypted key with no
    (or the wrong) passphrase raises ``RuntimeError`` naming the env var: a
    signing path must fail loud, never fall through to a fresh identity."""
    try:
        return serialization.load_pem_private_key(pem, password=None)
    except TypeError:
        pw = os.environ.get(KEY_PASSPHRASE_ENV)
        if not pw:
            raise RuntimeError(
                f"private key at {path} is passphrase-protected; set "
                f"{KEY_PASSPHRASE_ENV} to load it"
            ) from None
        try:
            return serialization.load_pem_private_key(pem, password=pw.encode())
        except ValueError as e:
            raise RuntimeError(
                f"private key at {path} did not decrypt with the passphrase "
                f"from {KEY_PASSPHRASE_ENV}: {e}"
            ) from None


# ---------------------------------------------------------------------------
# Host identity
# ---------------------------------------------------------------------------


def _machine_id() -> str:
    """Best-effort stable machine id: /etc/machine-id, the dbus copy, macOS
    IOPlatformUUID, else the literal ``"no-machine-id"``. Never raises."""
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            data = Path(p).read_text(encoding="utf-8").strip()
            if data:
                return data
        except (OSError, UnicodeDecodeError):
            continue
    try:
        out = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).decode("utf-8", errors="ignore")
        for line in out.splitlines():
            if "IOPlatformUUID" in line and "=" in line:
                _, _, rhs = line.partition("=")
                rhs = rhs.strip()
                if rhs.startswith('"') and rhs.endswith('"'):
                    val = rhs[1:-1].strip()
                    if val:
                        return val
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        _log.debug("machine-id probe via ioreg failed: %s", e)
    return "no-machine-id"


def _host_id_pin_path() -> Path:
    return _key_root_dir() / "host-id"


def _host_id() -> str:
    """Stable 12-char host identity: ``HOST_ID_ENV`` > the pin file at
    ``<root>/host-id`` > derive ``sha256(hostname|machine_id)[:12]`` and pin it.
    The pin exists because a hostname that tracks the network would otherwise
    re-key the host on every move."""
    env = os.environ.get(HOST_ID_ENV)
    if env and env.strip():
        return env.strip()
    pin = _host_id_pin_path()
    try:
        if pin.is_file():
            pinned = pin.read_text(encoding="utf-8").strip()
            if pinned:
                return pinned
    except OSError:
        pass
    h = socket.gethostname() or "unknown-host"
    m = _machine_id() or "no-machine-id"
    hid = hashlib.sha256(f"{h}|{m}".encode("utf-8")).hexdigest()[:12]
    try:
        pin.parent.mkdir(parents=True, exist_ok=True)
        pin.write_text(hid + "\n", encoding="utf-8")
    except OSError:
        pass
    return hid


def _key_dir() -> Path:
    return _key_root_dir() / _host_id()


def _private_key_path() -> Path:
    return _key_dir() / "identity.priv"


def _public_key_path() -> Path:
    return _key_dir() / "identity.pub"


def _controller_key_dir() -> Path:
    return _key_root_dir()


def _controller_private_key_path() -> Path:
    return _controller_key_dir() / "controller.priv"


def _controller_public_key_path() -> Path:
    return _controller_key_dir() / "controller.pub"


def ensure_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Return (private, public), generating on first call. Idempotent.

    A flat-root legacy keypair is moved into the host subdir here without an
    audit event; :func:`migrate_legacy_keypair_to_host_subdir` is the
    audited path.
    """
    kd = _key_dir()
    priv_path = _private_key_path()
    pub_path = _public_key_path()

    legacy_priv = _key_root_dir() / "identity.priv"
    legacy_pub = _key_root_dir() / "identity.pub"
    if not priv_path.exists() and legacy_priv.exists():
        kd.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(legacy_priv, priv_path)
            if legacy_pub.exists():
                os.replace(legacy_pub, pub_path)
            try:
                os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError as e:
                _log.debug("chmod 0600 on %s failed (best-effort): %s", priv_path, e)
        except OSError as e:
            # A silent failure here would generate a NEW identity on the signing path.
            _log.warning(
                "legacy key migration %s -> %s failed (%s); a new host key "
                "will be generated if none exists at the target",
                legacy_priv, priv_path, e,
            )

    if priv_path.exists():
        priv = _load_private_key(priv_path.read_bytes(), priv_path)
        if not isinstance(priv, Ed25519PrivateKey):
            raise TypeError(f"key at {priv_path} is not an Ed25519 private key")
        return priv, priv.public_key()

    # First-writer-wins generation. Two processes racing the first signature
    # must not each return a different key: the candidate is written to a
    # unique temp name and the canonical path claimed with a hard link
    # (atomic create-if-absent); the loser discards its candidate and loads
    # the winner's key. Readers never observe a partial private key.
    kd.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_key_encryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    tmp = priv_path.with_name(f".{priv_path.name}.tmp.{os.getpid()}")
    tmp.write_bytes(priv_pem)
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        _log.debug("chmod 0600 on %s failed (best-effort): %s", tmp, e)
    try:
        os.link(tmp, priv_path)
    except FileExistsError:
        tmp.unlink(missing_ok=True)
        winner = _load_private_key(priv_path.read_bytes(), priv_path)
        if not isinstance(winner, Ed25519PrivateKey):
            raise TypeError(f"key at {priv_path} is not an Ed25519 private key")
        return winner, winner.public_key()
    except OSError as e:
        # No hard links on this filesystem: non-atomic fallback.
        _log.debug("hard-link claim unavailable (%s); using os.replace", e)
        os.replace(tmp, priv_path)
    else:
        tmp.unlink(missing_ok=True)
    pub_path.write_bytes(pub_pem)
    return priv, pub


def sign_bytes(data: bytes, private_key: Optional[Ed25519PrivateKey] = None) -> str:
    """Hex Ed25519 signature over ``data`` with the identity key by default."""
    if private_key is None:
        private_key, _ = ensure_keypair()
    return private_key.sign(data).hex()


def verify_signature(
    data: bytes,
    signature_hex: str,
    public_key: Optional[Ed25519PublicKey] = None,
) -> bool:
    if public_key is None:
        _, public_key = ensure_keypair()
    try:
        public_key.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def public_key_pem() -> str:
    _, pub = ensure_keypair()
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def public_key_fingerprint() -> str:
    """First 16 hex chars of :func:`fingerprint_of` the identity public key."""
    _, pub = ensure_keypair()
    return fingerprint_of(pub)[:16]


def fingerprint_of(pub: Ed25519PublicKey) -> str:
    """Full sha256 hex of the raw public-key bytes — what a chain pins to."""
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def identity_fingerprint_or_none() -> Optional[str]:
    """Fingerprint of the on-disk identity public key without generating one."""
    pub = identity_public_key_or_none()
    return fingerprint_of(pub) if pub is not None else None


def identity_public_pem_or_none() -> Optional[str]:
    pub = identity_public_key_or_none()
    if pub is None:
        return None
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def register_identity() -> tuple[str, str]:
    """(fingerprint, PEM) for a genesis key_registration; generates if absent."""
    _, pub = ensure_keypair()
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return fingerprint_of(pub), pem


# ---------------------------------------------------------------------------
# Controller key
# ---------------------------------------------------------------------------


def ensure_controller_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Return (private, public) for the controller co-signing key; generates on
    first call. Flat at the key root: one controller per key root, every host."""
    kd = _controller_key_dir()
    priv_path = _controller_private_key_path()
    pub_path = _controller_public_key_path()

    if priv_path.exists():
        priv = _load_private_key(priv_path.read_bytes(), priv_path)
        if not isinstance(priv, Ed25519PrivateKey):
            raise TypeError(f"key at {priv_path} is not an Ed25519 private key")
        return priv, priv.public_key()

    kd.mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_path.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_key_encryption(),
    ))
    pub_path.write_bytes(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    try:
        os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        _log.debug("chmod 0600 on %s failed (best-effort): %s", priv_path, e)
    return priv, pub


def sign_with_controller(data: bytes) -> str:
    """Hex controller signature; generates the controller keypair on first use."""
    priv, _ = ensure_controller_keypair()
    return priv.sign(data).hex()


def verify_controller_signature(data: bytes, signature_hex: str) -> bool:
    _, pub = ensure_controller_keypair()
    try:
        pub.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def identity_public_key_or_none() -> Optional[Ed25519PublicKey]:
    """The on-disk identity PUBLIC key, or ``None``. Reads ``identity.pub``
    only: no write access, no passphrase."""
    try:
        pub_path = _public_key_path()
        if pub_path.exists():
            pub = serialization.load_pem_public_key(pub_path.read_bytes())
            if isinstance(pub, Ed25519PublicKey):
                return pub
    except Exception:
        return None
    return None


def controller_public_key_or_none() -> Optional[Ed25519PublicKey]:
    """The controller PUBLIC key without creating it; ``None`` when unregistered."""
    priv_path = _controller_private_key_path()
    pub_path = _controller_public_key_path()
    try:
        if pub_path.exists():
            pub = serialization.load_pem_public_key(pub_path.read_bytes())
            if isinstance(pub, Ed25519PublicKey):
                return pub
        if priv_path.exists():
            priv = _load_private_key(priv_path.read_bytes(), priv_path)
            if isinstance(priv, Ed25519PrivateKey):
                return priv.public_key()
    except Exception:
        return None
    return None


def verify_controller_signature_strict(data: bytes, signature_hex: str) -> bool:
    """Verify against the on-disk controller pubkey; ``False`` when none is
    registered. A record that CLAIMS controller co-signature must validate or
    it is a forgery — this never auto-creates a key to make it pass."""
    pub = controller_public_key_or_none()
    if pub is None:
        return False
    try:
        pub.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def public_controller_key_fingerprint() -> str | None:
    """16-hex fingerprint of the controller public key, or ``None`` when the
    controller keypair was never initialised (never auto-creates)."""
    if not _controller_private_key_path().exists():
        return None
    _, pub = ensure_controller_keypair()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Legacy-keypair migration
# ---------------------------------------------------------------------------


def migrate_legacy_keypair_to_host_subdir(
    *,
    audit_log: "object | None" = None,
) -> str:
    """Move a flat-root ``identity.{priv,pub}`` into ``<root>/<host_id>/``.

    Returns the active host_id either way. Idempotent. Refuses to clobber an
    existing host-scoped keypair (the stragglers stay put so an operator
    notices). With ``audit_log`` (a ``MutationLog``) the move is recorded as
    a ``system`` event with ``extra.kind == "key_migration"``.
    """
    root = _key_root_dir()
    host_id = _host_id()

    legacy_priv = root / "identity.priv"
    legacy_pub = root / "identity.pub"
    if not legacy_priv.exists() and not legacy_pub.exists():
        return host_id

    target_dir = root / host_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target_priv = target_dir / "identity.priv"
    target_pub = target_dir / "identity.pub"
    if target_priv.exists() or target_pub.exists():
        return host_id

    moved_from_priv: str | None = None
    moved_from_pub: str | None = None
    if legacy_priv.exists():
        os.replace(legacy_priv, target_priv)
        moved_from_priv = str(legacy_priv)
        try:
            os.chmod(target_priv, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as e:
            _log.debug("chmod 0600 on %s failed (best-effort): %s", target_priv, e)
    if legacy_pub.exists():
        os.replace(legacy_pub, target_pub)
        moved_from_pub = str(legacy_pub)

    if audit_log is not None and (moved_from_priv or moved_from_pub):
        try:
            from .mutation_log import LogEvent
            audit_log.append(LogEvent(
                event="system",
                folder_path=str(getattr(audit_log, "folder_path", "")),
                pair_id=f"key-migration:{host_id}",
                channel="system",
                actor="system:key_migration",
                extra={
                    "kind": "key_migration",
                    "from_path": moved_from_priv or moved_from_pub or "",
                    "to_path": str(target_priv),
                    "host_id": host_id,
                },
            ))
        except Exception:
            pass  # the move succeeded; a lost breadcrumb must not roll it back

    return host_id
