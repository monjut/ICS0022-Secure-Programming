"""Storage component.

Parses and validates the vault file, writes it atomically, keeps a backup and
sets restrictive permissions. Only ever sees ciphertext blobs and the header;
never plaintext or keys.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from dataclasses import dataclass

from .crypto import MAGIC, NONCE_LEN, SALT_LEN, VERSION

MAX_FILE_BYTES = 16 * 1024 * 1024
WRAPPED_CT_LEN = 32 + 16  # 32-byte vault key + 16-byte GCM tag
GCM_TAG_LEN = 16


class StorageError(Exception):
    """The file is missing structure, malformed or too large."""


@dataclass(frozen=True)
class VaultFile:
    m_kib: int
    t: int
    p: int
    salt: bytes
    wrapped_nonce: bytes
    wrapped_ct: bytes
    body_nonce: bytes
    body_ct: bytes


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value, *, exact: int | None = None, minimum: int = 0) -> bytes:
    if not isinstance(value, str):
        raise StorageError("invalid vault file")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise StorageError("invalid vault file") from None
    if exact is not None and len(raw) != exact:
        raise StorageError("invalid vault file")
    if len(raw) < minimum:
        raise StorageError("invalid vault file")
    return raw


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _block(doc: dict, name: str, keys: set[str]) -> dict:
    block = doc.get(name)
    if not isinstance(block, dict) or set(block) != keys:
        raise StorageError("invalid vault file")
    return block


def parse(raw: bytes) -> VaultFile:
    """Strict schema validation. Nothing is decrypted here."""
    if len(raw) > MAX_FILE_BYTES:
        raise StorageError("invalid vault file")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise StorageError("invalid vault file") from None
    if not isinstance(doc, dict) or set(doc) != {"magic", "version", "kdf", "wrapped_key", "body"}:
        raise StorageError("invalid vault file")
    if doc["magic"] != MAGIC or not _is_int(doc["version"]) or doc["version"] != VERSION:
        raise StorageError("invalid vault file")

    kdf = _block(doc, "kdf", {"alg", "m_kib", "t", "p", "salt"})
    if kdf["alg"] != "argon2id" or not all(_is_int(kdf[k]) for k in ("m_kib", "t", "p")):
        raise StorageError("invalid vault file")
    wrapped = _block(doc, "wrapped_key", {"alg", "nonce", "ct"})
    body = _block(doc, "body", {"alg", "nonce", "ct"})
    if wrapped["alg"] != "aes-256-gcm" or body["alg"] != "aes-256-gcm":
        raise StorageError("invalid vault file")

    return VaultFile(
        m_kib=kdf["m_kib"],
        t=kdf["t"],
        p=kdf["p"],
        salt=_unb64(kdf["salt"], exact=SALT_LEN),
        wrapped_nonce=_unb64(wrapped["nonce"], exact=NONCE_LEN),
        wrapped_ct=_unb64(wrapped["ct"], exact=WRAPPED_CT_LEN),
        body_nonce=_unb64(body["nonce"], exact=NONCE_LEN),
        body_ct=_unb64(body["ct"], minimum=GCM_TAG_LEN),
    )


def serialize(vf: VaultFile) -> bytes:
    doc = {
        "magic": MAGIC,
        "version": VERSION,
        "kdf": {"alg": "argon2id", "m_kib": vf.m_kib, "t": vf.t, "p": vf.p, "salt": _b64(vf.salt)},
        "wrapped_key": {"alg": "aes-256-gcm", "nonce": _b64(vf.wrapped_nonce), "ct": _b64(vf.wrapped_ct)},
        "body": {"alg": "aes-256-gcm", "nonce": _b64(vf.body_nonce), "ct": _b64(vf.body_ct)},
    }
    return json.dumps(doc, indent=2).encode("utf-8") + b"\n"


def exists(path: str) -> bool:
    return os.path.exists(path)


def read_vault(path: str) -> VaultFile:
    with open(path, "rb") as f:
        raw = f.read(MAX_FILE_BYTES + 1)
    return parse(raw)


def _chmod_private(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # e.g. filesystems without POSIX permissions


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_vault(path: str, vf: VaultFile) -> None:
    """Temp file in the same directory -> fsync -> .bak of old file -> atomic rename."""
    path = os.path.abspath(path)
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    data = serialize(vf)

    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")  # created 0600
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _chmod_private(tmp)

        if os.path.exists(path):
            with open(path, "rb") as old:
                previous = old.read()
            bak_fd = os.open(path + ".bak", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(bak_fd, "wb") as bak:
                bak.write(previous)
                bak.flush()
                os.fsync(bak.fileno())
            _chmod_private(path + ".bak")

        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(directory)
