"""Encryption component.

Argon2id KDF, AES-256-GCM, RNG, key wiping and password generation.
Never reads or writes files.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import string

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = "PWM-VAULT"
VERSION = 1

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

# Defaults from the design: m = 64 MiB, t = 3, p = 1.
DEFAULT_KDF = (65536, 3, 1)
# Minimum accepted on load (downgrade protection) and sanity maximums
# (a hostile file must not be able to demand gigabytes of RAM).
MIN_M_KIB, MIN_T, MIN_P = 19456, 2, 1
MAX_M_KIB, MAX_T, MAX_P = 1 << 20, 16, 16


class CryptoError(Exception):
    """Any cryptographic failure. Deliberately carries no detail."""


def wipe(buf) -> None:
    """Zero a bytearray in place (best effort; str/bytes cannot be wiped)."""
    if isinstance(buf, bytearray):
        buf[:] = bytes(len(buf))


def check_kdf_params(m_kib: int, t: int, p: int) -> None:
    if not (MIN_M_KIB <= m_kib <= MAX_M_KIB and MIN_T <= t <= MAX_T and MIN_P <= p <= MAX_P):
        raise CryptoError("unsupported KDF parameters")


def derive_kek(password, salt: bytes, m_kib: int, t: int, p: int) -> bytearray:
    """Argon2id(password, salt) -> 32-byte key-encryption key."""
    check_kdf_params(m_kib, t, p)
    if len(salt) != SALT_LEN:
        raise CryptoError("bad salt")
    raw = hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=t,
        memory_cost=m_kib,
        parallelism=p,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def header_aad(m_kib: int, t: int, p: int, salt: bytes) -> bytes:
    """AAD = magic || version || canonical KDF block (design section 3.3)."""
    kdf = {
        "alg": "argon2id",
        "m_kib": m_kib,
        "t": t,
        "p": p,
        "salt": base64.b64encode(salt).decode("ascii"),
    }
    canon = json.dumps(kdf, sort_keys=True, separators=(",", ":"))
    return f"{MAGIC}|{VERSION}|{canon}".encode("utf-8")


def encrypt(key, plaintext, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM with a fresh random 96-bit nonce. Returns (nonce, ciphertext+tag)."""
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), aad)
    return nonce, ct


def decrypt(key, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ct, aad)
    except (InvalidTag, ValueError):
        raise CryptoError("decryption failed") from None


def random_key() -> bytearray:
    return bytearray(os.urandom(KEY_LEN))


def random_salt() -> bytes:
    return os.urandom(SALT_LEN)


_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def generate_password(length: int = 20, symbols: bool = True) -> str:
    """Uniform selection with secrets.choice; guarantees every class is present."""
    if length < 8:
        raise ValueError("length must be at least 8")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append(_SYMBOLS)
    alphabet = "".join(classes)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw
