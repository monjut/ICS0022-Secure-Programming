"""User management component.

Lifecycle of the master credential (create, unlock, change, lock) and the
unlocked session. Orchestrates crypto and storage but never touches the file
format or the ciphers itself.
"""
from __future__ import annotations

import copy
import hmac
import json
import secrets
import time
from dataclasses import replace
from datetime import datetime, timezone

from . import crypto, storage

IDLE_TIMEOUT_S = 120
MAX_BACKOFF_S = 30
MIN_PASSWORD_LEN = 12

# Small built-in deny list; swap in a larger list file later.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789012", "1234567890123",
    "qwertyuiop12", "qwertyuiopas", "iloveyou1234", "letmein12345",
    "administrator", "welcome12345", "changeme1234", "passwordpassword",
    "correcthorsebatterystaple", "000000000000", "111111111111",
}

_ENTRY_STR_FIELDS = ("id", "name", "username", "password", "url", "notes", "created", "modified")


class UnlockError(Exception):
    """Generic failure: wrong password and corruption are indistinguishable by design."""


class WeakPasswordError(Exception):
    pass


class VaultExistsError(Exception):
    pass


class SessionLocked(Exception):
    pass


class EntryError(Exception):
    pass


def check_strength(password) -> None:
    try:
        text = bytes(password).decode("utf-8")
    except UnicodeDecodeError:
        raise WeakPasswordError("password must be valid UTF-8") from None
    if len(text) < MIN_PASSWORD_LEN:
        raise WeakPasswordError(f"master password must be at least {MIN_PASSWORD_LEN} characters")
    if text.lower() in COMMON_PASSWORDS or len(set(text)) < 4:
        raise WeakPasswordError("master password is too common or too repetitive")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate_body(body) -> tuple[list[dict], int]:
    """Runs only after authentication succeeded, so failures mean a buggy/foreign writer."""
    if not isinstance(body, dict) or set(body) != {"entries", "counter"}:
        raise ValueError("bad body")
    counter = body["counter"]
    if not isinstance(counter, int) or isinstance(counter, bool):
        raise ValueError("bad body")
    entries = body["entries"]
    if not isinstance(entries, list):
        raise ValueError("bad body")
    for e in entries:
        if not isinstance(e, dict) or set(e) != set(_ENTRY_STR_FIELDS) | {"tags"}:
            raise ValueError("bad entry")
        if not all(isinstance(e[k], str) for k in _ENTRY_STR_FIELDS):
            raise ValueError("bad entry")
        if not isinstance(e["tags"], list) or not all(isinstance(t, str) for t in e["tags"]):
            raise ValueError("bad entry")
    return entries, counter


class Session:
    """Unlocked vault. Plaintext entries and the vault key live only here."""

    def __init__(self, path, vault_key: bytearray, header: storage.VaultFile,
                 entries: list[dict], counter: int,
                 idle_timeout: float = IDLE_TIMEOUT_S, clock=time.monotonic):
        self._path = path
        self._vk = vault_key
        self._hdr = header
        self._entries = entries
        self._counter = counter
        self._idle_timeout = idle_timeout
        self._clock = clock
        self._last = clock()
        self._locked = False

    # ---- state -------------------------------------------------------
    @property
    def locked(self) -> bool:
        return self._locked

    def lock(self) -> None:
        """Wipe the vault key and drop all plaintext."""
        crypto.wipe(self._vk)
        for e in self._entries:
            e["password"] = ""
        self._entries.clear()
        self._locked = True

    def _require(self) -> None:
        if not self._locked and self._clock() - self._last > self._idle_timeout:
            self.lock()
        if self._locked:
            raise SessionLocked("session is locked")
        self._last = self._clock()

    # ---- reading -----------------------------------------------------
    def list_entries(self) -> list[dict]:
        """Summaries only: the password field is never included."""
        self._require()
        return [
            {k: e[k] for k in ("id", "name", "username", "url", "modified")}
            for e in sorted(self._entries, key=lambda e: e["name"].casefold())
        ]

    def get_entry(self, ref: str) -> dict:
        self._require()
        return copy.deepcopy(self._find(ref))

    def _find(self, ref: str) -> dict:
        for e in self._entries:
            if e["id"] == ref:
                return e
        matches = [e for e in self._entries if e["name"].casefold() == ref.casefold()]
        if len(matches) == 1:
            return matches[0]
        raise EntryError("no such entry")

    # ---- mutating ----------------------------------------------------
    def _mutate(self, change) -> None:
        snapshot = copy.deepcopy(self._entries)
        try:
            change()
            self._save()
        except BaseException:
            self._entries[:] = snapshot
            raise

    def add_entry(self, name: str, username: str, password: str, url: str = "",
                  notes: str = "", tags: list[str] | None = None) -> str:
        self._require()
        name = name.strip()
        if not name:
            raise EntryError("name must not be empty")
        if any(e["name"].casefold() == name.casefold() for e in self._entries):
            raise EntryError("an entry with that name already exists")
        stamp = _now()
        entry = {
            "id": secrets.token_hex(8), "name": name, "username": username,
            "password": password, "url": url, "notes": notes,
            "tags": list(tags or []), "created": stamp, "modified": stamp,
        }
        self._mutate(lambda: self._entries.append(entry))
        return entry["id"]

    def update_entry(self, ref: str, **fields) -> None:
        self._require()
        allowed = {"name", "username", "password", "url", "notes", "tags"}
        if not fields or set(fields) - allowed:
            raise EntryError("nothing valid to update")
        target = self._find(ref)

        def change():
            target.update(fields)
            target["modified"] = _now()

        self._mutate(change)

    def delete_entry(self, ref: str) -> None:
        self._require()
        target = self._find(ref)
        self._mutate(lambda: self._entries.remove(target))

    def _save(self) -> None:
        h = self._hdr
        body = {"entries": self._entries, "counter": self._counter + 1}
        plain = bytearray(json.dumps(body, separators=(",", ":")).encode("utf-8"))
        try:
            aad = crypto.header_aad(h.m_kib, h.t, h.p, h.salt)
            nonce, ct = crypto.encrypt(self._vk, plain, aad)  # fresh nonce on every save
        finally:
            crypto.wipe(plain)
        new_hdr = replace(h, body_nonce=nonce, body_ct=ct)
        storage.write_vault(self._path, new_hdr)
        self._hdr = new_hdr
        self._counter += 1

    # ---- master password change -------------------------------------
    def change_password(self, old_password: bytearray, new_password: bytearray) -> None:
        """Re-derive the KEK and re-wrap the same vault key.

        The vault key itself does not change. The header (including the salt) is
        bound as AAD to the body, so the body is re-encrypted too; this is cheap
        because the entries are already in memory.
        """
        self._require()
        kek_old = kek_new = None
        try:
            h = self._hdr
            try:
                kek_old = crypto.derive_kek(old_password, h.salt, h.m_kib, h.t, h.p)
                aad_old = crypto.header_aad(h.m_kib, h.t, h.p, h.salt)
                vk = crypto.decrypt(kek_old, h.wrapped_nonce, h.wrapped_ct, aad_old)
            except crypto.CryptoError:
                raise UnlockError("cannot unlock") from None
            if not hmac.compare_digest(vk, bytes(self._vk)):
                raise UnlockError("cannot unlock")
            check_strength(new_password)

            m, t, p = crypto.DEFAULT_KDF
            salt = crypto.random_salt()
            kek_new = crypto.derive_kek(new_password, salt, m, t, p)
            aad_new = crypto.header_aad(m, t, p, salt)
            w_nonce, w_ct = crypto.encrypt(kek_new, self._vk, aad_new)

            plain = bytearray(json.dumps(
                {"entries": self._entries, "counter": self._counter + 1},
                separators=(",", ":")).encode("utf-8"))
            try:
                b_nonce, b_ct = crypto.encrypt(self._vk, plain, aad_new)
            finally:
                crypto.wipe(plain)

            new_hdr = storage.VaultFile(m, t, p, salt, w_nonce, w_ct, b_nonce, b_ct)
            storage.write_vault(self._path, new_hdr)
            self._hdr = new_hdr
            self._counter += 1
        finally:
            for secret in (old_password, new_password, kek_old, kek_new):
                crypto.wipe(secret)


def create_vault(path: str, password: bytearray, kdf: tuple[int, int, int] = crypto.DEFAULT_KDF,
                 **session_kwargs) -> Session:
    """Create a new vault. The password buffer is wiped before returning."""
    kek = None
    try:
        if storage.exists(path):
            raise VaultExistsError("a vault already exists at that path")
        check_strength(password)
        m, t, p = kdf
        salt = crypto.random_salt()
        kek = crypto.derive_kek(password, salt, m, t, p)
        aad = crypto.header_aad(m, t, p, salt)
        vk = crypto.random_key()
        w_nonce, w_ct = crypto.encrypt(kek, vk, aad)
        header = storage.VaultFile(m, t, p, salt, w_nonce, w_ct, b"\x00" * crypto.NONCE_LEN, b"\x00" * 16)
        session = Session(path, vk, header, [], 0, **session_kwargs)
        session._save()  # writes the real (empty) body
        return session
    finally:
        crypto.wipe(password)
        crypto.wipe(kek)


def unlock(path: str, password: bytearray, **session_kwargs) -> Session:
    """Open an existing vault. Every failure is the same generic UnlockError.

    A missing file raises FileNotFoundError so the CLI can suggest `init`.
    The password buffer is wiped before returning.
    """
    kek = vk = None
    ok = False
    try:
        try:
            vf = storage.read_vault(path)
            crypto.check_kdf_params(vf.m_kib, vf.t, vf.p)  # enforced minimums: no downgrade
            kek = crypto.derive_kek(password, vf.salt, vf.m_kib, vf.t, vf.p)
            aad = crypto.header_aad(vf.m_kib, vf.t, vf.p, vf.salt)
            vk = bytearray(crypto.decrypt(kek, vf.wrapped_nonce, vf.wrapped_ct, aad))
            body = json.loads(crypto.decrypt(vk, vf.body_nonce, vf.body_ct, aad).decode("utf-8"))
            entries, counter = _validate_body(body)  # authenticate first, parse after
        except FileNotFoundError:
            raise
        except (storage.StorageError, crypto.CryptoError, ValueError, OSError):
            raise UnlockError("cannot unlock") from None
        session = Session(path, vk, vf, entries, counter, **session_kwargs)
        ok = True
        return session
    finally:
        crypto.wipe(password)
        crypto.wipe(kek)
        if not ok:
            crypto.wipe(vk)


class Unlocker:
    """Exponential back-off between failed unlock attempts within one run."""

    def __init__(self, path: str, sleep=None):
        self.path = path
        self.failures = 0
        self._sleep = sleep

    def unlock(self, password: bytearray, **session_kwargs) -> Session:
        if self.failures:
            (self._sleep or time.sleep)(min(2 ** (self.failures - 1), MAX_BACKOFF_S))
        try:
            session = unlock(self.path, password, **session_kwargs)
        except UnlockError:
            self.failures += 1
            raise
        self.failures = 0
        return session
