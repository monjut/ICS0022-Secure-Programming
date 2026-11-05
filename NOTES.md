# Checkpoint 2 progress note (Week 9)

## Done
- **Vault storage:** single JSON file, version 1, exactly as specified in Checkpoint 1 section 3.3. Strict schema validation, size limit, atomic write (temp file, fsync, `.bak`, rename), mode 0600 in a 0700 directory.
- **Encryption at rest:** random 32-byte vault key encrypts the whole body with AES-256-GCM (fresh nonce per save). The vault key is wrapped under a key derived from the master password with Argon2id (64 MiB, t=3, p=1). The header is bound as AAD to both the wrapped key and the body.
- **Master password authentication:** the vault unlocks only if the GCM tag on the wrapped key and the body verify. Wrong password and corruption give the same generic "cannot unlock" error. Minimum KDF parameters are enforced on load (downgrade protection). Master password strength check at `init` and `passwd`. Exponential back-off between failed attempts; 3 attempts per run.
- **Interface:** CLI (`init`, `add`, `list`, `get`, `rm`, `passwd`, `gen`). Secrets are prompted without echo, `list` and `get` never show passwords unless `get --show` is given, `get --copy` uses the clipboard with a 20 s auto-clear.
- **Memory hygiene (best effort):** keys and password buffers are `bytearray`s and are wiped; `lock()` wipes the vault key and drops entries; idle timeout in the session object; core dumps disabled.
- **Tests:** `python -m unittest discover -s tests -v` covers round trip, no plaintext in the file, permissions, backup, failed-write rollback, wrong password, weak password, tampering of every header field / wrapped key / body, KDF downgrade, back-off, lock and idle timeout, master password change and that the CLI does not print passwords.

## Differences from the Checkpoint 1 design
- **Master password change** re-derives the KEK and re-wraps the same vault key, but also re-encrypts the body, because the header (including the salt) is the AAD of the body. The vault key does not change.
- Entries are decrypted all at once on unlock instead of lazily (listed as a V2 limitation).

## Not yet done (later checkpoints)
- Interactive `shell` mode with idle auto-lock (the idle timeout exists in `Session` but each command is currently a single run).
- `edit` command for changing an existing entry from the CLI (the session API `update_entry` exists and is tested).
- `mlock` on key buffers, larger common-password list, crash-during-write test with a real kill, test that no secret appears in log/exception text beyond the CLI tests.
- Open questions from Checkpoint 1 (recovery key, persisted failed-attempt counter, non-Python crypto core) remain open.
