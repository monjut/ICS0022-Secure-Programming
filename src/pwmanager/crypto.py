"""Encryption module. The ONLY module that touches keys, KDFs, ciphers or the RNG.

Planned API (Checkpoint 2):
    derive_kek(password: bytearray, salt: bytes, params: KdfParams) -> bytearray
    new_vault_key() -> bytearray
    wrap_key(kek, vault_key, aad) -> (nonce, ciphertext)
    unwrap_key(kek, nonce, ciphertext, aad) -> bytearray   # raises DecryptionError
    encrypt(vault_key, plaintext, aad) -> (nonce, ciphertext)
    decrypt(vault_key, nonce, ciphertext, aad) -> bytes     # raises DecryptionError
    wipe(buf: bytearray) -> None
"""
