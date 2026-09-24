"""Storage layer. Reads/writes the vault file; never sees plaintext or keys.

Planned API (Checkpoint 2):
    read_vault(path) -> VaultFile          # parse + validate header, no decryption
    write_vault(path, VaultFile) -> None   # temp file + fsync + atomic rename, mode 0600, keeps .bak
"""
