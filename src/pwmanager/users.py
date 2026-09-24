"""User-management module: master credential lifecycle and unlocked session.

Planned API (Checkpoint 2):
    create_vault(path, password)              # first-run setup
    unlock(path, password) -> Session         # derives KEK, unwraps vault key, decrypts entries
    change_master_password(session, new_password)
    Session.lock()                            # wipes keys and decrypted entries
    Session idle timeout and failed-attempt back-off
"""
