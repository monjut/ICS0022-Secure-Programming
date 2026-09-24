# pwm: a local command-line password manager

Coursework project (Checkpoint 1: threat model and architecture).
**Status:** design phase. The code is a skeleton; see `docs/design.md`.

## Scope

**In scope**
- One user, one local encrypted vault file, fully offline.
- Store entries (name, username, password, URL, notes, tags); search, edit, delete.
- Generate strong random passwords.
- Change the master password without re-encrypting the whole vault.
- Authenticated encryption, so tampering with the file is detected.

**Out of scope**
- Cloud sync, multi-user sharing, browser extensions, autofill.
- Defence against a fully compromised OS (root malware, keyloggers) or physical/hardware attacks.
- Recovery of a forgotten master password (by design there is none).

## Planned commands

| Command | Purpose |
|---|---|
| `pwm init` | Create a new vault and set the master password |
| `pwm add <name>` | Add an entry (prompts for secrets, never via argv) |
| `pwm get <name>` | Show an entry; `--copy` copies the password to the clipboard and clears it after 20 s |
| `pwm list` / `pwm search <text>` | List or search entry names |
| `pwm edit <name>` / `pwm rm <name>` | Modify or delete an entry |
| `pwm gen [--length N]` | Generate a random password |
| `pwm passwd` | Change the master password |
| `pwm shell` | Interactive session with idle auto-lock (default 2 min) |

The vault path defaults to `~/.local/share/pwm/vault.vault`; override with `--vault PATH`.

## Build and run

Requires Python 3.11+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest              # run tests
pwm --help          # currently prints a "not implemented" notice
```

## Repository layout

```
src/pwmanager/crypto.py    encryption module (KDF, AEAD, key wrapping)
src/pwmanager/storage.py   storage layer (file format, atomic writes)
src/pwmanager/users.py     user management (master password, session, lock)
src/pwmanager/cli.py       interface
docs/design.md             architecture, threat model, format and crypto decisions
tests/                     unit tests
```
