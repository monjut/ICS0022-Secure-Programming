# Password Manager

A local, offline, single-user command-line password manager. Credentials live in one
encrypted vault file. Design: see Checkpoint 1 (Argon2id + AES-256-GCM, two-level key hierarchy).

## Requirements

- Python 3.11 or newer
- `pip` (dependencies: `cryptography`, `argon2-cffi`; both ship prebuilt wheels for Windows, macOS and Linux)
- Optional, for `get --copy`: a clipboard tool. macOS (`pbcopy`) and Windows (`clip`) work out of the box;
  on Linux install `xclip`, `xsel` or `wl-clipboard`.

## Build and run (clean machine)

```bash
git clone <repo-url> pwmanager && cd pwmanager

python3 -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

python -m unittest discover -s tests -v      # run the test suite (takes a few seconds)
python -m pwmanager --help
```

In VS Code: open the folder, run **Python: Select Interpreter** and pick `.venv`, then use the
integrated terminal for the commands above.

## Usage

The vault defaults to `~/.pwmanager/vault.pwm`. Override with `--vault PATH` or the `PWM_VAULT`
environment variable (a path, never a secret).

```bash
python -m pwmanager init                       # create the vault (asks for a master password, min 12 chars)
python -m pwmanager add GitHub --username alice --url https://github.com
                                               # prompts for the entry password; leave empty to generate one
python -m pwmanager list                       # names, usernames, URLs; never passwords
python -m pwmanager get GitHub                 # password shown as ********
python -m pwmanager get GitHub --copy          # clipboard, auto-cleared after 20 s
python -m pwmanager get GitHub --show          # explicit cleartext, only when you ask for it
python -m pwmanager passwd                     # change the master password
python -m pwmanager rm GitHub
python -m pwmanager gen --length 24            # standalone password generator
```

Example vault for a throwaway try-out: `python -m pwmanager --vault ./demo.pwm init`
(`*.pwm` files are git-ignored).

## Security notes

- Passwords are only read from a no-echo prompt, never from command-line arguments or environment variables.
- Passwords are never printed unless you pass `--show`.
- There is **no recovery**: a forgotten master password means the data is gone.
- Three wrong master passwords end the command, with exponentially growing delays between tries.
- Vault file and its `.bak` are created with mode 0600 inside a 0700 directory (POSIX).

## Layout

| File | Role |
|---|---|
| `pwmanager/cli.py` | Interface: commands, prompts, clipboard |
| `pwmanager/users.py` | Master credential lifecycle, session, back-off, idle timeout |
| `pwmanager/crypto.py` | Argon2id, AES-256-GCM, RNG, wiping, generator |
| `pwmanager/storage.py` | File parsing/validation, atomic writes, backup, permissions |
| `tests/test_vault.py` | Round-trip, tamper, downgrade, wrong-password, CLI no-leak tests |
