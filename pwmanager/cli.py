"""Interface component: a thin shell.

Parses commands, prompts for secrets without echo, prints results and handles
the clipboard. No crypto and no direct file I/O of the vault.
"""
from __future__ import annotations

import argparse
import getpass
import os
import shutil
import subprocess
import sys
import time

from . import crypto, users

CLIPBOARD_CLEAR_S = 20
UNLOCK_ATTEMPTS = 3
DEFAULT_VAULT = os.path.join("~", ".pwmanager", "vault.pwm")


# ---- process hardening (design V4) ---------------------------------------
def harden_process() -> None:
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            import ctypes
            ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0
        except Exception:
            pass


# ---- secret input -----------------------------------------------------------
def prompt_secret(label: str) -> bytearray:
    """No-echo prompt. Returned as a bytearray so callers can wipe it."""
    return bytearray(getpass.getpass(label).encode("utf-8"))


def vault_path(arg: str | None) -> str:
    return os.path.abspath(os.path.expanduser(arg or os.environ.get("PWM_VAULT") or DEFAULT_VAULT))


def open_session(path: str):
    unlocker = users.Unlocker(path)
    for _ in range(UNLOCK_ATTEMPTS):
        try:
            return unlocker.unlock(prompt_secret("Master password: "))
        except FileNotFoundError:
            print(f"error: no vault at {path}. Run 'init' first.", file=sys.stderr)
            return None
        except users.UnlockError:
            print("error: cannot unlock", file=sys.stderr)
    return None


# ---- clipboard (design I2) --------------------------------------------------
def _clipboard_cmds():
    if sys.platform == "darwin":
        return ["pbcopy"], ["pbpaste"]
    if sys.platform.startswith("win"):
        return ["clip"], ["powershell", "-NoProfile", "-Command", "Get-Clipboard"]
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
        return ["wl-copy"], ["wl-paste", "-n"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard"], ["xclip", "-selection", "clipboard", "-o"]
    if shutil.which("xsel"):
        return ["xsel", "-b", "-i"], ["xsel", "-b", "-o"]
    return None


def _clip_set(cmd, value: str) -> None:
    subprocess.run(cmd, input=value.encode("utf-8"), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _clip_get(cmd) -> str:
    out = subprocess.run(cmd, check=True, capture_output=True)
    return out.stdout.decode("utf-8", "replace")


def copy_with_autoclear(value: str) -> bool:
    cmds = _clipboard_cmds()
    if cmds is None:
        print("error: no clipboard tool found (install xclip, xsel or wl-clipboard)", file=sys.stderr)
        return False
    copy_cmd, paste_cmd = cmds
    try:
        _clip_set(copy_cmd, value)
    except (OSError, subprocess.CalledProcessError):
        print("error: could not access the clipboard", file=sys.stderr)
        return False
    print(f"Copied. Clipboard clears in {CLIPBOARD_CLEAR_S}s (Ctrl+C clears now).")
    try:
        time.sleep(CLIPBOARD_CLEAR_S)
    except KeyboardInterrupt:
        pass
    try:
        if _clip_get(paste_cmd).strip() == value:  # only clear if it is still ours
            _clip_set(copy_cmd, "")
    except (OSError, subprocess.CalledProcessError):
        pass
    return True


# ---- commands -------------------------------------------------------------------
def cmd_init(args) -> int:
    path = vault_path(args.vault)
    for _ in range(UNLOCK_ATTEMPTS):
        first = prompt_secret("New master password: ")
        second = prompt_secret("Repeat master password: ")
        if first != second:
            print("error: passwords do not match", file=sys.stderr)
            crypto.wipe(first)
            crypto.wipe(second)
            continue
        crypto.wipe(second)
        try:
            session = users.create_vault(path, first)
        except users.WeakPasswordError as exc:
            print(f"error: {exc}", file=sys.stderr)
            continue
        except users.VaultExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        session.lock()
        print(f"Vault created at {path}")
        print("There is no recovery: if you forget the master password the data is lost.")
        return 0
    return 1


def cmd_add(args) -> int:
    session = open_session(vault_path(args.vault))
    if session is None:
        return 1
    try:
        secret = prompt_secret("Entry password (empty = generate): ")
        if secret:
            password = bytes(secret).decode("utf-8", "replace")
            generated = False
        else:
            password = crypto.generate_password(args.length, symbols=not args.no_symbols)
            generated = True
        crypto.wipe(secret)
        tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else []
        session.add_entry(args.name, args.username or "", password, args.url or "", args.notes or "", tags)
        print(f"Saved '{args.name}'." + (" A password was generated (use 'get --copy')." if generated else ""))
        return 0
    except users.EntryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        session.lock()


def cmd_list(args) -> int:
    session = open_session(vault_path(args.vault))
    if session is None:
        return 1
    try:
        rows = session.list_entries()
    finally:
        session.lock()
    if not rows:
        print("(vault is empty)")
        return 0
    widths = [max(len(h), *(len(r[k]) for r in rows)) for h, k in
              (("NAME", "name"), ("USERNAME", "username"), ("URL", "url"), ("MODIFIED", "modified"))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format("NAME", "USERNAME", "URL", "MODIFIED"))
    for r in rows:
        print(fmt.format(r["name"], r["username"], r["url"], r["modified"]))
    return 0


def cmd_get(args) -> int:
    session = open_session(vault_path(args.vault))
    if session is None:
        return 1
    try:
        entry = session.get_entry(args.name)
    except users.EntryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        session.lock()
    try:
        print(f"name:      {entry['name']}")
        print(f"username:  {entry['username']}")
        print(f"url:       {entry['url']}")
        if entry["tags"]:
            print(f"tags:      {', '.join(entry['tags'])}")
        if entry["notes"]:
            print(f"notes:     {entry['notes']}")
        if args.show:
            print(f"password:  {entry['password']}")
        else:
            print("password:  ******** (use --copy, or --show to display)")
        if args.copy:
            return 0 if copy_with_autoclear(entry["password"]) else 1
        return 0
    finally:
        entry["password"] = ""


def cmd_rm(args) -> int:
    session = open_session(vault_path(args.vault))
    if session is None:
        return 1
    try:
        if not args.yes and input(f"Delete '{args.name}'? [y/N] ").strip().lower() != "y":
            print("Cancelled.")
            return 0
        session.delete_entry(args.name)
        print("Deleted.")
        return 0
    except users.EntryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        session.lock()


def cmd_passwd(args) -> int:
    path = vault_path(args.vault)
    session = open_session(path)
    if session is None:
        return 1
    try:
        old = prompt_secret("Current master password (again): ")
        new = prompt_secret("New master password: ")
        again = prompt_secret("Repeat new master password: ")
        if new != again:
            print("error: passwords do not match", file=sys.stderr)
            crypto.wipe(old)
            crypto.wipe(new)
            return 1
        crypto.wipe(again)
        session.change_password(old, new)
        print("Master password changed.")
        return 0
    except users.UnlockError:
        print("error: cannot unlock", file=sys.stderr)
        return 1
    except users.WeakPasswordError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        session.lock()


def cmd_gen(args) -> int:
    print(crypto.generate_password(args.length, symbols=not args.no_symbols))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwmanager", description="Local offline password manager.")
    p.add_argument("--vault", help=f"vault file (default: $PWM_VAULT or {DEFAULT_VAULT})")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)

    a = sub.add_parser("add", help="add an entry (secrets are prompted, never arguments)")
    a.add_argument("name")
    a.add_argument("--username")
    a.add_argument("--url")
    a.add_argument("--notes")
    a.add_argument("--tags", help="comma separated")
    a.add_argument("--length", type=int, default=20, help="length if generating (default 20)")
    a.add_argument("--no-symbols", action="store_true")
    a.set_defaults(func=cmd_add)

    sub.add_parser("list", help="list entries (no passwords)").set_defaults(func=cmd_list)

    g = sub.add_parser("get", help="show an entry; password hidden by default")
    g.add_argument("name")
    g.add_argument("--show", action="store_true", help="print the password in cleartext")
    g.add_argument("--copy", action="store_true", help="copy password to clipboard, auto-clear after 20s")
    g.set_defaults(func=cmd_get)

    r = sub.add_parser("rm", help="delete an entry")
    r.add_argument("name")
    r.add_argument("-y", "--yes", action="store_true")
    r.set_defaults(func=cmd_rm)

    sub.add_parser("passwd", help="change the master password").set_defaults(func=cmd_passwd)

    gen = sub.add_parser("gen", help="print a random password")
    gen.add_argument("--length", type=int, default=20)
    gen.add_argument("--no-symbols", action="store_true")
    gen.set_defaults(func=cmd_gen)
    return p


def main(argv=None) -> int:
    harden_process()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # generic text only: never echo data that could hold secrets
        print(f"error: operation failed ({type(exc).__name__})", file=sys.stderr)
        return 1
