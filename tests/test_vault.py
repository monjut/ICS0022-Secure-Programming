"""Checkpoint 2 tests. Run with: python -m unittest discover -s tests -v"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from pwmanager import cli, crypto, storage, users

PW = "correct horse battery 42"
FAST = (crypto.MIN_M_KIB, crypto.MIN_T, crypto.MIN_P)  # keep the suite quick


def pw(text: str = PW) -> bytearray:
    return bytearray(text.encode())


def edit_file(path, fn):
    with open(path) as f:
        doc = json.load(f)
    fn(doc)
    with open(path, "w") as f:
        json.dump(doc, f)


def flip(b64: str) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode()


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "vault", "vault.pwm")

    def make(self, **kw):
        return users.create_vault(self.path, pw(), kdf=FAST, **kw)

    def unlock(self, password=PW):
        return users.unlock(self.path, pw(password))


class RoundTrip(VaultTestCase):
    def test_create_add_reopen(self):
        s = self.make()
        s.add_entry("GitHub", "alice", "s3cret-pass!", url="https://github.com", tags=["dev"])
        s.lock()
        s2 = self.unlock()
        e = s2.get_entry("github")  # case-insensitive
        self.assertEqual((e["username"], e["password"], e["tags"]), ("alice", "s3cret-pass!", ["dev"]))

    def test_list_never_contains_passwords(self):
        s = self.make()
        s.add_entry("A", "u", "topsecretvalue")
        rows = s.list_entries()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("password", rows[0])
        self.assertNotIn("topsecretvalue", json.dumps(rows))

    def test_update_and_delete(self):
        s = self.make()
        s.add_entry("A", "u", "p1")
        s.update_entry("A", password="p2")
        self.assertEqual(self.unlock().get_entry("A")["password"], "p2")
        s.delete_entry("A")
        with self.assertRaises(users.EntryError):
            self.unlock().get_entry("A")

    def test_duplicate_name_rejected(self):
        s = self.make()
        s.add_entry("A", "u", "p")
        with self.assertRaises(users.EntryError):
            s.add_entry("a", "u", "p")


class AtRest(VaultTestCase):
    def test_file_contains_no_plaintext(self):
        s = self.make()
        s.add_entry("UniqueSiteName", "unique_user_name", "unique-password-value", notes="unique note text")
        raw = open(self.path, "rb").read()
        for needle in (b"UniqueSiteName", b"unique_user_name", b"unique-password-value", b"unique note text"):
            self.assertNotIn(needle, raw)

    def test_fresh_nonce_each_save(self):
        s = self.make()
        s.add_entry("A", "u", "p")
        n1 = storage.read_vault(self.path).body_nonce
        s.add_entry("B", "u", "p")
        n2 = storage.read_vault(self.path).body_nonce
        self.assertNotEqual(n1, n2)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_permissions(self):
        self.make()
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(self.path)).st_mode & 0o777, 0o700)

    def test_backup_written_on_second_save(self):
        s = self.make()
        s.add_entry("A", "u", "p")
        self.assertTrue(os.path.exists(self.path + ".bak"))
        storage.parse(open(self.path + ".bak", "rb").read())  # still a valid vault file

    def test_failed_write_keeps_old_file_and_memory_state(self):
        s = self.make()
        s.add_entry("A", "u", "p")
        before = open(self.path, "rb").read()
        with mock.patch("pwmanager.storage.os.replace", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                s.add_entry("B", "u", "p")
        self.assertEqual(open(self.path, "rb").read(), before)
        self.assertEqual([e["name"] for e in s.list_entries()], ["A"])
        leftovers = [f for f in os.listdir(os.path.dirname(self.path)) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_refuses_to_overwrite_existing_vault(self):
        self.make()
        with self.assertRaises(users.VaultExistsError):
            users.create_vault(self.path, pw(), kdf=FAST)


class Authentication(VaultTestCase):
    def test_wrong_password(self):
        self.make()
        with self.assertRaises(users.UnlockError):
            self.unlock("this is not the password")

    def test_missing_file_is_distinct_for_cli_hint(self):
        with self.assertRaises(FileNotFoundError):
            self.unlock()

    def test_weak_passwords_rejected(self):
        for bad in ("short", "aaaaaaaaaaaaaaaa", "password123", "correcthorsebatterystaple"):
            with self.assertRaises(users.WeakPasswordError, msg=bad):
                users.create_vault(self.path, pw(bad), kdf=FAST)
        self.assertFalse(os.path.exists(self.path))

    def test_password_buffer_is_wiped(self):
        buf = pw()
        users.create_vault(self.path, buf, kdf=FAST)
        self.assertEqual(bytes(buf), bytes(len(buf)))
        buf2 = pw()
        users.unlock(self.path, buf2)
        self.assertEqual(bytes(buf2), bytes(len(buf2)))

    def test_backoff_between_failed_attempts(self):
        self.make()
        sleeps = []
        u = users.Unlocker(self.path, sleep=sleeps.append)
        for _ in range(2):
            with self.assertRaises(users.UnlockError):
                u.unlock(pw("wrong wrong wrong"))
        u.unlock(pw())
        self.assertEqual(sleeps, [1, 2])
        self.assertEqual(u.failures, 0)


class Tamper(VaultTestCase):
    """Every modification must fail closed with the same generic error."""

    def setUp(self):
        super().setUp()
        s = self.make()
        s.add_entry("A", "u", "p")
        s.lock()

    def assert_fails(self, fn):
        edit_file(self.path, fn)
        with self.assertRaises(users.UnlockError):
            self.unlock()

    def test_flip_salt(self):
        self.assert_fails(lambda d: d["kdf"].__setitem__("salt", flip(d["kdf"]["salt"])))

    def test_flip_wrapped_nonce(self):
        self.assert_fails(lambda d: d["wrapped_key"].__setitem__("nonce", flip(d["wrapped_key"]["nonce"])))

    def test_flip_wrapped_ct(self):
        self.assert_fails(lambda d: d["wrapped_key"].__setitem__("ct", flip(d["wrapped_key"]["ct"])))

    def test_flip_body_nonce(self):
        self.assert_fails(lambda d: d["body"].__setitem__("nonce", flip(d["body"]["nonce"])))

    def test_flip_body_ct(self):
        self.assert_fails(lambda d: d["body"].__setitem__("ct", flip(d["body"]["ct"])))

    def test_change_kdf_time_cost(self):
        self.assert_fails(lambda d: d["kdf"].__setitem__("t", d["kdf"]["t"] + 1))

    def test_downgrade_below_minimum(self):
        self.assert_fails(lambda d: d["kdf"].__setitem__("m_kib", 1024))

    def test_absurd_memory_cost_rejected(self):
        self.assert_fails(lambda d: d["kdf"].__setitem__("m_kib", 1 << 30))

    def test_bad_version_and_magic(self):
        self.assert_fails(lambda d: d.__setitem__("version", 2))
        self.assert_fails(lambda d: d.__setitem__("magic", "NOPE"))

    def test_extra_or_missing_fields(self):
        self.assert_fails(lambda d: d.__setitem__("extra", 1))

    def test_garbage_file(self):
        with open(self.path, "wb") as f:
            f.write(b"\x00\xff not json")
        with self.assertRaises(users.UnlockError):
            self.unlock()

    def test_error_text_identical_for_wrong_password_and_corruption(self):
        with self.assertRaises(users.UnlockError) as wrong:
            self.unlock("this is not the password")
        edit_file(self.path, lambda d: d["body"].__setitem__("ct", flip(d["body"]["ct"])))
        with self.assertRaises(users.UnlockError) as corrupt:
            self.unlock()
        self.assertEqual(str(wrong.exception), str(corrupt.exception))


class SessionLifecycle(VaultTestCase):
    def test_lock_wipes_key_and_blocks_access(self):
        s = self.make()
        s.add_entry("A", "u", "p")
        vk = s._vk
        s.lock()
        self.assertEqual(bytes(vk), bytes(len(vk)))
        self.assertTrue(s.locked)
        with self.assertRaises(users.SessionLocked):
            s.list_entries()
        with self.assertRaises(users.SessionLocked):
            s.add_entry("B", "u", "p")

    def test_idle_timeout_locks(self):
        now = [0.0]
        s = self.make(idle_timeout=10, clock=lambda: now[0])
        s.add_entry("A", "u", "p")
        now[0] = 5
        s.list_entries()  # activity resets the timer
        now[0] = 14
        s.list_entries()
        now[0] = 100
        with self.assertRaises(users.SessionLocked):
            s.list_entries()

    def test_change_master_password(self):
        s = self.make()
        s.add_entry("A", "u", "keepme")
        s.change_password(pw(), pw("a brand new passphrase 99"))
        with self.assertRaises(users.UnlockError):
            self.unlock()
        self.assertEqual(self.unlock("a brand new passphrase 99").get_entry("A")["password"], "keepme")

    def test_change_master_password_checks_old_and_strength(self):
        s = self.make()
        with self.assertRaises(users.UnlockError):
            s.change_password(pw("not the old password"), pw("a brand new passphrase 99"))
        with self.assertRaises(users.WeakPasswordError):
            s.change_password(pw(), pw("short"))
        self.unlock()  # unchanged


class Generator(unittest.TestCase):
    def test_length_and_classes(self):
        for _ in range(50):
            p = crypto.generate_password(20)
            self.assertEqual(len(p), 20)
            self.assertTrue(any(c.islower() for c in p) and any(c.isupper() for c in p))
            self.assertTrue(any(c.isdigit() for c in p) and any(not c.isalnum() for c in p))

    def test_no_symbols_option(self):
        self.assertTrue(crypto.generate_password(30, symbols=False).isalnum())

    def test_too_short(self):
        with self.assertRaises(ValueError):
            crypto.generate_password(4)


class CliNeverPrintsPasswords(VaultTestCase):
    def run_cli(self, argv, secrets):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("pwmanager.cli.getpass.getpass", side_effect=list(secrets)), \
                mock.patch("pwmanager.users.time.sleep"), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--vault", self.path] + argv)
        return code, out.getvalue(), err.getvalue()

    def test_flow(self):
        entry_pw = "entry-pass-VALUE-1234"
        self.assertEqual(self.run_cli(["init"], [PW, PW])[0], 0)
        self.assertEqual(self.run_cli(["add", "Site", "--username", "bob"], [PW, entry_pw])[0], 0)

        code, out, err = self.run_cli(["list"], [PW])
        self.assertEqual(code, 0)
        self.assertIn("Site", out)
        self.assertNotIn(entry_pw, out + err)

        code, out, err = self.run_cli(["get", "Site"], [PW])
        self.assertEqual(code, 0)
        self.assertNotIn(entry_pw, out + err)
        self.assertIn("********", out)

        code, out, _ = self.run_cli(["get", "Site", "--show"], [PW])
        self.assertIn(entry_pw, out)

    def test_wrong_master_password_prints_nothing_sensitive(self):
        self.run_cli(["init"], [PW, PW])
        code, out, err = self.run_cli(["list"], ["wrong one 1", "wrong one 2", "wrong one 3"])
        self.assertEqual(code, 1)
        self.assertIn("cannot unlock", err)
        self.assertEqual(out, "")

    def test_generated_password_not_printed(self):
        self.run_cli(["init"], [PW, PW])
        code, out, err = self.run_cli(["add", "Gen"], [PW, ""])
        self.assertEqual(code, 0)
        stored = self.unlock().get_entry("Gen")["password"]
        self.assertEqual(len(stored), 20)
        self.assertNotIn(stored, out + err)


if __name__ == "__main__":
    unittest.main()
