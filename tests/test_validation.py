import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from d13dp.policy import PROFILE_DIR, load_policy_file
from d13dp.render import write_generated


class ValidationTests(unittest.TestCase):
    def test_invalid_profile_schema(self):
        original = (PROFILE_DIR / "minimal.toml").read_text()
        cases = [
            ('name = "minimal"', 'name = 123'),
            ('name = "minimal"', 'name = "../escape"'),
            ('description = "Minimal Debian 13 VPS, SSH only"', 'description = []'),
            ('description = "Minimal Debian 13 VPS, SSH only"', 'description = ""'),
            ('[ssh]', 'ssh = 1\n[other]'),
            ('port = 22', 'port = true'),
            ('port = 22', 'port = 0'),
            ('root_login = "prohibit-password"', 'root_login = []'),
            ('root_login = "prohibit-password"', 'root_login = "yes"'),
            ('login_grace_seconds = 45', 'login_grace_seconds = 121'),
            ('mode = "standalone"', 'mode = []'),
            ('inbound_tcp = [22]', 'inbound_tcp = [[22]]'),
            ('inbound_tcp = [22]', 'inbound_tcp = [true]'),
            ('inbound_tcp = [22]', 'inbound_tcp = [22, 22]'),
            ('inbound_tcp = [22]', 'inbound_tcp = [80]'),
            ('inbound_tcp = [22]', 'inbound_tcp = [0, 22]'),
            ('inbound_tcp = [22]', 'inbound_tcp = [22, 65536]'),
            ('inbound_tcp = [22]', 'inbound_tcp = []'),
            ('inbound_tcp = [22]', 'inbound_tcp = "22"'),
            ('nftables = true', 'nftables = "true"'),
            ('nftables = true', 'nftable = true'),
            ('mode = "standalone"', 'mode = "external"'),
            ('port = 22', 'port = 22\nport_typo = 23'),
            ('name = "minimal"', 'name = "minimal"\nunknown = 1'),
            ('name = "minimal"', ''),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "bad.toml"
            for before, after in cases:
                with self.subTest(replacement=after):
                    config.write_text(original.replace(before, after))
                    with self.assertRaises(ValueError):
                        load_policy_file(config)

    def test_symlink_directories_are_rejected(self):
        for placement in ("root", "ancestor", "nested", "dangling"):
            with self.subTest(placement=placement), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                outside = root / "outside"
                outside.mkdir()
                out = root / "output"
                if placement in {"root", "ancestor"}:
                    out.symlink_to(outside, target_is_directory=True)
                    if placement == "ancestor":
                        out /= "child"
                else:
                    out.mkdir()
                    (out / "ssh").symlink_to(outside if placement == "nested" else root / "missing", target_is_directory=True)
                with self.assertRaises(ValueError):
                    write_generated({"ssh/test.conf": "data"}, out, replace=True)
                self.assertEqual(list(outside.iterdir()), [])

    def test_file_symlink_rejected_even_with_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "victim"
            victim.write_text("keep")
            out = root / "out"
            out.mkdir()
            (out / "target").symlink_to(victim)
            with self.assertRaises(ValueError):
                write_generated({"target": "overwrite"}, out, replace=True)
            self.assertEqual(victim.read_text(), "keep")

    def test_escaping_paths_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            for name in ("../escape", "/absolute", "", "."):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    write_generated({"a/ok": "ok", name: "bad"}, out)
                self.assertFalse(out.exists())

    def test_non_utf8_and_crlf_files_are_preserved_without_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for previous in (b"\xff", b"content\r\n"):
                with self.subTest(previous=previous):
                    (out / "file").write_bytes(previous)
                    with self.assertRaises(ValueError):
                        write_generated({"file": "content\n"}, out)
                    self.assertEqual((out / "file").read_bytes(), previous)
                    write_generated({"file": "content\n"}, out, replace=True)
                    self.assertEqual((out / "file").read_bytes(), b"content\n")

    def test_temp_file_removed_after_failed_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            with patch("d13dp.render.os.fsync", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    write_generated({"file": "content"}, out)
            self.assertEqual(list(out.iterdir()), [])

    def test_non_directory_parent_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "z").write_text("keep")
            with self.assertRaises(ValueError):
                write_generated({"a/file": "first", "z/file": "last"}, out)
            self.assertFalse((out / "a").exists())
