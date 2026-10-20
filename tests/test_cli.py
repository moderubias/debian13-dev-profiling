from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from d13dp.cli import main


class CliTests(unittest.TestCase):
    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = main(list(args))
        return status, out.getvalue(), err.getvalue()

    def test_profiles_plan_and_manifest(self):
        for profile in ("minimal", "web", "docker"):
            with self.subTest(profile=profile):
                status, output, _ = self.invoke("plan", "--profile", profile)
                self.assertEqual(status, 0)
                self.assertIn(f"Profile: {profile}", output)
                status, output, _ = self.invoke("manifest", "--profile", profile)
                self.assertEqual(status, 0)
                self.assertTrue(json.loads(output))

    def test_bad_configs_fail_without_tracebacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "bad.toml"
            for content in (b'name = 123', b'not toml', b'\xff'):
                config.write_bytes(content)
                for command in ("plan", "render", "manifest"):
                    with self.subTest(command=command, content=content):
                        status, _, error = self.invoke(command, "--config", str(config))
                        self.assertEqual(status, 1)
                        self.assertIn("Invalid profile:", error)
                        self.assertNotIn("Traceback", error)
            status, _, error = self.invoke("plan", "--config", str(config / "missing"))
            self.assertEqual(status, 1)

    def test_profile_and_config_are_mutually_exclusive(self):
        for command in ("plan", "render", "manifest"):
            with self.subTest(command=command), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                main([command, "--profile", "web", "--config", "custom.toml"])
            self.assertEqual(caught.exception.code, 2)

    def test_render_conflict_and_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = ("render", "--output", tmp)
            self.assertEqual(self.invoke(*args)[0], 0)
            target = Path(tmp) / "ssh/00-d13dp-hardening.conf"
            target.write_bytes(b"\xff")
            status, _, error = self.invoke(*args)
            self.assertEqual(status, 1)
            self.assertIn("Render aborted:", error)
            self.assertEqual(target.read_bytes(), b"\xff")
            self.assertEqual(self.invoke(*args, "--replace")[0], 0)

    @patch("d13dp.cli.collect")
    def test_audit_strict_exit_codes(self, collect):
        for severity, status, expected in (("high", "unknown", 2), ("high", "unsupported", 2), ("high", "review", 2), ("high", "fail", 2), ("high", "pass", 0), ("medium", "review", 0)):
            with self.subTest(severity=severity, status=status):
                collect.return_value = {"host": {"id": "debian", "version": "13"}, "findings": [{"id": "test", "severity": severity, "status": status, "detail": "test", "action": "review"}], "notes": []}
                code, output, _ = self.invoke("audit", "--json", "--strict")
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(output), collect.return_value)
                self.assertEqual(self.invoke("audit")[0], 0)
