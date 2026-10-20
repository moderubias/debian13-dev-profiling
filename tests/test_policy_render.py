import tempfile
import unittest
from pathlib import Path

from d13dp.policy import load_policy, load_policy_file
from d13dp.render import GENERATED_PATHS, generate, digest_manifest, write_generated


class PolicyRenderTests(unittest.TestCase):
    def test_profiles_are_valid(self):
        for name in ("minimal", "web", "docker"):
            with self.subTest(profile=name):
                policy = load_policy(name)
                self.assertIn(policy.ssh_port, policy.inbound_tcp)
                self.assertIn("ssh", policy.modules)

    def test_generated_paths_cover_all_bundled_artifacts(self):
        actual = set().union(*(generate(load_policy(name)) for name in ("minimal", "web", "docker")))
        self.assertEqual(actual, GENERATED_PATHS)

    def test_profile_switch_refuses_stale_firewall(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            write_generated(generate(load_policy("web")), path)
            before = {str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*") if p.is_file()}
            for replace in (False, True):
                with self.subTest(replace=replace), self.assertRaisesRegex(ValueError, "fresh output directory"):
                    write_generated(generate(load_policy("docker")), path, replace=replace)
            after = {str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*") if p.is_file()}
            self.assertEqual(before, after)

    def test_render_is_deterministic(self):
        files = generate(load_policy("web"))
        self.assertEqual(digest_manifest(files), digest_manifest(generate(load_policy("web"))))

    def test_repeating_render_does_not_rewrite(self):
        files = generate(load_policy("minimal"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            first = write_generated(files, path)
            before = {name: (path / name).stat().st_mtime_ns for name in files}
            second = write_generated(files, path)
            after = {name: (path / name).stat().st_mtime_ns for name in files}
            self.assertTrue(all(v == "written" for v in first.values()))
            self.assertTrue(all(v == "unchanged" for v in second.values()))
            self.assertEqual(before, after)

    def test_modified_generated_file_requires_replace(self):
        files = generate(load_policy("minimal"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            write_generated(files, path)
            (path / "ssh/00-d13dp-hardening.conf").write_text("user change\n")
            with self.assertRaises(ValueError):
                write_generated(files, path)
            self.assertEqual((path / "ssh/00-d13dp-hardening.conf").read_text(), "user change\n")

    def test_preflight_avoids_partial_overwrite(self):
        files = generate(load_policy("minimal"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            write_generated(files, path)
            (path / "ssh/00-d13dp-hardening.conf").write_text("user change\n")
            previous = (path / "apt/52-d13dp-security").read_text()
            altered = dict(files)
            altered["apt/52-d13dp-security"] = "new data\n"
            with self.assertRaises(ValueError):
                write_generated(altered, path)
            self.assertEqual((path / "apt/52-d13dp-security").read_text(), previous)

    def test_unsafe_custom_profile_name_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.toml"
            original = (Path(__file__).resolve().parents[1] / "src/d13dp/profiles/minimal.toml").read_text()
            path.write_text(original.replace('name = "minimal"', 'name = "../../escape"'))
            with self.assertRaises(ValueError):
                load_policy_file(path)

    def test_docker_does_not_generate_firewall(self):
        files = generate(load_policy("docker"))
        self.assertFalse(any(name.startswith("nft/") for name in files))

    def test_render_keeps_fail2ban_table_untouched(self):
        conf = generate(load_policy("minimal"))["nft/d13dp.nft"]
        self.assertNotIn("flush ruleset", conf)
        self.assertIn("destroy table inet d13dp_filter", conf)
        self.assertNotIn("f2b-table", conf)

    def test_web_profile_opens_http_https(self):
        conf = generate(load_policy("web"))["nft/d13dp.nft"]
        self.assertIn("tcp dport { 22, 80, 443 } accept", conf)


if __name__ == "__main__":
    unittest.main()
