"""hooks/pre-commit, run in temporary repositories, in both directions.

The hook is run the way git runs it: `sh hooks/pre-commit` in the root of a
repository with something staged. One test also installs it and lets
`git commit` call it.
"""

import os
import re
import shutil
import subprocess
import unittest

from support import (HOOK, clean_env, commit, google_key, init_repo, jwt,
                     pem_private_key, run_git, uri_with_credentials, write)

D = "-" * 5


def run_hook(repo, **env):
    return subprocess.run(("sh", HOOK), cwd=repo, env=clean_env(**env),
                          capture_output=True, text=True)


def stage(repo, files):
    for name, content in files.items():
        write(repo, name, content)
    run_git(repo, "add", "-A")


@unittest.skipUnless(shutil.which("sh") and shutil.which("awk"),
                     "the hook needs sh and awk")
class Shapes(unittest.TestCase):
    """Every shape the hook knows, fired one at a time."""

    CASES = {
        "URI with credentials": uri_with_credentials(),
        "PEM private key": pem_private_key(),
        "GitHub token": "gh" + "p_" + "FakeFixture" * 3,
        "Google API key": google_key(),
        "Slack token": "xo" + "xb-" + "0000-fake-fixture",
        "AWS access key": "AK" + "IA" + "FAKEFIXTURE00000",
        "JWT": jwt(),
        "high-variety value near a secret name":
            "api_key = '" + "Fq7Lm2Zx9Rk4Tw8Hv3Nc" + "'",
    }

    def test_each_shape_fires(self):
        for label, value in self.CASES.items():
            with self.subTest(label=label):
                repo = init_repo(self)
                stage(repo, {"a.txt": "first\n" + value + "\n"})
                r = run_hook(repo)
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn("a.txt:2  " + label, r.stderr)
                self.assertNotIn(value.strip(), r.stderr + r.stdout)

    def test_clean_content_passes_silently(self):
        repo = init_repo(self)
        stage(repo, {
            "config.php": "<?php\n$token = getenv('API_TOKEN');\n"
                          "define('AUTH_KEY', '');\n",
            "app.js": "export const apiKey = process.env.API_KEY;\n",
            "README.md": "Set the password in the environment.\n",
        })
        r = run_hook(repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr, "")

    def test_names_without_variety_are_not_values(self):
        repo = init_repo(self)
        stage(repo, {"a.py": "password_reset_token_lifetime = 3600\n"})
        self.assertEqual(run_hook(repo).returncode, 0)

    def test_nothing_staged(self):
        repo = init_repo(self)
        commit(repo, {"a.txt": "x\n"})
        r = run_hook(repo)
        self.assertEqual((r.returncode, r.stderr), (0, ""))


@unittest.skipUnless(shutil.which("sh") and shutil.which("awk"),
                     "the hook needs sh and awk")
class WhichFiles(unittest.TestCase):
    """The value must be found whatever the file is called and however it
    got into the index."""

    def assert_blocked(self, repo, where):
        r = run_hook(repo)
        self.assertEqual(r.returncode, 1, "hook passed: " + r.stderr)
        self.assertIn(where, r.stderr)

    def test_plain_name(self):
        repo = init_repo(self)
        stage(repo, {"a.txt": google_key() + "\n"})
        self.assert_blocked(repo, "a.txt:1")

    def test_name_with_a_space(self):
        repo = init_repo(self)
        stage(repo, {"my notes.txt": google_key() + "\n"})
        self.assert_blocked(repo, "my notes.txt:1")

    def test_name_with_non_ascii_letters(self):
        repo = init_repo(self)
        stage(repo, {"caffè.txt": google_key() + "\n"})
        self.assert_blocked(repo, ":1  Google API key")

    def test_name_that_is_a_glob(self):
        repo = init_repo(self)
        commit(repo, {"b.txt": "nothing\n"})
        stage(repo, {"*.txt": google_key() + "\n"})
        self.assert_blocked(repo, ":1  Google API key")

    def test_renamed_and_edited(self):
        repo = init_repo(self)
        commit(repo, {"cfg.txt": "".join("line %d\n" % i for i in range(40))})
        run_git(repo, "mv", "cfg.txt", "cfg2.txt")
        with open(os.path.join(repo, "cfg2.txt"), "a") as fh:
            fh.write(google_key() + "\n")
        run_git(repo, "add", "-A")
        self.assert_blocked(repo, "cfg2.txt:41")

    def test_symlink_turned_into_a_file(self):
        repo = init_repo(self)
        os.symlink("elsewhere", os.path.join(repo, "link"))
        commit(repo)
        os.remove(os.path.join(repo, "link"))
        stage(repo, {"link": google_key() + "\n"})
        self.assert_blocked(repo, "link:1")

    def test_only_the_staged_version_is_read(self):
        # Staged clean, dirty in the working tree only: git commits the
        # index, so the hook must pass.
        repo = init_repo(self)
        stage(repo, {"a.txt": "nothing\n"})
        write(repo, "a.txt", google_key() + "\n")
        self.assertEqual(run_hook(repo).returncode, 0)

    def test_installed_hook_stops_git_commit(self):
        repo = init_repo(self)
        dest = os.path.join(repo, ".git", "hooks", "pre-commit")
        shutil.copy(HOOK, dest)
        os.chmod(dest, 0o755)
        stage(repo, {"a.txt": google_key() + "\n"})
        r = run_git(repo, "commit", "-q", "-m", "x", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"Google API key", r.stderr)
        r = run_git(repo, "rev-parse", "-q", "--verify", "HEAD", check=False)
        self.assertNotEqual(r.returncode, 0, "the commit went through")
        # and the deliberate way past it still works
        r = run_git(repo, "commit", "-q", "--no-verify", "-m", "x", check=False)
        self.assertEqual(r.returncode, 0)


@unittest.skipUnless(shutil.which("sh") and shutil.which("awk"),
                     "the hook needs sh and awk")
class Declared(unittest.TestCase):
    """What was not inspected is said, and a failure is not a pass."""

    def test_binary_is_declared(self):
        repo = init_repo(self)
        stage(repo, {"a.bin": b"\x00\x01\x02" + google_key().encode() + b"\n"})
        r = run_hook(repo)
        self.assertEqual(r.returncode, 0)
        self.assertIn("1 file not inspected", r.stderr)

    def test_binary_with_its_first_nul_past_line_one(self):
        # A PNG header has its first NUL on the third line. The old check
        # looked at line one only, and read the rest as text.
        repo = init_repo(self)
        stage(repo, {"a.dat": b"\x89PNG\r\n\x1a\n\x00\x00\r\n"
                              + google_key().encode() + b"\n"})
        r = run_hook(repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 file not inspected", r.stderr)

    def test_too_large_is_declared(self):
        repo = init_repo(self)
        stage(repo, {"big.txt": "x" * 200 + "\n" + google_key() + "\n"})
        r = run_hook(repo, LEAKFORM_MAX_BYTES="100")
        self.assertEqual(r.returncode, 0)
        self.assertIn("1 file not inspected", r.stderr)

    def test_name_git_still_quotes_is_declared(self):
        # A double quote, a tab or a newline in a name: git quotes it even
        # with core.quotePath=false. It cannot be read back from here, so
        # it is counted as not inspected rather than passed in silence.
        repo = init_repo(self)
        stage(repo, {'say "hi".txt': google_key() + "\n"})
        r = run_hook(repo)
        self.assertIn("1 file not inspected", r.stderr)

    def test_unreadable_index_is_not_a_pass(self):
        repo = init_repo(self)
        stage(repo, {"a.txt": google_key() + "\n"})
        bad = os.path.join(repo, "bad-index")
        with open(bad, "w") as fh:
            fh.write("not an index\n")
        r = run_hook(repo, GIT_INDEX_FILE=bad)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("nothing was inspected", r.stderr)


class Portable(unittest.TestCase):

    def test_hook_under_every_awk_given(self):
        # LEAKFORM_TEST_AWKS: a colon-separated list of awk binaries to run
        # the hook with, as `awk` first on PATH. Unset, the system awk only.
        # Measured this way: mawk 1.3.4-20200120 and -20240123, gawk 5.2.1,
        # and the BWK awk 20250116 that macOS also ships.
        awks = [a for a in os.environ.get("LEAKFORM_TEST_AWKS", "").split(":") if a]
        if not awks:
            self.skipTest("LEAKFORM_TEST_AWKS not set")
        from support import TempDir
        for awk in awks:
            with self.subTest(awk=awk):
                d = TempDir(self).path
                os.symlink(os.path.abspath(awk), os.path.join(d, "awk"))
                path = d + os.pathsep + os.environ["PATH"]
                repo = init_repo(self)
                stage(repo, {"a.txt": "first\n" + google_key() + "\n" + jwt()
                             + "\n" + uri_with_credentials() + "\n",
                             "b.txt": "nothing here\n"})
                r = run_hook(repo, PATH=path)
                self.assertEqual(r.returncode, 1, r.stderr)
                for where in ("a.txt:2  Google API key", "a.txt:3  JWT",
                              "a.txt:4  URI with credentials"):
                    self.assertIn(where, r.stderr)
                self.assertNotIn("not inspected", r.stderr)

    def test_no_interval_expressions_in_the_awk_program(self):
        # mawk 1.3.4-20200120 - the default awk on Debian 11 and 12 and on
        # Ubuntu 22.04 - reads `x{20,}` as a literal brace, not a repeat.
        # A hook written with intervals matched nothing there and passed
        # every commit. Measured with that build; this guards the source.
        with open(HOOK) as fh:
            src = fh.read()
        self.assertEqual(re.findall(r"[\])][{][0-9]+,?[0-9]*[}]", src), [])


if __name__ == "__main__":
    unittest.main()
