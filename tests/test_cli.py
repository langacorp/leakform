"""The command line: exit codes, output modes, and the self-test."""

import json
import unittest

from support import (clean_env, google_key, leakform, make_repo, run_cli)


class Cli(unittest.TestCase):

    def test_version_is_the_module_constant(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), leakform.__version__)

    def test_selftest_passes(self):
        r = run_cli("--selftest")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("selftest passed", r.stdout)

    def test_no_repository_is_a_usage_error(self):
        r = run_cli()
        self.assertEqual(r.returncode, 2)
        self.assertIn("repository path is required", r.stderr)

    def test_not_a_git_repository(self):
        tmp = __import__("support").TempDir(self).path
        r = run_cli(tmp, env=clean_env(GIT_CEILING_DIRECTORIES=tmp))
        self.assertEqual(r.returncode, 2)
        self.assertIn("not a git repository", r.stderr)

    def test_text_exit_codes(self):
        clean = make_repo(self, {"a.txt": "nothing\n"}, name="clean")
        dirty = make_repo(self, {"a.txt": "k = " + google_key() + "\n"},
                          name="dirty")
        self.assertEqual(run_cli(clean).returncode, 0)
        r = run_cli(dirty)
        self.assertEqual(r.returncode, 1)
        self.assertIn("google-api-key", r.stdout)
        self.assertNotIn(google_key(), r.stdout)

    def test_json_output(self):
        dirty = make_repo(self, {"a.txt": "k = " + google_key() + "\n"})
        r = run_cli(dirty, "--json")
        self.assertEqual(r.returncode, 1)
        res = json.loads(r.stdout)
        self.assertEqual(res["version"], leakform.__version__)
        self.assertEqual(res["findings"][0]["category"], "google-api-key")
        self.assertEqual(set(res["findings"][0]), {
            "category", "path", "line", "value_length", "blob", "in_head"})
        self.assertNotIn(google_key(), r.stdout)

    def test_json_clean_is_0(self):
        clean = make_repo(self, {"a.txt": "nothing\n"})
        self.assertEqual(run_cli(clean, "--json").returncode, 0)

    def test_git_timeout_is_2(self):
        repo = make_repo(self, {"a.txt": "nothing\n"})
        r = run_cli(repo, env=clean_env(LEAKFORM_GIT_TIMEOUT="0"))
        # 0 seconds: the first git call cannot finish in time.
        self.assertEqual(r.returncode, 2)
        self.assertIn("NOTHING WAS EXAMINED", r.stderr)

    def test_json_nothing_examined_is_2(self):
        # Same outcome as the text mode: an empty scan is not a pass.
        repo = make_repo(self, {"a.png": "\x89PNG\r\n"})
        r = run_cli(repo, "--json")
        self.assertEqual(run_cli(repo).returncode, 2)
        self.assertEqual(r.returncode, 2)
        self.assertEqual(json.loads(r.stdout)["coverage"]["blobs_examined"], 0)


if __name__ == "__main__":
    unittest.main()
