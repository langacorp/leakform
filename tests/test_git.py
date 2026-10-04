"""How the scanner talks to git: the right repository, every failure seen."""

import os
import unittest

from support import (TempDir, categories, clean_env, commit, google_key,
                     init_repo, leakform, make_repo, run_cli, run_git,
                     uri_with_credentials)


class Environment(unittest.TestCase):

    def test_git_dir_in_the_environment_does_not_redirect_the_scan(self):
        # Inside a git hook GIT_DIR points at the repository being committed
        # to. The repository named on the command line is the one to read.
        other = make_repo(self, {"a.txt": "k = " + google_key() + "\n"},
                          name="other")
        target = make_repo(self, {"a.txt": "nothing\n"}, name="target")
        r = run_cli(target, env=clean_env(
            GIT_DIR=os.path.join(other, ".git")))
        self.assertNotIn("google-api-key", r.stdout)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_selftest_survives_a_global_hooks_path(self):
        # A user who installed a pre-commit hook globally - this project's
        # own hook, say - must still be able to run the self-test, whose
        # fixtures are commits of planted secrets.
        tmp = TempDir(self).path
        hooks = os.path.join(tmp, "hooks")
        os.makedirs(hooks)
        with open(os.path.join(hooks, "pre-commit"), "w") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        os.chmod(os.path.join(hooks, "pre-commit"), 0o755)
        cfg = os.path.join(tmp, "gitconfig")
        with open(cfg, "w") as fh:
            fh.write("[core]\n\thooksPath = %s\n" % hooks)
        r = run_cli("--selftest", env=clean_env(GIT_CONFIG_GLOBAL=cfg))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
