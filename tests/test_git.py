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


class EveryPath(unittest.TestCase):
    """A blob can live at several paths. Every one of them counts."""

    def test_file_renamed_away_from_a_sensitive_name(self):
        repo = init_repo(self)
        commit(repo, {".env": "A=1\n"})
        run_git(repo, "mv", ".env", "notes.txt")
        commit(repo, message="rename")
        names = {s["path"] for s in leakform.scan(repo)["sensitive_names"]}
        self.assertEqual(names, {".env"})

    def test_same_content_under_a_sensitive_and_an_ordinary_name(self):
        # tree order puts a.txt first, which is the one path git reports
        repo = make_repo(self, {"a.txt": "same\n", "z/.env": "same\n"})
        names = {s["path"] for s in leakform.scan(repo)["sensitive_names"]}
        self.assertEqual(names, {"z/.env"})

    def test_same_content_under_a_binary_and_a_text_name(self):
        planted = "k = " + google_key() + "\n"
        repo = make_repo(self, {"a.png": planted, "a.txt": planted})
        res = leakform.scan(repo)
        self.assertEqual(categories(res), {"google-api-key"})
        self.assertEqual(res["coverage"]["blobs_examined"], 1)

    def test_still_silent_when_every_path_is_binary(self):
        planted = "k = " + google_key() + "\n"
        repo = make_repo(self, {"a.png": planted, "b.png": planted,
                                "c.txt": "nothing\n"})
        res = leakform.scan(repo)
        self.assertEqual(res["findings"], [])
        self.assertEqual(res["coverage"]["skipped_by_reason"],
                         {"binary-extension": 1})


def _shim(testcase, body):
    """A `git` first on PATH that runs `body` (sh) before the real one."""
    import shutil
    real = shutil.which("git")
    d = TempDir(testcase).path
    with open(os.path.join(d, "git"), "w") as fh:
        fh.write("#!/bin/sh\n%s\nexec %s \"$@\"\n" % (body, real))
    os.chmod(os.path.join(d, "git"), 0o755)
    return clean_env(PATH=d + os.pathsep + os.environ.get("PATH", ""))


class GitFailures(unittest.TestCase):
    """A git call that fails is a measurement that did not happen."""

    def test_broken_ref_is_not_a_clean_repository(self):
        repo = make_repo(self, {".env": "A=1\n", "a.txt": "nothing\n"})
        with open(os.path.join(repo, ".git", "refs", "heads", "broken"), "w") as fh:
            fh.write("0123456789012345678901234567890123456789\n")
        r = run_cli(repo)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("NOTHING WAS EXAMINED", r.stderr)

    def test_unreadable_blob_is_not_counted_as_examined(self):
        repo = make_repo(self, {"a.txt": "k = " + google_key() + "\n"})
        sha = run_git(repo, "rev-parse", "HEAD:a.txt").stdout.decode().strip()
        obj = os.path.join(repo, ".git", "objects", sha[:2], sha[2:])
        os.chmod(obj, 0o644)
        with open(obj, "rb") as fh:
            data = fh.read()
        with open(obj, "wb") as fh:
            fh.write(data[:len(data) // 2])
        res = leakform.scan(repo)
        self.assertEqual(res["coverage"]["blobs_examined"], 0)
        self.assertEqual(res["coverage"]["skipped_by_reason"], {"unreadable": 1})
        self.assertEqual(run_cli(repo).returncode, 2)

    def test_head_is_found_with_a_git_older_than_2_36(self):
        # `git ls-tree --format` arrived in git 2.36. Ubuntu 22.04 ships 2.34.
        env = _shim(self, 'case "$*" in *ls-tree*--format*) '
                          'echo "error: unknown option" >&2; exit 129;; esac')
        repo = make_repo(self, {"a.txt": "k = " + google_key() + "\n"})
        r = run_cli(repo, "--json", env=env)
        import json
        res = json.loads(r.stdout)
        self.assertEqual([f["in_head"] for f in res["findings"]], [True])

    def test_head_is_the_whole_tree_when_given_a_subdirectory(self):
        repo = init_repo(self)
        commit(repo, {"top.txt": "k = " + google_key() + "\n",
                      "sub/a.txt": "nothing\n"})
        res = leakform.scan(os.path.join(repo, "sub"))
        self.assertEqual(categories(res, in_head=True), {"google-api-key"})

    def test_repository_without_commits_is_nothing_examined(self):
        repo = init_repo(self)
        r = run_cli(repo)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_unborn_head_with_other_refs_still_scans(self):
        repo = make_repo(self, {"a.txt": "k = " + google_key() + "\n"})
        run_git(repo, "symbolic-ref", "HEAD", "refs/heads/nothing-here")
        res = leakform.scan(repo)
        self.assertEqual(categories(res, in_head=False), {"google-api-key"})


if __name__ == "__main__":
    unittest.main()
