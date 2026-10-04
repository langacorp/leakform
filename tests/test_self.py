"""The repository, scanned by its own tools.

Fixtures are assembled at run time precisely so that this passes: a tool
that flags its own source cannot be told apart, from its output, from a
repository that really leaks.
"""

import os
import re
import shutil
import subprocess
import unittest

from support import ROOT, HOOK, clean_env, leakform


def tracked_files():
    r = subprocess.run(("git", "ls-files", "-z"), cwd=ROOT, env=clean_env(),
                       capture_output=True)
    if r.returncode != 0:
        return None
    return [p for p in r.stdout.decode().split("\0") if p]


class OwnRepository(unittest.TestCase):

    def setUp(self):
        self.files = tracked_files()
        if not self.files:
            self.skipTest("not run from a git checkout")

    def test_scanner_finds_nothing_in_the_tracked_files(self):
        pats = leakform.compiled()
        hits = []
        for path in self.files:
            with open(os.path.join(ROOT, path), "rb") as fh:
                data = fh.read()
            for name, rx in pats:
                m = rx.search(data)
                if not m:
                    continue
                value = m.group(1) if m.groups() else m.group(0)
                if m.groups() and leakform.PLACEHOLDER.match(value.strip()):
                    continue
                hits.append((path, name))
        self.assertEqual(hits, [])

    @unittest.skipUnless(shutil.which("sh") and shutil.which("awk"),
                         "the hook needs sh and awk")
    def test_hook_finds_nothing_in_the_tracked_files(self):
        from support import init_repo, run_git
        repo = init_repo(self)
        for path in self.files:
            dest = os.path.join(repo, path)
            os.makedirs(os.path.dirname(dest) or repo, exist_ok=True)
            shutil.copy(os.path.join(ROOT, path), dest)
        run_git(repo, "add", "-A")
        r = subprocess.run(("sh", HOOK), cwd=repo, env=clean_env(),
                           capture_output=True, text=True)
        # No known shape anywhere. The high-variety heuristic does match
        # kebab-case category names such as uri-with-credentials next to the
        # word "credential"; it is left as it is, because a hyphenated
        # passphrase has the same shape. Those lines are listed, not hidden.
        hits = [l.strip() for l in r.stderr.splitlines()
                if re.match(r"\s+\S+:\d+  ", l)]
        known = [h for h in hits
                 if not h.endswith("high-variety value near a secret name")]
        self.assertEqual(known, [], r.stderr)
        allowed = {
            "leakform.py": ("putty-private-key", "uri-with-credentials"),
            "tests/test_scan.py": ("uri-with-credentials", "service-account"),
            # this file names them too, to say which lines are allowed
            "tests/test_self.py": ("uri-with-credentials", "service-account"),
        }
        for h in hits:
            path, line = h.split(":")[0], int(h.split(":")[1].split()[0])
            with open(os.path.join(ROOT, path)) as fh:
                text = fh.read().splitlines()[line - 1]
            with self.subTest(hit=h):
                self.assertTrue(any(w in text for w in allowed.get(path, ())),
                                "heuristic hit on a line that is not a "
                                "category name: " + h)


if __name__ == "__main__":
    unittest.main()
