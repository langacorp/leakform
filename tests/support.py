"""Shared helpers for the test suite.

Every secret-shaped value used here is built at run time by concatenation, so
that this file, as stored in the repository, contains nothing that a scanner -
leakform itself included - would report. The values are fake and say so.
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import leakform  # noqa: E402

HOOK = os.path.join(ROOT, "hooks", "pre-commit")
SCRIPT = os.path.join(ROOT, "leakform.py")


def clean_env(**extra):
    """The environment minus anything that would point git somewhere else.

    The suite may itself run inside a git hook, where GIT_DIR and
    GIT_INDEX_FILE are set; without this a fixture repository would be
    created in, or read from, the wrong place.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(extra)
    return env


# ---- fake secrets, assembled at run time -----------------------------------

def google_key():
    return ("AI" + "za" + "FAKE_FIXTURE_not_a_real_key_" + "0" * 20)[:39]


def uri_with_credentials():
    return "postgres" + "://" + "appuser" + ":" + "fake-fixture-pw" + "@db.example.invalid/app"


def pem_private_key():
    dash = "-" * 5
    return (dash + "BEGIN RSA " + "PRIVATE KEY" + dash + "\n"
            + "FAKEFIXTURENOTAKEY" * 3 + "\n"
            + dash + "END RSA " + "PRIVATE KEY" + dash + "\n")


def jwt():
    head = "ey" + "J" + "hbGciOiJub25lIn0"
    body = "ey" + "J" + "zdWIiOiJmYWtlLWZpeHR1cmUifQ"
    return head + "." + body + "." + "fake_fixture_signature"


def long_hex(prefix="0f1e"):
    """40 hexadecimal characters, starting with `prefix`."""
    filler = "0123456789abcdef" * 3
    return (prefix + filler)[:40]


# ---- repositories ----------------------------------------------------------

def run_git(cwd, *args, check=True):
    return subprocess.run(("git",) + args, cwd=cwd, env=clean_env(),
                          capture_output=True, check=check)


class TempDir:
    def __init__(self, testcase):
        self.path = tempfile.mkdtemp(prefix="leakform-test-")
        testcase.addCleanup(shutil.rmtree, self.path, True)


def init_repo(testcase, name="repo"):
    path = os.path.join(TempDir(testcase).path, name)
    os.makedirs(path)
    run_git(path, "init", "-q")
    run_git(path, "symbolic-ref", "HEAD", "refs/heads/main")
    run_git(path, "config", "user.email", "test@example.invalid")
    run_git(path, "config", "user.name", "test")
    run_git(path, "config", "commit.gpgsign", "false")
    return path


def write(repo, name, content):
    full = os.path.join(repo, name)
    d = os.path.dirname(full)
    if d:
        os.makedirs(d, exist_ok=True)
    if isinstance(content, str):
        content = content.encode("utf-8")
    with open(full, "wb") as fh:
        fh.write(content)


def commit(repo, files=None, message="commit", remove=()):
    for name, content in (files or {}).items():
        write(repo, name, content)
    for name in remove:
        run_git(repo, "rm", "-q", name)
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "--allow-empty", "-m", message)


def make_repo(testcase, files, name="repo"):
    repo = init_repo(testcase, name)
    commit(repo, files)
    return repo


def run_cli(*args, env=None):
    return subprocess.run((sys.executable, SCRIPT) + args,
                          env=env if env is not None else clean_env(),
                          capture_output=True, text=True)


def categories(result, in_head=None):
    return {f["category"] for f in result["findings"]
            if in_head is None or f["in_head"] == in_head}
