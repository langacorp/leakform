#!/usr/bin/env python3
"""leakform - find secrets in a git repository by shape, across all refs.

Two things make this different from grepping for the word "secret":

  1. It searches by SHAPE, not by field name. A secret does not only live where
     something is called `secret`, and a repository that has been cleaned of the
     word still contains the values.
  2. It reads every blob reachable from EVERY ref, not the working tree. A file
     deleted three years ago is still in the history, and the value in it is
     still out.

It never prints a value. Position and category only: a value reported is a value
that has left a second time.

Born from a defect measured on 2026-08-27: a repository whose last commit was
five years old was searched for the first time, and the secrets in it had been
readable the whole time. Nobody had looked, and nothing said so.

Standard library only, plus git on PATH. MIT licensed.
"""

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

__version__ = "1.2.0"

# --------------------------------------------------------------------------
# shapes
# --------------------------------------------------------------------------
# Ordered roughly from most specific to least. The generic ones at the end are
# the noisy ones; they earn their place because a private key does not always
# announce itself with a vendor prefix.

PATTERNS = [
    # The PEM headers are split in two literals, so that this file does not
    # match itself: the tool is run over its own repository.
    ("pem-private-key",     rb"-----BEGIN [A-Z ]{0,30}PRIVATE" rb" KEY-----"),
    ("pem-certificate",     rb"-----BEGIN CERTIFI" rb"CATE-----"),
    ("ssh-private-key",     rb"-----BEGIN OPENSSH PRIVATE" rb" KEY-----"),
    ("putty-private-key",   rb"PuTTY-User-Key-File-\d"),
    ("pgp-private-key",     rb"-----BEGIN PGP PRIVATE" rb" KEY BLOCK-----"),
    ("google-api-key",      rb"AIza[0-9A-Za-z_\-]{35}"),
    ("google-oauth-client", rb"[0-9]{10,14}-[0-9a-z]{20,40}\.apps\.googleusercontent\.com"),
    ("google-client-secret", rb"GOCSPX-[0-9A-Za-z_\-]{20,}"),
    ("aws-access-key",      rb"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}"),
    ("github-token",        rb"gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{50,}"),
    ("gitlab-token",        rb"glpat-[0-9A-Za-z_\-]{20,}"),
    ("slack-token",         rb"xox[baprse]-[0-9A-Za-z\-]{10,}"),
    ("slack-webhook",       rb"https://hooks\.slack\.com/services/[0-9A-Za-z/]{20,}"),
    ("stripe-key",          rb"[sr]k_(?:live|test)_[0-9A-Za-z]{20,}"),
    ("openai-key",          rb"sk-(?:proj-)?[0-9A-Za-z_\-]{32,}"),
    ("sendgrid-key",        rb"SG\.[0-9A-Za-z_\-]{15,}\.[0-9A-Za-z_\-]{20,}"),
    ("mailgun-key",         rb"key-[0-9a-f]{32}"),
    ("twilio-sid",          rb"AC[0-9a-f]{32}"),
    ("npm-token",           rb"npm_[0-9A-Za-z]{36}"),
    ("fcm-legacy-key",      rb"AAAA[0-9A-Za-z_\-]{7}:APA91b[0-9A-Za-z_\-]{100,}"),
    ("jwt",                 rb"eyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}"),
    ("uri-with-credentials",
     rb"(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|ftps?|https?)://"
     rb"[^\s'\"<>/:@]{1,64}:[^\s'\"<>/@]{3,}@"),
    # assignment shapes: the name is a hint, the VALUE decides
    ("assigned-secret",
     rb"""(?i)\b(?:pass(?:word|wd|phrase)?|secret|token|api[_\-]?key|apikey"""
     rb"""|auth[_\-]?key|access[_\-]?key|private[_\-]?key|client[_\-]?secret"""
     rb"""|app[_\-]?secret|hmac(?:[_\-]?secret)?|salt|credential|bearer)\b"""
     rb"""\s*(?:=>|=|:)\s*['"`]([^'"`\s]{8,})['"`]"""),
    ("defined-secret",
     rb"""(?i)define\s*\(\s*['"](?:[A-Z0-9_]*(?:KEY|SALT|SECRET|PASS|TOKEN|HMAC)"""
     rb"""[A-Z0-9_]*)['"]\s*,\s*['"]([^'"]{8,})['"]"""),
    ("long-hex",    rb"""['"=:\s]([0-9a-fA-F]{40,128})['"\s,;)]"""),
    ("long-base64", rb"""['"=:\s]([A-Za-z0-9+/]{60,}={0,2})['"\s,;)]"""),
]

# Values that look like secrets and are not. Every entry here is a decision to
# stay silent, so the list is deliberately short and literal.
PLACEHOLDER = re.compile(
    rb"(?i)^(?:x{3,}|y{3,}|z{3,}|\*{3,}|\.{3,}|-{3,}|_{3,}|0+|1234\d*"
    rb"|test\w*|example\w*|changeme|change[_\-]?me|your[_\-]?\w*|put[_\-]?your\w*"
    rb"|placeholder|todo|tbd|none|null|nan|false|true|undefined|secret|password"
    rb"|passw0rd|dummy|sample|demo|foo|bar|baz|abc\w*|<[^>]*>|\$\{[^}]*\}"
    rb"|%[a-z_]+%|\{\{[^}]*\}\}|\$[A-Za-z_][A-Za-z0-9_]*)$")

BINARY_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".svg", ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".mp3", ".mp4", ".mov", ".webm", ".wav", ".ogg", ".avi", ".mkv",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".aar",
    ".pdf", ".psd", ".ai", ".sketch", ".fig", ".glb", ".gltf", ".fbx", ".obj",
    ".bin", ".hdr", ".exr", ".ktx", ".ktx2", ".basis", ".dds",
    ".so", ".dll", ".dylib", ".class", ".pyc", ".wasm", ".o", ".a",
)

NOISY_PATH = re.compile(
    r"(?:^|/)(?:node_modules|bower_components|\.git)/"
    r"|(?:\.min\.(?:js|css)|-min\.js|\.map)$"
    r"|(?:^|/)(?:package-lock\.json|yarn\.lock|composer\.lock|pubspec\.lock"
    r"|Podfile\.lock|Cargo\.lock|Gemfile\.lock|poetry\.lock)$")

# Files whose NAME is the finding, whatever is inside them.
SENSITIVE_NAME = re.compile(
    r"(?:^|/)(?:\.env(?:\..*)?|.*\.pem|.*\.p12|.*\.pfx|.*\.jks|.*\.keystore"
    r"|id_rsa.*|id_dsa.*|id_ecdsa.*|id_ed25519.*|.*\.ppk"
    r"|.*service[-_]account.*\.json|google-services\.json"
    r"|GoogleService-Info\.plist|wp-config\.php|key\.properties"
    r"|credentials(?:\.json|\.ya?ml)?|secrets?\.(?:json|ya?ml|php|js|dart|py)"
    r"|\.npmrc|\.pypirc|\.netrc|htpasswd)$", re.I)

MAX_BLOB_BYTES = 2_000_000


# --------------------------------------------------------------------------

class Finding:
    __slots__ = ("category", "path", "line", "length", "blob", "in_head")

    def __init__(self, category, path, line, length, blob, in_head):
        self.category, self.path, self.line = category, path, line
        self.length, self.blob, self.in_head = length, blob, in_head

    def as_dict(self):
        # length, never value. A value reported is a value out a second time.
        return {"category": self.category, "path": self.path, "line": self.line,
                "value_length": self.length, "blob": self.blob[:12],
                "in_head": self.in_head}

    def key(self):
        return (self.category, self.path, self.line, self.blob)


# Read once, at import. A value that is not a number must not stop the module
# from importing: main() reports it as a usage error instead of a traceback.
_TIMEOUT_RAW = os.environ.get("LEAKFORM_GIT_TIMEOUT", "120")
try:
    GIT_TIMEOUT = int(_TIMEOUT_RAW)
    _TIMEOUT_ERROR = None
except ValueError:
    GIT_TIMEOUT = 120
    _TIMEOUT_ERROR = ("LEAKFORM_GIT_TIMEOUT must be a whole number of seconds, "
                      "not %r" % _TIMEOUT_RAW)


class GitTimeout(RuntimeError):
    """git did not answer. Never silently treated as an empty repository."""


class GitFailed(RuntimeError):
    """git answered with an error. Its empty output is not an empty answer."""


def git_ok(repo, *args):
    """Run git and return stdout, or raise: a failure is not an empty list."""
    r = git(repo, *args)
    if r.returncode != 0:
        msg = r.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitFailed("git %s failed (exit %d): %s" % (
            args[0], r.returncode, msg[-1] if msg else "no message"))
    return r.stdout


# Variables with which git locates a repository. Inside a git hook they point
# at the repository being committed to, and they win over cwd: left in place,
# the scan reads that repository and reports on it under another name.
_GIT_LOCATION_ENV = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_PREFIX",
    "GIT_IMPLICIT_WORK_TREE", "GIT_NAMESPACE", "GIT_SHALLOW_FILE",
    "GIT_GRAFT_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE",
)


def _git_env():
    return {k: v for k, v in os.environ.items() if k not in _GIT_LOCATION_ENV}


def git(repo, *args):
    """
    Run git, and never wait forever.

    Without a timeout a wedged git — a stale lock, a repository on a mount
    that stopped answering — leaves the scan hanging with no output. In CI
    that is a runner held until someone notices: it looks like work in
    progress and it is nothing.
    """
    try:
        return subprocess.run(("git",) + args, cwd=repo, env=_git_env(),
                              capture_output=True, timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise GitTimeout(
            "git %s took longer than %ds. Raise LEAKFORM_GIT_TIMEOUT if the "
            "repository is genuinely that large." % (args[0], GIT_TIMEOUT))


def is_git_repo(path):
    r = git(path, "rev-parse", "--git-dir")
    return r.returncode == 0


def blob_paths(repo):
    """Every path every blob has had, in any commit reachable from any ref.

    `rev-list --objects` names each blob once, under the first path it meets.
    A blob that also lived at `.env`, or was renamed there or away from there,
    keeps only one of its names - and the scan decides on the names: what is
    reported by name, what is skipped as binary or vendored. So the paths
    from every commit's changes are added to it. rev-list stays, because it
    also covers a tag that points straight at a blob or a tree.
    """
    paths = collections.defaultdict(set)
    for line in git_ok(repo, "rev-list", "--objects", "--all").split(b"\n"):
        if b" " in line:
            sha, _, p = line.partition(b" ")
            paths[sha.decode()].add(p.decode("utf-8", "replace"))

    # -z: paths verbatim, not quoted. --no-renames: a rename is a delete and
    # an add, so both names appear. -m: merges against each parent.
    out = git_ok(repo, "log", "--all", "--raw", "--no-renames", "--root", "-m",
                 "--no-abbrev", "--format=", "-z")
    fields = out.split(b"\0")
    i = 0
    while i < len(fields):
        meta = fields[i]
        if not meta.startswith(b":"):
            i += 1
            continue
        # :old_mode new_mode old_sha new_sha status, then the path
        parts = meta.split()
        p = fields[i + 1].decode("utf-8", "replace") if i + 1 < len(fields) else ""
        i += 2
        if len(parts) < 5 or not p:
            continue
        for mode, sha in ((parts[0][1:], parts[2]), (parts[1], parts[3])):
            # 160000 is a submodule: the sha is a commit somewhere else.
            if mode != b"160000" and sha.strip(b"0"):
                paths[sha.decode()].add(p)
    return paths


def blobs_in_head(repo):
    """The blobs of the whole tree at HEAD. Empty only if there is no HEAD.

    `--full-tree`: given a subdirectory, ls-tree lists only that directory,
    and everything above it was reported as history only. No `--format`:
    it arrived in git 2.36, and on an older git the call failed, its empty
    output was read as an empty HEAD, and every finding moved to history.
    """
    if git(repo, "rev-parse", "--verify", "-q", "HEAD^{tree}").returncode != 0:
        return set()   # unborn branch: there is no HEAD to be in
    out = git_ok(repo, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    head = set()
    for entry in out.split(b"\0"):
        # <mode> SP <type> SP <object> TAB <path>
        meta = entry.partition(b"\t")[0].split()
        if len(meta) == 3 and meta[1] == b"blob":
            head.add(meta[2].decode())
    return head


def compiled():
    return [(name, re.compile(rx)) for name, rx in PATTERNS]


def scan(repo, max_blob_bytes=MAX_BLOB_BYTES):
    """Read every blob reachable from every ref. Return findings and coverage."""
    pats = compiled()

    # blob -> the paths it has ever had. One blob can live at several paths.
    paths = blob_paths(repo)

    head_blobs = blobs_in_head(repo)

    blobs = []
    check = git_ok(repo, "cat-file", "--batch-all-objects",
                   "--batch-check=%(objectname) %(objecttype) %(objectsize)")
    for line in check.split(b"\n"):
        f = line.split()
        if len(f) == 3 and f[1] == b"blob":
            blobs.append((f[0].decode(), int(f[2])))

    total = len(blobs)
    examined = 0
    skipped = collections.Counter()
    findings = []
    sensitive_names = set()

    for sha, size in blobs:
        ps = paths.get(sha) or {"(unreachable-from-any-ref)"}
        for p in ps:
            if SENSITIVE_NAME.search(p):
                sensitive_names.add((p, sha[:12], sha in head_blobs))
        if all(p.lower().endswith(BINARY_EXT) for p in ps):
            skipped["binary-extension"] += 1
            continue
        if all(NOISY_PATH.search(p) for p in ps):
            skipped["vendored-or-generated"] += 1
            continue
        if size > max_blob_bytes:
            skipped["larger-than-limit"] += 1
            continue
        r = git(repo, "cat-file", "blob", sha)
        if r.returncode != 0:
            # A blob git cannot read was not examined. Counting it as
            # examined would turn a corrupt object into a clean one.
            skipped["unreadable"] += 1
            continue
        data = r.stdout
        if b"\x00" in data[:8192]:
            skipped["binary-content"] += 1
            continue
        examined += 1
        # Report the finding under a path that was read for what it is: a
        # text path when there is one, the first in order otherwise.
        path = min(ps, key=lambda p: (p.lower().endswith(BINARY_EXT),
                                      bool(NOISY_PATH.search(p)), p))
        in_head = sha in head_blobs
        for name, rx in pats:
            for m in rx.finditer(data):
                value = m.group(1) if m.groups() else m.group(0)
                if m.groups() and PLACEHOLDER.match(value.strip()):
                    continue
                # The line of the value, not of the match: long-hex and
                # long-base64 open with the delimiter before it, which can
                # be the newline at the end of the previous line.
                start = m.start(1) if m.groups() else m.start()
                line = data.count(b"\n", 0, start) + 1
                findings.append(Finding(name, path, line, len(value), sha, in_head))
                break  # one hit per category per blob is enough to act on

    refs = [l.strip().decode("utf-8", "replace") for l in
            git_ok(repo, "for-each-ref", "--format=%(refname)").split(b"\n")
            if l.strip()]

    return {
        "version": __version__,
        "repository": os.path.abspath(repo),
        "coverage": {
            "blobs_total": total,
            "blobs_examined": examined,
            "blobs_skipped": sum(skipped.values()),
            "skipped_by_reason": dict(skipped),
            "refs_examined": len(refs),
            "refs": refs,
        },
        "sensitive_names": [{"path": p, "blob": b, "in_head": h}
                            for p, b, h in sorted(sensitive_names)],
        "findings": [f.as_dict() for f in
                     sorted({f.key(): f for f in findings}.values(),
                            key=lambda f: (not f.in_head, f.category, f.path))],
    }


def report(res, stream=sys.stdout):
    c = res["coverage"]
    head = [f for f in res["findings"] if f["in_head"]]
    hist = [f for f in res["findings"] if not f["in_head"]]

    for title, group in (("in the current HEAD", head),
                         ("in history only", hist)):
        if not group:
            continue
        stream.write(f"\n{len(group)} found {title}\n")
        for f in group:
            stream.write(f"  {f['category']:<22} {f['path']}:{f['line']} "
                         f"(length {f['value_length']}, blob {f['blob']})\n")

    if res["sensitive_names"]:
        stream.write(f"\n{len(res['sensitive_names'])} file names that are "
                     f"themselves the finding\n")
        for s in res["sensitive_names"]:
            where = "HEAD" if s["in_head"] else "history"
            stream.write(f"  {s['path']}  ({where}, blob {s['blob']})\n")

    if not res["findings"] and not res["sensitive_names"]:
        stream.write("\nnothing found\n")

    stream.write(f"\ncoverage: {c['blobs_examined']}/{c['blobs_total']} blobs "
                 f"examined across {c['refs_examined']} refs, "
                 f"{c['blobs_skipped']} skipped\n")
    for reason, n in sorted(c["skipped_by_reason"].items()):
        stream.write(f"  not examined: {n} - {reason}\n")

    if c["blobs_examined"] == 0:
        stream.write("NOTHING WAS EXAMINED. This is not a pass.\n")
    return exit_code(res)


def exit_code(res):
    """0 nothing found, 1 findings, 2 nothing was examined. One rule for
    every output mode: --json used to return 0 for an empty scan."""
    if res["coverage"]["blobs_examined"] == 0:
        return 2
    return 1 if (res["findings"] or res["sensitive_names"]) else 0


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def _make_repo(path, files, then_delete=(), second_commit=None):
    # The fixtures are planted secrets: a pre-commit hook installed globally
    # (this project's own, for instance) is right to refuse them, and a
    # refused commit would leave the self-test scanning an empty repository.
    os.makedirs(path, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "selftest@invalid")
    git(path, "config", "user.name", "selftest")
    for name, content in files.items():
        full = os.path.join(path, name)
        os.makedirs(os.path.dirname(full), exist_ok=True) if os.path.dirname(full) else None
        with open(full, "wb") as fh:
            fh.write(content)
    git(path, "add", "-A")
    git(path, "-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", "first")
    if then_delete:
        for name in then_delete:
            os.remove(os.path.join(path, name))
        for name, content in (second_commit or {}).items():
            with open(os.path.join(path, name), "wb") as fh:
                fh.write(content)
        git(path, "add", "-A")
        git(path, "-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", "second")
    return path


def selftest(stream=sys.stdout):
    """The check must fire on a planted secret and stay silent on a clean file.

    A check exercised only in the direction where it passes is indistinguishable
    from one that always passes, so both directions run here and either one
    failing fails the whole test.
    """
    failures = []
    tmp = tempfile.mkdtemp(prefix="leakform-selftest-")
    try:
        # ---- direction 1: must fire, and on a blob that is NO LONGER in HEAD
        # Fake values, assembled at run time: stored whole in this file they
        # would be found by any scanner run over this repository - this one
        # included - and by push protection on the way in.
        dirty_env = (
            b"DB_URL=postgres" + b"://appuser:" + b"fake-fixture-pw"
            + b"@db.example.invalid:5432/app\n"
            + b"API_KEY=" + b"AI" + b"za" + b"FAKEfixture_not_a_real" + b"_key_00000000\n"
            + b"SESSION=" + b"ey" + b"JhbGciOiJub25lIn0" + b"."
            + b"ey" + b"JzdWIiOiJmYWtlLWZpeHR1cmUifQ" + b".fake_fixture_sig\n")
        dash = b"-" * 5
        key = (dash + b"BEGIN RSA PRIVATE" + b" KEY" + dash + b"\n"
               + b"FAKEFIXTURENOTAKEY" * 3 + b"\n"
               + dash + b"END RSA PRIVATE" + b" KEY" + dash + b"\n")
        clean_after = (b"<?php\n$dsn = getenv('DB_URL');\n"
                       b"$key = $_ENV['API_KEY'];\n")
        dirty = _make_repo(
            os.path.join(tmp, "dirty"),
            {".env": dirty_env, "deploy.pem": key},
            then_delete=[".env", "deploy.pem"],
            second_commit={"config.php": clean_after})

        r = scan(dirty)
        cats = {f["category"] for f in r["findings"]}
        stream.write("direction 1 - must fire on secrets removed from HEAD but "
                     "still in history\n")
        stream.write(f"  categories: {', '.join(sorted(cats)) or '(none)'}\n")
        stream.write(f"  sensitive names: {len(r['sensitive_names'])}\n")
        for expected in ("uri-with-credentials", "google-api-key", "jwt",
                         "pem-private-key"):
            if expected not in cats:
                failures.append(f"planted {expected} was not found")
        if not r["sensitive_names"]:
            failures.append(".env and deploy.pem were not reported by name")
        if any(f["in_head"] for f in r["findings"]):
            failures.append("findings were attributed to HEAD, but the files "
                            "were deleted before the last commit")

        # ---- direction 2: must stay silent
        clean = _make_repo(os.path.join(tmp, "clean"), {
            "config.php": (b"<?php\n"
                           b"define('DB_PASSWORD', getenv('DB_PASS'));\n"
                           b"define('AUTH_KEY', '');\n"
                           b"$token = $_ENV['API_TOKEN'];\n"
                           b"$secret = 'changeme';\n"),
            ".env.example": (b"API_KEY=\nDB_PASSWORD=your_password_here\n"
                             b"SECRET=${SECRET}\n"),
            "app.js": (b"export const cfg = { apiKey: process.env.API_KEY,\n"
                       b"  endpoint: 'https://api.example.org/v1' };\n"),
        })
        r2 = scan(clean)
        stream.write("direction 2 - must stay silent on code that only "
                     "references environment variables\n")
        stream.write(f"  findings: {len(r2['findings'])}\n")
        if r2["findings"]:
            got = ", ".join(sorted({f["category"] for f in r2["findings"]}))
            failures.append(f"clean repository produced findings: {got}")
        # .env.example is reported by NAME on purpose: the name is the finding,
        # not the contents. That is not a false positive and must not be one.
        if len(r2["sensitive_names"]) != 1:
            failures.append("expected .env.example to be reported by name once")

        # ---- direction 3: an empty scan must never look like a pass
        empty = _make_repo(os.path.join(tmp, "empty"), {"a.png": b"\x89PNG\r\n"})
        r3 = scan(empty)
        rc = report(r3, open(os.devnull, "w"))
        stream.write("direction 3 - a scan that examined nothing is not a pass\n")
        stream.write(f"  blobs examined: {r3['coverage']['blobs_examined']}, "
                     f"exit code would be {rc}\n")
        if r3["coverage"]["blobs_examined"] != 0:
            failures.append("the binary-only repository was not fully skipped")
        if rc == 0:
            failures.append("a scan that examined nothing exited 0")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        stream.write("\nSELFTEST FAILED\n")
        for f in failures:
            stream.write(f"  {f}\n")
        return 1
    stream.write("\nselftest passed: the search fires in one direction and is "
                 "silent in the other\n")
    return 0


# --------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        prog="leakform",
        description="Find secrets in a git repository by shape, across all refs. "
                    "Reports position and category, never the value.")
    p.add_argument("repository", nargs="?",
                   help="path to a git repository or a --mirror clone")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--max-blob-bytes", type=int, default=MAX_BLOB_BYTES)
    p.add_argument("--selftest", action="store_true",
                   help="prove the search in both directions and exit")
    p.add_argument("--version", action="version", version=__version__)
    if _TIMEOUT_ERROR:
        p.error(_TIMEOUT_ERROR)
    args = p.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.repository:
        p.error("a repository path is required (or use --selftest)")
    if shutil.which("git") is None:
        p.error("git was not found on PATH")
    try:
        if not os.path.isdir(args.repository) or not is_git_repo(args.repository):
            p.error(f"not a git repository: {args.repository}")
        res = scan(args.repository, max_blob_bytes=args.max_blob_bytes)
    except (GitTimeout, GitFailed) as e:
        # Same class of outcome as an empty scan: nothing was measured.
        # Exit 2, not 1 and not 0 — a timeout or a git error is not a
        # clean repository.
        sys.stderr.write("%s\nNOTHING WAS EXAMINED. This is not a pass.\n" % e)
        return 2
    if args.json:
        json.dump(res, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return exit_code(res)
    return report(res)


def _entry():
    """Console script entry point: `leakform` once installed with pip."""
    sys.exit(main())


if __name__ == "__main__":
    _entry()
