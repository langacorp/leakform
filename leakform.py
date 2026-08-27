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

__version__ = "0.1.0"

# --------------------------------------------------------------------------
# shapes
# --------------------------------------------------------------------------
# Ordered roughly from most specific to least. The generic ones at the end are
# the noisy ones; they earn their place because a private key does not always
# announce itself with a vendor prefix.

PATTERNS = [
    ("pem-private-key",     rb"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----"),
    ("pem-certificate",     rb"-----BEGIN CERTIFICATE-----"),
    ("ssh-private-key",     rb"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("putty-private-key",   rb"PuTTY-User-Key-File-\d"),
    ("pgp-private-key",     rb"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
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


def git(repo, *args):
    return subprocess.run(("git",) + args, cwd=repo, capture_output=True)


def is_git_repo(path):
    r = git(path, "rev-parse", "--git-dir")
    return r.returncode == 0


def compiled():
    return [(name, re.compile(rx)) for name, rx in PATTERNS]


def scan(repo, max_blob_bytes=MAX_BLOB_BYTES):
    """Read every blob reachable from every ref. Return findings and coverage."""
    pats = compiled()

    # blob -> the paths it has ever had. One blob can live at several paths.
    paths = collections.defaultdict(set)
    for line in git(repo, "rev-list", "--objects", "--all").stdout.split(b"\n"):
        if b" " in line:
            sha, _, p = line.partition(b" ")
            paths[sha.decode()].add(p.decode("utf-8", "replace"))

    head_blobs = set()
    out = git(repo, "ls-tree", "-r", "--format=%(objectname)", "HEAD").stdout
    for line in out.split(b"\n"):
        if line.strip():
            head_blobs.add(line.strip().decode())

    blobs = []
    check = git(repo, "cat-file", "--batch-all-objects",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)")
    for line in check.stdout.split(b"\n"):
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
        data = git(repo, "cat-file", "blob", sha).stdout
        if b"\x00" in data[:8192]:
            skipped["binary-content"] += 1
            continue
        examined += 1
        path = sorted(ps)[0]
        in_head = sha in head_blobs
        for name, rx in pats:
            for m in rx.finditer(data):
                value = m.group(1) if m.groups() else m.group(0)
                if m.groups() and PLACEHOLDER.match(value.strip()):
                    continue
                line = data.count(b"\n", 0, m.start()) + 1
                findings.append(Finding(name, path, line, len(value), sha, in_head))
                break  # one hit per category per blob is enough to act on

    refs = [l.split()[-1].decode() for l in
            git(repo, "for-each-ref", "--format=%(refname)").stdout.split(b"\n")
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
        return 2
    return 1 if (res["findings"] or res["sensitive_names"]) else 0


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def _make_repo(path, files, then_delete=(), second_commit=None):
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
    git(path, "commit", "-q", "-m", "first")
    if then_delete:
        for name in then_delete:
            os.remove(os.path.join(path, name))
        for name, content in (second_commit or {}).items():
            with open(os.path.join(path, name), "wb") as fh:
                fh.write(content)
        git(path, "add", "-A")
        git(path, "commit", "-q", "-m", "second")
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
        dirty_env = (
            b"DB_URL=postgres://appuser:hunter2hunter2@db.internal:5432/app\n"
            b"API_KEY=AIzaSyB1nP7qX9wLmK4tR6vZ2yH8jC3dF5gN0aQ\n"
            b"SESSION=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            b".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk\n")
        key = (b"-----BEGIN RSA PRIVATE KEY-----\n"
               b"MIIEowIBAAKCAQEA0Z9k3mQpLxVrTnB7cWfHsYdKgJ4uEaN2iOvXlQzRtMbC\n"
               b"-----END RSA PRIVATE KEY-----\n")
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
    args = p.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.repository:
        p.error("a repository path is required (or use --selftest)")
    if shutil.which("git") is None:
        p.error("git was not found on PATH")
    if not is_git_repo(args.repository):
        p.error(f"not a git repository: {args.repository}")

    res = scan(args.repository, max_blob_bytes=args.max_blob_bytes)
    if args.json:
        json.dump(res, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 1 if (res["findings"] or res["sensitive_names"]) else 0
    return report(res)


if __name__ == "__main__":
    sys.exit(main())
