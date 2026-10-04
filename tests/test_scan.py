"""The scanner, measured in both directions.

Each shape must fire on a planted value and stay silent on its placeholder.
Fixtures are assembled at run time (see support.py): the repository itself
must not contain a value that a scanner would report.
"""

import io
import os
import unittest

from support import (categories, commit, google_key, init_repo, jwt, leakform,
                     long_hex, make_repo, pem_private_key, uri_with_credentials)

D = "-" * 5


def positives():
    """One fake value per category, each in its own file."""
    return {
        "pem-private-key": D + "BEGIN EC " + "PRIVATE KEY" + D,
        "pem-certificate": D + "BEGIN " + "CERTIFICATE" + D,
        "ssh-private-key": D + "BEGIN OPENSSH " + "PRIVATE KEY" + D,
        "putty-private-key": "PuTTY-User-" + "Key-File-3: ssh-ed25519",
        "pgp-private-key": D + "BEGIN PGP " + "PRIVATE KEY BLOCK" + D,
        "google-api-key": "k = " + google_key(),
        "google-oauth-client": "123456789012" + "-" + "fakefixture0000000000"
                               + ".apps." + "googleusercontent.com",
        "google-client-secret": "GOC" + "SPX-" + "FakeFixture_0000000000",
        "aws-access-key": "AK" + "IA" + "FAKEFIXTURE00000",
        "github-token": "gh" + "p_" + "FakeFixture" * 3,
        "gitlab-token": "gl" + "pat-" + "FakeFixture_00000000",
        "slack-token": "xo" + "xb-" + "0000-fake-fixture",
        "slack-webhook": "https://hooks." + "slack.com/services/"
                         + "T000/B000/FakeFixture0000",
        "stripe-key": "sk" + "_test_" + "FakeFixture" * 2,
        "openai-key": "sk" + "-" + "FakeFixture" * 3,
        "sendgrid-key": "S" + "G." + "FakeFixture0000" + "." + "FakeFixture" * 2,
        "mailgun-key": "ke" + "y-" + "0f" * 16,
        "twilio-sid": "A" + "C" + "0f" * 16,
        "npm-token": "np" + "m_" + "FakeFixture0" * 3,
        "fcm-legacy-key": "AAAA" + "fakefix" + ":" + "APA91b" + "FakeFixture" * 10,
        "jwt": jwt(),
        "uri-with-credentials": uri_with_credentials(),
        "assigned-secret": "password = '" + "Fake-Fixture-9x" + "'",
        "defined-secret": "define('AUTH_" + "KEY', '" + "fake-fixture-value" + "');",
        "long-hex": 'digest = "' + long_hex() + '"',
        "long-base64": 'blob = "' + "Fa+k3/Fixture" * 6 + '"',
    }


class EveryShape(unittest.TestCase):

    def test_every_category_fires_on_its_own_fixture(self):
        cases = positives()
        self.assertEqual(set(cases), {name for name, _ in leakform.PATTERNS},
                         "a category without a fixture is a category never "
                         "seen firing")
        repo = make_repo(self, {"f/%s.txt" % name: value + "\n"
                                for name, value in cases.items()})
        res = leakform.scan(repo)
        by_path = {}
        for f in res["findings"]:
            by_path.setdefault(f["path"], set()).add(f["category"])
        for name in cases:
            with self.subTest(category=name):
                self.assertIn(name, by_path.get("f/%s.txt" % name, set()))

    def test_placeholders_stay_silent(self):
        lines = [
            "password = 'changeme'",
            "password = '${DB_PASSWORD}'",
            "token: 'your_token_here'",
            "api_key = 'xxxxxxxxxxxx'",
            "secret = '<replace-me>'",
            "define('AUTH_KEY', '');",
            "$secret = getenv('SECRET');",
        ]
        repo = make_repo(self, {"config.php": "\n".join(lines) + "\n"})
        self.assertEqual(leakform.scan(repo)["findings"], [])

    def test_value_is_never_in_the_result(self):
        value = google_key()
        repo = make_repo(self, {"a.txt": "k = " + value + "\n"})
        res = leakform.scan(repo)
        self.assertEqual(categories(res), {"google-api-key"})
        self.assertNotIn(value, repr(res))
        out = io.StringIO()
        leakform.report(res, out)
        self.assertNotIn(value, out.getvalue())
        self.assertEqual(res["findings"][0]["value_length"], len(value))


class HeadAndHistory(unittest.TestCase):

    def test_deleted_file_is_history_only(self):
        repo = init_repo(self)
        commit(repo, {"old.txt": "k = " + google_key() + "\n"})
        commit(repo, {"keep.txt": "nothing\n"}, remove=["old.txt"])
        res = leakform.scan(repo)
        self.assertEqual(categories(res, in_head=False), {"google-api-key"})
        self.assertEqual(categories(res, in_head=True), set())

    def test_file_still_present_is_head(self):
        repo = make_repo(self, {"a.txt": "k = " + google_key() + "\n"})
        self.assertEqual(categories(leakform.scan(repo), in_head=True),
                         {"google-api-key"})

    def test_other_branch_is_read(self):
        repo = init_repo(self)
        commit(repo, {"a.txt": "nothing\n"})
        leakform_git = __import__("support").run_git
        leakform_git(repo, "checkout", "-q", "-b", "side")
        commit(repo, {"b.txt": uri_with_credentials() + "\n"})
        leakform_git(repo, "checkout", "-q", "main")
        res = leakform.scan(repo)
        self.assertEqual(categories(res, in_head=False), {"uri-with-credentials"})
        self.assertIn("refs/heads/side", res["coverage"]["refs"])

    def test_line_number_of_a_prefixed_shape(self):
        repo = make_repo(self, {"a.txt": "one\ntwo\nk = " + google_key() + "\n"})
        self.assertEqual(leakform.scan(repo)["findings"][0]["line"], 3)

    def test_one_blob_reported_once_per_category(self):
        body = "\n".join("k%d = %s" % (i, google_key()) for i in range(3))
        repo = make_repo(self, {"a.txt": body + "\n"})
        self.assertEqual(len(leakform.scan(repo)["findings"]), 1)


class SensitiveNames(unittest.TestCase):

    def test_names_are_findings_whatever_the_content(self):
        names = [".env", ".env.example", "deploy.pem", "id_rsa", "id_ed25519.pub",
                 "wp-config.php", "app/google-services.json", ".npmrc",
                 "conf/secrets.yml", "my-service-account-x.json"]
        # distinct content per file, so that each is its own blob
        repo = make_repo(self, {n: "file %d\n" % i for i, n in enumerate(names)})
        got = {s["path"] for s in leakform.scan(repo)["sensitive_names"]}
        self.assertEqual(got, set(names))

    def test_ordinary_names_are_not(self):
        repo = make_repo(self, {"README.md": "x\n", "environment.py": "x\n",
                                "src/keys.py": "x\n", "envelope.txt": "x\n"})
        self.assertEqual(leakform.scan(repo)["sensitive_names"], [])


class Coverage(unittest.TestCase):

    def test_skip_reasons_are_declared(self):
        def planted(n):
            # distinct content per file: identical files are one blob
            return "k = " + google_key() + "\n# %d\n" % n
        repo = make_repo(self, {
            "img.png": planted(1),
            "node_modules/x/index.js": planted(2),
            "dist/app.min.js": planted(3),
            "big.txt": planted(4) + "x" * 200,
            "data.bin.txt": b"\x00\x01" + planted(5).encode(),
            "ok.txt": "nothing here\n",
        })
        res = leakform.scan(repo, max_blob_bytes=100)
        c = res["coverage"]
        self.assertEqual(c["skipped_by_reason"], {
            "binary-extension": 1, "vendored-or-generated": 2,
            "larger-than-limit": 1, "binary-content": 1})
        self.assertEqual(c["blobs_examined"], 1)
        self.assertEqual(c["blobs_total"], 6)
        self.assertEqual(res["findings"], [])


class ReportExitCodes(unittest.TestCase):

    def _rc(self, files):
        repo = make_repo(self, files)
        return leakform.report(leakform.scan(repo), io.StringIO())

    def test_clean_is_0(self):
        self.assertEqual(self._rc({"a.txt": "nothing\n"}), 0)

    def test_finding_is_1(self):
        self.assertEqual(self._rc({"a.txt": jwt() + "\n"}), 1)

    def test_sensitive_name_alone_is_1(self):
        self.assertEqual(self._rc({".env": "nothing\n"}), 1)

    def test_nothing_examined_is_2(self):
        out = io.StringIO()
        repo = make_repo(self, {"a.png": "\x89PNG\r\n"})
        self.assertEqual(leakform.report(leakform.scan(repo), out), 2)
        self.assertIn("NOTHING WAS EXAMINED", out.getvalue())


if __name__ == "__main__":
    unittest.main()
