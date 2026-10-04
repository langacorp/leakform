# Changelog

All notable changes to this project are recorded here.
Dates are the date of the commit, not of a release.

## 1.2.0 - 2026-10-04

Every defect below was reproduced first, and each fix comes with a test that
failed on the old code.

- A git error is no longer read as an empty answer. A ref pointing at a missing
  object used to empty the path map, and a repository holding a `.env` exited
  `0`. The listing calls now exit `2`, "NOTHING WAS EXAMINED", as a timeout
  does. A blob git cannot read is skipped as `unreadable` instead of counted as
  examined.
- HEAD is found on git older than 2.36. `ls-tree --format` failed there, HEAD
  read as empty, and every finding was reported as history only. HEAD is also
  the whole tree when a subdirectory is given.
- Every path a blob has had counts. A `.env` renamed away, or the same content
  at `.env` and at another path, was not reported by name; the same text at
  `a.png` and `a.txt` was skipped as binary.
- The repository named on the command line is the one scanned. Inside a git
  hook, `GIT_DIR` used to win, and another repository was reported under its
  name. The self-test commits its fixtures with `--no-verify`, so a globally
  installed pre-commit hook no longer makes it fail.
- `--json` exits `2` when nothing was examined. It used to exit `0`; the text
  output already exited `2`. This changes an exit code to the documented one.
- Findings from `long-hex` and `long-base64` that start a line are reported on
  that line, not on the one before.
- A path that does not exist, or a `LEAKFORM_GIT_TIMEOUT` that is not a number,
  is a usage error (exit `2`), not a traceback with exit `1`.
- pre-commit: files whose name has a space or a non-ASCII letter, files renamed
  and edited in the same commit, and symlinks replaced by files were not read,
  and the hook passed. An index git cannot read no longer passes as "nothing
  staged".
- pre-commit: the awk program found nothing under mawk 1.3.4-20200120 (Debian
  11 and 12, Ubuntu 22.04), missed JWTs and credential URIs under mawk
  1.3.4-20240123, and declared every file binary under BWK awk. It now has no
  interval expressions, and size and binary content are measured outside awk.
  A binary whose first NUL is past line one is no longer read as text.
- The tool and the hook no longer report their own source: PEM headers are
  split into two literals and the self-test's fixtures are built at run time.
- Add a unit test suite in `tests/` (`python -m unittest discover -s tests`),
  including the hook in temporary repositories and a scan of this repository
  by both tools.
- Add `pyproject.toml`: `pip install` or `pipx install` from the repository
  gives a `leakform` command. The version is read from `leakform.__version__`.
- CI runs the unit tests on Python 3.8 (ubuntu-22.04), 3.9, 3.11 and 3.13, and
  the hook under mawk and gawk. actions/checkout@v5, actions/setup-python@v6.

## 2026-08-30

- Every git call now has a timeout. A wedged git used to hang the scan with no
  output; it now exits `2` — nothing was measured — instead of never returning.
- Add `hooks/pre-commit`: stop a secret one second before it is committed.
  POSIX sh and awk, one pass per file, no temporary files. Finds known shapes
  and unknown ones (a high-variety value next to a name that promises a
  secret). Reports file, line and category, never the value — and declares
  what it did not inspect even when it passes.
- README: show the self-test badge
- README: link the Galaxy products the tool was built against
- README: correct a claim that did not match the code, and drop install counts

## 2026-08-28

- README: say where this came from, and name the service it happened on
- README: follow the renamed page
- README: name the domains, with links
- README: the set is four

## 2026-08-27

- leakform: find secrets in a git repository by shape, across every ref
- README: link the two companion tools
