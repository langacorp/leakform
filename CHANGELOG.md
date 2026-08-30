# Changelog

All notable changes to this project are recorded here.
Dates are the date of the commit, not of a release.

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
