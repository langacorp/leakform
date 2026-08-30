# leakform

[![self-test](https://github.com/langacorp/leakform/actions/workflows/selftest.yml/badge.svg)](https://github.com/langacorp/leakform/actions/workflows/selftest.yml)

Find secrets in a git repository **by shape**, across **every ref** — and report
position and category, **never the value**.

## The defect it was born from

**2026-08-27.** One of our own repositories, last touched in 2021, was searched for
secrets for the first time. It contained a database URI with credentials, a mail
provider token and three signing keys — all readable the whole time, all in files
that had been deleted years earlier and were still in the history.

Nobody had looked. Nothing in the repository said so. The absence of a finding and
the absence of a search look identical from the outside, and that is the problem
this tool is built around.

## What makes it different

**It searches by shape, not by field name.** A secret does not only live where
something is called `secret`. A repository cleaned of the *word* still contains the
*values*.

**It reads every blob reachable from every ref**, not the working tree. Deleting a
file does not retract what was in it. Findings are split into two groups:

- **in the current HEAD** — the value is in the code that runs today
- **in history only** — the file is gone, the value is not

That distinction changes what you do next, so it is in the output rather than left
to the reader.

**It never prints a value.** Not truncated, not masked, not in an error path. Only
the path, the line, the category and the length. A value reported is a value that
has left a second time — and a rotation does not retract a value that is already
out, so the report must not create a new copy of it.

**Some findings are the file name.** `.env`, `*.pem`, `id_rsa`,
`service-account.json`, `wp-config.php` and their relatives are reported by name
whatever is inside them. `.env.example` is reported too: that is not a false
positive, the name is the finding.

## Coverage is always declared

Every run states how many blobs were examined out of how many exist, across how
many refs, and **how many were skipped and why** — binary content, vendored or
generated paths, larger than the limit.

A run that examined nothing prints `NOTHING WAS EXAMINED. This is not a pass.` and
exits `2`. A search that looked at zero blobs and returned success is exactly the
defect this tool exists to make visible.

## Install

None. Python 3.8+, standard library only, plus `git` on `PATH`.

```
curl -O https://raw.githubusercontent.com/langacorp/leakform/main/leakform.py
python3 leakform.py --selftest
```

## Prove it before you trust it

```
python3 leakform.py --selftest
```

The self-test builds three temporary repositories and asserts all three directions:

1. **must fire** — a repository where an `.env` and a private key were committed and
   then **deleted in a later commit**. The values must still be found, and must be
   reported as *history only*, not as HEAD.
2. **must stay silent** — a repository whose code only references environment
   variables, with `changeme`, `${SECRET}` and empty strings. Zero findings.
3. **must not look like a pass** — a repository containing only a binary file.
   Zero blobs examined, non-zero exit.

Either of the first two failing fails the whole test. A check that has only been
exercised in the direction where it passes is indistinguishable from one that
always passes.

## Use

```
# a working repository
python3 leakform.py /path/to/repo

# a mirror clone, which is the honest way to cover every ref
git clone --mirror https://example.org/team/project.git project.git
python3 leakform.py project.git

python3 leakform.py project.git --json
```

Exit codes: `0` nothing found · `1` findings · `2` nothing was examined.

## The hook: one second earlier

The scanner finds secrets that are already in the history. `hooks/pre-commit`
finds them one second before, which is the only second that matters — once a
secret is committed it is in the history for good, and rewriting history does
not revoke the value.

```sh
cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

POSIX sh, nothing beyond `git` and `grep`. It reports **file, line and
category — never the value**: knowing where is enough to remove it. A false
positive is committed deliberately with `git commit --no-verify`.

## Limits, stated

- It reads blobs. It does not see build artefacts, CI secrets, or anything that
  never entered the repository.
- The generic shapes — long hex strings, long base64 blobs, `name = "value"` —
  will match things that are not secrets. They earn their place because a key does
  not always announce itself with a vendor prefix. Read them, do not trust them.
- The placeholder list is deliberately short. Every entry is a decision to stay
  silent, and a longer list is a quieter tool, not a better one.
- Finding nothing is not proof that there is nothing. It is proof that these shapes
  were not present in the blobs that were examined — which is why the coverage line
  is not optional.

## After a finding

It now runs before every publication of ours — every repository under
[github.com/langacorp](https://github.com/langacorp) — and none goes public until
this has been run over it.

Rotate at the source. Rewriting the history or deleting the repository does not
retract a value that has already been readable: only revoking it does. Write two
dates — when the credential lost its power, and when the last copy of it expires.
The second one is usually *never*, as long as the history exists.

## The other three

`realroute`, `leakform`, `samecheck` and `provenreal` came out of the same
weeks of measuring. Each one is standalone and depends on none of the others.

- **[realroute](https://github.com/langacorp/realroute)** — checks that a route
  really exists, by content and not by status code. Born from a site that answered
  200 to an address that could not exist.
- **[samecheck](https://github.com/langacorp/samecheck)** — measures whether the
  copies that should be identical still are. Born from a component that turned
  out to have six distinct contents across its installations.
- **[provenreal](https://github.com/langacorp/provenreal)** — compares what a
  system claims with what can be measured. Born from six different numbers
  answering the same question.


## Where this comes from

LANGA runs 16 digital services across 5 networks on its own infrastructure.
This tool came out of a defect we hit while running them, and it is the reason
the code behind those products could be opened up at all:

- [LANGA](https://langa.tv) — the ecosystem
- [easy LANGA](https://easy.langa.tv) — client management, reports, support
- [LANGA Tools](https://tools.langa.tv) — WordPress toolkit for developers
- [Fertilyze](https://fertilyze.langa.tv) — WordPress SEO audit and plugin

See [How we work](https://about.langa.tv/how-we-work/).

---

## License

MIT. See `LICENSE`.

---

Built and maintained by LANGA.
