# Contributing to foundation

Changes land through pull requests. `main` is protected and `CI Complete` gates the merge.

## Check the PR title and body first

CI fails a PR whose title or body breaks the PR Hygiene rules, and that only
shows after `gh pr create`. Write the body to a file from the PR template and
run the check locally before opening the PR:

```sh
gh api -H 'Accept: application/vnd.github.raw' \
  repos/MustardSeedNetworks/.github/contents/scripts/check-pr-body.py |
  python3 - --title 'fix(api): handle empty body' --body-file body.md
```

It runs `scripts/check-pr-body.py` from `MustardSeedNetworks/.github`, which
reads the rules out of this repo's own `.github/workflows/pr-hygiene.yml`
instead of keeping a copy, so it cannot disagree with CI. It needs `gh` signed
in. Exit 0 means the title and body pass; the failures it prints are the ones
CI would print.
