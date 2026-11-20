# ci-cache setup (vendored copy)

The `rust: ci-cache` step of `.github/workflows/ci.yml` uses this action. It gets a compile-cache session from the ci-cache Worker with the job's GitHub OIDC token, mounts the checkout at `/home/user/klav` and starts sccache against that cache.

- **Source:** the `OmarAlex24/ci-cache` repository, at commit `c8972d60665c09e92455a710e406308f9e1bcbbd`. That repository is private, and GitHub lets only private repositories use an action from a private repository, so Klav, once public, keeps its own copy.
- **What is here:** the three files the action needs at run time, byte for byte and at the same paths relative to each other as in the source: `setup/action.yml`, `setup/setup.sh` and `scripts/cache-fingerprint.sh`. `action.yml` runs the fingerprint script through `$GITHUB_ACTION_PATH/../scripts/`, which is why `scripts/` sits next to `setup/`.
- **Kept in step by hand.** Don't edit these files here, not even to translate their Spanish comments or reformat them: a copy that differs from its source can't be diffed against it. Change the action in `ci-cache`, then update the copy.

## Updating the copy

From the repository root, with `gh` signed in to an account that can read `ci-cache`, and `SHA` set to the full commit to copy:

```sh
SHA=<full commit SHA>
for f in setup/action.yml setup/setup.sh scripts/cache-fingerprint.sh; do
  gh api -H "Accept: application/vnd.github.raw" \
    "repos/OmarAlex24/ci-cache/contents/$f?ref=$SHA" >".github/actions/ci-cache/$f"
done
git add .github/actions/ci-cache
# Each blob must equal the source's (same SHA-1, same mode):
git ls-files -s .github/actions/ci-cache
gh api "repos/OmarAlex24/ci-cache/git/trees/$SHA?recursive=1" \
  --jq '.tree[] | select(.path | test("^setup/|^scripts/cache-fingerprint")) | [.mode, .sha, .path] | @tsv'
```

Then:

1. Check that the action still needs only these files. Look for new `$GITHUB_ACTION_PATH` paths, `uses:` lines, `github.action_*` references and downloads from `ci-cache`.
2. Read the diff for anything that must not be public.
3. Update the commit SHA in this file and in the comment above the step in `ci.yml`, in the same PR.

The PR's own CI run is the test. In the `rust: ci-cache` step's log, look for the session line (`ci-cache: sesión …`), the mount and `sccache … listo`. The step has `continue-on-error`, so a broken copy shows up as a slower run, not a red one.
