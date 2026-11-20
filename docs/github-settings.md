# GitHub settings

**Before merging the PR that moves the feature form to Discussions, do steps 1 and 2** (Discussions and the labels). Everything else can wait.

The repository settings that [ADR 0031](decisiones/0031-repositorio-en-ingles-y-open-source.md) §6 and [ADR 0040](decisiones/0040-contribution-gating-and-discussions.md) decide, as an ordered checklist. **Omar applies every one by hand**, in *Settings*; no agent changes a repository setting. Each step says where it is in the GitHub UI and how to check it afterwards with a read-only `gh api` command.

This is a separate file, not a section of ADR 0040, because it has to change after the ADR is accepted: a new CI task adds its check here and in the ruleset in the same PR (ADR 0040 §5), and GitHub moves its menus. An accepted ADR isn't edited.

**Availability** is for a repository owned by a personal account on GitHub Free, taken from GitHub's docs (read on 2026-11-13 in the page sources of the public `github/docs` repository). "Not verified" means the docs I read don't say.

## Before you start

What `gh api` returned on 2026-11-13, with the repository private:

| Setting | Value today |
|---|---|
| Visibility | `private` |
| Merge methods | squash, merge commit and rebase all allowed |
| Automatically delete head branches | on (`delete_branch_on_merge: true`) |
| Default `GITHUB_TOKEN` | `read`, and Actions can't approve PRs |
| Discussions | off |
| Rulesets | none; `main` has no branch protection |
| Dependabot alerts | off (`vulnerability-alerts` answers 404) |
| Private vulnerability reporting | not available (404) |
| Fork PR approval | "Fork PR approval is not allowed for private repositories" (422) |
| Who can open a PR | `pull_request_creation_policy: "all"`; stays so (ADR 0040, not option b) |
| Labels | GitHub's defaults only |

## Part 1: can be applied today, while private

### 1. Discussions and its three categories (ADR 0040 Q2)
**Do this before merging the PR that moves the feature form to Discussions**, together with step 2. Until Discussions is on, that form has nowhere to show and the issue chooser's "Propose a feature" link answers 404.

- **Where:** *Settings › General › Features*, check **Discussions**. Then, in the *Discussions* tab, edit the categories: keep **Announcements**, **Ideas** and **Q&A**; delete **General**, **Polls** and **Show and tell**. GitHub asks where to move the discussions of a deleted category; there are none yet.
- **Availability:** public and private repositories.
- **Check:**
  ```sh
  gh api repos/OmarAlex24/klav --jq .has_discussions
  gh api graphql -f query='query { repository(owner: "OmarAlex24", name: "klav") { discussionCategories(first: 25) { nodes { name slug isAnswerable } } } }'
  ```
  Expect `true`, then exactly three categories: Announcements, Ideas and Q&A (answerable). **Check the slugs** (not verified for Klav): the form is `.github/DISCUSSION_TEMPLATE/ideas.yml` and works only while the Ideas slug is `ideas`, and `.github/ISSUE_TEMPLATE/config.yml` and `CONTRIBUTING.md` link to `…/discussions/categories/ideas` and `…/categories/q-a`. If a slug differs, rename the file or fix the links in a PR.
- After the PR merges, *Discussions › New discussion › Ideas* should show the form.

### 2. Labels (ADR 0031 §4 and §6.8)
**Do this before merging the PR that moves the feature form to Discussions**, together with step 1. The forms add `needs-triage`, and `CONTRIBUTING.md` uses `accepted`, `needs-info`, `crypto`, `adr-needed` and the `area:*` labels. None exist yet. For issue forms, GitHub's docs say a label that doesn't exist "will not be automatically added to the issue": the issue opens without it, silently. For discussion category forms the docs don't say what happens, so create the labels first.

- **Where:** *Issues › Labels*, or `gh label create` by hand.
- **The set, from ADR 0031 §4:**
  - type: `bug`, `enhancement`, `documentation` and `question` (these exist);
  - area: `area:core`, `area:server`, `area:cli`, `area:klavd`, `area:extension`, `area:ios`, `area:mac`, `area:web` and `area:ci`;
  - review: `crypto` and `adr-needed`;
  - status: `needs-triage`, `needs-info` and `accepted`;
  - entry: `good first issue` and `help wanted` (these exist);
  - closing: `duplicate`, `wontfix` and `invalid` (these exist).
- **Availability:** no plan limit.
- **Check:** `gh api repos/OmarAlex24/klav/labels --paginate --jq '.[].name'`.

### 3. Squash only (ADR 0031 P7, ADR 0040 Q9)
- **Where:** *Settings › General › Pull Requests*: keep **Allow squash merging**; uncheck **Allow merge commits** and **Allow rebase merging**.
- **Availability:** the docs set no plan limit.
- **Check:**
  ```sh
  gh api repos/OmarAlex24/klav --jq '{allow_squash_merge, allow_merge_commit, allow_rebase_merge}'
  ```
  Expect `true`, `false`, `false`. The ruleset (step 9) also allows only squash.

### 4. Automatically delete head branches (ADR 0031 §6.7)
Already on; nothing to do.

- **Where:** *Settings › General › Pull Requests*, **Automatically delete head branches**.
- **Availability:** the docs set no plan limit. For a PR from a fork, GitHub uses the fork's setting.
- **Check:** `gh api repos/OmarAlex24/klav --jq .delete_branch_on_merge` → `true`.

### 5. Read-only default token (ADR 0031 §6.5, ADR 0040 Q12)
Already so; nothing to do.

- **Where:** *Settings › Actions › General › Workflow permissions*: **Read repository contents and packages permissions**, and **Allow GitHub Actions to create and approve pull requests** unchecked.
- **Availability:** on a personal-account repository this is the default.
- **Check:** `gh api repos/OmarAlex24/klav/actions/permissions/workflow` → `{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}` (what it returned on 2026-11-13).

### 6. Dependabot alerts (ADR 0031 §6.4)
ADR 0031 lists it for the day the repository goes public. **Not decided by any ADR; my choice:** doing it now, while private. The docs allow it, and turning it on early only brings the alerts sooner. Its automatic updates stay off: `cargo-deny` watches the advisories.

- **Where:** *Settings › Advanced Security*, **Dependabot alerts** › **Enable**.
- **Availability:** "available for organization-owned and user-owned repositories".
- **Check:** `gh api -i repos/OmarAlex24/klav/vulnerability-alerts | head -1` → `204` when enabled, `404` when not (the REST docs' status codes; 404 today).

## Part 2: on the day the repository goes public
In this order. Steps 1–3 of ADR 0031 §6 come first: the secret scan of the whole history, the renames of wave 3, and the review of `docs/`.

**Before step 7, check that no workflow uses an action from a private repository.** GitHub shares a private repository's actions "only from private repositories". It resolves every `uses:` when the job is set up, before `continue-on-error` can apply, so one such line fails the whole `ci` job on every run. The ci-cache action is a local copy for this reason (`.github/actions/ci-cache/README.md`). List every `uses:` that names another repository and check its visibility:

```sh
grep -rhoE --include='*.yml' --include='*.yaml' 'uses: *[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+' .github/ | sed -E 's/uses: *//' | sort -u |
  while read -r repo; do printf '%s\t' "$repo"; gh api "repos/$repo" --jq .visibility; done
```

Expect `public` on every line. Local actions (`uses: ./…`) don't appear.

The check above reads one checkout. A pull request runs the `ci.yml` of its merge commit with its base branch. So a stacked PR whose base isn't `main` keeps the old `uses:` line until `main` is merged into the bottom of its stack and passed up. Once the repository is public, each of those fails its whole `ci` job at setup on its next push. A PR based on `main` gets `main`'s line in its merge commit, so it is fine. List the open PRs whose base isn't `main` and that still name a private action:

```sh
gh pr list --state open --limit 200 --json number,baseRefName,headRefOid \
  --jq '.[] | select(.baseRefName != "main") | "\(.number) \(.headRefOid)"' |
  while read -r n sha; do
    if ! f=$(gh api -H "Accept: application/vnd.github.raw" "repos/OmarAlex24/klav/contents/.github/workflows/ci.yml?ref=$sha"); then
      echo "#$n: could not read its ci.yml"
    elif printf '%s\n' "$f" | grep -q 'OmarAlex24/ci-cache/setup@'; then
      echo "#$n"
    fi
  done
```

It reads each PR's head, which can only over-report: a head with the old line whose base already has the new one merges clean. Expect no output. Otherwise, merge `main` into the bottom of those stacks and pass it up before step 7.

### 7. Make the repository public
- **Where:** *Settings › General › Danger Zone › Change repository visibility*.
- **Check:** `gh api repos/OmarAlex24/klav --jq .visibility` → `public`.
- **Do step 8 immediately after.** Until its setting is saved, GitHub's default applies: approval only for first-time contributors.

### 8. Actions: approval for all external contributors (ADR 0040 Q12)
`ci.yml`'s `if:` skips fork PRs, but a fork PR runs its own copy of the workflow and can remove that line; approval is what stops it. Approving a fork PR's run starts a Boat machine for the fork's own copy of `ci.yml`, without that `if:`, so don't approve one. Pushing its branch here runs the same code on Boat with this repository's `ci.yml` permissions (`id-token: write` for the compile cache), so read the whole diff first: `.github/`, `build.rs`, scripts and tests included. Push only what you would merge. The setting does not cover `pull_request_target` (ADR 0040 §4).

- **Where:** *Settings › Actions › General › Approval for running fork pull request workflows from contributors*: **Require approval for all external contributors**, then **Save**. Leave *Fork pull request workflows* (the private-repository policy) as it is: all off.
- **Availability:** public repositories only (the docs' section is "in public repositories"; on 2026-11-13 the API refused it for the private repository).
- **Check:** `gh api repos/OmarAlex24/klav/actions/permissions/fork-pr-contributor-approval --jq .approval_policy` → `all_external_contributors` (a value from the REST docs).

### 9. The ruleset on `main` (ADR 0031 §6.6, ADR 0040 Q1 (a) and Q10)
- **Where:** *Settings › Rules › Rulesets › New ruleset › Import a ruleset*, then pick a file with the JSON below and click **Create**.
- **Availability:** public repositories on Free ("Rulesets are available in public repositories with GitHub Free…").

What it holds:

- **Decided by ADR 0031 §6 and ADR 0040 (Q10 as amended twice on 2026-11-13):**
  - a PR is required, with **0 approvals** and no required code-owner review;
  - conversations resolved: not required (ADR 0040 Q10, second amendment; ADR 0031 §6.6 had it). Review comments stay visible; they don't block;
  - the eight checks, each pinned to GitHub Actions (integration 15368, the app that publishes them from the `ci` job);
  - squash only, no force push, no deletion;
  - **an empty bypass list**: the rules bind everyone, the owner included.
- **Not decided by any ADR; my values, change them if you want:**
  - `strict_required_status_checks_policy: false`: requiring branches to be up to date would make every merge to `main` force a rebase, and a new Boat start, on every open PR;
  - `dismiss_stale_reviews_on_push` and `require_last_push_approval`: `false`, as GitHub's defaults. With 0 approvals they do nothing today; they matter once the count goes to 1.
- **`CODEOWNERS`** still requests a review from `@OmarAlex24` on the paths it lists. With `require_code_owner_review: false` it never blocks a merge.
- **The approval count goes to 1**, by a new ADR, when Klav has a second maintainer.

The check names come from `.github/ci-tasks.json`, mapped through `CI_TASK_CHECK_NAMES` in `.github/workflows/ci.yml` (`test-postgres` publishes `test (postgres)`):

```json
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": [
        "~DEFAULT_BRANCH"
      ],
      "exclude": []
    }
  },
  "bypass_actors": [],
  "rules": [
    {
      "type": "deletion"
    },
    {
      "type": "non_fast_forward"
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "require_code_owner_review": false,
        "required_review_thread_resolution": false,
        "dismiss_stale_reviews_on_push": false,
        "require_last_push_approval": false,
        "allowed_merge_methods": [
          "squash"
        ]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          {
            "context": "fmt",
            "integration_id": 15368
          },
          {
            "context": "cargo-deny",
            "integration_id": 15368
          },
          {
            "context": "extension",
            "integration_id": 15368
          },
          {
            "context": "docs",
            "integration_id": 15368
          },
          {
            "context": "test",
            "integration_id": 15368
          },
          {
            "context": "docker",
            "integration_id": 15368
          },
          {
            "context": "clippy",
            "integration_id": 15368
          },
          {
            "context": "test (postgres)",
            "integration_id": 15368
          }
        ]
      }
    }
  ]
}
```

- **Check:**
  ```sh
  gh api repos/OmarAlex24/klav/rulesets --jq '.[] | {name, enforcement}'
  gh api repos/OmarAlex24/klav/rules/branches/main --jq '[.[].type]'
  gh api repos/OmarAlex24/klav/rules/branches/main --jq '.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context'
  ```
  Expect `main` and `active`; the four rule types `deletion`, `non_fast_forward`, `pull_request` and `required_status_checks`; and the eight check names.
- **`gh stack merge --squash` keeps working:** nothing in this ruleset needs a bypass. A stack merges once every layer has its eight checks green.
- **In an emergency**, Omar, as repository admin, can disable the ruleset in *Settings › Rules › Rulesets* (set *Enforcement status* to **Disabled**) and enable it again afterwards. That is the only way around it, and it is deliberate: any change to the ruleset itself is an admin action in *Settings*.
- **A fork PR** never shows these checks from its own run, because CI doesn't run on forks. It merges only after a maintainer tests its branch here (`CONTRIBUTING.md`; see "Not verified yet" below).

### 10. Native open-PR limit (ADR 0040 Q6)
- **Where:** *Settings › Moderation options › Interaction limits*, section **Pull request limits**:
  - maximum **3** open pull requests for users without write access;
  - **Count draft pull requests toward the limit** checked;
  - **Exempt users based on merged pull requests** on, with **1**;
  - **Exempt users based on account age** off, and the exemption list (the docs call it a *bypass list*; it has nothing to do with the ruleset's) empty. **Not decided by any ADR; my choice:** ADR 0040 Q6 sets only the count, drafts and the merged-PR exemption.

  On the same page, set **no** temporary interaction limit (ADR 0040 Q13).
- **Availability:** public repositories ("In a public repository, you can set a maximum number of pull requests…").
- **Check:** `gh api repos/OmarAlex24/klav/interaction-limits/pulls/creation-cap` → `enabled: true`, `max_open_pull_requests: 3`, `include_drafts: true`, and `gh api repos/OmarAlex24/klav/interaction-limits/pulls/bypass-list` → an empty array, no users (endpoints from the REST docs, *Interactions › Repository*; on 2026-11-13 both answered 405, "Interaction limits are not available for private repositories"). The merged-PR and account-age exemptions are not among the endpoint's documented fields: check them in the UI. For the temporary limits: `gh api repos/OmarAlex24/klav/interaction-limits` should give "an empty response" (the REST docs' words for no restrictions).

### 11. Private vulnerability reporting (ADR 0031 §6.4)
`SECURITY.md` already points to it.

- **Where:** *Settings › Advanced Security*, **Private vulnerability reporting** › **Enable**.
- **Availability:** "available for public repositories".
- **Check:** `gh api repos/OmarAlex24/klav/private-vulnerability-reporting --jq .enabled` → `true` (the endpoint returns a boolean, per the REST docs; 404 today).

### 12. Secret scanning with push protection (ADR 0031 §6.4)
- **Where:** *Settings › Advanced Security*, under **Secret Protection**: **Enable** if it isn't, then **Push protection** › **Enable**.
- **Availability:**
  - secret scanning: on public repositories it "runs automatically for free"; on a private repository of a personal account it is not available on Free;
  - push protection for a repository: available on public repositories at no cost ("Available for public repositories by default", *GitHub security features*).
- **Check:** `gh api repos/OmarAlex24/klav --jq .security_and_analysis` shows `secret_scanning` and `secret_scanning_push_protection` with `"status": "enabled"` (field names from the REST docs; it returned `null` while private).

### 13. The Discussions links answer publicly
The issue chooser, the Ideas form and `CONTRIBUTING.md` link to the categories. Signed out, or with `curl`:

```sh
for c in ideas q-a; do curl -s -o /dev/null -w "$c %{http_code}\n" "https://github.com/OmarAlex24/klav/discussions/categories/$c"; done
```

Expect `200` for both. Before the repository is public they answer 404 to anyone who is not signed in with access.

## Left as they are, on purpose
- **Who can open a PR:** `all`. ADR 0040 rejected "Collaborators only" (option b). Check: `gh api repos/OmarAlex24/klav --jq .pull_request_creation_policy` → `"all"`.
- **No temporary interaction limits** at launch (Q13). They stay a tool for an incident.
- **No contribution workflows:** no vouch list, no automatic close windows and no repository variable to enforce them (Q5, Q7). Any later workflow follows ADR 0040 §4.

## Not verified yet
- **The exemption after one merged PR, for a fork contributor.** `CONTRIBUTING.md` promises that once one of your PRs is merged here, the open-PR limit no longer applies. A fork PR gets no CI, and pushing its branch here is not enough either: `ci.yml` runs on pushes to `main` and on same-repository PRs, so a maintainer has to open a PR from the pushed branch, after reading the whole diff (step 8). Its run publishes the eight checks on the same commit as the fork PR's head. If the fork PR shows them, the maintainer merges the fork PR itself and it counts as the contributor's; if it doesn't, the maintainer merges the copy, the fork PR is closed, not merged, and the exemption never applies. On the first outside PR, check:
  - whether the fork PR lists the eight checks after the copy's run, with the same head SHA;
  - whether, merged that way, it shows **Merged**, not **Closed**;
  - whether the author's next PRs count toward the limit.

  If the fork PR can't be merged itself, add its author by hand to the limit's exemption list (step 10), so `CONTRIBUTING.md` stays true, and fix this note.
- **`gh stack merge` under the ruleset.** GitHub's docs don't say whether the atomic stack merge judges the required checks per layer, against each layer's head after retargeting, nor whether it honors `allowed_merge_methods` with `--squash`. The first stack merged under the ruleset is the test. If it refuses, merge the layers one at a time from the bottom with `gh stack merge <pr> --squash` (without `--yes`, so it shows what it will merge: a bare number is read as a stack number first); it merges everything up to and including that PR. If the refusal is about the merge method, use the other way: `gh stack unstack`, then `gh pr merge --squash` on each PR, bottom first: `gh pr merge` doesn't merge a PR that is still in a stack, and `gh stack unstack` leaves stacked any PR that is queued for merge or has auto-merge on.
