# 0040 · Contribution gating and Discussions: what "block PRs" means for Klav, Discussions with Ideas and Q&A, and the eight required checks

- Status: accepted (Omar answered on 2026-11-13 with the default of every question, then amended Q10 twice and clarified Q4 the same day; see "Omar's answer")
- Date: 2026-11-13
- Changes: [ADR 0031](0031-repositorio-en-ingles-y-open-source.md) §4 and §6, and its answer P6. P10 stands

## Context

### The request
On 2026-11-13 Omar asked, for the open-source launch, to "block PRs, create Discussions, and so on, the way the T3 Code repository has it today" (`pingdotgg/t3code`). That reverses parts of [ADR 0031](0031-repositorio-en-ingles-y-open-source.md), accepted on 2026-11-05:

- **P6** said no Discussions for now; ideas go to an issue with the feature form.
- **§4** rejected T3 Code's "we are not looking for outside contributions" stance ("Klav quiere comunidad"), its automatic `size:*` and `vouch:*` labels, its model blacklist ("not auditable, and it ages badly"), and automatic triage or closing.
- **P10** kept triage weekly and by hand, with `needs-info` closed by hand after 14 days.

A change that contradicts an accepted ADR starts with a new ADR. This one started as a **proposal**: it lays out the mechanisms, what each costs and gives, and asked Omar to choose. It changes no file besides itself, its row in the ADR index and the glossary. `CONTRIBUTING.md`, the templates, the workflows and every GitHub setting change only after the answers, and the settings only by Omar's hand.

### What "block PRs" can mean
Five independent mechanisms. They combine.

| | Mechanism | What it gives | What it costs |
|---|---|---|---|
| **(a)** | A ruleset on `main` | Nobody, outsiders or maintainers, lands code on `main` without a PR, green required checks and the merge method allowed; with an empty bypass list, that includes the owner. ADR 0031 §6 already asked for a ruleset | Nothing for outsiders: they can still open any PR. It only protects `main` |
| **(b)** | GitHub's native "Collaborators only" for pull requests | Only collaborators can open a PR. Everyone else can still read and comment on them | On a repository owned by a personal account, as Klav's is, a collaborator has write access (see below), so the only way to let a person open a PR is to let them push. Outside PRs end |
| **(c)** | T3 Code's way: anyone opens, then automation sorts | Labels mark trust (`vouch:*`) and size; workflows close a PR over an open-PR limit, a PR that stays in conflict, and a PR left unanswered after a triage notice | New `pull_request_target` workflows with a write token on untrusted events (the security section below); a trust list to keep; and, in T3 Code, an agent that judges PRs, which this repository cannot see run |
| **(d)** | A narrower `CONTRIBUTING.md` | Says what is accepted from outside (T3 Code: bug fixes only) and sends ideas to Discussions; a maintainer closes the rest, citing the rule | Only words: someone still has to read and close each PR |
| **(e)** | GitHub's native limit on open PRs per person | Caps how many open PRs a person without write access can have; exemptions by account age, by merged PRs and by a list of up to 100 users. No workflow | A recent GitHub setting: its organization-level version went GA in August 2026, per the `github/docs` commit `dd4ebad4a` "[2026-08-06] Add ability to set PR limits at an org level [GA] (#62492)", dated 2026-08-10, which adds `data/features/pull-request-limit.yml`; how it behaves at the limit, beyond what the docs say, is not tested here |

Option (e) was not in the request. I found it in GitHub's documentation while checking (b), and it does natively the part of T3 Code's `pr-limits.yml` that closes a fourth PR.

## What I read, and when

All reads on **2026-11-13**, read-only.

### T3 Code (`pingdotgg/t3code`), at `main` = `2953fda660c2e5e327a1f5e52f742a59980af618`
Read with `gh api` (repository, rulesets, Discussions over GraphQL, labels) and the raw contents of each file at that commit. The repository is public and MIT, `Copyright (c) 2026 T3 Tools Inc.`

**Repository settings that anyone can see.**

- `has_discussions: true`, with three categories (GraphQL `discussionCategories`): **Announcements** ("Updates from maintainers"), **Ideas** ("Share ideas for new features") and **Q&A** ("Ask the community for help", answerable). GitHub creates six by default; the other three (General, Polls, Show and tell) are gone. There is no `.github/DISCUSSION_TEMPLATE/` (404), so no category has a form.
- `pull_request_creation_policy: "all"`: **anyone can open a PR**. The filtering happens afterwards.
- Volume at the time of reading: 2,857 open PRs, 1,333 open issues and 3,582 discussions. Klav has no outside PRs today.
- One ruleset, "Passing CI on main", active on `~DEFAULT_BRANCH`: restrict deletion; eight required checks (`Test`, `Check`, `Mobile Native Static Analysis`, `Release Smoke`, `Test Server 1`, `Test Server 2`, `Test Server 3`, `Rust`), each pinned to integration 15368 (GitHub Actions), not strict (the branch need not be up to date); PR required with **zero** approvals, no code-owner review, merge methods **squash or rebase**. No visible rule blocks force pushes.

**Workflows that gate contributions.** Each one read whole. All run on GitHub-hosted runners (`ubuntu-24.04`, except `stale-needs-more-info.yml` on `ubuntu-latest`), and every action is pinned to a commit SHA.

| File | Triggers | `permissions` | What it does |
|---|---|---|---|
| [`pr-vouch.yml`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/workflows/pr-vouch.yml) | `pull_request_target` (opened, reopened, synchronize, ready_for_review, converted_to_draft); `issue_comment` created; `push` to `main` touching `VOUCHED.td` or the workflow | `contents: read`, `issues: write`, `pull-requests: write` | Collects targets: the PR on a PR event; the PR on a comment containing `/recheck-vouch` (an `if:` skips every other comment before a runner starts; **anyone** who can comment can trigger it); every open PR on a push. For each, runs `mitchellh/vouch/action/check-user` (v1.5.0, with `allow-fail`) and keeps exactly one of `vouch:trusted` (status bot, collaborator or vouched), `vouch:denounced` or `vouch:unvouched`, creating or updating the three labels' colors and descriptions. Never comments or closes. No checkout |
| [`pr-size.yml`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/workflows/pr-size.yml) | `pull_request_target` (same five types) | `contents: read` at the top; the label job adds `issues: read`, `pull-requests: write` | A config job builds the six `size:*` definitions (XS < 10, S < 30, M < 100, L < 500, XL < 1,000, XXL beyond). The label-definition sync job runs only on events other than `pull_request_target`, which this workflow has none of, so it never runs. The label job checks out the **default branch**, then fetches the PR head into `refs/remotes/pr-size/<n>` as git data only (a comment says never to install or build there), counts `git diff --numstat` ignoring whitespace and excluding test paths unless the PR is only tests, and sets one `size:*` label. A second step loads `.github/scripts/test-delta.cjs` from the base checkout, counts `it(`/`test(` declarations added and removed in test files, and creates, updates or deletes one marked bot comment when the net is 20 or more, or a browser test file is new. The comment can quote file paths from the PR |
| [`pr-limits.yml`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/workflows/pr-limits.yml) with [`scripts/pr-limits.cjs`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/scripts/pr-limits.cjs) | `pull_request_target` (opened, reopened); `schedule` daily at 05:23 UTC; `workflow_dispatch` with `dry_run` (default true) | `contents: read`, `issues: write`, `pull-requests: write` | Both jobs sparse-check out `.github/scripts` (and, by cone mode, the `.td` lists beside it) **from the default branch**, never PR code. **Dry run unless the repository variable `PR_LIMITS_ENFORCE` is `true`**; a dry run only logs. *Open-PR limit* (on open or reopen): skips bots, logins in `TRIAGE_EXEMPTIONS.td` or `VOUCHED.td`, anyone with write, maintain or admin, PRs labelled `triage:keep-open`, and a reopen by someone other than the author; otherwise counts the author's older open PRs by search and, at 3 or more, comments and closes. *Daily sweep* over open PRs labelled `vouch:unvouched`, `needs-rebase` or `triage:closing`: a conflicting PR from an unvouched, non-exempt author gets a comment and `needs-rebase`; after 7 days with no activity and still conflicting it is commented on and closed; `needs-rebase` is removed once mergeable. A PR labelled `triage:closing` is closed 72 hours after the label unless it moved since (then the label is removed). Re-reads each PR before closing; caps of 100 rebase requests, 50 closes and 150 re-reads per run; 1 s between writes; fails closed on a malformed exemption list |
| [`issue-vouch.yml`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/workflows/issue-vouch.yml) | `issues` (opened, reopened); `push` to `main` touching `VOUCHED.td` or the workflow; `workflow_dispatch` | `contents: read`, `issues: write` | Reads `VOUCHED.td` from the default branch through the API and labels issues `vouch:trusted` or `vouch:denounced`; unlisted authors get no label. Never comments or closes |
| [`issue-labels.yml`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/workflows/issue-labels.yml) | `push` to `main` touching the issue templates or the workflow; `workflow_dispatch` | `issues: write` | Creates or updates the labels `bug`, `enhancement` and `needs-triage`. Touches no issue |
| [`stale-needs-more-info.yml`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/workflows/stale-needs-more-info.yml) | `schedule` daily at 06:17 UTC; `workflow_dispatch` | `actions: write`, `issues: write` | `actions/stale` v9.1.0 closes as "not planned", with a comment, issues labelled `needs more info` for 7 days with no update. Never marks anything stale itself and never touches PRs |

**Lists.** [`.github/VOUCHED.td`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/VOUCHED.td): `github:<login>` per line, `-github:<login> reason` to denounce; 78 vouched and 2 denounced entries. [`.github/TRIAGE_EXEMPTIONS.td`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/TRIAGE_EXEMPTIONS.td): 6 logins, the team, who skip triage and the limits.

**The agent.** The `triage:closing` label is applied by an agent skill, [`.agents/skills/contribution-triage/SKILL.md`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.agents/skills/contribution-triage/SKILL.md), not by a workflow. It loads the policy from a freshly resolved `main`, never from the PR; judges "bug fix", "one problem", evidence and the model rule; posts a notice citing the rule; then labels `triage:closing` when `PR_LIMITS_ENFORCE` reads `true` (the sweep closes 72 hours later) and closes the PR itself otherwise; it hands eligible PRs to an outside reviewer with a `macroscope-review` label. No workflow in the repository references it, so **what runs it, when and with which credentials cannot be seen from outside**.

**Templates and guide.** [`ISSUE_TEMPLATE/config.yml`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/.github/ISSUE_TEMPLATE/config.yml) turns blank issues off and has one contact link, "Feature request", to the Ideas category. Issue forms: `bug_report.yml`, which also points features to Ideas, and `via-triage.yml` for reports filed by its own diagnostics agent. The PR template has Problem, Change, Scope and Verification. [`CONTRIBUTING.md`](https://github.com/pingdotgg/t3code/blob/2953fda660c2e5e327a1f5e52f742a59980af618/CONTRIBUTING.md) says the team does not want feature PRs from outside and lists what it auto-closes; accepts only bug fixes, unless a maintainer asked for the PR; and sets these rules for a PR, drafts included: one problem, evidence, named models whose PRs it closes, 3 open PRs per person, a 7-day conflict window, bans for spam and harassment, and a 72-hour close after a notice. Vouched contributors skip the limit and the conflict window.

**What cannot be observed from outside**, and I don't guess:

- the value of `PR_LIMITS_ENFORCE`, so whether the limits close anything or only log;
- the ruleset's bypass actors (the API returns `null` to a non-admin);
- interaction limits, and whether the native open-PR limit (e) is set (`GET /interaction-limits` returns 403 without admin);
- who has write access, and the Actions settings: approval for outside contributors, the default `GITHUB_TOKEN` permissions;
- what runs the triage skill, and how the `macroscope-review` handoff is configured.

### GitHub's own settings
Read on docs.github.com and, for exact wording, in the page sources of the public `github/docs` repository at `8b64cbd` (2026-11-13). The pages show no "last updated" date. Quotes are verbatim; the rest is paraphrase.

- **Restricting who can open a PR** ([Disabling pull requests](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/disabling-pull-requests); [REST "Update a repository"](https://docs.github.com/en/rest/repos/repos#update-a-repository); [changelog, 2026-02-13](https://github.blog/changelog/2026-02-13-new-repository-settings-for-configuring-pull-request-access/)). The setting exists: "To restrict pull requests to collaborators only, in the dropdown under "Pull requests" select **Collaborators only**." The API field is `pull_request_creation_policy`, with values `all` and `collaborators_only`. "In personal repositories, a collaborator is anyone who has been invited to the repository", and on such a repository "Collaborators can't have read-only access" ([permission levels for a personal account repository](https://docs.github.com/en/account-and-profile/reference/permission-levels-for-a-personal-account-repository)): they can push and merge. The changelog says the PR tab stays visible and anyone can still read and comment; it says nothing about bots or apps.
- **Turning PRs off.** A public repository can: "To disable pull requests entirely, under "Features", deselect **Pull requests**." The changelog adds that the tab then disappears. Not proposed: nobody could read Klav's PRs.
- **Temporary interaction limits** ([Limiting interactions in your repository](https://docs.github.com/en/communities/moderating-comments-and-conversations/limiting-interactions-in-your-repository)): "Enabling an interaction limit for a repository restricts certain users from commenting, opening issues, creating pull requests, reacting with emojis, editing existing comments, and editing titles of issues and pull requests." Durations: "24 hours, 3 days, 1 week, 1 month, or 6 months." Three types: existing users (accounts under 24 hours old with no prior contributions), prior contributors (those who have contributed to the default branch) and collaborators only. A tool for an incident, not a policy.
- **Native open-PR limit** (same page, section "Limiting concurrent open pull requests for users without write access", feature flag `pull-request-limit`, enabled for github.com; live on docs.github.com on 2026-11-13): "In a public repository, you can set a maximum number of pull requests that a user without write access can have open at the same time." Drafts count only if "Count draft pull requests toward the limit" is on. Exemptions: by account age in days, by number of merged PRs in the repository, and a list that "supports up to 100 users."
- **Rulesets** ([About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets); [Available rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)): "Rulesets are available in public repositories with GitHub Free and GitHub Free for organizations, and in public and private repositories with GitHub Pro, GitHub Team, and GitHub Enterprise Cloud." "Anyone with read access to a repository can view its active rulesets." Required status checks can name the app expected to set them; the PR rule can require approvals, code-owner review and a merge method.
- **Approval for workflows from outside contributors** ([Managing GitHub Actions settings for a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)): three levels, the strictest being "Require approval for all external contributors". And the line that matters most here: "Workflows triggered by `pull_request_target` events are run in the context of the base branch. Since the base branch is considered trusted, workflows triggered by these events will always run, regardless of approval settings." The default `GITHUB_TOKEN` of a personal-account repository reads only `contents` and `packages`.
- **Events** ([Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)): `pull_request_target` "runs in the context of the default branch of the base repository, rather than in the context of the merge commit, as the `pull_request` event does"; "Avoid using this event if you need to build or run code from the pull request." On `pull_request` from a fork, the `GITHUB_TOKEN` "has read-only permissions in pull requests from forked repositories" and no other secrets are passed. `schedule` and `issue_comment` run from the default branch.
- **Secure use** ([Security hardening](https://docs.github.com/en/actions/reference/security/secure-use)): such workflows "must not explicitly check out untrusted code, including from pull request forks"; put untrusted context values in an intermediate environment variable rather than in the generated script; pin actions to a full commit SHA; and "self-hosted runners should almost never be used for public repositories on GitHub."
- **Discussions** ([Managing categories](https://docs.github.com/en/discussions/managing-discussions-for-your-community/managing-categories-for-discussions); [category forms](https://docs.github.com/en/discussions/managing-discussions-for-your-community/creating-discussion-category-forms)): six default categories; "Each repository or organization can have up to 25 categories"; in an announcement category "only people with maintain or admin permissions can create new discussions, but anyone can comment and reply." A category form is `.github/DISCUSSION_TEMPLATE/<category-slug>.yml` on the default branch, in the same YAML form schema as issue forms; polls can't have one.
- **Cost** ([GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)): free and not counted against included usage: "Standard GitHub-hosted runners in public repositories". "Larger runners are billed for public repositories." While Klav is private, a GitHub-hosted job uses the account's included usage (the page lists 12 USD a month on GitHub Free).

### Klav today (`gh api`, 2026-11-13)
Private; `has_discussions: false`; `pull_request_creation_policy: "all"`; squash, merge commit **and** rebase all allowed (P7's "squash only" is a setting not yet applied); `delete_branch_on_merge: true`; no rulesets. The only workflow is `ci.yml`, triggered by `push` to `main` and `pull_request`. Its single `ci` job runs on Boat and skips PRs whose head is a fork, before a runner is requested (ADR 0023's note of 2026-11-05, ADR 0034 §6). `.github/` belongs to `@OmarAlex24` in `CODEOWNERS`. `THIRD-PARTY-NOTICES.md` does not exist on `main` and no open PR adds it.

## Proposed decision
Omar chose the default answer of every question, then amended Q10 twice and clarified Q4 the same day (see "Omar's answer"), so each part below is what Klav does. The settings are applied by hand, in the order of `docs/github-settings.md`, which the PR applying this ADR adds.

### 1. Gating: (a) + (d) + (e); not (b), not (c)
- **(a) The ruleset** (Q10, as amended twice) is exactly: a PR required, with **0 approvals**; the eight checks (§5 below) required, pinned to GitHub Actions; squash only; no force push; no deletion; an **empty** bypass list. It requires no code-owner review and no resolved conversations. It binds everyone, the owner included, and is the floor under any other option. ADR 0031 §6 had 1 approval, code-owner review, resolved conversations and Omar as bypass; see the amendments for why that changed.
  - Review comments stay visible on the PR; they don't block a merge.
  - A maintainer still reviews every outside PR and is the only one who can merge it. That comes from write access, not from the ruleset.
  - `CODEOWNERS` stays. With no required code-owner review, it requests a review and never blocks a merge.
  - The approval count goes to 1, by a new ADR, when Klav has a second maintainer.
  - In an emergency, Omar, as repository admin, can disable the ruleset in *Settings* and enable it again. That is the only way around it, and it is deliberate: any change to the ruleset itself is an admin action in *Settings*.
- **(e) The native open-PR limit**: 3 open PRs per person without write access, drafts counted, anyone with one merged PR in Klav exempt. It does the part of `pr-limits.yml` that closes a fourth PR, with no workflow, no token and no list to keep. T3 Code's limit is also 3.
- **(d) A narrower `CONTRIBUTING.md`**: see Q4.
- **Not (b).** In a personal-account repository a collaborator has write access, so "Collaborators only" means either no outside PRs, or push rights for anyone who wants to send one. A PR from a branch in this repository starts the Boat `ci` job (`ci.yml` runs on every same-repository PR), which pays a start and gets an OIDC token for the compile cache (`id-token: write`). Both outcomes are worse than (a) + (d) + (e).
- **Not (c).** T3 Code built it for thousands of open PRs; Klav has none from outside. Its parts, and when each might be worth it:
  - the *vouch list* (Q5) replaces the native limit's exemption list once there are more than its 100 slots, or once it should also mark issues;
  - the *conflict and close windows* (Q7) are what a person can do in the weekly triage of P10 while volume stays low;
  - the *size labels* tell a reviewer what `gh pr view` already shows.
  Adding any of them takes a new ADR; its workflows would be Klav's own and follow §4.

### 2. Discussions on, with Announcements, Ideas and Q&A
- Turn Discussions on and keep T3 Code's three categories: **Announcements** (only maintainers start one; release notes and calls for testing), **Ideas** (open-ended) and **Q&A** (answerable). Delete General, Polls and Show and tell: every extra category is something to watch.
- **Feature requests move to Ideas** (Q3). The YAML feature form becomes the Ideas category form, `.github/DISCUSSION_TEMPLATE/ideas.yml`, with the same fields, including the required "Security and agents" question that Klav's form has and T3 Code's lacks. `feature_request.yml` goes away; issues are for bugs.
- **Questions move to Q&A.** `CONTRIBUTING.md` says today "Questions are welcome as issues"; that line changes.
- **`ISSUE_TEMPLATE/config.yml`** keeps `blank_issues_enabled: false` and has three contact links: "Report a security vulnerability" (`SECURITY.md`, first, as today), "Propose a feature" (the Ideas category) and "Ask a question" (the Q&A category).
- **Security**: `SECURITY.md` already says never to open a public discussion about a vulnerability. No security category: a category would invite exactly that.
- **An Idea that a maintainer accepts** becomes an issue (`enhancement`, `accepted`), and an ADR when it changes the design, as `CONTRIBUTING.md` already requires. The PR links that issue.

### 3. What the guide accepts from outside (d)
Recommended: **bug fixes, docs and translations that follow the glossary, and anything a maintainer has accepted in an Idea or an issue**. Other PRs are closed with a comment that cites the rule and points to Ideas. This sits between ADR 0031 (which also invites performance fixes, importers and platforms up front) and T3 Code (bug fixes only). Performance fixes, importers and platforms go through Ideas first (Q4, as clarified); a reliability fix is a bug fix and comes in directly.

### 4. Security bar for any workflow triggered by an outsider
Q5 and Q7 were answered no, so Klav adds no such workflow now. The bar applies to any that a later ADR adds. The bar: **no automation that an outsider triggers can write repository contents, read a secret, or publish a release.**

- **Trigger.** `pull_request_target`, `issue_comment`, `issues` and `discussion` run the default branch's workflow with a token that can write. The Actions approval setting concerns workflows on fork pull requests: for `pull_request_target`, GitHub says they "will always run, regardless of approval settings" (quoted above), and the docs I read tie no approval to the other three. Use them only to read metadata and to label, comment or close.
- **Checkout.** At most a sparse checkout of trusted files from the default branch (`ref: ${{ github.event.repository.default_branch }}`), as `pr-limits.yml` does. Never the PR's head, merge ref or fork, not even as git data, as `pr-size.yml` does. A size count comes from the API (`pulls.listFiles`). Nothing from the PR is installed, built, run, `require`d or `source`d.
- **Permissions.** `permissions: {}` at the top, and per job only what it uses: `pull-requests: write` and/or `issues: write`, `contents: read` only for the sparse checkout. Never `contents: write`, `actions: write`, `id-token: write`, `packages`, `checks` or `statuses`. No `secrets.*` besides the automatic token, no `environment:`. Repository default: read-only token (ADR 0031 §6).
- **Runner and cache.** `runs-on: ubuntu-24.04`, GitHub-hosted, never Boat or `vars.CI_RUNS_ON` (§5). No `actions/cache`, no `setup-*` with caching, no sccache or ci-cache session: `pull_request_target` shares the default branch's cache, and poisoning it would reach `main`'s CI.
- **Actions.** Only `actions/github-script` (and `actions/checkout` for the sparse checkout), pinned to a full SHA, like `ci.yml`. No third-party action that runs with the write token. That rules out `mitchellh/vouch` as T3 Code uses it: at v1.5.0 its `check-user` step installs Nushell with `version: "*"`, the latest release at run time, inside a job holding `pull-requests: write`.
- **Untrusted text.** A PR's title, body, branch name, labels, the author's login and comment bodies are attacker-controlled. Never put them in `${{ }}` inside `run:` or `script:`: a branch named `` a`$(curl …)` `` or a title with `"); …` becomes code. Read them from `context.payload` in JavaScript, or through `env:`, and quote them in shell. Never build a regular expression, a path or a GraphQL query string from them; pass them as variables. Treat a label as data, never as authority: anyone with triage rights can add one, and the policy (what is exempt, the limits) comes only from files on the default branch, which change only through a PR that a maintainer merges (`CODEOWNERS` requests `@OmarAlex24`'s review of `.github/`).
- **What an attacker can still do** under this bar: make the workflow run on every event they can cause (a comment, a push to their PR), which costs Klav nothing on a GitHub-hosted runner and is capped by GitHub's API limits; and get a comment, label or close from the bot on their own PR or issue. Nothing reaches contents, secrets, releases or Boat.
- **Dry run first.** Like T3 Code's `PR_LIMITS_ENFORCE`: a repository variable that Omar sets to `true` after a week of logs.
- **Releases.** Klav has no release workflow yet. Whenever one comes, no outsider-triggered event may start it.

### 5. Where automation runs, and the eight checks
- **Community automation runs on GitHub-hosted runners**, free for a public repository. It must never start a Boat machine: Boat bills a start for every job that gets a machine ([ADR 0034](0034-ci-en-boat.md)), and these jobs are started by strangers. `ci.yml` stays as it is: Boat only for pushes to `main` and same-repository PRs.
- **Before the repository goes public**, a GitHub-hosted job counts against the account's included usage. None is planned (Q5 and Q7 are no); one added later most likely lands after the repository opens.
- **Required checks: eight, not seven.** ADR 0031 §6 lists seven; [ADR 0039](0039-public-docs-site.md) Q2 added an eighth CI task, `docs`, and `.github/ci-tasks.json` has eight. The ruleset requires `fmt`, `clippy`, `test`, `test (postgres)`, `docker`, `extension`, `cargo-deny` and `docs`, each pinned to the GitHub Actions app (`github-actions`, id 15368), which publishes all eight from the `ci` job (check runs on `bb283a1`). A ninth task adds its name to the ruleset in the PR that adds it.
- **A fork PR** still gets no CI and therefore never shows these checks, so it cannot merge until a maintainer pushes its branch here (ADR 0023's note; `CONTRIBUTING.md` says so).

### 6. Licence and attribution
- **Prefer Klav's own small scripts.** Each rule Klav might want from (c) is a short `actions/github-script` step; written from the rules in Klav's `CONTRIBUTING.md`, it owes nothing to anyone.
- **If a file copies or adapts T3 Code's** (`pr-limits.cjs` is the likeliest), the MIT licence requires its copyright and permission notice "in all copies or substantial portions":
  - a header in the file: adapted from `pingdotgg/t3code`, the path and the commit, `Copyright (c) 2026 T3 Tools Inc.`, MIT, see `THIRD-PARTY-NOTICES.md`;
  - an entry in `THIRD-PARTY-NOTICES.md` with the full MIT text. That file, proposed in ADR 0031 §5, does not exist yet; if it still doesn't, the PR that copies creates it.
- Using an action at runtime (`uses:`) copies nothing and owes no notice.
- **Prose.** Klav's guide stays Klav's own; it can cite T3 Code, as this ADR does, but doesn't copy its text.

### 7. Licence detection
Checked on 2026-11-13: `gh repo view --json licenseInfo` and `GET /repos/{owner}/{repo}/license` return Apache-2.0, read from `LICENSE-APACHE`. ADR 0031 §5 stands; nothing to decide.

### 8. What stays with Omar
Every GitHub setting, in *Settings* (no agent changes repository settings):

- Discussions and their categories;
- the ruleset;
- the merge methods;
- the open-PR limit and its exemptions;
- interaction limits;
- the Actions approval level and the token default;
- any repository variable such as an enforce switch;
- the labels, if they are created by hand.

The PR that follows the answers changes only files: `CONTRIBUTING.md`, `.github/ISSUE_TEMPLATE/*`, `.github/DISCUSSION_TEMPLATE/ideas.yml`, other community files only where a sentence becomes false, a dated note in ADR 0031 next to each line this ADR replaces and its index row, and `docs/github-settings.md`, the ordered checklist of the settings above.

## Lines of ADR 0031 that each answer would replace

| Answer | ADR 0031 text it replaces |
|---|---|
| Discussions on (Q2) | P6 ("Sin *Discussions* por ahora"); §4 *Plantillas*, "No hay *Discussions* por ahora" |
| Features to Ideas (Q3) | §4 *Plantillas*, "Formularios YAML de error y de función"; *CONTRIBUTING*, "Las funciones se discuten en un issue antes" |
| Narrower guide (Q4) | §4 *CONTRIBUTING*, "Dice qué se acepta (correcciones, rendimiento, documentación, importadores, plataformas)" |
| Bug fixes only (Q4, T3 Code's option) | Also §4 *CONTRIBUTING*, "No copia el «no buscamos contribuciones» de T3 Code: Klav quiere comunidad" |
| Vouch list (Q5) or size labels | §4 *Etiquetas y triage*, "Sin `size:*` ni `vouch:*` automáticos (T3 Code)" |
| Automatic close windows (Q7) | §4 *Plantillas*, "Tampoco hay triage automático con agentes ni cierre a las dos horas"; P10 ("Sí, a mano") |
| Model blacklist (Q8) | §4 *Contribuciones con IA*, "Klav no tiene lista negra de modelos (T3 Code sí): no es auditable y envejece mal" |
| Eight checks (Q10) | §4 *Revisión, CI y protección de `main`*, "los siete checks"; §6.6, the list of seven |
| No resolved conversations required (Q10, second amendment) | §4 *Revisión, CI y protección de `main`*, "conversaciones resueltas"; §6.6, "conversaciones resueltas" |
| 0 approvals, no required code-owner review, no bypass (Q10, first amendment) | §4 *Revisión, CI y protección de `main`*, "revisión de CODEOWNERS" and "Omar queda en la lista de *bypass*"; §6.6, "PR obligatorio, con 1 aprobación y revisión de CODEOWNERS" and "*bypass*: Omar" |
| Performance through Ideas (Q4, clarified) | §4 *CONTRIBUTING*, "rendimiento" in the list of what is accepted |
| Native open-PR limit (Q6) | Nothing: ADR 0031 had no limit |

## Consequences

### What a first-time outside contributor experiences

| Option | They open a PR… |
|---|---|
| (a) only | It opens. No CI runs (fork). A maintainer reads it, pushes the branch here to test it, and merges it or says why not |
| (b) | They can't. The button isn't there for them; they can comment on existing PRs or open an Idea. To contribute they must be invited, with push access |
| (c) at T3 Code's settings | It opens and gets `vouch:unvouched` and a `size:*` label within a minute. A fourth open PR is closed at once with a comment. If it conflicts, a bot asks for a rebase and closes it 7 days later. If triage finds a rule broken, a notice, then a close 72 hours later unless they answer |
| (d) | It opens. If it is a feature nobody agreed to, a maintainer closes it, citing the rule and pointing to Ideas |
| (e) | Up to three open at once (drafts too); the fourth can't be opened until one closes. After one merged PR, no limit |
| Recommended (a)+(d)+(e) | It opens, within the three-PR limit. A bug fix, docs or an agreed Idea gets a human review and the maintainer runs CI; anything else is closed by a person with a pointer to Ideas |

### Against "Klav quiere comunidad" (ADR 0031 §4)
- **(b)** ends outside PRs; it contradicts it outright.
- **(c)** says, with a yellow label, that a newcomer is untrusted; it closes their work on a timer, by a bot. It answers a volume problem that Klav doesn't have, and costs goodwill Klav does need.
- **Bug fixes only (d, T3 Code's version)** turns away docs, translations and importers, which ADR 0031 named as the most welcome.
- **The model blacklist** judges the tool, not the work, against ADR 0031's "the work, not who typed it", and depends on what each author declares.
- **The recommended set** limits volume (three PRs) and scope (Ideas first), keeps a person in every close, and stays open to newcomers.

### Other consequences
- **Two places to watch** instead of one: issues and Discussions. In exchange, ideas and questions stop crowding the bug list, and Ideas can be upvoted.
- **The weekly triage** of P10 now covers Ideas and Q&A too.
- **Fork PRs still need a maintainer** to push their branch before CI runs. With the native limit, at most three per person wait at once.
- **If a later ADR adds** workflows with a write token on untrusted events, §4 bounds them. `CODEOWNERS` on `/.github/` requests Omar's review of any change to them, but with no required code-owner review (Q10, amended) it does not block a merge: what keeps them in check is that only a maintainer can merge.

## Questions for Omar

| # | Question | Default answer if you say nothing |
|---|---|---|
| Q1 | What does "block PRs" mean? (a) ruleset on `main`; (b) "Collaborators only"; (c) T3 Code's workflows; (d) a narrower `CONTRIBUTING.md`; (e) GitHub's native open-PR limit. They combine | (a) + (d) + (e). Not (b): in a personal repository a collaborator can push. (c) waits for volume (Q5, Q7) |
| Q2 | Turn Discussions on? Which categories? | Yes: Announcements, Ideas and Q&A, as T3 Code; delete General, Polls and Show and tell |
| Q3 | Do feature requests move from the issue form to Discussions › Ideas? | Yes: `feature_request.yml` becomes the Ideas category form, same fields; `config.yml` links Security, Ideas and Q&A; issues are for bugs |
| Q4 | What does the guide accept from outside? (i) bug fixes only, as T3 Code; (ii) bug fixes, docs and translations, plus what a maintainer accepted in an Idea or issue; (iii) ADR 0031's list as is | (ii) |
| Q5 | A vouch list (`VOUCHED.td` and `vouch:*` labels)? | No: the native limit's exemptions (one merged PR, plus a list of up to 100) do its job now |
| Q6 | An open-PR limit? How many? | Yes, the native setting: 3, drafts counted, exempt after 1 merged PR |
| Q7 | Automatic close windows (rebase request, then close after 7 days in conflict; close 72 h after a triage notice)? | No: a person closes in the weekly triage (P10). If yes: Klav's own workflow under §4, in dry run for a week, with those numbers |
| Q8 | A model blacklist? | No, as ADR 0031: not auditable, and it judges the tool, not the work |
| Q9 | Merge method on `main`? | Squash only (P7), in the ruleset and in *Settings › General*; today merge commits and rebase are also on |
| Q10 | Required checks and reviews in the ruleset? | The eight checks (`fmt`, `clippy`, `test`, `test (postgres)`, `docker`, `extension`, `cargo-deny`, `docs`) pinned to GitHub Actions; 1 approval and code-owner review with Omar as bypass, as ADR 0031 §6 |
| Q11 | Licence detection fix? | Withdrawn before the answers: GitHub detects Apache-2.0 (§7) |
| Q12 | Actions approval for outside contributors? | "Require approval for all external contributors" and a read-only default token. It doesn't cover `pull_request_target` (§4) |
| Q13 | Temporary interaction limits at launch? | None. Keep them for an incident (24 h to 6 months) |

## Omar's answer (2026-11-13)

| # | Answer |
|---|---|
| Q1 | (a) + (d) + (e): the ruleset on `main`, a narrower guide, and GitHub's native open-PR limit. Not (b), not (c) |
| Q2 | Discussions on, with Announcements, Ideas and Q&A; General, Polls and Show and tell deleted |
| Q3 | Yes: feature requests move to Discussions › Ideas; issues are for bugs |
| Q4 | (ii): bug fixes, docs and translations, plus what a maintainer accepted in an Idea or an issue (clarified the same day; see below) |
| Q5 | No vouch list |
| Q6 | The native limit: 3 open PRs, drafts counted, exempt after 1 merged PR |
| Q7 | No automatic close windows; a person closes in the weekly triage |
| Q8 | No model blacklist |
| Q9 | Squash only |
| Q10 | The eight checks, 1 approval and code-owner review, no force push, Omar as bypass (amended the same day; see below) |
| Q11 | Not asked: nothing to decide. GitHub detects Apache-2.0 (§7) |
| Q12 | Approval required for all external contributors; read-only default token |
| Q13 | No interaction limits at launch |

### Amendments and clarification (2026-11-13)
The table above is the first answer and stays as given. Later the same day, after two reviews of this ADR and of the PR that applies it, Omar amended Q10 twice and clarified Q4. The rows are in the order they were decided.

| # | Change |
|---|---|
| Q10 | **Amended.** The first answer was the eight checks, 1 approval and code-owner review, no force push, and Omar as bypass. It is now: a PR required with **0 approvals**, the eight checks, squash only, no force push, no deletion, no required code-owner review, and an **empty bypass list**, so the ruleset binds everyone, the owner included. Why: the gh-stack extension's own help says "Bypassing merge requirements is not supported for stacks", so with one required approval `gh stack merge` would refuse every stack Omar opens, since nobody else can approve Omar's PRs; and a bypass skips the required checks too, so on Omar's own PRs the checks would only advise. Outsiders can't merge anyway: Omar's is the only account with write access. With nothing that needs a bypass, a stack merges like any other PR, and the checks bind everyone. The count goes to 1, by a new ADR, when Klav has a second maintainer. `CODEOWNERS` stays and only requests reviews |
| Q4 | **Clarified.** An outside performance PR goes through Discussions › Ideas first, like importers and platforms. A reliability fix counts as a bug fix and still comes in directly |
| Q10 | **Amended again.** After the first amendment the ruleset still required resolved conversations: ADR 0031 §6.6 had them, the question's default was "as ADR 0031 §6", and the first amendment didn't mention them. They are no longer required. Why: once the repository is public, any signed-in user can open a review thread on Omar's PRs, and one unresolved thread on any layer fails a whole `gh stack merge`, which is all-or-nothing; and Omar is the only one who merges, so the requirement would bind only Omar. Comments stay visible; they don't block. The ruleset on `main` is now exactly: a PR required with 0 approvals, the eight checks required, squash only, no force push, no deletion, and an empty bypass list |
