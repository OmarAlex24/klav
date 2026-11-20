# Contributing to Klav

Thanks for helping. Klav is an end-to-end encrypted password manager built for people and for AI agents. A mistake in it can leak someone's secrets, so this guide asks for more care than most. It's short; please read all of it.

> **Status:** the docs are moving from Spanish to English in waves ([ADR 0031](docs/decisiones/0031-repositorio-en-ingles-y-open-source.md)). Some files are still in Spanish. Write new issues, PRs and docs in English, and use the terms in the [glossary](docs/glossary.md). If you edit a file that is still in Spanish, keep your change in Spanish: the file is translated in its wave, so it never mixes languages.
>
> [`AGENTS.md`](AGENTS.md) says the same: everything in the repository is in English, the UI ships in English and Spanish, and a document still in Spanish is edited in Spanish until its translation wave.

## Before you start

- **Found a vulnerability?** Don't open an issue, a discussion or a pull request. Follow [SECURITY.md](SECURITY.md).
- **Read the design first.** Start with [`docs/diseno.md`](docs/diseno.md), the [roadmap](docs/roadmap.md) (work happens only in the current phase) and the [decisions](docs/decisiones/) (ADRs).
- **Agents** working in this repo follow [`AGENTS.md`](AGENTS.md). It holds the same rules as below, plus the commands.

### What we accept from outside

Pull requests from people outside the team ([ADR 0040](docs/decisiones/0040-contribution-gating-and-discussions.md)):

- **Bug fixes**, with a test that fails before the fix. A reliability fix (for example, a crash, a hang, or lost or corrupted data) is a bug fix.
- **Documentation**.
- **Translations** that follow the [glossary](docs/glossary.md).
- **Anything a maintainer has accepted** in an Idea or an issue. Link it in the PR.

Everything else starts as an [Idea](https://github.com/OmarAlex24/klav/discussions/categories/ideas) in Discussions: new features, changed behavior, performance changes, importers from other password managers, new platforms or browsers. For a performance change, put the measurement in the Idea: what you measured, how, and the numbers before and after. A PR that arrives without an accepted Idea or issue is closed by a maintainer, with a comment that names this rule and points to Ideas. The idea isn't lost: we keep the problem it describes.

### What needs a discussion first

- **New features or changed behavior:** open an [Idea](https://github.com/OmarAlex24/klav/discussions/categories/ideas) and wait for a maintainer to agree on the direction and the scope. An Idea a maintainer accepts becomes an issue labelled `accepted`; your PR links that issue.
- **Anything that changes the design:** cryptography, a binary format, the server API, the agent permission model, or what reaches an agent's context. These need a new ADR in `docs/decisiones/` before the code. A maintainer will help you write it.
- **New dependencies:** a new cryptographic dependency always needs an ADR. Any other dependency needs a reason in the PR, and `cargo-deny` has to pass.

## Rules that are never negotiable

These come from [`AGENTS.md`](AGENTS.md). A PR that breaks one of them is not merged, however good the rest is.

- **Cryptography lives only in `crates/klav-core`.** Other crates and apps call the core; they never implement primitives.
- **No home-made cryptography.** Only the RustCrypto crates, `hpke` and `opaque-ke`, plus what an ADR has approved.
- **Secrets are never logged or printed**, tests included. Types holding secrets use `secrecy`/`zeroize`, and never derive `Debug` or `Display`.
- **Agents get actions, not values.** Any new path that returns a secret in clear goes through the `reveal` permission.
- **Binary formats carry a version from their first byte.** Each one is documented in the crypto spec, with test vectors in `docs/vectores/`.
- **`unsafe` is forbidden** except in `klav-ffi` and the Touch ID shim, and always with a `// SAFETY:` comment.
- **Never paste real secrets or vault data** into an issue, a PR, a log or a test: not yours, not anyone's. Redact before you share anything.

## Making a change

### Setup

You need the Rust toolchain from `rust-toolchain.toml` (an exact release that rustup installs the first time you run `cargo` here; the file says how to bump it), and Node with pnpm for the extension. [`docs/self-hosting.md`](docs/self-hosting.md) runs the server; the component guides in `docs/` cover the rest. Before you open a PR, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

To run only `klav-cli`'s tests, build the binaries they start first (`cargo build -p klav-daemon -p klav-server`): the tests take them from the build's own `target/` directory, never from an installed copy, and fail at once if one is missing.

For the extension, run `pnpm install`, `pnpm build`, `pnpm lint`, `pnpm typecheck` and `pnpm test` from the repository root, and `pnpm --filter @klav/extension e2e` for the end-to-end tests.

### One problem per PR

A PR solves **one underlying problem**. Include everything that problem needs: core, server, clients, tests and docs. Split anything else into its own PR: a second fix, an unrelated cleanup, a refactor. Count problems, not issues: several reports can describe one bug.

If you change a deliverable on the roadmap, check its box in `docs/roadmap.md` in the same PR.

### Show what you ran

Explain how you found the problem, what you changed and how you checked it. "Tests pass" alone is not evidence.

- Give the commands you ran and what you saw. Say what you couldn't check, like a real iPhone, Touch ID or Firefox.
- In the PR template's **Test plan**, list only what you actually ran, as checked boxes (`- [x]`). Delete anything you didn't run. Don't leave unchecked boxes.
- UI changes need before and after screenshots, light and dark. Attach them to the PR; don't commit them unless a doc uses them.

### Commits and PR titles

```
<type>: <description>
<type>(<scope>): <description>
```

- **Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore` and `ci`.
- **Scope:** optional. Use the area, for example `fix(extension): …` or `feat(core): …`.
- **The PR title follows the same form:** it becomes the commit when the PR is merged.
- **Sign off every commit** (`git commit -s`) under the [Developer Certificate of Origin](https://developercertificate.org/). The `Signed-off-by:` line must be a person, the one responsible for the change.
  - Klav doesn't ask for a CLA.
  - Contributions come in under the license of the code they touch: AGPL-3.0-only in `crates/klav-server`, Apache-2.0 everywhere else ([ADR 0003](docs/decisiones/0003-licencias.md)).

### Contributions made with AI tools

Klav is built for agents, and agents help build it. AI-assisted contributions are welcome. We judge the problem, the scope and the evidence, not who or what typed the code. In return:

1. **Say so.** Name the model and the harness in the PR, and add a `Co-Authored-By:` line to the commits, for example `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
2. **A person owns it.** The person who signs off has read every line, can explain why it works and answers the review. If you don't understand part of the change, say which part.
3. **Evidence, not volume.** Describe the change briefly, in your own words. We may ask you to shorten long generated descriptions before we review.
4. **The agent follows `AGENTS.md`.** Point your agent at it. It has the same rules as this guide.
5. **Keep secrets away from the model.** Never give an agent real vault contents, a master password or a Secret Key to "test" something. Use `klav` with a throwaway account on a local server.

We don't block any particular model.

## Maintainers and outside contributors

- **Maintainers** push branches to this repository and send stacked PRs with `gh stack`, one branch per layer. The CI runs on them.
- **Three open PRs per person.** If you don't have write access, you can have up to 3 open pull requests here at a time, drafts included. GitHub enforces it: with three open, you can't open a fourth until one of them is merged or closed. Once one of your PRs has been merged here, the limit no longer applies to you.
- **Pull requests from a fork** don't get a CI runner ([ADR 0023](docs/decisiones/0023-ci-en-celesto.md)). When your PR is ready, a maintainer reads the whole diff, including `.github/`, `build.rs`, scripts and tests, and only then pushes your branch here so the checks run: here it runs on Klav's CI machines with this repository's permissions. Your commits keep your authorship and your sign-off.
- **A maintainer reviews and merges.** Only someone with write access can merge, and a maintainer does it once the required checks are green and the review is done. `.github/CODEOWNERS` asks a code owner to review changes to `klav-core`, CI, builds and deployment.
- **No bot closes PRs.** In the weekly triage, a maintainer may close a PR that conflicts with `main` or waits on an answer from you, with a comment saying why. Fix it and comment there, or open a new PR that links the old one.

## Issues and Discussions

- **Issues are for bugs.** Use the bug report form; blank issues are disabled.
- **Ideas and feature requests** go to [Discussions › Ideas](https://github.com/OmarAlex24/klav/discussions/categories/ideas), with its form.
- **Questions** go to [Discussions › Q&A](https://github.com/OmarAlex24/klav/discussions/categories/q-a).
- Search first; add what's new to the existing issue or discussion instead of opening a duplicate.
- For a bug, give the commit or version, the component and the steps. Redact any secrets from logs.

### Triage

A maintainer goes through new issues, Ideas, questions and open PRs about once a week:

- They label each one by type and area (`bug`, `enhancement`, `area:core`, `area:extension`…).
- `crypto` marks issues that need a review of the cryptographic core, and `adr-needed` marks those that would change the design.
- `needs-info` waits for an answer. Without one in 14 days, the issue is closed; it can be reopened at any time.
- `good first issue` and `help wanted` are the best places to start.

## Code of conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
