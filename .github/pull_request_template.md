<!--
Read CONTRIBUTING.md first. One underlying problem per PR.
Title: `<type>: <description>` or `<type>(<scope>): <description>`, in English.
Vulnerabilities never go in a PR: follow SECURITY.md.
-->

## Problem

<!-- One or two sentences: what's wrong or missing, and how to see it.
Link the issue, and for a feature the comment where a maintainer agreed on the scope (`Closes #123`). -->

## Change

<!-- What you changed and why it solves the problem. If it touches several
components, say why each one is needed for this same problem. -->

## Design and rules

<!-- Delete the lines that don't apply, and explain any that do. -->

- Changes cryptography, a binary format or test vectors (`klav-core`, crypto spec, `docs/vectores/`):
- Changes what an agent or the server can see or do, or adds a path that returns a secret (`reveal`):
- Adds a dependency (crypto dependencies need an ADR):
- ADR: <!-- link, or "not needed" -->

## Test plan

<!-- List ONLY what you actually ran, as checked boxes, with the result.
Delete every line you didn't run. Don't leave unchecked boxes.
Say below the list what you couldn't check (a real device, Touch ID, Firefox…).
Examples:
- [x] `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
- [x] `cargo test --workspace`: 522 passed
-->


## Screenshots

<!-- For UI changes: before and after, light and dark. Otherwise, delete this section. -->

<!-- If an agent did the work, end with the model and the harness, for example:
Made with Claude Opus 5.5 in Claude Code. -->
