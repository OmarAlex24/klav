# 0004 · Vault = profile, project = scope; each with its own key

- Status: accepted
- Date: 2026-11-02

## Context
We need to separate Work from Personal and, on top of that, give an agent access to "the keys for this repo" without giving it the whole vault.

## Decision
There are two levels with their own key: **vault** (profile: Personal, Work) and **project** (a group inside the vault). Agents receive grants per project or per vault. A `klav.toml` in the repo links a directory to a project, and there `run` and the agents are scoped to it by default.

## Consequences
- Per-project scope is also enforced by cryptography.
- Moving an item between projects means rewrapping its item key.
