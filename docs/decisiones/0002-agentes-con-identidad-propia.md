# 0002 · Agents have their own key pair

- Status: accepted
- Date: 2026-11-02

## Context
An agent needs to decrypt secrets, but giving it the master password would give it access to everything, with no way to revoke or audit it separately.

## Decision
Each agent generates an X25519 + Ed25519 pair locally. The human approves the registration (checking the 6-word fingerprint) and their client uses HPKE to wrap, for the agent's public key, only the keys of the shared projects. Every request is signed. The default is to hand over actions (`fill`, `inject`), not values (`reveal` off), because the LLM is not trusted even if the agent runtime is.

## Consequences
- An agent's scope is limited by cryptography, not just by the server.
- Revoking does not erase what the agent already saw: the audit log says which secrets to rotate.
- Rotating a project key means rewrapping the item keys (it is cheap; the data does not need to be re-encrypted).
