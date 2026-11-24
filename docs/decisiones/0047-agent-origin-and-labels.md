# 0047 · Agent origin, machine metadata and person-owned labels

- Status: accepted (2026-11-24; Omar approved Q1a, Q2a and Q3a — layer 1 implemented, layer 2 pending server deploy)
- Date: 2026-11-24
- Builds on: [ADR 0014](0014-agentes-fase-4.md) (agent registration and signed grants), [ADR 0033](0033-agentes-desde-la-app-de-mac.md) (Mac app Development › Agents), [ADR 0036](0036-sandboxes-de-agentes.md) (credential proxy and sandbox issuers), [ADR 0044](0044-proxy-key-at-rest.md) (proxy networks), and [ADR 0046](0046-agent-secret-requests.md) (HPKE-encrypted agent metadata to the account)

## Context

Today `Development › Agents` on Mac and `Agents` on iOS list every agent in the account (`klav-proxy`, `sandbox-issuer`, `release-mac`, `claude-code`, `antigravity`, …). Even after surfacing the **grant-verified role** (`Credential proxy`, `Sandbox issuer → klav-proxy (host)`, `MCP · <client>`, `CLI / agent`) and whether an agent's local config lives on **this Mac**, two everyday questions remain unanswered across devices:

1. **Where does a remote agent live?** If you have `claude-code` on two Macs, a `release-mac` runner on a build box, and `klav-proxy` on `pve-home`, iOS (and any other Mac) cannot tell which machine each agent runs on when deciding which one to pause or revoke.
2. **What is this agent for, in *your* words?** An agent's `name` and `note` are chosen by the agent at registration time (T136) and cannot be renamed or annotated by the person afterwards without revoking and re-registering.

### Constraints from Klav's threat model

1. **Zero-knowledge server.** Internal hostnames (`pve-home`, `omars-macbook-pro`, `prod-bastion-01`), OS versions, and client runtimes reveal a person's infrastructure topology. The server must not receive or store machine/origin metadata in clear text.
2. **Untrusted self-reporting (T136).** Anything an agent reports about itself (`hostname`, `os`, `runtime_kind`) can be spoofed by a compromised agent or an attacker holding a stolen key. The UI must always distinguish:
   - **Verified by Klav / this device** (grant role: Proxy / Issuer, proxy channel host from signed issuer grants, local key presence on this Mac, or locally launched registration);
   - **Labeled by you** (person-authored alias / machine label stored E2E-encrypted in the vault);
   - **Reported by the agent** (optional self-reported host/OS/runtime, clearly marked *"reported by agent"*).

## Proposal

### 1. Person-owned agent labels (E2E-encrypted in the system project)

Store a new optional key `agent_labels` inside the account's existing encrypted `preferences` system item (`ItemKind::Preferences`, spec §7.1, in the personal vault's system project — never included in any agent grant):

```json
{
  "agent_labels": {
    "<agent_id>": {
      "label": "Work MacBook",
      "host": "pve-home",
      "role_hint": "proxy"
    }
  }
}
```

- **Why `preferences` (or a sibling system item `ItemKind::AgentDirectory`)?**
  - **Zero server changes:** syncs end-to-end encrypted to Mac, iOS, CLI and extension with full history.
  - **Agents never see or tamper with it:** the system project is never granted to any agent.
  - **Editable at any time:** the person can set a machine/host label when approving an agent (pre-filled with the Mac's local computer name when this Mac launched the registration) and edit it later from `AgentPage` / `AgentDetailView` / `klav agent label <id> --host "pve-home" --label "Proxmox proxy"`.
  - **Compatibility note:** `Preferences` currently uses `#[serde(deny_unknown_fields)]`, so as with ADR 0032, **readers ship before writers** (or we use a dedicated system item `ItemKind::AgentLabels` so older clients skip only that item without failing to open `preferences.proxy`).

### 2. Optional self-reported origin from active agents (HPKE-encrypted to the account)

For agents running on servers or other computers (such as `klav-proxy` on `pve-home` or `klav agent register` on Linux), the person shouldn't have to type every hostname by hand:

- At registration time (`POST /v1/agents/register`), the agent does not yet hold the account's public key, so registration stays unchanged (no plaintext hostname sent to the server).
- **Once approved** (the agent receives and pins the account's public identity in `AgentConfig`), the agent may optionally upload an **HPKE-encrypted origin report** (new blob kind `0x26`, label `klav/v1/agent/origin`, sealed to the account's X25519 identity, signed with `klav/v1/sig/agent-request`):

```json
{
  "v": 1,
  "hostname": "pve-home",
  "os": "linux",
  "arch": "x86_64",
  "runtime": "klav-proxy",
  "klav_version": "0.9.3"
}
```

- The server stores only the opaque ciphertext blob per `agent_id` (max 1 KiB, replaced on update, deleted on agent revocation/account deletion) and returns it inside `AgentInfo`.
- Clients decrypt it with the account's X25519 key and display it **only as a secondary fallback** when the person has not set their own label, explicitly marked *"reported by agent"* (T136).
- Opt-out flag `--no-host-report` / `KLAV_NO_HOST_REPORT=1` for privacy-sensitive environments.

### 3. Integration with ADR 0044 (Proxy networks)

When ADR 0044's `agent_addresses` / egress pin layers ship, `AgentPage` for a `Proxy` shows:
1. Verified role & channel host (`Credential proxy · Host: pve-home`),
2. Person-owned label (if set),
3. Self-reported origin (`linux/x86_64 · klav-proxy 0.9.3`, *"reported by agent"*),
4. Observed network / egress profile from ADR 0044.

## Proposed threats (to add to `docs/modelo-de-amenazas.md` upon acceptance)

- **T240 (Spoofed origin report):** A compromised agent uploads a false `hostname` (e.g., claiming to be the person's MacBook) to avoid being revoked.
  - *Mitigation:* Self-reported fields are always badged *"reported by agent"* and never override *"On this Mac"* (checked locally in `$KLAV_HOME/agents/`) or the person's own label.
- **T241 (Hostname leak to server):** Sending hostnames in clear during `RegisterAgent` leaks internal network names.
  - *Mitigation:* Registration carries no hostname; post-approval origin reports are HPKE-encrypted (`0x26`) to the account's X25519 identity, and person-owned labels live encrypted inside the vault.

## Decisions (2026-11-24)

Omar accepted the recommended options for all three questions:

1. **Q1 → (a) Dedicated system item `ItemKind::AgentLabels`:** Person-owned labels live in a dedicated system item (`kind: "agent_labels"`, title `"Agent Labels"`) inside the personal vault's system project (`system_project_id`). No grant includes the system project, and older clients skip the item without breaking `preferences`.
2. **Q2 → (a) Two-layer rollout:** Layer 1 (person-owned E2E labels, zero server changes) ships immediately across `klav-core`, `klav-client`, `klav-daemon`, `klav-ffi`, `klav-cli`, Mac and iOS; Layer 2 (optional post-approval HPKE `0x26` origin reports from remote agents) follows with the next server migration.
3. **Q3 → (a) Automatic pre-fill on local Mac approval:** When the Mac app launches a registration (`matched == true`), `AgentReviewView` pre-fills the editable machine/host field with the Mac's localized computer name so local agents are tagged in one click.
