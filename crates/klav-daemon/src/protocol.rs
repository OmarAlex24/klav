//! Wire protocol between `klav` and `klavd` (version 1, `docs/klavd.md`).
//!
//! One JSON object per line in each direction. Every request carries the
//! protocol version `v` and an `id` that the response echoes:
//!
//! ```text
//! → {"v":1,"id":7,"request":{"op":"view","query":"GitHub","reveal":false}}
//! ← {"v":1,"id":7,"ok":{…},"warnings":[]}
//! ← {"v":1,"id":7,"error":{"code":"locked","message":"klavd is locked"}}
//! ```
//!
//! Requests and responses may contain secrets (the master password on
//! `unlock`, revealed values): the socket is only reachable by the same
//! user, and neither side logs them.

use klav_client::ItemFilter;
use klav_client::ops::{ItemPatch, NewItem, SecretBytes, SecretText};
use serde::{Deserialize, Serialize};

/// Protocol version spoken by this build.
pub const PROTOCOL_VERSION: u32 = 1;

/// What `agent_rotate_begin` adds to its error when filling failed after
/// the new password was stored as pending: this, the item's title and a
/// hint to cancel the change. The SDK cuts it off once the server has the
/// change closed: by the SDK's own cancel, or already before it.
pub const ROTATE_KEPT_PENDING: &str = ". The new password is kept as pending in ";

/// Longest accepted line (an attachment of 64 MiB in base64 plus framing).
pub const MAX_LINE: usize = 100 * 1024 * 1024;

/// A request line.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Protocol version.
    pub v: u32,
    /// Echoed in the response.
    pub id: u64,
    /// The request.
    pub request: Request,
    /// With the presence gate on (ADR 0041 §2.4): write a notice line
    /// ([`Notice::TouchId`]) just before a Touch ID dialog for this
    /// request's value. Send it only to a `klavd` whose `status` has
    /// `presence`: an older one refuses the field.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub notify: bool,
    /// With the presence gate on, only for `unlock` with `password`: the
    /// window the client's own question said the password opens
    /// (`always`: none), from `status`'s `presence`. `klavd` opens it only
    /// if it is what it would open now, and otherwise opens none. Missing
    /// means none. Send it only to a `klavd` whose `status` has `presence`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shown: Option<crate::uv::Window>,
    /// With the presence gate on, only for `unlock` with `password`: the
    /// client didn't read this password on its terminal (stdin, a pipe, a
    /// program that keeps it). The unlock then opens no window, whatever
    /// `shown` says, and isn't the passkey verification of ADR 0020 §8
    /// (Omar's decisions 4 and B of 2026-11-19). Missing means typed, as
    /// before. Send it only to a `klavd` whose `status` has `presence`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub untyped: bool,
}

/// What the client asks for.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Daemon status; works locked.
    Status,
    /// Unlock with the master password, or (without `password`) with the
    /// platform's biometric unlock when enrolled.
    Unlock {
        /// Master password.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
        /// Klav's passkey frame asked: under «Always», this unlock is the
        /// verification of the passkey use it was for (ADR 0020 §8). Only
        /// the extension's background sets it, for that frame.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        passkey_flow: bool,
    },
    /// Forget the unlocked state now.
    Lock,
    /// Pull changes from the server.
    Sync,
    /// Forget the cached vaults and the rollback marks (keeping revoked
    /// agents and signed vault keys) and sync from scratch.
    ResetCache,
    /// List vaults.
    Vaults,
    /// List projects.
    Projects {
        /// Only this vault.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
    },
    /// Create a vault.
    CreateVault {
        /// Name.
        name: String,
    },
    /// Create a project.
    CreateProject {
        /// Vault (default vault when absent).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
        /// Name.
        name: String,
    },
    /// Replace the linked Git repositories of a project (ADR 0032 §2).
    SetProjectRepos {
        /// Vault name or ID (default vault when absent).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
        /// Project name or ID.
        project: String,
        /// Repository URLs or normalized `host/owner/repo` identifiers.
        repos: Vec<String>,
    },
    /// List items.
    List {
        /// Filter.
        filter: ItemFilter,
    },
    /// Show an item.
    View {
        /// Reference, ID or title.
        query: String,
        /// Include secret values.
        reveal: bool,
        /// The master password, sent again after `presence_required` (ADR
        /// 0041 §3.2): a real verification for the presence gate. Ignored
        /// while the gate is off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Create an item.
    Create {
        /// The item.
        item: NewItem,
    },
    /// Edit an item.
    Edit {
        /// Reference, ID or title.
        query: String,
        /// Changes.
        patch: ItemPatch,
    },
    /// Move an item to the trash.
    Trash {
        /// Reference, ID or title.
        query: String,
    },
    /// Current TOTP code.
    Totp {
        /// Reference, ID or title.
        query: String,
        /// Field (first TOTP field when absent).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field: Option<String>,
        /// The master password, sent again after `presence_required` (ADR
        /// 0041 §3.2): a real verification for the presence gate. Ignored
        /// while the gate is off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Resolve `klav://` references to values (`run`, `inject`).
    Resolve {
        /// References.
        references: Vec<String>,
        /// The master password, sent again after `presence_required` (ADR
        /// 0041 §3.2): a real verification for the presence gate. Ignored
        /// while the gate is off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Items to offer on a page (browser extension): matching logins, the
    /// one-time codes saved on their own that name the page (`codes`),
    /// cards and identities, metadata only.
    Suggest {
        /// The page's address, as the browser reports it.
        url: String,
    },
    /// The values of one item to type into a page (browser extension). A
    /// login whose URLs do not match `url` is refused (`denied`).
    Autofill {
        /// Item ID.
        item: String,
        /// The page's address, as the browser reports it.
        url: String,
        /// Every value, or only the TOTP code.
        #[serde(default)]
        part: klav_client::fill::FillPart,
        /// The person picked this login in the menu or the popup, from the
        /// «Saved for a subdomain» group: only then does a login saved for a
        /// subdomain of the page fill (ADR 0025 §2). Fills without a click,
        /// and agents, never set it.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        chosen: bool,
        /// The master password, sent again after `presence_required` (ADR
        /// 0041 §3.2): a real verification for the presence gate. Ignored
        /// while the gate is off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// The logins with a passkey for the page (ADR 0020): metadata only.
    /// Without an `rp_id` in the answer, the call goes to the browser.
    PasskeyCandidates {
        /// The sender's origin (or URL), as the browser reported it.
        origin: String,
        /// `rpId` of the request; the origin's host when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rp_id: Option<String>,
        /// `allowCredentials`, base64url IDs.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        allow_credentials: Vec<String>,
    },
    /// Sign in with the passkey of `item` (ADR 0020): asks for Touch ID
    /// (or `password`) first, then returns the assertion for the page.
    PasskeyGet {
        /// The sender's origin (or URL), as the browser reported it.
        origin: String,
        /// `rpId` of the request; the origin's host when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rp_id: Option<String>,
        /// `challenge`, base64url.
        challenge: String,
        /// The login the person picked.
        item: String,
        /// Master password instead of Touch ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Create a passkey (ADR 0020): asks for Touch ID (or `password`)
    /// first, then stores it and returns the registration for the page, or
    /// says why not (`browser`, `excluded`, `exists`).
    PasskeyCreate {
        /// What the page asked for.
        request: klav_client::passkeys::PasskeyCreateRequest,
        /// Master password instead of Touch ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Store a file in a `file` field.
    Attach {
        /// Reference, ID or title.
        query: String,
        /// Field name.
        field: String,
        /// File name to record.
        file_name: String,
        /// Content.
        content: SecretBytes,
    },
    /// Stop the daemon.
    /// The account's agents (pending, active, denied, revoked).
    Agents,
    /// Person-owned labels and machine/host notes for agents (ADR 0047).
    AgentLabels,
    /// Sets or clears a person-owned label and/or host for an agent (ADR 0047).
    SetAgentLabel {
        agent: klav_core::ids::AgentId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    /// Approves an agent or replaces its grant. Asks for presence first:
    /// Touch ID, or the master password in `password` (ADR 0014).
    ApproveAgent {
        agent: klav_core::ids::AgentId,
        grant: klav_client::agents::GrantRequest,
        /// The six words the person compared.
        pairing_code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Denies a pending registration.
    DenyAgent {
        agent: klav_core::ids::AgentId,
    },
    /// Approval requests of agents (pending, or `all` recent ones).
    Approvals {
        #[serde(default)]
        all: bool,
    },
    /// Decides on an approval request (ID or unique prefix). Approving asks
    /// for presence like `approve_agent`.
    DecideApproval {
        approval: String,
        approve: bool,
        /// `request_digest` of the card the person decided on (ADR 0030
        /// §5): nothing is signed if the request changed since.
        digest: String,
        /// Approve for this many seconds instead of once.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lease_secs: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Task requests and running tasks (or `all` recent ones), as cards
    /// completed by this client (ADR 0021 §3).
    Tasks {
        #[serde(default)]
        all: bool,
    },
    /// Approves (with the person's changes) or denies a pending task (ID or
    /// unique prefix). Approving asks for presence like `approve_agent`.
    DecideTask {
        task: String,
        approve: bool,
        /// `request_digest` of the card the person decided on (ADR 0030 §5).
        digest: String,
        #[serde(default)]
        choice: klav_client::tasks::TaskChoice,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// «Add to the task»: adds a pending approval request to the agent's
    /// running task and approves it once. Asks for presence.
    AddToTask {
        approval: String,
        /// `request_digest` of the card the person decided on (ADR 0030 §5).
        digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Ends a running task («End task»).
    EndTask {
        task: String,
    },
    /// The audit summary of a task (`klav log --task`).
    TaskLog {
        task: String,
    },
    /// Pending (or all recent) agent secret requests (ADR 0046).
    SecretRequests {
        #[serde(default)]
        all: bool,
    },
    /// Fulfills a pending agent secret request: saves the secret into the
    /// vault, optionally grants `klav-proxy` access (requiring presence when
    /// `input.grant_proxy` is true), and posts the account-signed decision.
    FulfillSecretRequest {
        /// Request ID or unique prefix.
        request: String,
        /// Person's fulfillment inputs (secret, destination, optional proxy
        /// toggle, and the card's `proposal_digest`).
        input: klav_client::secret_requests::FulfillSecretRequest,
        /// Master password for presence when `input.grant_proxy` is true and
        /// Touch ID is unavailable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Denies a pending agent secret request with an account-signed decision.
    DenySecretRequest {
        /// Request ID or unique prefix.
        request: String,
        /// Card's `proposal_digest` (hex): refuses if the request changed.
        digest: String,
    },
    /// What an agent saw, from its grant and the audit log.
    AgentExposure {
        agent: klav_core::ids::AgentId,
    },
    /// Revokes an agent; with `rotate`, also rotates its projects' keys,
    /// one project at a time, releasing the session between projects
    /// (ADR 0033, amendment of 2026-11-10, F2). The progress goes in
    /// `status` (`revocations`) while it runs. Called again with `rotate`
    /// on a revoked agent, it finishes what is left.
    RevokeAgent {
        agent: klav_core::ids::AgentId,
        #[serde(default)]
        rotate: bool,
        /// With `rotate`: answer once the agent is revoked and the key
        /// change is written down, and change the keys in the background
        /// (the Mac app, F2). The request survives the app quitting: a
        /// lock cuts it and the next unlock resumes it (P11). Absent from
        /// older callers; an older `klavd` rejects it as an unknown field.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        background: bool,
    },
    /// The revocations whose key change was asked for and is not finished,
    /// from this device's sealed record (F4): agent, projects, rotated,
    /// pending, grants still to issue again and the last error. A
    /// revocation without a key change asked for never shows. Answer:
    /// `[PendingRevocation]`. No presence.
    AgentRevocations,
    /// An active agent's grant in force, in the apps' editor model, or
    /// read-only with the reason (F3, F4). Answer: `GrantEditor`. No
    /// presence.
    GrantEditor {
        agent: klav_core::ids::AgentId,
    },
    /// The sheet of a change to an active agent's grant: only the
    /// differences, which widen, and the digest that binds the sheet to
    /// the grant in force and to `change` (F3). Signs nothing. Answer:
    /// `GrantChangePreview`. No presence.
    GrantChangePrepare {
        agent: klav_core::ids::AgentId,
        change: klav_client::grant_change::GrantChange,
    },
    /// Signs a change shown with `grant_change_prepare`: syncs, verifies
    /// the grant in force again and refuses unless `digest` is still the
    /// sheet's (F3). Asks for presence (Touch ID, or `password`) only when
    /// the change widens, as `klavd` computes it (P8). Answer:
    /// `GrantChangeReport`.
    GrantChangeApply {
        agent: klav_core::ids::AgentId,
        change: klav_client::grant_change::GrantChange,
        /// The `digest` of the sheet the person saw.
        digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// The account's credential proxy, what it holds and what is lost
    /// without one (ADR 0036 §13). Names, hosts and the proxy's words:
    /// never a value.
    ProxyStatus,
    /// Sets which agent is the account's credential proxy (`agent`, a name
    /// or ID), or none. Asks for presence first (ADR 0036 §14).
    ProxyUse {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// What `proxy_grant` would sign for `item` (the profile, its rules,
    /// the proxy's words and warnings), without signing or asking for
    /// presence.
    ProxyGrantPreview {
        item: String,
        credential: klav_client::proxy_admin::ProxyCredentialSpec,
    },
    /// Grants `item` to the account's proxy with `credential`'s profile and
    /// rules. `base_version` is the grant version the preview showed:
    /// nothing is signed if it changed. The presence prompt shows what is
    /// signed, and, while the proxy is pending, the 6 words of the key
    /// klavd fetched. `every_device_updated` acknowledges what older
    /// devices lose, needed for the account's first per-item grant.
    ProxyGrant {
        item: String,
        credential: klav_client::proxy_admin::ProxyCredentialSpec,
        base_version: u64,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        every_device_updated: bool,
        /// The proxy's 6 words the preview showed, while it is pending.
        /// Only a staleness check, like `base_version`: klavd refuses if
        /// the key it fetches now gives other words (with the master
        /// password there is no dialog to show them in). They authorise
        /// nothing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shown_words: Option<String>,
        /// The item the preview showed (`item_id`): klavd resolves `item`
        /// again and refuses if it names another item now. A staleness
        /// check too, like `base_version`; it can only refuse.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shown_item: Option<klav_core::ids::ItemId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// What a change to the local MCP client `name` of the account's proxy
    /// would sign (ADR 0049 §3.2), without signing or asking for presence.
    LocalClientPreview {
        name: String,
        change: klav_client::proxy_admin::LocalClientChange,
    },
    /// Signs a change to the local MCP client `name`. A new token's digest
    /// comes in `change`, never the token. `base_version` and
    /// `shown_proxy` are what the preview showed: nothing is signed if
    /// either changed. Asks for presence.
    LocalClientChange {
        name: String,
        change: klav_client::proxy_admin::LocalClientChange,
        base_version: u64,
        shown_proxy: klav_core::ids::AgentId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Takes `item` away from the account's proxy and changes its key
    /// (ADR 0036 §18). Asks for presence.
    ProxyRevoke {
        item: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// What `proxy_issuer_add` would sign for `agent` (ADR 0036 E6.2):
    /// profiles, limits, the proxy's address, the agent's words and the
    /// warnings, without signing or asking for presence.
    ProxyIssuerPreview {
        agent: String,
        issuer: klav_client::issuers::IssuerSpec,
    },
    /// Lets `agent` start sandboxes through the account's proxy: signs the
    /// issuer's grant and the proxy's. The base versions and the words are
    /// what the preview showed: nothing is signed if they changed. Asks for
    /// presence, with what it signs.
    ProxyIssuerAdd {
        agent: String,
        issuer: klav_client::issuers::IssuerSpec,
        proxy_base_version: u64,
        issuer_base_version: u64,
        /// The issuer and the proxy the preview showed: agents name
        /// themselves at registration, so klavd refuses if `agent` or the
        /// account's proxy is another agent now.
        shown_issuer: klav_core::ids::AgentId,
        shown_proxy: klav_core::ids::AgentId,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        every_device_updated: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shown_words: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Stops `agent` from starting sandboxes. Asks for presence.
    ProxyIssuerRemove {
        agent: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Pauses every agent (no `agent`) or one (ADR 0033 §7), now and
    /// without asking for presence: a scare costs one click (P2). Unlocked,
    /// `klavd` signs it with the account and sends it at once; offline, it
    /// applies it here and keeps trying. Locked, pausing every agent works
    /// too: `klavd` applies it here at once and signs and sends it after
    /// the next unlock; pausing one agent needs `klavd` unlocked. Works
    /// locked. Answer: [`PauseInEffect`] list, as in `status`.
    PauseAgents {
        /// Agent ID (the client resolves names with `agents`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<klav_core::ids::AgentId>,
        /// When the pause ends by itself (Unix ms); none: until the person
        /// resumes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        until: Option<i64>,
    },
    /// Resumes every agent (no `agent`) or one, after Touch ID or the
    /// master password (ADR 0033 P2). Resuming every agent does not lift
    /// the pauses of single agents. Answer: [`PauseInEffect`] list.
    ResumeAgents {
        /// Agent ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<klav_core::ids::AgentId>,
        /// Master password, where there is no Touch ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Touch ID only, to confirm the person is there (ADR 0037 §1): opens
    /// this Mac's Secure Enclave key, which takes only the enrolled
    /// fingers and never the Mac's password, and drops what it gives
    /// back. It deletes nothing, needs no unlock and takes no password:
    /// the caller (the Mac app, the CLI) asks for the master password
    /// next and talks to the server itself. The prompt's words are
    /// `klavd`'s, for the `purpose`. Answer: `{ "ok": true }`, or
    /// `biometry_unavailable` / `biometry_failed`.
    ConfirmPresence {
        /// What the presence is for.
        purpose: PresencePurpose,
    },
    /// Cancels the deletion of the account the person asked for (ADR 0037
    /// §2), after Touch ID or the master password, like
    /// [`Request::ResumeAgents`] (ADR 0037 A2): canceling brings the
    /// agents back. Answer: `{ "canceled": bool }` (`false`: there was
    /// none).
    CancelAccountDeletion {
        /// Master password, where there is no Touch ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// The audit log, filtered (`klav log`).
    AuditLog {
        #[serde(default)]
        filter: klav_client::audit::LogFilter,
    },
    /// Verifies the audit log and signs its head (`klav log verify`).
    VerifyAudit,
    /// The person's list of sandboxes (ADR 0036 E2.1): every sandbox in the
    /// verified chain, with the last heartbeat of the account's proxy,
    /// checked against this device's watermark. Verifies the log as
    /// `verify_audit` does. Answer: [`klav_client::sandboxes::SandboxList`].
    /// Preferences an agent wrote are a `security` error here, as in every
    /// `klavd` before `sandbox_list_flagged`.
    SandboxList,
    /// [`Request::SandboxList`] for a caller that shows a security flag:
    /// preferences an agent wrote give the chain's rows of every proxy, no
    /// proxy and `security` ([`klav_client::sandboxes::SecurityFlag`])
    /// instead of an error. An older `klavd` answers `bad_request`: ask
    /// `sandbox_list` then, which fails closed.
    SandboxListFlagged,
    /// [`Request::SandboxListFlagged`] for a caller that says in its own
    /// words which check refused the list. Answer:
    /// [`klav_client::sandboxes::CheckedList`], with the list, or `refused`
    /// with the check ([`klav_client::sandboxes::ListCheck`]) and the
    /// `security` error's words, instead of that error. Every other failure,
    /// a `security` one of no known check included, is the same error as
    /// `sandbox_list_flagged`'s. An older `klavd` answers `bad_request`:
    /// ask `sandbox_list_flagged` then, which fails with `security`.
    SandboxListChecked,
    /// The person's revocation of sandboxes of `proxy`, signed with the
    /// account's identity without presence (ADR 0036 E2.3). `scope` is
    /// `"all"` (every sandbox of `proxy` issued so far) or one sandbox ID,
    /// always given: a request without it, or with anything else, is a
    /// `bad_request` and revokes nothing. Answer:
    /// [`klav_client::sandbox_revoke::RevokeOutcome`]; a later revocation
    /// of the same scope is its `not_applied`, not an error.
    SandboxRevoke {
        proxy: klav_core::ids::AgentId,
        scope: String,
    },
    /// «Who used it» for one item (ADR 0033 §8.1): every event an agent
    /// wrote about it, newest first, with how it went. Answer:
    /// [`klav_client::activity::ItemActivity`].
    ItemActivity {
        /// Reference, title or ID (an ID also finds a purged item).
        item: String,
    },
    /// How far this device downloaded and verified the audit log («Verified
    /// up to event #N»), without asking the server. Answer:
    /// [`klav_client::audit::ChainStatus`].
    AuditStatus,
    /// `klav log reset` (ADR 0033 §8.4): forgets this device's copy of the
    /// audit log, in memory too, and the head it verified, for a server
    /// restored from a backup the person trusts. Also while locked; no
    /// network. Answer: the files removed (`audit-chain.bin`,
    /// `audit-head.json`).
    AuditReset,
    /// Records a generated password in the local outbox (ADR 0022 §2),
    /// durably, before the caller types it anywhere. Works offline; the
    /// outbox goes to the generator history in the background.
    GeneratorRecord {
        /// The password.
        value: SecretText,
        /// The site it is for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    /// The generator history, newest first, without values.
    GeneratorHistory,
    /// The value of one generator history entry.
    GeneratedValue {
        /// The entry's `created_at`.
        created_at: i64,
        /// The master password, sent again after `presence_required` (ADR
        /// 0041 §3.2): a real verification for the presence gate. Ignored
        /// while the gate is off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Deletes generator history entries (and the versions that hold them).
    GeneratorDelete {
        /// Which.
        which: klav_client::history::GeneratedSelection,
    },
    /// The previous passwords of an item, without values.
    PasswordHistory {
        /// Reference, ID or title.
        query: String,
    },
    /// One previous password of an item.
    PreviousPassword {
        /// Reference, ID or title.
        query: String,
        /// Its `index` in `password_history`.
        index: usize,
        /// The master password, sent again after `presence_required` (ADR
        /// 0041 §3.2): a real verification for the presence gate. Ignored
        /// while the gate is off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// The vault health report (ADR 0022 §4): reused, weak and old
    /// passwords, and breached ones if the person turned the breach check
    /// on (`health.json`). Items, hosts and reasons; never values.
    VaultHealth,
    /// Adds an export file (or a Google Authenticator link or QR image) to
    /// an import (ADR 0024). Without `session`, starts a new one. A file
    /// larger than a message goes in pieces: every piece but the last has
    /// `more`. Answer: [`ImportAdded`]. The import lives until `lock`.
    ImportAdd {
        /// The import, from a previous answer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
        /// File name, for messages.
        name: String,
        /// What the person says it is (`bitwarden`, `google`…).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from: Option<String>,
        /// The content (or this piece of it).
        data: SecretBytes,
        /// More pieces of this file follow.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        more: bool,
    },
    /// What importing would do, without values
    /// (`klav_client::import::ImportPreview`). Changes nothing.
    ImportPreview {
        /// The import.
        session: String,
        /// Destination vault (default vault when absent).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
        /// Destination project.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<String>,
    },
    /// Imports: creates and merges as the preview said, keeping replaced
    /// passwords in the history (`klav_client::import::ImportResult`).
    /// The import is forgotten afterwards.
    ImportApply {
        /// The import.
        session: String,
        /// Destination vault (default vault when absent).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vault: Option<String>,
        /// Destination project.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<String>,
    },
    /// Forgets an import without importing.
    ImportCancel {
        /// The import.
        session: String,
    },
    /// Registers this connection as a browser extension that fills pages
    /// for agents (sent by the extension through `klav-native-host`).
    /// [`EventEnvelope`] lines then arrive on it between responses.
    ExtensionAttach {
        /// Which browser, for messages (`Chrome`, `Firefox`…).
        browser: String,
    },
    /// The extension's answer to an event.
    ExtensionReply {
        /// The event's `id`.
        event: u64,
        /// Result on success.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ok: Option<serde_json::Value>,
        /// Error.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<ErrorBody>,
    },
    /// The extension's answer to [`Event::Presence`]: the master password
    /// the person typed in Klav's own frame (ADR 0041 §3.1, §3.2). Only on
    /// the connection the event was sent to. `klavd` checks it against the
    /// unlocked session: right, the connection is verified and `{}` comes
    /// back; wrong, `wrong_credentials`, and the event keeps waiting for
    /// another try. Canceling is an `extension_reply` with an `error`; an
    /// `extension_reply` with `ok` never verifies anything.
    ExtensionPresence {
        /// The event's `id`.
        event: u64,
        /// The master password.
        password: klav_client::ops::SecretText,
    },
    /// The tab an agent would fill: the active tab of the focused browser
    /// with the extension attached ([`BrowserTab`]). Works locked.
    BrowserTab,
    /// Types an agent's values into that tab, if it is still on `host`
    /// (ADR 0017). The values never come back. The agent brings the
    /// values, decrypted under its own grant, but the connection's
    /// presence needs the unlocked session (ADR 0041 §3.1): locked, it
    /// answers `locked`, after a pause's `agents_paused`.
    BrowserFill {
        /// [`BrowserTab::tab`].
        tab: String,
        /// The host the agent checked against the item's URLs.
        host: String,
        /// Agent name, shown to the person in the page.
        agent: String,
        /// Agent ID: `klavd` refuses the fill while the person has it
        /// paused (ADR 0033 §7.2). Without it, only a pause of every agent
        /// stops the fill (older SDKs).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_id: Option<klav_core::ids::AgentId>,
        /// The agent's reason, shown too.
        reason: String,
        /// The item the values come from: with the presence gate on, the
        /// prompt names its title as the vault has it, never as the agent
        /// says (ADR 0041 §3.1, T140). A hint: the agent sends it unsigned.
        /// Missing from older SDKs, and then the prompt names no item.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        item: Option<klav_core::ids::ItemId>,
        /// Item type.
        kind: klav_core::model::item::ItemKind,
        /// Values to type.
        fields: Vec<klav_client::fill::FillValue>,
        /// CSS selectors for some fields (field name → selector).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        selectors: Vec<FieldSelector>,
        /// Submit the form afterwards.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        submit: bool,
    },
    /// An agent uses the passkey of a login in the person's browser (ADR
    /// 0020 §9), after `POST /v1/agent/access` with `passkey`: `klavd`
    /// checks the request the agent signed and its task on its own, then
    /// arms one use in tab `tab` for 60 s. If the page there already waits
    /// for a passkey of that site, the extension uses it at once. Answer:
    /// [`PasskeyArmed`], never the assertion. Needs `klavd` unlocked; a
    /// locked `klavd` says `locked` and does not ask the person.
    AgentPasskeyArm {
        /// [`BrowserTab::tab`].
        tab: String,
        /// The use and the agent's signed request.
        step: klav_client::agent_passkeys::PasskeyArmStep,
    },
    /// The extension answers a page's sign-in with the use an agent armed
    /// in that tab ([`Event::PasskeyArm`]): `klavd` signs with UV (the
    /// task's approval is the verification, ADR 0020 §8) and without the
    /// person's surface. Only from the extension's connection the use was
    /// armed for, once, before it expires, and for the armed site and
    /// login. Answer: the assertion, like `passkey_get`.
    AgentPasskeyUse {
        /// Browser tab ID.
        tab_id: u64,
        /// The sender's origin (or URL), as the browser reported it.
        origin: String,
        /// `rpId` of the request; the origin's host when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rp_id: Option<String>,
        /// `challenge`, base64url.
        challenge: String,
        /// The token of [`Event::PasskeyArm`].
        token: SecretText,
    },
    /// An agent starts changing a login's password in the person's browser
    /// (ADR 0022 §5, steps 2–5), after `POST /v1/agent/rotations`: `klavd`
    /// checks the request the agent signed and its task, asks the tab for
    /// the field's rules, stores the new password as pending in the item
    /// and only then fills «current» with the old one and «new» (and
    /// «confirm») with the new one. Answer: `{filled, pending_id}`, never a
    /// value. Needs `klavd` unlocked.
    AgentRotateBegin {
        /// [`BrowserTab::tab`].
        tab: String,
        /// The change and the agent's signed request.
        step: klav_client::rotate::RotationStep,
        /// Submit the form afterwards.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        submit: bool,
    },
    /// The site took the new password (`rotate_confirm`, step 7), after
    /// `POST /v1/agent/rotations/{id}/confirm`: it becomes current and the
    /// old one goes to the history. Answer: `{ok: true}`.
    AgentRotateConfirm {
        /// The change and the agent's signed request.
        step: klav_client::rotate::RotationStep,
    },
    /// The site refused it, or the agent gave up (`rotate_cancel`): the
    /// current one stays and the pending one goes to the history, marked
    /// unconfirmed. Answer: `{ok: true}`.
    AgentRotateCancel {
        /// The change and the agent's signed request.
        step: klav_client::rotate::RotationStep,
    },
    /// Whether the item's pending password is this change's, asked before
    /// the agent sends a confirm or a cancel to the server (read only;
    /// `klav_client::Unlocked::rotation_pending`). The step carries a
    /// signed request of its own, `POST /v1/agent/rotations/{id}/pending`
    /// (a path the server has no route for), which `klavd` checks as for a
    /// step and uses up. Answer: `{pending}`. An older `klavd` answers
    /// `bad_request`.
    AgentRotatePending {
        /// The change and the agent's signed request.
        step: klav_client::rotate::RotationStep,
    },
    /// The person decides on a pending password from the item's card:
    /// `accept` makes it current («Use the new one»), else it goes to the
    /// history («Keep the current one»).
    ResolvePending {
        /// Reference, ID or title.
        query: String,
        /// Use the new one.
        accept: bool,
    },
    /// «Fix my reused passwords» (ADR 0022 §6), for the person: the
    /// logins that share a password, sorted by host, with their change
    /// pages, checked against `agent`'s grant, and the agents that can
    /// take the task (`klav_client::offer::ReusedOffer`). Never for an
    /// agent: no MCP tool or agent command asks for it.
    ReusedOffer {
        /// The agent (ID, prefix or name); the only one when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent: Option<String>,
    },
    /// The person offers an agent a task with `rotate` on these logins
    /// (ADR 0022 §6), signed without a request from the agent. Asks for
    /// presence like `decide_task`. Answer: the task's `TaskCard`.
    OfferTask {
        /// The agent, the logins and, optionally, title, reason and
        /// duration.
        offer: klav_client::offer::OfferRequest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// Each site of a task with `rotate`: changed, pending or failed
    /// (`klav_client::offer::TaskProgress`).
    TaskProgress {
        /// ID or unique prefix.
        task: String,
    },
    /// The passkey user-verification window of this `klavd` (ADR 0020
    /// §8): with `window`, sets it first. Loosening it asks for Touch ID
    /// (or `password`); tightening does not. Answer: `{window}`. Works
    /// locked while the presence gate is off; with it on, the setting is
    /// sealed in `klavd`'s local data and this answers `locked` while
    /// locked, and loosening opens no passkey window (ADR 0041 §2.4).
    PasskeyUv {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        window: Option<crate::uv::Window>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
    /// The health settings of this home (`health.json`): with
    /// `breach_check`, turns the breach check on or off first. Answer:
    /// `{breach_check, notice}`. Works locked.
    HealthSettings {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        breach_check: Option<bool>,
    },
    Shutdown,
    /// Declares that this connection's `unlock`, or its first window
    /// verification, should last until Klav locks (ADR 0041 §1.2): the
    /// held connection. No argument; it grants nothing by itself. Answers
    /// `not_supported` until layer 6 turns it on, and always on Linux.
    Hold,
    /// The presence window of this `klavd` (ADR 0041 §2.4): with `window`,
    /// sets it first. Loosening asks for Touch ID (or `password`) and
    /// opens no window; tightening asks for nothing and applies at once.
    /// Answer: `{window}`. `locked` while locked; `not_supported` while the
    /// presence gate is off.
    PresenceWindow {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        window: Option<crate::uv::Window>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<SecretText>,
    },
}

/// Where a field goes, when the agent knows better than detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSelector {
    /// Field name in the item.
    pub field: String,
    /// CSS selector of the input.
    pub selector: String,
}

/// What [`Request::AgentPasskeyArm`] answers: all the agent learns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyArmed {
    /// The page already waited for a passkey of the site and got it.
    pub used: bool,
    /// The passkey's rpId.
    pub rp_id: String,
    /// Not used yet: the next sign-in of that site in the tab, within this
    /// many seconds, gets it (the agent clicks the site's button now).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_s: Option<u64>,
}

/// The tab [`Request::BrowserTab`] found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTab {
    /// Opaque handle for [`Request::BrowserFill`].
    pub tab: String,
    /// The tab's address, as the browser reports it.
    pub url: String,
    /// Which browser.
    pub browser: String,
}

/// A line from `klavd` to an attached extension that is not a response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelope {
    /// Protocol version.
    pub v: u32,
    /// The event.
    pub event: Event,
}

/// What `klavd` asks an attached extension; it answers with
/// [`Request::ExtensionReply`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    /// Which tab is active, and whether its window has the focus. Answer:
    /// [`ExtensionTab`].
    Tab {
        /// Event ID.
        id: u64,
    },
    /// With the presence gate on, where `klavd` can't show Touch ID: an
    /// agent's event for tab `tab_id` waits for the person's presence on
    /// this connection (ADR 0041 §3.1, §3.2). The extension opens Klav's
    /// own frame in that tab, says what `presence` grants, and answers
    /// with [`Request::ExtensionPresence`] (the master password), or with
    /// an `extension_reply` `error` when the person cancels.
    Presence {
        /// Event ID.
        id: u64,
        /// Browser tab ID.
        tab_id: u64,
        /// What the frame says it grants; `browser` is always set.
        presence: PresenceAsk,
    },
    /// Fill tab `tab_id` (if its page is on `host`) and tell the person.
    /// Answer: the fill report (field names, addresses; never values).
    Fill {
        /// Event ID.
        id: u64,
        /// Browser tab ID.
        tab_id: u64,
        /// Expected host.
        host: String,
        /// Agent name.
        agent: String,
        /// The agent's reason.
        reason: String,
        /// Item type.
        item_kind: klav_core::model::item::ItemKind,
        /// Values.
        fields: Vec<klav_client::fill::FillValue>,
        /// Selectors.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        selectors: Vec<FieldSelector>,
        /// Submit afterwards.
        #[serde(default)]
        submit: bool,
    },
    /// An assisted change (ADR 0022 §5) is about to fill tab `tab_id`: find
    /// the frame to fill (the focused password box of a frame on the item's
    /// site, else the top frame's change form) and read its rules. Nothing
    /// is typed. Answer: [`RotateTarget`].
    RotateProbe {
        /// Event ID.
        id: u64,
        /// Browser tab ID.
        tab_id: u64,
        /// The host the agent signed.
        host: String,
        /// The item's addresses (metadata), for the frame check.
        urls: Vec<String>,
    },
    /// An agent armed one use of a passkey in this tab (ADR 0020 §9): the
    /// extension checks the tab is still on `host`, keeps the use for
    /// `expires_in_ms`, and answers `{used}`: `true` if the page already
    /// waited for a passkey of `rp_id` and got it.
    PasskeyArm {
        /// Event ID.
        id: u64,
        /// Browser tab ID.
        tab_id: u64,
        /// Expected host.
        host: String,
        /// The passkey's rpId.
        rp_id: String,
        /// The login.
        item: String,
        /// Its title, for the in-page notice.
        title: String,
        /// Agent name, for the notice.
        agent: String,
        /// The agent's reason, for the notice.
        reason: String,
        /// What the extension hands back in `agent_passkey_use`.
        token: klav_client::ops::SecretText,
        /// How long the use stays armed.
        expires_in_ms: u64,
    },
    /// Fill the change form found by [`Event::RotateProbe`]: `current` into
    /// «current password», `new` into the focused box (or «new password»)
    /// and «confirm». Only `type=password` inputs. Answer: the fill report
    /// (field roles; never values).
    RotateFill {
        /// Event ID.
        id: u64,
        /// Browser tab ID.
        tab_id: u64,
        /// [`RotateTarget::frame_id`].
        frame_id: u64,
        /// [`RotateTarget::document_id`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        document_id: Option<String>,
        /// The probe's token in that frame.
        token: String,
        /// Expected host.
        host: String,
        /// Agent name, for the in-page notice.
        agent: String,
        /// The agent's reason, for the notice.
        reason: String,
        /// The current password.
        current: klav_client::ops::SecretText,
        /// The new password.
        new: klav_client::ops::SecretText,
        /// Submit afterwards.
        #[serde(default)]
        submit: bool,
    },
}

/// The extension's answer to [`Event::RotateProbe`]: where it would fill,
/// with the address the browser reports for that frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateTarget {
    /// Browser frame ID (0: the top frame).
    pub frame_id: u64,
    /// Browser document ID, when the browser has one (Chromium).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    /// The frame's address, from the browser.
    pub url: String,
    /// A password box had the focus there.
    #[serde(default)]
    pub focused: bool,
    /// Ties the fill to the box the probe found.
    pub token: String,
    /// The field's rules.
    #[serde(default)]
    pub rules: klav_client::rotate::PageRules,
}

/// The extension's answer to [`Event::Tab`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionTab {
    /// Browser tab ID.
    pub tab_id: u64,
    /// The tab's address.
    pub url: String,
    /// Whether the tab's window has the focus.
    #[serde(default)]
    pub focused: bool,
}

/// A response line.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    /// Protocol version.
    pub v: u32,
    /// The request's `id` (0 if the request could not be parsed).
    pub id: u64,
    /// Result on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<serde_json::Value>,
    /// Error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    /// Non-fatal notices (offline, undecryptable entries…).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// A notice before the answer, with neither `ok` nor `error`: the
    /// answer follows on a later line with the same `id`. Only to a request
    /// whose envelope set `notify`, so a client that never sets it never
    /// reads one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<Notice>,
}

/// A daemon error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// Stable code (`docs/klavd.md` §4).
    pub code: ErrorCode,
    /// Human-readable message (no secrets).
    pub message: String,
    /// With [`ErrorCode::AgentsPaused`] only: the pause that holds the
    /// agent (ADR 0033 §7.4). Never sent with another code, so a client
    /// older than the pause, which cannot read `agents_paused` anyway, is
    /// not broken by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused: Option<klav_proto::agent::AgentPaused>,
    /// With [`ErrorCode::PresenceRequired`] only: what the client's
    /// password prompt must say (ADR 0041 §2.4). Never sent with another
    /// code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<Box<PresenceAsk>>,
}

/// What a client that asks for the master password itself must say it
/// grants (`presence_required`, ADR 0041 §2.4 and §3.2). `klavd` keeps the
/// ask it sent on the connection, and a password sent again on it is
/// checked only if `klavd` would still ask exactly this, for the same
/// request: it then grants what this says, never more. Otherwise the
/// answer is a new `presence_required`, and the password isn't checked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PresenceAsk {
    /// What the window is keyed on: `session`, `parent`, `connection`, or
    /// `none` (no window: each value asks).
    pub key: PresenceKey,
    /// The presence setting now.
    pub window: crate::uv::Window,
    /// The peer's controlling terminal, when it has one with a name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
    /// The connection declared `hold`: the verification would hold it
    /// until Klav locks.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub declared: bool,
    /// What the verification grants: a window for the key, lasting this
    /// long. Missing: no window, only `value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lasts: Option<AskLasts>,
    /// With no window: the one value it hands out, for the client to word
    /// in its own language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<AskValue>,
    /// Only in [`Event::Presence`]: the presence of an extension's
    /// connection, and the agent's event that caused it (ADR 0041 §3.1),
    /// for the extension's frame to word as `klavd`'s Touch ID dialog does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserAsk>,
}

/// [`PresenceAsk::browser`]: what an extension connection's presence
/// grants, and what caused it (ADR 0041 §3.1). With `lasts`, agents may
/// fill through the connection until Klav locks; without it, only this
/// event (the setting on Always).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserAsk {
    /// The agent's event.
    pub event: BrowserCause,
    /// The agent's name, cleaned as `klavd`'s prompts clean it.
    pub agent: String,
    /// The item's title from the vault, cleaned: for a fill (missing when
    /// the agent didn't say which item, or the vault has no such item), a
    /// password change and a passkey sign-in (the passkey's login).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// For a passkey sign-in: the rpId of the passkey `klavd` armed, from
    /// the vault and checked against the tab's host; never the site the
    /// agent claims (T140).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// How many extension connections are attached, when more than one: a
    /// hint (N11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached: Option<u32>,
    /// Word it as "this browser connection" (the connection's peer is
    /// keyed by its connection, as on Linux), not "a browser" (macOS: the
    /// browser's hosts share the browser's parent key). Own choice 3.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub connection: bool,
}

/// [`BrowserAsk::event`]: the value-carrying event that caused the
/// presence (Omar's decision of 2026-11-19: a text per event).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserCause {
    /// `browser_fill`.
    Fill,
    /// The fill step of `agent_rotate_begin`.
    PasswordChange,
    /// `agent_passkey_arm`.
    PasskeySignIn,
}

/// [`PresenceAsk::lasts`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AskLasts {
    /// Five minutes.
    #[serde(rename = "5m")]
    FiveMinutes,
    /// Until Klav locks.
    #[serde(rename = "until_lock")]
    UntilLock,
}

/// [`PresenceAsk::value`]: the kind of value, and the item `klavd`
/// resolved, never the query the client wrote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AskValue {
    /// What is handed out.
    pub kind: AskValueKind,
    /// The item's title from the vault, cleaned as in `klavd`'s own
    /// prompts. Missing when the item couldn't be named, and for
    /// `generated` and `resolve`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// For `resolve`: how many references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

/// [`AskValue::kind`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AskValueKind {
    /// `view` with `reveal`: an item's values.
    Show,
    /// `previous_password`.
    Previous,
    /// `totp`.
    Code,
    /// `autofill`.
    Fill,
    /// `generated_value`.
    Generated,
    /// `resolve`.
    Resolve,
}

/// A line `klavd` writes before a request's answer, only to a request
/// whose envelope asked for notices (`notify`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Notice {
    /// `klavd` is about to show a Touch ID dialog for this request's value
    /// (ADR 0041 §2.4, N9): the client prints its terminal's name.
    TouchId,
}

/// [`PresenceAsk::key`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PresenceKey {
    /// The peer's terminal session.
    Session,
    /// The peer's parent process (macOS, a peer with no terminal).
    Parent,
    /// This connection only.
    Connection,
    /// No window at all.
    None,
}

/// Stable error codes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The daemon is locked: unlock first.
    Locked,
    /// No account in this `KLAV_HOME`.
    NotLoggedIn,
    /// Wrong master password.
    WrongCredentials,
    /// Possible rollback attack (threat T7).
    Rollback,
    /// Not found.
    NotFound,
    /// Invalid input (including ambiguous names).
    Invalid,
    /// Concurrent edit.
    Conflict,
    /// The server is unreachable.
    Network,
    /// The server session expired or was revoked.
    SessionExpired,
    /// Biometric unlock is not available or not enrolled.
    BiometryUnavailable,
    /// The user cancelled or failed the biometric prompt.
    BiometryFailed,
    /// The request is malformed or for another protocol version.
    BadRequest,
    /// A security check failed (altered grant, wrong pairing words).
    Security,
    /// Refused on purpose (a login on a page that is not its site).
    Denied,
    /// The person paused this agent, or every agent (ADR 0033 §7): stop
    /// and tell the person.
    AgentsPaused,
    /// The person asked to delete the account (ADR 0037 §3): `klavd` stops
    /// what it mediates for agents. Stop and tell the person.
    AccountDeleting,
    /// The server deleted the account (ADR 0037 §3): this device keeps its
    /// copy, read-only.
    AccountDeleted,
    /// Sent by `klav-native-host`, never by `klavd`: the browser extension
    /// that started it is not on its allow list. The message names the
    /// command that adds it.
    ExtensionNotAllowed,
    /// The presence gate needs a real verification and `klavd` can't show
    /// Touch ID (ADR 0041 §3.2): ask for the master password and send the
    /// same request again with `password`. `presence` says what to ask.
    PresenceRequired,
    /// Another presence prompt (or, for `unlock`, an unlock prompt) is open
    /// in `klavd` (ADR 0041 §2.4): try again when it closes.
    PresenceBusy,
    /// This `klavd` does not offer the operation (`hold`, ADR 0041 §1.2;
    /// `presence_window` while the gate is off).
    NotSupported,
    /// With the presence gate on and more than one browser connection
    /// attached, none or several report focus (ADR 0041 §3.1, P25): the
    /// person brings the browser to the front, or closes the others.
    BrowserAmbiguous,
    /// Anything else.
    Internal,
}

/// `import_add` result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportAdded {
    /// The import, for the next requests.
    pub session: String,
    /// Waiting for more pieces of this file.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
    /// What each file added so far contributed.
    pub sources: Vec<klav_client::klav_import::SourceReport>,
    /// Entries read so far.
    pub entries: usize,
    /// Passkeys found (not imported).
    pub passkeys: usize,
    /// Google Authenticator codes still missing.
    pub missing: Vec<klav_client::klav_import::MissingBatch>,
}

/// `status` result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// `klavd` version: the workspace's version number, the same for every
    /// build until a release changes it.
    pub version: String,
    /// The commit this `klavd` was built from. With `commit_time`, what
    /// tells two builds of the same `version` apart (the Mac app restarts a
    /// `klavd` that is not its own build). Absent from older `klavd`, and
    /// from a build whose source had no Git history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// That commit's committer time, in Unix seconds. Absent with `commit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_time: Option<u64>,
    /// Protocol version.
    pub protocol: u32,
    /// Process ID.
    pub pid: u32,
    /// An account exists in this home.
    pub logged_in: bool,
    /// Holding an unlocked account.
    pub unlocked: bool,
    /// Account e-mail, when logged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// How it was unlocked (`password` or `touch_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlocked_with: Option<String>,
    /// Inactivity before locking, in seconds.
    pub idle_lock_secs: u64,
    /// Seconds left before the idle lock, when unlocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locks_in_secs: Option<u64>,
    /// Touch ID state.
    #[serde(default)]
    pub touch_id: BiometricStatus,
    /// Moves whenever what the reads answer may have changed (a sync that
    /// brought changes, a new unlock): read again when it does (ADR 0026).
    #[serde(default)]
    pub revision: u64,
    /// A background sync is in flight.
    #[serde(default)]
    pub syncing: bool,
    /// The passkey user-verification window (ADR 0020 §8). With the
    /// presence gate on it is sealed in `klavd`'s local data, and absent
    /// while locked (ADR 0041 §2.4): show the setting only from an
    /// unlocked `klavd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_uv: Option<crate::uv::Window>,
    /// A passkey use now needs no new verification (within the window).
    #[serde(default)]
    pub passkey_verified: bool,
    /// Browsers whose extension attached since `klavd` started (the Mac
    /// app's «Connected in Dia», ADR 0027 §4). Absent from older `klavd`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub browsers: Vec<BrowserSeen>,
    /// The pauses of agents in effect (ADR 0033 §7), also while locked:
    /// the ones this device learned signed by the account, and the ones
    /// decided here that the server does not know yet (`local`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents_paused: Vec<PauseInEffect>,
    /// The deletion of the account the person asked for, as the last sync
    /// left it (ADR 0037 §3); kept while locked. Absent from older `klavd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_deletion: Option<klav_proto::auth::AccountDeletion>,
    /// The server deleted the account: a sync got `401` at or after the
    /// deletion's date (ADR 0037 §3). `klavd` stops syncing and keeps the
    /// local copy, read-only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub account_deleted: bool,
    /// Revocations whose key change was asked for and is not finished
    /// (ADR 0033, amendment of 2026-11-10, F2): how far each one got, also
    /// while locked (as the last unlocked moment left it, counts only).
    /// Never to the browser extension. Absent from older `klavd`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocations: Vec<RevocationProgress>,
    /// This device's record of owed key changes (`revocations.bin`) did not
    /// open at the last read: `revocations` may be out of date, and no key
    /// change may be taken for finished (`agent_revocations` says why).
    /// Absent from older `klavd`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revocations_unreadable: bool,
    /// With `revocations_unreadable`: the record is of a newer format,
    /// written by a newer Klav. Updating Klav reads it; it must not be
    /// moved aside. Absent from older `klavd`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revocations_newer: bool,
    /// In `unlock`'s answer only, with the presence gate on: `klavd` was
    /// already unlocked by another key (ADR 0041 §2.4, Omar's decision on
    /// Q-N1). Without `password` this unlock granted the caller nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub already_unlocked: bool,
    /// Only with the presence gate on, and about the caller's key (ADR 0041
    /// §2.4): what a master password the caller gives to `unlock` would
    /// open, and whether another key unlocked `klavd`. Its presence is how
    /// a client knows the gate is on. Absent with the gate off and from
    /// older `klavd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<StatusPresence>,
}

/// [`DaemonStatus::presence`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusPresence {
    /// `klavd` is unlocked, and another key than the caller's unlocked it
    /// (Q-N1): an `unlock` without the password would grant nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub elsewhere: bool,
    /// What the caller's own master password at `unlock` would open, as
    /// the unlock's Touch ID prompt would say it: a window for this key,
    /// lasting `lasts` (missing: no window). The client words its question
    /// from these and sends back, in the request envelope's `shown`, what
    /// it said; `klavd` opens no more.
    pub key: PresenceKey,
    /// The caller's controlling terminal, when it has one with a name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
    /// The connection declared `hold`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub declared: bool,
    /// How long the window would last; missing: none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lasts: Option<AskLasts>,
}

/// How far a revocation's key change got (`status`, F2): «Changing keys: 2
/// of 5 projects». No secret. While locked, only the agent and the counts:
/// no name, and no error (it may name a vault or project).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationProgress {
    /// The revoked agent.
    pub agent_id: klav_core::ids::AgentId,
    /// Its name when it was revoked (the agent's own words, T136); only
    /// while unlocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Projects whose key it held.
    pub projects: usize,
    /// Those already rotated.
    pub rotated: usize,
    /// Rotated projects whose other agents still need a new grant.
    #[serde(default)]
    pub regrants: usize,
    /// This device does not know which projects the agent had: never
    /// "done" (T189).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unknown_projects: bool,
    /// The agent is active: this is the key change of projects taken away
    /// from it (`rotate_removed`), not a revocation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub narrowed: bool,
    /// Items granted one by one still without a new key.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub items: usize,
    /// The audit log has not been read for this key change yet: never
    /// "done" (T189).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub log_unchecked: bool,
    /// A revocation without the key change: only the keys of items granted
    /// one by one change, never a project's, so the apps never say "every
    /// key changed" for it (fifth re-check, 1). Absent from an older
    /// `klavd`, and ignored by older apps.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub without_key_change: bool,
    /// Projects or items whose key cannot change from this device (deleted,
    /// their vault no longer listed, or an item this device no longer
    /// sees): they do not keep it from being done.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped: usize,
    /// Projects whose key is still to change (`projects` less those
    /// rotated and those skipped).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub to_change: usize,
    /// Something is left that `klavd` or «Finish» can do: projects, grants
    /// to issue again, items, or the audit log to read. False when only
    /// skipped ones are left, or the projects are unknown (that waits for
    /// the person).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_work: bool,
    /// `klavd` is changing keys for it right now; never while locked.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub running: bool,
    /// What stopped the last step; only while unlocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl RevocationProgress {
    /// The progress of `pending`, from this device's record.
    #[must_use]
    pub fn of(pending: &klav_client::revoke::PendingRevocation, running: bool) -> Self {
        RevocationProgress {
            agent_id: pending.agent_id,
            name: Some(pending.name.clone()),
            projects: pending.projects.len(),
            rotated: pending.rotated.len(),
            regrants: pending.regrants.len(),
            unknown_projects: pending.unknown_projects,
            narrowed: pending.narrowed,
            items: pending.items,
            log_unchecked: pending.log_unchecked,
            without_key_change: pending.without_key_change,
            skipped: pending.skipped.len(),
            to_change: pending.pending.len(),
            needs_work: pending.needs_work(),
            running,
            last_error: pending.last_error.clone(),
        }
    }

    /// Only the agent and the counts (what `status` says while locked).
    #[must_use]
    pub fn counts(mut self) -> Self {
        self.name = None;
        self.last_error = None;
        self
    }
}

/// What [`Request::ConfirmPresence`] is for: the prompt names it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PresencePurpose {
    /// Asking to delete the account (ADR 0037 §1).
    DeleteAccount,
}

/// A pause of agents in effect (`status`, `pause_agents`, ADR 0033 §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseInEffect {
    /// The agent; none: every agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<klav_core::ids::AgentId>,
    /// When the person decided it (Unix ms).
    pub since: i64,
    /// When it ends by itself (Unix ms); none: until the person resumes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,
    /// Applied only here: `klavd` was locked or offline, and signs and
    /// sends it as soon as it can. Until then, only what `klavd` mediates
    /// is stopped («Paused on this Mac»).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub local: bool,
    /// With `local`: the server answered that it does not support pausing
    /// agents (one older than the pauses). It holds on this Mac only, and
    /// `klavd` stops sending it; each unlock tries once more («Paused on
    /// this Mac only: update the server»).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub server_unsupported: bool,
}

impl PauseInEffect {
    /// A pause signed by the account, as the server lists it.
    #[must_use]
    pub fn signed(pause: &klav_proto::agent::AgentPause) -> Self {
        Self {
            agent_id: pause.agent_id,
            since: pause.at,
            until: (pause.until != 0).then_some(pause.until),
            local: false,
            server_unsupported: false,
        }
    }
}

/// A browser whose extension attached to `klavd` (`extension_attach`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserSeen {
    /// The name the extension gave (`Dia`, `Google Chrome`, `Firefox`…).
    pub browser: String,
    /// Attached now.
    pub connected: bool,
    /// When it last attached or, if it is gone, left (Unix ms).
    pub at_ms: u64,
}

/// Biometric unlock state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BiometricStatus {
    /// The platform supports it on this machine.
    pub available: bool,
    /// A Secure Enclave key protects this device's local key.
    pub enrolled: bool,
    /// Why the master password is required next time, if it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_required: Option<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An older `klavd`'s `status`, without the build, reads with none;
    /// a build without one leaves both fields out, so what older apps and
    /// extensions read is unchanged.
    #[test]
    fn status_build_fields_are_optional_both_ways() {
        let old: DaemonStatus = serde_json::from_value(serde_json::json!({
            "version": "0.0.0", "protocol": 1, "pid": 1, "logged_in": false,
            "unlocked": false, "idle_lock_secs": 900,
        }))
        .expect("older status");
        assert_eq!((old.commit.as_deref(), old.commit_time), (None, None));
        let line = serde_json::to_value(&old).expect("json");
        assert!(line.get("commit").is_none() && line.get("commit_time").is_none());
        assert_eq!(line["version"], "0.0.0");

        let mut new = old;
        new.commit = Some("ce4fa50990924bf17d349b752ad8020ff6b3a9ff".into());
        new.commit_time = Some(1_794_593_822);
        let line = serde_json::to_value(&new).expect("json");
        assert_eq!(line["commit"], "ce4fa50990924bf17d349b752ad8020ff6b3a9ff");
        assert_eq!(line["commit_time"], 1_794_593_822);
        assert_eq!(line["version"], "0.0.0");
    }

    #[test]
    fn wire_format_is_stable() {
        let line = serde_json::to_string(&RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: 7,
            request: Request::View {
                query: "GitHub".into(),
                reveal: false,
                password: None,
            },
            notify: false,
            shown: None,
            untyped: false,
        })
        .unwrap();
        assert_eq!(
            line,
            r#"{"v":1,"id":7,"request":{"op":"view","query":"GitHub","reveal":false}}"#
        );
        let parsed: RequestEnvelope =
            serde_json::from_str(r#"{"v":1,"id":1,"request":{"op":"unlock"}}"#).unwrap();
        assert!(matches!(
            parsed.request,
            Request::Unlock {
                password: None,
                passkey_flow: false,
            }
        ));
        // An `autofill` without `chosen` (an older extension, or any fill
        // without the person's pick) never reaches a parent page's login
        // (ADR 0025 §2).
        let parsed: RequestEnvelope = serde_json::from_str(
            r#"{"v":1,"id":1,"request":{"op":"autofill","item":"x","url":"https://a.example/"}}"#,
        )
        .unwrap();
        assert!(matches!(
            parsed.request,
            Request::Autofill { chosen: false, .. }
        ));
        assert!(
            serde_json::from_str::<RequestEnvelope>(
                r#"{"v":1,"id":1,"request":{"op":"trash","query":"x","extra":1}}"#
            )
            .is_err()
        );
        let error = ResponseEnvelope {
            v: 1,
            id: 7,
            ok: None,
            error: Some(ErrorBody {
                code: ErrorCode::Locked,
                message: "locked".into(),
                paused: None,
                presence: None,
            }),
            warnings: vec![],
            notice: None,
        };
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            r#"{"v":1,"id":7,"error":{"code":"locked","message":"locked"}}"#
        );
    }

    /// The presence gate's additions (ADR 0041 §2.4, layer 3's review)
    /// leave every line an older client or `klavd` reads as it was: the
    /// envelope's `notify` and `shown`, a response's `notice` and `status`'s
    /// `presence` are left out when unset, and an older `klavd`, which
    /// refuses unknown fields, never gets them unasked.
    #[test]
    fn the_presence_additions_are_absent_unless_set() {
        let plain = RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: 3,
            request: Request::Unlock {
                password: None,
                passkey_flow: false,
            },
            notify: false,
            shown: None,
            untyped: false,
        };
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            r#"{"v":1,"id":3,"request":{"op":"unlock"}}"#
        );
        let asked = RequestEnvelope {
            notify: true,
            shown: Some(crate::uv::Window::FiveMinutes),
            untyped: true,
            ..plain
        };
        assert_eq!(
            serde_json::to_string(&asked).unwrap(),
            r#"{"v":1,"id":3,"request":{"op":"unlock"},"notify":true,"shown":"5m","untyped":true}"#
        );
        let notice = ResponseEnvelope {
            v: 1,
            id: 3,
            ok: None,
            error: None,
            warnings: vec![],
            notice: Some(Notice::TouchId),
        };
        assert_eq!(
            serde_json::to_string(&notice).unwrap(),
            r#"{"v":1,"id":3,"notice":"touch_id"}"#
        );
        let ask = PresenceAsk {
            key: PresenceKey::Session,
            window: crate::uv::Window::Always,
            terminal: Some("ttys003".into()),
            declared: false,
            lasts: None,
            value: Some(AskValue {
                kind: AskValueKind::Code,
                title: Some("GitHub".into()),
                count: None,
            }),
            browser: None,
        };
        assert_eq!(
            serde_json::to_value(&ask).unwrap(),
            serde_json::json!({
                "key": "session", "window": "always", "terminal": "ttys003",
                "value": { "kind": "code", "title": "GitHub" },
            })
        );
    }

    #[test]
    fn debug_never_shows_secrets() {
        let request = Request::Unlock {
            password: Some(SecretText::new("hunter2-hunter2")),
            passkey_flow: false,
        };
        assert!(!format!("{request:?}").contains("hunter2"));
    }

    /// `sandbox_revoke` names its scope: without `scope` the line does not
    /// parse, so klavd answers `bad_request` and revokes nothing.
    #[test]
    fn a_sandbox_revoke_without_its_scope_is_malformed() {
        let line = |request: serde_json::Value| {
            serde_json::from_value::<RequestEnvelope>(serde_json::json!({
                "v": PROTOCOL_VERSION, "id": 1, "request": request,
            }))
        };
        let proxy = "6f1c2b8e-4d3a-4f5b-9c7d-1e2f3a4b5c6d";
        assert!(line(serde_json::json!({"op": "sandbox_revoke", "proxy": proxy})).is_err());
        assert!(
            line(serde_json::json!({"op": "sandbox_revoke", "proxy": proxy, "sandbox": proxy}))
                .is_err()
        );
        let all = line(serde_json::json!({"op": "sandbox_revoke", "proxy": proxy, "scope": "all"}))
            .expect("with its scope");
        assert!(matches!(all.request, Request::SandboxRevoke { scope, .. } if scope == "all"));
    }

    /// The flagged list is its own op: an older `klavd` cannot take it for
    /// `sandbox_list` and answers `bad_request`, so the caller asks
    /// `sandbox_list`, which fails closed on what it would flag.
    #[test]
    fn the_flagged_sandbox_list_is_its_own_op() {
        let line = |op: &str| {
            serde_json::from_value::<RequestEnvelope>(serde_json::json!({
                "v": PROTOCOL_VERSION, "id": 1, "request": {"op": op},
            }))
            .expect(op)
            .request
        };
        assert!(matches!(line("sandbox_list"), Request::SandboxList));
        assert!(matches!(
            line("sandbox_list_flagged"),
            Request::SandboxListFlagged
        ));
        assert!(matches!(
            line("sandbox_list_checked"),
            Request::SandboxListChecked
        ));
    }
}
