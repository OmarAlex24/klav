//! Agents (design §5, spec §13): the 6-word pairing code, the agent
//! secret-key format and the signed objects of the agent protocol.
//!
//! * **Pairing code:** six words of the EFF Large Wordlist derived from the
//!   identity fingerprint (spec §6.2); the human compares them on both
//!   screens before approving an agent (threat T10).
//! * **Agent secret key** (kind `0x07`): the agent's private keys, stored by
//!   the agent itself (keychain, 0600 file or environment variable). It is
//!   not encrypted: whoever reads it *is* the agent, which is why grants are
//!   scoped, expire and can be revoked (T23).
//! * **Signatures** (spec §9): requests of an agent, grants and approval
//!   decisions of a person, revocations, and pauses and resumes of agents.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::context::ProjectContext;
use super::encoding::{Kind, Tuple, strip_header};
use super::identity::{IdentityKeyPair, PublicIdentity};
use super::keys::{ProjectKey, sealed::Sealed};
use super::sign::{self, Signature};
use super::{CryptoError, aead};
use crate::generator::wordlist;
use crate::ids::{AccountId, AgentId, ApprovalId, TaskId};

/// Number of words in a pairing code.
pub const PAIRING_WORDS: usize = 6;
/// Length of an encoded agent secret key: header(2) ‖ x25519(32) ‖ ed25519(32).
pub const AGENT_SECRET_LEN: usize = 66;
/// Prefix of the text form of an agent secret key.
pub const AGENT_SECRET_PREFIX: &str = "kag1_";
/// Length of a request nonce.
pub const NONCE_LEN: usize = 16;

/// Label of a signed agent request.
pub const LABEL_REQUEST: &str = "klav/v1/sig/agent-request";
/// Label of a grant signed by the account.
pub const LABEL_GRANT: &str = "klav/v1/sig/agent-grant";
/// Label of an approval decision signed by the account.
pub const LABEL_APPROVAL: &str = "klav/v1/sig/approval";
/// Label of a revocation signed by the account.
pub const LABEL_REVOCATION: &str = "klav/v1/sig/agent-revocation";
/// Label of a task decision signed by the account (spec §13.8).
pub const LABEL_TASK_DECISION: &str = "klav/v1/sig/task-decision";
/// Label of the person ending a task, signed by the account (spec §13.8).
pub const LABEL_TASK_END: &str = "klav/v1/sig/task-end";
/// Label of a pause or resume of agents, signed by the account (spec
/// §13.9, ADR 0033 §7).
pub const LABEL_AGENT_PAUSE: &str = "klav/v1/sig/agent-pause";
/// AAD label of the names that travel with a grant (kind `0x14`).
pub const LABEL_GRANT_LABELS: &str = "klav/v1/agent/labels";
/// Label of the local digest that binds a grant change to the sheet the
/// person saw (ADR 0033, amendment of 2026-11-10, F3). Not a signature: it
/// never leaves the device.
pub const LABEL_GRANT_CHANGE: &str = "klav/v1/grant-change";

/// The six pairing words of an identity (spec §13.1):
/// `word_i = EFF[u32_be(fingerprint[4i..4i+4]) mod 7776]`. The modulus is
/// the length of the list itself (`wordlist().len()`, 7776 and pinned by a
/// test in `generator`), so the two cannot drift apart.
pub fn pairing_words(public: &PublicIdentity) -> [&'static str; PAIRING_WORDS] {
    let fingerprint = public.fingerprint();
    let words = wordlist();
    let len = u32::try_from(words.len()).expect("wordlist fits in u32");
    std::array::from_fn(|i| {
        let chunk: [u8; 4] = fingerprint[4 * i..4 * i + 4]
            .try_into()
            .expect("4-byte chunk");
        words[usize::try_from(u32::from_be_bytes(chunk) % len).expect("index fits")]
    })
}

/// The pairing words joined by spaces.
pub fn pairing_code(public: &PublicIdentity) -> String {
    pairing_words(public).join(" ")
}

/// Whether `typed` (words separated by spaces, hyphens or commas, any case)
/// is the pairing code of `public`.
///
/// The expected words go through the same split, because four EFF words
/// carry a hyphen (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`): comparing
/// them whole against a typed code split on hyphens would never match.
pub fn pairing_code_matches(public: &PublicIdentity, typed: &str) -> bool {
    fn tokens(text: &str) -> impl Iterator<Item = String> + '_ {
        text.split(|c: char| c.is_whitespace() || c == '-' || c == ',')
            .filter(|w| !w.is_empty())
            .map(str::to_lowercase)
    }
    let expected = pairing_words(public);
    tokens(typed).eq(expected.iter().flat_map(|w| tokens(w)))
}

/// Encodes the agent's private keys (kind `0x07`) in text form:
/// `"kag1_" ‖ BASE64URL(0x01 ‖ 0x07 ‖ x25519_sk ‖ ed25519_seed)`.
pub fn encode_agent_secret(keys: &IdentityKeyPair) -> Zeroizing<String> {
    let mut blob = Zeroizing::new([0u8; AGENT_SECRET_LEN]);
    blob[..2].copy_from_slice(&Kind::AgentSecret.header());
    blob[2..].copy_from_slice(keys.secrets_plaintext().as_ref());
    let mut text = Zeroizing::new(String::with_capacity(
        AGENT_SECRET_PREFIX.len() + BASE64URL_NOPAD.encode_len(AGENT_SECRET_LEN),
    ));
    text.push_str(AGENT_SECRET_PREFIX);
    BASE64URL_NOPAD.encode_append(blob.as_ref(), &mut text);
    text
}

/// Decodes [`encode_agent_secret`]. Surrounding whitespace is ignored.
pub fn decode_agent_secret(text: &str) -> Result<IdentityKeyPair, CryptoError> {
    let body = text
        .trim()
        .strip_prefix(AGENT_SECRET_PREFIX)
        .ok_or(CryptoError::Malformed("agent key must start with kag1_"))?;
    let blob = Zeroizing::new(
        BASE64URL_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| CryptoError::Malformed("agent key is not base64url"))?,
    );
    if blob.len() != AGENT_SECRET_LEN {
        return Err(CryptoError::Malformed("agent key length"));
    }
    let keys = strip_header(&blob, Kind::AgentSecret)?;
    let mut x = Zeroizing::new([0u8; 32]);
    let mut ed = Zeroizing::new([0u8; 32]);
    x.copy_from_slice(&keys[..32]);
    ed.copy_from_slice(&keys[32..]);
    Ok(IdentityKeyPair::from_secret_bytes(&x, &ed))
}

/// `SHA-256(body)`: the body digest signed in agent requests.
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// `SHA-256(request)` in lowercase hex: the digest of the exact request
/// bytes a person was shown on an approval or task card (ADR 0030 §5).
/// Deciding passes it back, and the client refuses to sign if the request
/// it is about to sign hashes to anything else.
pub fn request_digest(request: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(request))
}

/// Whether `shown` (a [`request_digest`], any case, surrounding blanks
/// ignored) is the digest of `request`.
pub fn shown_matches(request: &[u8], shown: &str) -> bool {
    shown.trim().eq_ignore_ascii_case(&request_digest(request))
}

/// `SHA-256(tuple("klav/v1/grant-change", current, change))` in lowercase
/// hex (ADR 0033, amendment of 2026-11-10, F3): `current` are the signed
/// bytes of the agent's grant in force, and `change` the change the person
/// was shown, as the caller sent it. Preparing a change returns it; signing
/// computes it again from the grant in force at that moment and signs
/// nothing if it differs. Local only: no format or signature changes.
pub fn grant_change_digest(current: &[u8], change: &[u8]) -> String {
    let mut tuple = Tuple::new(LABEL_GRANT_CHANGE);
    tuple.push(current).push(change);
    HEXLOWER.encode(&Sha256::digest(tuple.as_bytes()))
}

/// Whether `shown` (a [`grant_change_digest`], any case, surrounding
/// blanks ignored) is the digest of `current` and `change`.
pub fn grant_change_matches(current: &[u8], change: &[u8], shown: &str) -> bool {
    shown
        .trim()
        .eq_ignore_ascii_case(&grant_change_digest(current, change))
}

/// An agent request as signed (spec §13.3).
#[derive(Debug, Clone, Copy)]
pub struct SignedRequest<'a> {
    /// The agent.
    pub agent: AgentId,
    /// HTTP method, upper case (`GET`, `POST`…).
    pub method: &'a str,
    /// Path and query exactly as sent (`/v1/agent/me`).
    pub path: &'a str,
    /// Client time, Unix milliseconds.
    pub timestamp_ms: u64,
    /// Fresh random nonce.
    pub nonce: &'a [u8; NONCE_LEN],
    /// SHA-256 of the body ([`body_digest`]; of the empty string without body).
    pub body_digest: &'a [u8; 32],
}

impl SignedRequest<'_> {
    pub(crate) fn fields(&self) -> [Vec<u8>; 6] {
        [
            self.agent.as_bytes().to_vec(),
            self.method.as_bytes().to_vec(),
            self.path.as_bytes().to_vec(),
            self.timestamp_ms.to_be_bytes().to_vec(),
            self.nonce.to_vec(),
            self.body_digest.to_vec(),
        ]
    }
}

pub(crate) fn refs(fields: &[Vec<u8>]) -> Vec<&[u8]> {
    fields.iter().map(Vec::as_slice).collect()
}

/// Signs an agent request with the agent's identity.
pub fn sign_request(keys: &IdentityKeyPair, request: &SignedRequest<'_>) -> Signature {
    sign::sign(keys, LABEL_REQUEST, &refs(&request.fields())).expect("valid label")
}

/// Verifies an agent request signature.
pub fn verify_request(
    agent: &PublicIdentity,
    request: &SignedRequest<'_>,
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(agent, LABEL_REQUEST, &refs(&request.fields()), signature)
}

/// What a grant signature covers (spec §13.4): the account, the agent, its
/// public identity and the exact bytes of the grant payload.
#[derive(Debug, Clone, Copy)]
pub struct GrantToSign<'a> {
    /// Account that issues the grant.
    pub account: AccountId,
    /// The agent.
    pub agent: AgentId,
    /// The agent's public identity, as approved after comparing the words.
    pub agent_public: &'a PublicIdentity,
    /// The grant payload (JSON bytes, stored and returned verbatim).
    pub payload: &'a [u8],
}

impl GrantToSign<'_> {
    pub(crate) fn fields(&self) -> [Vec<u8>; 4] {
        [
            self.account.as_bytes().to_vec(),
            self.agent.as_bytes().to_vec(),
            self.agent_public.encode().to_vec(),
            self.payload.to_vec(),
        ]
    }
}

/// Signs a grant with the account identity.
pub fn sign_grant(account: &IdentityKeyPair, grant: &GrantToSign<'_>) -> Signature {
    sign::sign(account, LABEL_GRANT, &refs(&grant.fields())).expect("valid label")
}

/// Verifies a grant signature against the account's public identity.
pub fn verify_grant(
    account: &PublicIdentity,
    grant: &GrantToSign<'_>,
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(account, LABEL_GRANT, &refs(&grant.fields()), signature)
}

/// A person's decision on an approval request (spec §13.5).
#[derive(Debug, Clone, Copy)]
pub struct ApprovalToSign<'a> {
    /// The approval request.
    pub approval: ApprovalId,
    /// The agent that asked.
    pub agent: AgentId,
    /// The request exactly as stored by the server and shown to the person
    /// (JSON bytes).
    pub request: &'a [u8],
    /// `true` to approve, `false` to deny.
    pub approve: bool,
    /// Approvals valid for a while ("approve 15 min"): end of the lease in
    /// Unix ms. `0` for "approve once" and for denials.
    pub lease_until_ms: u64,
    /// When the person decided, Unix ms.
    pub decided_at_ms: u64,
}

impl ApprovalToSign<'_> {
    pub(crate) fn fields(&self) -> [Vec<u8>; 6] {
        [
            self.approval.as_bytes().to_vec(),
            self.agent.as_bytes().to_vec(),
            self.request.to_vec(),
            if self.approve {
                &b"approve"[..]
            } else {
                &b"deny"[..]
            }
            .to_vec(),
            self.lease_until_ms.to_be_bytes().to_vec(),
            self.decided_at_ms.to_be_bytes().to_vec(),
        ]
    }
}

/// Signs an approval decision with the account identity.
pub fn sign_approval(account: &IdentityKeyPair, decision: &ApprovalToSign<'_>) -> Signature {
    sign::sign(account, LABEL_APPROVAL, &refs(&decision.fields())).expect("valid label")
}

/// Verifies an approval decision.
pub fn verify_approval(
    account: &PublicIdentity,
    decision: &ApprovalToSign<'_>,
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(
        account,
        LABEL_APPROVAL,
        &refs(&decision.fields()),
        signature,
    )
}

/// Signs the revocation of an agent (spec §13.6).
pub fn sign_revocation(
    account: &IdentityKeyPair,
    account_id: AccountId,
    agent: AgentId,
    revoked_at_ms: u64,
) -> Signature {
    sign::sign(
        account,
        LABEL_REVOCATION,
        &[
            account_id.as_bytes(),
            agent.as_bytes(),
            &revoked_at_ms.to_be_bytes(),
        ],
    )
    .expect("valid label")
}

/// Verifies a revocation.
pub fn verify_revocation(
    account: &PublicIdentity,
    account_id: AccountId,
    agent: AgentId,
    revoked_at_ms: u64,
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(
        account,
        LABEL_REVOCATION,
        &[
            account_id.as_bytes(),
            agent.as_bytes(),
            &revoked_at_ms.to_be_bytes(),
        ],
        signature,
    )
}

/// A person's decision on a task request (spec §13.8).
#[derive(Debug, Clone, Copy)]
pub struct TaskDecisionToSign<'a> {
    /// The task.
    pub task: TaskId,
    /// The agent that asked.
    pub agent: AgentId,
    /// The agent's request exactly as stored by the server (JSON bytes of
    /// `klav_core::task::TaskRequest`); empty for a task the person offers.
    pub request: &'a [u8],
    /// The decision exactly as stored (JSON bytes of
    /// `klav_core::task::TaskDecision`).
    pub decision: &'a [u8],
    /// `true` to approve, `false` to deny.
    pub approve: bool,
    /// When the person decided, Unix ms.
    pub decided_at_ms: u64,
}

impl TaskDecisionToSign<'_> {
    pub(crate) fn fields(&self) -> [Vec<u8>; 6] {
        [
            self.task.as_bytes().to_vec(),
            self.agent.as_bytes().to_vec(),
            self.request.to_vec(),
            self.decision.to_vec(),
            if self.approve {
                &b"approve"[..]
            } else {
                &b"deny"[..]
            }
            .to_vec(),
            self.decided_at_ms.to_be_bytes().to_vec(),
        ]
    }
}

/// Signs a task decision with the account identity.
pub fn sign_task_decision(
    account: &IdentityKeyPair,
    decision: &TaskDecisionToSign<'_>,
) -> Signature {
    sign::sign(account, LABEL_TASK_DECISION, &refs(&decision.fields())).expect("valid label")
}

/// Verifies a task decision.
pub fn verify_task_decision(
    account: &PublicIdentity,
    decision: &TaskDecisionToSign<'_>,
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(
        account,
        LABEL_TASK_DECISION,
        &refs(&decision.fields()),
        signature,
    )
}

/// Signs the person ending a task (spec §13.8), shaped like a revocation:
/// `tuple("klav/v1/sig/task-end", account_id, task_id, agent_id, u64_be(ended_at_ms))`.
pub fn sign_task_end(
    account: &IdentityKeyPair,
    account_id: AccountId,
    task: TaskId,
    agent: AgentId,
    ended_at_ms: u64,
) -> Signature {
    sign::sign(
        account,
        LABEL_TASK_END,
        &[
            account_id.as_bytes(),
            task.as_bytes(),
            agent.as_bytes(),
            &ended_at_ms.to_be_bytes(),
        ],
    )
    .expect("valid label")
}

/// Verifies [`sign_task_end`].
pub fn verify_task_end(
    account: &PublicIdentity,
    account_id: AccountId,
    task: TaskId,
    agent: AgentId,
    ended_at_ms: u64,
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(
        account,
        LABEL_TASK_END,
        &[
            account_id.as_bytes(),
            task.as_bytes(),
            agent.as_bytes(),
            &ended_at_ms.to_be_bytes(),
        ],
        signature,
    )
}

/// Which agents a pause covers (spec §13.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PauseScope {
    /// Every agent of the account, including those approved later.
    All,
    /// One agent.
    Agent(AgentId),
}

impl PauseScope {
    /// The signed `scope` field: the ASCII bytes `all`, or the agent's 16
    /// raw ID bytes. The lengths differ, so the two never collide.
    pub fn signed_bytes(&self) -> &[u8] {
        match self {
            PauseScope::All => b"all",
            PauseScope::Agent(agent) => agent.as_bytes(),
        }
    }
}

/// A pause or a resume of agents, as the account signs it (spec §13.9):
/// `tuple("klav/v1/sig/agent-pause", account_id, scope, state,
/// u64_be(at_ms), u64_be(until_ms))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PauseToSign {
    /// The account.
    pub account: AccountId,
    /// Every agent, or one.
    pub scope: PauseScope,
    /// `true` to pause (`"pause"`), `false` to resume (`"resume"`).
    pub pause: bool,
    /// When the person decided, Unix ms. Each decision on a scope must be
    /// later than the previous one, so an old resume cannot be replayed.
    pub at_ms: u64,
    /// End of the pause, Unix ms; `0` for no end, and always `0` in a
    /// resume.
    pub until_ms: u64,
}

impl PauseToSign {
    pub(crate) fn fields(&self) -> [Vec<u8>; 5] {
        [
            self.account.as_bytes().to_vec(),
            self.scope.signed_bytes().to_vec(),
            if self.pause {
                &b"pause"[..]
            } else {
                &b"resume"[..]
            }
            .to_vec(),
            self.at_ms.to_be_bytes().to_vec(),
            self.until_ms.to_be_bytes().to_vec(),
        ]
    }
}

/// Signs a pause or a resume with the account identity.
pub fn sign_pause(account: &IdentityKeyPair, decision: &PauseToSign) -> Signature {
    sign::sign(account, LABEL_AGENT_PAUSE, &refs(&decision.fields())).expect("valid label")
}

/// Verifies [`sign_pause`].
pub fn verify_pause(
    account: &PublicIdentity,
    decision: &PauseToSign,
    signature: &Signature,
) -> Result<(), CryptoError> {
    sign::verify(
        account,
        LABEL_AGENT_PAUSE,
        &refs(&decision.fields()),
        signature,
    )
}

pub(crate) fn labels_tuple(ctx: &ProjectContext, agent: AgentId) -> Tuple {
    let mut tuple = Tuple::new(LABEL_GRANT_LABELS);
    tuple
        .push(ctx.account.as_bytes())
        .push(ctx.vault.as_bytes())
        .push(ctx.project.as_bytes())
        .push(agent.as_bytes());
    tuple
}

/// Seals the names an agent needs to resolve references (the vault name is
/// sealed with the vault key, which agents never receive) with the project
/// key (kind `0x14`, spec §13.4):
/// `AAD = header ‖ tuple("klav/v1/agent/labels", account, vault, project, agent)`.
pub fn seal_grant_labels(
    key: &ProjectKey,
    ctx: &ProjectContext,
    agent: AgentId,
    plaintext: &[u8],
) -> Vec<u8> {
    aead::seal(
        key.secret_bytes(),
        Kind::GrantLabels,
        &labels_tuple(ctx, agent),
        plaintext,
    )
}

/// [`seal_grant_labels`] with a fixed nonce (test vectors only).
#[cfg(test)]
pub(crate) fn seal_grant_labels_with_nonce(
    key: &ProjectKey,
    ctx: &ProjectContext,
    agent: AgentId,
    nonce: &[u8; aead::NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    aead::seal_with_nonce(
        key.secret_bytes(),
        Kind::GrantLabels,
        &labels_tuple(ctx, agent),
        nonce,
        plaintext,
    )
}

/// Opens [`seal_grant_labels`].
pub fn open_grant_labels(
    key: &ProjectKey,
    ctx: &ProjectContext,
    agent: AgentId,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    aead::open(
        key.secret_bytes(),
        Kind::GrantLabels,
        &labels_tuple(ctx, agent),
        blob,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_change_digest_binds_the_grant_and_the_change() {
        let d = grant_change_digest(b"grant v3", b"{\"projects\":[]}");
        assert_eq!(d.len(), 64);
        assert!(grant_change_matches(b"grant v3", b"{\"projects\":[]}", &d));
        assert!(grant_change_matches(
            b"grant v3",
            b"{\"projects\":[]}",
            &format!(" {} ", d.to_uppercase())
        ));
        // Another grant in force, or another change: no match.
        assert!(!grant_change_matches(b"grant v4", b"{\"projects\":[]}", &d));
        assert!(!grant_change_matches(
            b"grant v3",
            b"{\"projects\":[1]}",
            &d
        ));
        // The fields are length-prefixed: moving bytes across does not
        // collide.
        assert_ne!(d, grant_change_digest(b"grant v", b"3{\"projects\":[]}"));
        // Not the plain request digest of either part.
        assert_ne!(d, request_digest(b"grant v3"));
    }

    #[test]
    fn the_shown_digest_is_the_sha256_of_the_exact_bytes() {
        // SHA-256("abc"), FIPS 180-2 B.1.
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(request_digest(b"abc"), abc);
        assert!(shown_matches(b"abc", abc));
        assert!(shown_matches(b"abc", &format!(" {} ", abc.to_uppercase())));
        assert!(!shown_matches(b"abc ", abc));
        assert!(!shown_matches(b"abc", ""));
    }

    #[test]
    fn pairing_words_are_stable_and_comparable() {
        let keys = IdentityKeyPair::generate();
        let words = pairing_words(keys.public());
        assert_eq!(words, pairing_words(keys.public()));
        let code = pairing_code(keys.public());
        assert!(pairing_code_matches(keys.public(), &code));
        assert!(pairing_code_matches(
            keys.public(),
            &code.to_uppercase().replace(' ', "-")
        ));
        assert!(!pairing_code_matches(keys.public(), &words[..5].join(" ")));
        let other = IdentityKeyPair::generate();
        assert!(!pairing_code_matches(other.public(), &code));
    }

    #[test]
    fn pairing_words_with_a_hyphen_still_match() {
        // About 0.3 % of identities get a hyphenated EFF word; search one.
        let keys = (0..50_000)
            .map(|_| IdentityKeyPair::generate())
            .find(|k| pairing_words(k.public()).iter().any(|w| w.contains('-')))
            .expect("an identity with a hyphenated pairing word");
        let code = pairing_code(keys.public());
        assert!(pairing_code_matches(keys.public(), &code));
        assert!(pairing_code_matches(keys.public(), &code.to_uppercase()));
        assert!(pairing_code_matches(keys.public(), &code.replace(' ', ",")));
        let words = pairing_words(keys.public());
        assert!(!pairing_code_matches(keys.public(), &words[1..].join(" ")));
    }

    #[test]
    fn agent_secret_roundtrip() {
        let keys = IdentityKeyPair::generate();
        let text = encode_agent_secret(&keys);
        assert!(text.starts_with(AGENT_SECRET_PREFIX));
        let back = decode_agent_secret(&format!("  {}\n", text.as_str())).unwrap();
        assert_eq!(back.public(), keys.public());
        for bad in ["", "kag1_", "kag2_AAAA", "kag1_!!!!"] {
            assert!(decode_agent_secret(bad).is_err(), "{bad}");
        }
        // Another kind in the header is rejected.
        let mut blob = BASE64URL_NOPAD
            .decode(text[AGENT_SECRET_PREFIX.len()..].as_bytes())
            .unwrap();
        blob[1] = Kind::IdentitySecrets as u8;
        let wrong = format!("{AGENT_SECRET_PREFIX}{}", BASE64URL_NOPAD.encode(&blob));
        assert!(matches!(
            decode_agent_secret(&wrong),
            Err(CryptoError::UnexpectedKind { .. })
        ));
    }

    #[test]
    fn request_signature_binds_every_field() {
        let keys = IdentityKeyPair::generate();
        let agent = AgentId::generate();
        let nonce = [7u8; NONCE_LEN];
        let digest = body_digest(b"{}");
        let request = SignedRequest {
            agent,
            method: "POST",
            path: "/v1/agent/access",
            timestamp_ms: 1_800_000_000_000,
            nonce: &nonce,
            body_digest: &digest,
        };
        let sig = sign_request(&keys, &request);
        assert_eq!(verify_request(keys.public(), &request, &sig), Ok(()));
        let other_body = body_digest(b"{\"x\":1}");
        let other_nonce = [8u8; NONCE_LEN];
        for tampered in [
            SignedRequest {
                method: "GET",
                ..request
            },
            SignedRequest {
                path: "/v1/agent/me",
                ..request
            },
            SignedRequest {
                timestamp_ms: 1,
                ..request
            },
            SignedRequest {
                nonce: &other_nonce,
                ..request
            },
            SignedRequest {
                body_digest: &other_body,
                ..request
            },
            SignedRequest {
                agent: AgentId::generate(),
                ..request
            },
        ] {
            assert_eq!(
                verify_request(keys.public(), &tampered, &sig),
                Err(CryptoError::Signature)
            );
        }
    }

    #[test]
    fn grant_and_approval_signatures() {
        let account = IdentityKeyPair::generate();
        let agent_keys = IdentityKeyPair::generate();
        let grant = GrantToSign {
            account: AccountId::generate(),
            agent: AgentId::generate(),
            agent_public: agent_keys.public(),
            payload: b"{\"v\":1}",
        };
        let sig = sign_grant(&account, &grant);
        assert_eq!(verify_grant(account.public(), &grant, &sig), Ok(()));
        let swapped = IdentityKeyPair::generate();
        assert!(
            verify_grant(
                account.public(),
                &GrantToSign {
                    agent_public: swapped.public(),
                    ..grant
                },
                &sig
            )
            .is_err()
        );

        let decision = ApprovalToSign {
            approval: ApprovalId::generate(),
            agent: grant.agent,
            request: b"{\"permission\":\"reveal\"}",
            approve: true,
            lease_until_ms: 0,
            decided_at_ms: 5,
        };
        let sig = sign_approval(&account, &decision);
        assert_eq!(verify_approval(account.public(), &decision, &sig), Ok(()));
        assert!(
            verify_approval(
                account.public(),
                &ApprovalToSign {
                    approve: false,
                    ..decision
                },
                &sig
            )
            .is_err()
        );

        let sig = sign_revocation(&account, grant.account, grant.agent, 9);
        assert!(verify_revocation(account.public(), grant.account, grant.agent, 9, &sig).is_ok());
        assert!(verify_revocation(account.public(), grant.account, grant.agent, 10, &sig).is_err());
    }

    #[test]
    fn task_signatures_bind_every_field() {
        let account = IdentityKeyPair::generate();
        let decision = TaskDecisionToSign {
            task: TaskId::generate(),
            agent: AgentId::generate(),
            request: b"{\"v\":1}",
            decision: b"{\"revision\":1}",
            approve: true,
            decided_at_ms: 7,
        };
        let sig = sign_task_decision(&account, &decision);
        assert_eq!(
            verify_task_decision(account.public(), &decision, &sig),
            Ok(())
        );
        for tampered in [
            TaskDecisionToSign {
                task: TaskId::generate(),
                ..decision
            },
            TaskDecisionToSign {
                agent: AgentId::generate(),
                ..decision
            },
            TaskDecisionToSign {
                request: b"{}",
                ..decision
            },
            TaskDecisionToSign {
                decision: b"{\"revision\":2}",
                ..decision
            },
            TaskDecisionToSign {
                approve: false,
                ..decision
            },
            TaskDecisionToSign {
                decided_at_ms: 8,
                ..decision
            },
        ] {
            assert_eq!(
                verify_task_decision(account.public(), &tampered, &sig),
                Err(CryptoError::Signature)
            );
        }
        // A task decision is not an approval decision (domain separation).
        let as_approval = ApprovalToSign {
            approval: ApprovalId::from_bytes(*decision.task.as_bytes()),
            agent: decision.agent,
            request: decision.request,
            approve: true,
            lease_until_ms: 0,
            decided_at_ms: 7,
        };
        assert!(verify_approval(account.public(), &as_approval, &sig).is_err());

        let account_id = AccountId::generate();
        let sig = sign_task_end(&account, account_id, decision.task, decision.agent, 11);
        assert!(
            verify_task_end(
                account.public(),
                account_id,
                decision.task,
                decision.agent,
                11,
                &sig
            )
            .is_ok()
        );
        assert!(
            verify_task_end(
                account.public(),
                account_id,
                decision.task,
                decision.agent,
                12,
                &sig
            )
            .is_err()
        );
    }

    #[test]
    fn pause_signatures_bind_every_field() {
        let account = IdentityKeyPair::generate();
        let agent = AgentId::generate();
        let pause = PauseToSign {
            account: AccountId::generate(),
            scope: PauseScope::Agent(agent),
            pause: true,
            at_ms: 1_800_000_000_000,
            until_ms: 1_800_003_600_000,
        };
        let sig = sign_pause(&account, &pause);
        assert_eq!(verify_pause(account.public(), &pause, &sig), Ok(()));
        for tampered in [
            PauseToSign {
                account: AccountId::generate(),
                ..pause
            },
            PauseToSign {
                scope: PauseScope::All,
                ..pause
            },
            PauseToSign {
                scope: PauseScope::Agent(AgentId::generate()),
                ..pause
            },
            // A pause is not a resume: the replayed bytes say «pause».
            PauseToSign {
                pause: false,
                ..pause
            },
            PauseToSign {
                at_ms: pause.at_ms + 1,
                ..pause
            },
            PauseToSign {
                until_ms: 0,
                ..pause
            },
        ] {
            assert_eq!(
                verify_pause(account.public(), &tampered, &sig),
                Err(CryptoError::Signature)
            );
        }
        // Not a revocation of the same agent at the same time.
        assert!(
            verify_revocation(account.public(), pause.account, agent, pause.at_ms, &sig).is_err()
        );
        // Another identity did not sign it.
        let other = IdentityKeyPair::generate();
        assert!(verify_pause(other.public(), &pause, &sig).is_err());
    }
}
