//! Test vectors in `docs/vectores/` (spec §11).
//!
//! Each file holds cases with *inputs* and *outputs*. [`vectors_match_spec`]
//! recomputes every output from the inputs and also runs the decryption /
//! verification path on the stored outputs. Run with `KLAV_REGEN_VECTORS=1`
//! to rewrite the files after an intentional format change.

use std::convert::Infallible;
use std::path::PathBuf;

use hpke::rand_core::{TryCryptoRng, TryRng};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::attachment;
use super::context::{AttachmentContext, ItemContext, ProjectContext, VaultContext};
use super::encoding::{Kind, aad};
use super::identity::{self, IdentityKeyPair, PublicIdentity};
use super::item::{self, Section};
use super::kdf::{self, KdfParams, MasterPassword};
use super::keys::{AttachmentKey, ItemKey, Kek, LocalKey, ProjectKey, VaultKey, sealed::Sealed};
use super::secret_key::SecretKey;
use super::{aead, agent, keystore, local, meta, passkey, record, sandbox, share, sign, wrap};
use crate::ids::{
    AccountId, AgentId, ApprovalId, AttachmentId, DeviceId, ItemId, ProjectId, SandboxId, TaskId,
    VaultId,
};
use crate::policy::Permission;
use crate::task;

// ---------------------------------------------------------------- helpers --

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectores")
}

/// Deterministic pseudo-random bytes for vector inputs: SHA-256 chain of a label.
fn det<const N: usize>(label: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let mut block = Sha256::digest(format!("klav test vector: {label}").as_bytes());
    for chunk in out.chunks_mut(32) {
        chunk.copy_from_slice(&block[..chunk.len()]);
        block = Sha256::digest(block);
    }
    out
}

fn hx(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn bytes(case: &Value, key: &str) -> Vec<u8> {
    let s = case[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing hex field {key}"));
    hex::decode(s).unwrap_or_else(|_| panic!("field {key} is not hex"))
}

fn array<const N: usize>(case: &Value, key: &str) -> [u8; N] {
    bytes(case, key)
        .try_into()
        .unwrap_or_else(|_| panic!("field {key} must be {N} bytes"))
}

fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn number(case: &Value, key: &str) -> u64 {
    case[key]
        .as_u64()
        .unwrap_or_else(|| panic!("missing number field {key}"))
}

fn item_ctx(case: &Value) -> ItemContext {
    ItemContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        vault: VaultId::from_bytes(array(case, "vault_id")),
        project: ProjectId::from_bytes(array(case, "project_id")),
        item: ItemId::from_bytes(array(case, "item_id")),
    }
}

/// An RNG that replays fixed bytes, used to make HPKE encapsulation
/// deterministic (the ephemeral key is `DeriveKeyPair(ikmE)`).
struct FixedRng(Vec<u8>);

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        assert!(dst.len() <= self.0.len(), "FixedRng exhausted");
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

/// Merges `outputs` into a copy of `inputs`.
fn with_outputs(inputs: &Value, outputs: Value) -> Value {
    let mut case = inputs.clone();
    for (k, v) in outputs.as_object().expect("outputs object") {
        case[k] = v.clone();
    }
    case
}

/// A vector file: metadata, the case inputs, how to compute outputs, and the
/// extra checks (decryption, verification) to run on stored cases.
struct VectorFile {
    name: &'static str,
    description: &'static str,
    spec: &'static str,
    inputs: fn() -> Vec<Value>,
    compute: fn(&Value) -> Value,
    check: fn(&Value),
}

// -------------------------------------------------------------- secret key --

fn secret_key_inputs() -> Vec<Value> {
    vec![
        json!({"name": "zeros", "key": hx(&[0u8; 16])}),
        json!({"name": "ones", "key": hx(&[0xFFu8; 16])}),
        json!({"name": "pseudo-random", "key": hx(&det::<16>("secret-key"))}),
    ]
}

fn secret_key_compute(case: &Value) -> Value {
    let key = SecretKey::from_bytes(array(case, "key"));
    let mut tuple = super::encoding::Tuple::new(super::secret_key::CHECKSUM_LABEL);
    tuple.push(key.bytes());
    let checksum = &Sha256::digest(tuple.as_bytes())[..4];
    json!({"checksum": hx(checksum), "text": key.to_text().expose_secret()})
}

fn secret_key_check(case: &Value) {
    let parsed = SecretKey::parse(text(case, "text")).expect("stored Secret Key parses");
    assert_eq!(parsed.bytes(), &array::<16>(case, "key"));
}

// --------------------------------------------------------------------- kdf --

fn kdf_inputs() -> Vec<Value> {
    let sk_text = SecretKey::from_bytes(det("kdf secret key"))
        .to_text()
        .expose_secret()
        .to_string();
    vec![
        json!({
            "name": "reduced-params-ascii",
            "note": "Parámetros reducidos (solo pruebas): m=64 KiB, t=1, p=1.",
            "password": "correct horse battery staple",
            "secret_key_text": sk_text,
            "m_kib": 64, "t": 1, "p": 1,
            "salt": hx(&det::<16>("kdf salt 1")),
        }),
        json!({
            "name": "reduced-params-nfkd",
            "note": "Contraseña con é precompuesta (U+00E9) y ligadura ﬁ (U+FB01); NFKD las descompone.",
            "password": "caf\u{e9} \u{fb01}esta",
            "secret_key_text": sk_text,
            "m_kib": 128, "t": 2, "p": 2,
            "salt": hx(&det::<16>("kdf salt 2")),
        }),
        json!({
            "name": "production-params",
            "note": "Parámetros de producción v1: m=256 MiB, t=3, p=4.",
            "password": "correct horse battery staple",
            "secret_key_text": sk_text,
            "m_kib": KdfParams::DEFAULT_M_KIB, "t": KdfParams::DEFAULT_T, "p": KdfParams::DEFAULT_P,
            "salt": hx(&det::<16>("kdf salt 3")),
        }),
    ]
}

fn kdf_params(case: &Value) -> KdfParams {
    let n = |k| u32::try_from(number(case, k)).expect("u32");
    KdfParams::insecure_for_tests(n("m_kib"), n("t"), n("p"), array(case, "salt"))
}

fn kdf_compute(case: &Value) -> Value {
    let params = kdf_params(case);
    let password = MasterPassword::new(text(case, "password"));
    let sk = SecretKey::parse(text(case, "secret_key_text")).expect("valid Secret Key");
    let parts = kdf::derive_parts(&password, &sk, &params).expect("KDF runs");
    use unicode_normalization::UnicodeNormalization;
    let nfkd: String = text(case, "password").nfkd().collect();
    json!({
        "secret_key": hx(sk.bytes()),
        "password_nfkd_utf8": hx(nfkd.as_bytes()),
        "params_encoded": hx(&params.encode()),
        "argon2id": hx(parts.argon2.as_ref()),
        "secret_key_hkdf": hx(parts.secret_key.as_ref()),
        "kek": hx(parts.kek.as_ref()),
        "opaque_input": hx(parts.opaque.as_ref()),
    })
}

fn kdf_check(case: &Value) {
    let decoded = KdfParams::decode_insecure_for_tests(&bytes(case, "params_encoded"))
        .expect("params decode");
    assert_eq!(decoded, kdf_params(case));
    let production = KdfParams::decode(&bytes(case, "params_encoded"));
    assert_eq!(
        production.is_ok(),
        text(case, "name") == "production-params"
    );
}

// ---------------------------------------------------------------- identity --

fn identity_inputs() -> Vec<Value> {
    vec![json!({
        "name": "account-identity",
        "x25519_seed": hx(&det::<32>("identity x25519")),
        "ed25519_seed": hx(&det::<32>("identity ed25519")),
        "account_id": hx(&det::<16>("account")),
        "kek": hx(&det::<32>("kek")),
        "nonce": hx(&det::<24>("identity nonce")),
    })]
}

fn identity_compute(case: &Value) -> Value {
    let keys = IdentityKeyPair::from_secret_bytes(
        &array(case, "x25519_seed"),
        &array(case, "ed25519_seed"),
    );
    let account = AccountId::from_bytes(array(case, "account_id"));
    let kek = Kek::from_bytes(array(case, "kek"));
    let public = keys.public().encode();
    let mut tuple = super::encoding::Tuple::new(identity::LABEL_SECRETS);
    tuple.push(account.as_bytes()).push(&public);
    json!({
        "x25519_private_clamped": hx(&keys.hpke_private_key_bytes()),
        "public_identity": hx(&public),
        "fingerprint": hx(&keys.public().fingerprint()),
        "aad": hx(&aad(&Kind::IdentitySecrets.header(), &tuple)),
        "sealed": hx(&identity::seal_identity_with_nonce(&kek, account, &keys, &array(case, "nonce"))),
    })
}

fn identity_check(case: &Value) {
    let public =
        PublicIdentity::decode(&bytes(case, "public_identity")).expect("public identity decodes");
    let kek = Kek::from_bytes(array(case, "kek"));
    let account = AccountId::from_bytes(array(case, "account_id"));
    let keys = identity::open_identity(&kek, account, &public, &bytes(case, "sealed"))
        .expect("identity opens");
    assert_eq!(keys.public(), &public);
}

// -------------------------------------------------------------------- wrap --

fn wrap_inputs() -> Vec<Value> {
    let ids = json!({
        "account_id": hx(&det::<16>("account")),
        "vault_id": hx(&det::<16>("vault")),
        "project_id": hx(&det::<16>("project")),
        "item_id": hx(&det::<16>("item")),
        "attachment_id": hx(&det::<16>("attachment")),
    });
    ["project-key", "item-key", "attachment-key"]
        .into_iter()
        .map(|kind| {
            with_outputs(
                &ids,
                json!({
                    "name": kind,
                    "wrapping_key": hx(&det::<32>(&format!("{kind} wrapping key"))),
                    "key": hx(&det::<32>(&format!("{kind} key"))),
                    "nonce": hx(&det::<24>(&format!("{kind} nonce"))),
                }),
            )
        })
        .collect()
}

fn wrap_parts(case: &Value) -> (Kind, super::encoding::Tuple) {
    let ctx = item_ctx(case);
    match text(case, "name") {
        "project-key" => (
            Kind::ProjectKeyWrap,
            wrap::project_tuple(&ctx.project_context()),
        ),
        "item-key" => (Kind::ItemKeyWrap, wrap::item_tuple(&ctx)),
        "attachment-key" => (
            Kind::AttachmentKeyWrap,
            wrap::attachment_tuple(
                &ctx.attachment(AttachmentId::from_bytes(array(case, "attachment_id"))),
            ),
        ),
        other => panic!("unknown wrap case {other}"),
    }
}

fn wrap_compute(case: &Value) -> Value {
    let (kind, tuple) = wrap_parts(case);
    let blob = aead::seal_with_nonce(
        &array(case, "wrapping_key"),
        kind,
        &tuple,
        &array(case, "nonce"),
        &bytes(case, "key"),
    );
    json!({"aad": hx(&aad(&kind.header(), &tuple)), "wrapped": hx(&blob)})
}

fn wrap_check(case: &Value) {
    let ctx = item_ctx(case);
    let blob = bytes(case, "wrapped");
    let wrapping = array::<32>(case, "wrapping_key");
    let unwrapped: [u8; 32] = match text(case, "name") {
        "project-key" => *wrap::unwrap_project_key(
            &VaultKey::from_bytes(wrapping),
            &ctx.project_context(),
            &blob,
        )
        .expect("unwraps")
        .secret_bytes(),
        "item-key" => *wrap::unwrap_item_key(&ProjectKey::from_bytes(wrapping), &ctx, &blob)
            .expect("unwraps")
            .secret_bytes(),
        _ => *wrap::unwrap_attachment_key(
            &ItemKey::from_bytes(wrapping),
            &ctx.attachment(AttachmentId::from_bytes(array(case, "attachment_id"))),
            &blob,
        )
        .expect("unwraps")
        .secret_bytes(),
    };
    assert_eq!(unwrapped, array::<32>(case, "key"));
}

// -------------------------------------------------------------------- item --

fn item_inputs() -> Vec<Value> {
    let base = json!({
        "account_id": hx(&det::<16>("account")),
        "vault_id": hx(&det::<16>("vault")),
        "project_id": hx(&det::<16>("project")),
        "item_id": hx(&det::<16>("item")),
        "item_key": hx(&det::<32>("item key")),
    });
    vec![
        with_outputs(
            &base,
            json!({
                "name": "overview-v1",
                "section": "overview",
                "version": 1,
                "nonce": hx(&det::<24>("overview nonce")),
                "plaintext": r#"{"v":1,"kind":"login","title":"GitHub","urls":["https://github.com"],"username":"omar"}"#,
            }),
        ),
        with_outputs(
            &base,
            json!({
                "name": "details-v7",
                "section": "details",
                "version": 7,
                "nonce": hx(&det::<24>("details nonce")),
                "plaintext": format!(
                    r#"{{"v":1,"kind":"login","fields":[{{"id":"{}","name":"password","label":"Password","type":"password","value":"hunter2"}}]}}"#,
                    crate::ids::FieldId::from_bytes(det("field"))
                ),
            }),
        ),
    ]
}

fn section(case: &Value) -> Section {
    match text(case, "section") {
        "overview" => Section::Overview,
        "details" => Section::Details,
        other => panic!("unknown section {other}"),
    }
}

fn item_compute(case: &Value) -> Value {
    let key = ItemKey::from_bytes(array(case, "item_key"));
    let ctx = item_ctx(case);
    let version = number(case, "version");
    let tuple = item::item_tuple(section(case), &ctx, version);
    let kind = match section(case) {
        Section::Overview => Kind::ItemOverview,
        Section::Details => Kind::ItemDetails,
    };
    let blob = item::encrypt_item_section_with_nonce(
        &key,
        &ctx,
        version,
        section(case),
        &array(case, "nonce"),
        text(case, "plaintext").as_bytes(),
    );
    json!({"aad": hx(&aad(&kind.header(), &tuple)), "ciphertext": hx(&blob)})
}

fn item_check(case: &Value) {
    let key = ItemKey::from_bytes(array(case, "item_key"));
    let version = number(case, "version");
    let blob = bytes(case, "ciphertext");
    let plain = item::decrypt_item_section(&key, &item_ctx(case), version, section(case), &blob)
        .expect("decrypts");
    assert_eq!(&**plain, text(case, "plaintext").as_bytes());
    assert!(
        item::decrypt_item_section(&key, &item_ctx(case), version + 1, section(case), &blob)
            .is_err()
    );
}

// ------------------------------------------------------------------- share --

fn share_inputs() -> Vec<Value> {
    let base = json!({
        "account_id": hx(&det::<16>("account")),
        "vault_id": hx(&det::<16>("vault")),
        "project_id": hx(&det::<16>("project")),
        "recipient_x25519_seed": hx(&det::<32>("agent x25519")),
        "recipient_ed25519_seed": hx(&det::<32>("agent ed25519")),
    });
    vec![
        with_outputs(
            &base,
            json!({
                "name": "vault-key",
                "key": hx(&det::<32>("shared vault key")),
                "ikm_e": hx(&det::<32>("vault ikmE")),
            }),
        ),
        with_outputs(
            &base,
            json!({
                "name": "project-key",
                "key": hx(&det::<32>("shared project key")),
                "ikm_e": hx(&det::<32>("project ikmE")),
            }),
        ),
    ]
}

fn share_recipient(case: &Value) -> IdentityKeyPair {
    IdentityKeyPair::from_secret_bytes(
        &array(case, "recipient_x25519_seed"),
        &array(case, "recipient_ed25519_seed"),
    )
}

fn share_parts(case: &Value, recipient: &PublicIdentity) -> (Kind, super::encoding::Tuple) {
    let project = ProjectContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        vault: VaultId::from_bytes(array(case, "vault_id")),
        project: ProjectId::from_bytes(array(case, "project_id")),
    };
    match text(case, "name") {
        "vault-key" => (
            Kind::SharedVaultKey,
            share::vault_info(&project.vault_context(), recipient),
        ),
        _ => (
            Kind::SharedProjectKey,
            share::project_info(&project, recipient),
        ),
    }
}

fn share_compute(case: &Value) -> Value {
    let recipient = share_recipient(case);
    let (kind, info) = share_parts(case, recipient.public());
    let blob = share::seal_with_rng(
        recipient.public(),
        kind,
        &info,
        &array(case, "key"),
        &mut FixedRng(bytes(case, "ikm_e")),
    )
    .expect("HPKE seals");
    json!({
        "recipient_public_identity": hx(&recipient.public().encode()),
        "info": hx(info.as_bytes()),
        "aad": hx(&kind.header()),
        "shared": hx(&blob),
    })
}

fn share_check(case: &Value) {
    let recipient = share_recipient(case);
    let blob = bytes(case, "shared");
    let account = AccountId::from_bytes(array(case, "account_id"));
    let vault = VaultId::from_bytes(array(case, "vault_id"));
    let opened: [u8; 32] = if text(case, "name") == "vault-key" {
        *share::open_shared_vault_key(&recipient, &VaultContext { account, vault }, &blob)
            .expect("opens")
            .secret_bytes()
    } else {
        let ctx = ProjectContext {
            account,
            vault,
            project: ProjectId::from_bytes(array(case, "project_id")),
        };
        *share::open_shared_project_key(&recipient, &ctx, &blob)
            .expect("opens")
            .secret_bytes()
    };
    assert_eq!(opened, array::<32>(case, "key"));
}

// -------------------------------------------------------------- item grant --

/// The item key of a per-item grant (kind `0x23`, spec §8.2) and a signed
/// `v: 2` grant that carries it (spec §13.4, ADR 0036 §2).
fn item_grant_inputs() -> Vec<Value> {
    let ctx = ItemContext {
        account: AccountId::from_bytes(det::<16>("account")),
        vault: VaultId::from_bytes(det::<16>("vault")),
        project: ProjectId::from_bytes(det::<16>("project")),
        item: ItemId::from_bytes(det::<16>("item")),
    };
    let recipient =
        IdentityKeyPair::from_secret_bytes(&det::<32>("proxy x25519"), &det::<32>("proxy ed25519"));
    let key = det::<32>("shared item key");
    let ikm_e = det::<32>("item ikmE");
    let shared = share::seal_with_rng(
        recipient.public(),
        Kind::SharedItemKey,
        &share::item_info(&ctx, recipient.public()),
        &key,
        &mut FixedRng(ikm_e.to_vec()),
    )
    .expect("HPKE seals");
    let agent_id = det::<16>("proxy agent id");
    let item = ctx.item.to_string();
    let payload = json!({
        "v": 2,
        "account_id": ctx.account.to_string(),
        "agent_id": AgentId::from_bytes(agent_id).to_string(),
        "version": 1,
        "issued_at": 1_800_000_000_000u64,
        "policy": {
            "rules": [
                {
                    "permission": "proxy",
                    "effect": "allow",
                    "scope": {
                        "domains": ["backboard.railway.app"],
                        "items": [item],
                        "methods": ["POST"],
                        "path_prefixes": ["/graphql"]
                    }
                },
                { "permission": "reveal", "effect": "deny" },
                { "permission": "inject", "effect": "deny" },
                { "permission": "fill", "effect": "deny" }
            ]
        },
        "projects": [],
        "items": [{
            "vault_id": ctx.vault.to_string(),
            "owner_account_id": ctx.account.to_string(),
            "project_id": ctx.project.to_string(),
            "item_id": item,
            "shared_key": data_encoding::BASE64URL_NOPAD.encode(&shared),
        }],
        "profiles": [{
            "name": "railway",
            "item_id": item,
            "field": "password",
            "header": "authorization",
            "prefix": "Bearer ",
            "upstream": "https://backboard.railway.app",
            "rate_per_minute": 30
        }]
    });
    vec![json!({
        "name": "item-grant",
        "account_id": hx(ctx.account.as_bytes()),
        "vault_id": hx(ctx.vault.as_bytes()),
        "project_id": hx(ctx.project.as_bytes()),
        "item_id": hx(ctx.item.as_bytes()),
        "agent_id": hx(&agent_id),
        "recipient_x25519_seed": hx(&det::<32>("proxy x25519")),
        "recipient_ed25519_seed": hx(&det::<32>("proxy ed25519")),
        "account_x25519_seed": hx(&det::<32>("identity x25519")),
        "account_ed25519_seed": hx(&det::<32>("identity ed25519")),
        "key": hx(&key),
        "ikm_e": hx(&ikm_e),
        "grant_payload": serde_json::to_string(&payload).expect("serializes"),
    })]
}

fn item_grant_parts(case: &Value) -> (IdentityKeyPair, IdentityKeyPair, ItemContext) {
    (
        IdentityKeyPair::from_secret_bytes(
            &array(case, "recipient_x25519_seed"),
            &array(case, "recipient_ed25519_seed"),
        ),
        agent_keys(case, "account"),
        item_ctx(case),
    )
}

fn item_grant_compute(case: &Value) -> Value {
    let (recipient, account, ctx) = item_grant_parts(case);
    let info = share::item_info(&ctx, recipient.public());
    let blob = share::seal_with_rng(
        recipient.public(),
        Kind::SharedItemKey,
        &info,
        &array(case, "key"),
        &mut FixedRng(bytes(case, "ikm_e")),
    )
    .expect("HPKE seals");
    let grant = agent::GrantToSign {
        account: ctx.account,
        agent: AgentId::from_bytes(array(case, "agent_id")),
        agent_public: recipient.public(),
        payload: text(case, "grant_payload").as_bytes(),
    };
    json!({
        "recipient_public_identity": hx(&recipient.public().encode()),
        "account_public_identity": hx(&account.public().encode()),
        "info": hx(info.as_bytes()),
        "aad": hx(&Kind::SharedItemKey.header()),
        "shared": hx(&blob),
        "grant_message": hx(
            &sign::signed_message(agent::LABEL_GRANT, &agent::refs(&grant.fields()))
                .expect("valid label"),
        ),
        "grant_signature": hx(&agent::sign_grant(&account, &grant).to_bytes()),
    })
}

fn item_grant_check(case: &Value) {
    let (recipient, account, ctx) = item_grant_parts(case);
    let blob = bytes(case, "shared");
    assert_eq!(blob.len(), 82);
    assert_eq!(&blob[..2], &[0x01, 0x23]);
    let opened = share::open_shared_item_key(&recipient, &ctx, &blob).expect("opens");
    assert_eq!(opened.secret_bytes(), &array::<32>(case, "key"));
    // Only for this item, and never read as a project key.
    let other = ItemContext {
        item: ItemId::from_bytes(det::<16>("another item")),
        ..ctx
    };
    assert!(share::open_shared_item_key(&recipient, &other, &blob).is_err());
    assert!(
        share::open_shared_project_key(
            &recipient,
            &ProjectContext {
                account: ctx.account,
                vault: ctx.vault,
                project: ctx.project,
            },
            &blob
        )
        .is_err()
    );
    // The payload carries this very blob, and the account signed it.
    let payload: Value = serde_json::from_str(text(case, "grant_payload")).expect("payload");
    assert_eq!(payload["v"], 2);
    assert_eq!(
        payload["items"][0]["shared_key"],
        Value::String(data_encoding::BASE64URL_NOPAD.encode(&blob))
    );
    let grant = agent::GrantToSign {
        account: ctx.account,
        agent: AgentId::from_bytes(array(case, "agent_id")),
        agent_public: recipient.public(),
        payload: text(case, "grant_payload").as_bytes(),
    };
    agent::verify_grant(
        account.public(),
        &grant,
        &sign::Signature::from_bytes(array(case, "grant_signature")),
    )
    .expect("grant");
}

// ---------------------------------------------------------- sandbox grant --

/// Grants `v: 3` (spec §13.4, ADR 0036 §3–§4): the proxy's, with an issuer
/// in `issuers`, and the issuer's, with `sandbox` and no projects. Both
/// signed by the account like any grant.
fn sandbox_grant_inputs() -> Vec<Value> {
    let account = AccountId::from_bytes(det::<16>("account"));
    let proxy_id = AgentId::from_bytes(det::<16>("proxy agent id"));
    let issuer_id = AgentId::from_bytes(det::<16>("issuer agent id"));
    let public = |who: &str| {
        IdentityKeyPair::from_secret_bytes(
            &det::<32>(&format!("{who} x25519")),
            &det::<32>(&format!("{who} ed25519")),
        )
        .public()
        .encode()
    };
    let b64 = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let item = ItemId::from_bytes(det::<16>("item")).to_string();
    let proxy_payload = json!({
        "v": 3,
        "account_id": account.to_string(),
        "agent_id": proxy_id.to_string(),
        "version": 2,
        "issued_at": 1_800_000_060_000u64,
        "policy": {
            "rules": [
                {
                    "permission": "proxy",
                    "effect": "allow",
                    "scope": {
                        "domains": ["backboard.railway.app"],
                        "items": [item],
                        "methods": ["POST"],
                        "path_prefixes": ["/graphql"]
                    }
                },
                { "permission": "reveal", "effect": "deny" },
                { "permission": "inject", "effect": "deny" },
                { "permission": "fill", "effect": "deny" }
            ]
        },
        "projects": [],
        "items": [{
            "vault_id": VaultId::from_bytes(det::<16>("vault")).to_string(),
            "owner_account_id": account.to_string(),
            "project_id": ProjectId::from_bytes(det::<16>("project")).to_string(),
            "item_id": item,
            "shared_key": b64(&det::<82>("a shared item key blob")),
        }],
        "profiles": [{
            "name": "railway",
            "item_id": item,
            "header": "authorization",
            "prefix": "Bearer ",
            "upstream": "https://backboard.railway.app"
        }],
        "issuers": [{
            "agent_id": issuer_id.to_string(),
            "public_identity": b64(&public("issuer")),
            "profiles": ["railway"],
            "max_ttl_secs": 28_800,
            "max_live": 3
        }]
    });
    let issuer_payload = json!({
        "v": 3,
        "account_id": account.to_string(),
        "agent_id": issuer_id.to_string(),
        "version": 1,
        "issued_at": 1_800_000_000_000u64,
        "policy": { "rules": [] },
        "projects": [],
        "sandbox": {
            "proxy": {
                "agent_id": proxy_id.to_string(),
                "public_identity": b64(&public("proxy")),
                "url": "tls://proxy.example.com:8443"
            }
        }
    });
    [
        ("proxy-with-issuer", "proxy", proxy_id, proxy_payload),
        ("issuer", "issuer", issuer_id, issuer_payload),
    ]
    .into_iter()
    .map(|(name, who, id, payload)| {
        json!({
            "name": name,
            "account_id": hx(account.as_bytes()),
            "agent_id": hx(id.as_bytes()),
            "agent_x25519_seed": hx(&det::<32>(&format!("{who} x25519"))),
            "agent_ed25519_seed": hx(&det::<32>(&format!("{who} ed25519"))),
            "account_x25519_seed": hx(&det::<32>("identity x25519")),
            "account_ed25519_seed": hx(&det::<32>("identity ed25519")),
            "grant_payload": serde_json::to_string(&payload).expect("serializes"),
        })
    })
    .collect()
}

fn sandbox_grant_parts(case: &Value) -> (IdentityKeyPair, IdentityKeyPair, AccountId, AgentId) {
    (
        agent_keys(case, "agent"),
        agent_keys(case, "account"),
        AccountId::from_bytes(array(case, "account_id")),
        AgentId::from_bytes(array(case, "agent_id")),
    )
}

fn sandbox_grant_compute(case: &Value) -> Value {
    let (agent_keys, account_keys, account, agent) = sandbox_grant_parts(case);
    let grant = agent::GrantToSign {
        account,
        agent,
        agent_public: agent_keys.public(),
        payload: text(case, "grant_payload").as_bytes(),
    };
    json!({
        "agent_public_identity": hx(&agent_keys.public().encode()),
        "account_public_identity": hx(&account_keys.public().encode()),
        "grant_message": hx(
            &sign::signed_message(agent::LABEL_GRANT, &agent::refs(&grant.fields()))
                .expect("valid label"),
        ),
        "grant_signature": hx(&agent::sign_grant(&account_keys, &grant).to_bytes()),
    })
}

fn sandbox_grant_check(case: &Value) {
    let (agent_keys, account_keys, account, agent) = sandbox_grant_parts(case);
    let payload: Value = serde_json::from_str(text(case, "grant_payload")).expect("payload");
    assert_eq!(payload["v"], 3);
    assert!(payload.get("issuers").is_some() || payload.get("sandbox").is_some());
    let grant = agent::GrantToSign {
        account,
        agent,
        agent_public: agent_keys.public(),
        payload: text(case, "grant_payload").as_bytes(),
    };
    agent::verify_grant(
        account_keys.public(),
        &grant,
        &sign::Signature::from_bytes(array(case, "grant_signature")),
    )
    .expect("grant");
    // Bound to its agent: the same bytes for another agent do not verify.
    let other = agent::GrantToSign {
        agent: AgentId::from_bytes(det::<16>("another agent")),
        ..grant
    };
    assert!(
        agent::verify_grant(
            account_keys.public(),
            &other,
            &sign::Signature::from_bytes(array(case, "grant_signature")),
        )
        .is_err()
    );
}

// ---------------------------------------------------------- sandbox events --

/// The proxy's requests for a sandbox's life (ADR 0036 §9, E3.3, spec
/// §13.3 and §13.7): `sandbox.issued`, `sandbox.claimed` and
/// `sandbox.revoked`. Each is an ordinary signed agent request whose body
/// the log keeps; `channel_key_sha256` is `channel_key_digest` of the
/// channel's Ed25519 key.
fn sandbox_event_inputs() -> Vec<Value> {
    let sandbox = crate::ids::SandboxId::from_bytes(det::<16>("sandbox id"));
    let issuer = AgentId::from_bytes(det::<16>("issuer agent id"));
    let channel = IdentityKeyPair::from_secret_bytes(
        &det::<32>("channel x25519"),
        &det::<32>("channel ed25519"),
    );
    let channel_digest = sandbox::channel_key_digest(channel.public().ed25519());
    let b64 = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let issued = json!({
        "sandbox_id": sandbox.to_string(),
        "issuer_id": issuer.to_string(),
        "label": "chat-123",
        "profiles": ["railway"],
        "expires_at": 1_800_028_800_000u64,
    });
    let claimed = json!({ "channel_key_sha256": b64(&channel_digest) });
    let revoked = json!({ "reason": "stop" });
    [
        (
            "issued",
            "/v1/agent/sandboxes".to_owned(),
            issued,
            1_800_000_000_000u64,
        ),
        (
            "claimed",
            format!("/v1/agent/sandboxes/{sandbox}/claimed"),
            claimed,
            1_800_000_060_000,
        ),
        (
            "revoked",
            format!("/v1/agent/sandboxes/{sandbox}/revoked"),
            revoked,
            1_800_000_120_000,
        ),
    ]
    .into_iter()
    .map(|(name, path, body, ts)| {
        json!({
            "name": name,
            "proxy_agent_id": hx(&det::<16>("proxy agent id")),
            "proxy_x25519_seed": hx(&det::<32>("proxy x25519")),
            "proxy_ed25519_seed": hx(&det::<32>("proxy ed25519")),
            "channel_ed25519_public": hx(channel.public().ed25519()),
            "method": "POST",
            "path": path,
            "timestamp_ms": ts,
            "nonce": hx(&det::<16>(&format!("sandbox {name} nonce"))),
            "body": serde_json::to_string(&body).expect("serializes"),
        })
    })
    .collect()
}

fn sandbox_event_parts(case: &Value) -> (IdentityKeyPair, AgentId, [u8; 16], [u8; 32]) {
    (
        agent_keys(case, "proxy"),
        AgentId::from_bytes(array(case, "proxy_agent_id")),
        array(case, "nonce"),
        agent::body_digest(text(case, "body").as_bytes()),
    )
}

fn sandbox_event_request<'a>(
    case: &'a Value,
    proxy: AgentId,
    nonce: &'a [u8; 16],
    digest: &'a [u8; 32],
) -> agent::SignedRequest<'a> {
    agent::SignedRequest {
        agent: proxy,
        method: text(case, "method"),
        path: text(case, "path"),
        timestamp_ms: case["timestamp_ms"].as_u64().expect("timestamp"),
        nonce,
        body_digest: digest,
    }
}

fn sandbox_event_compute(case: &Value) -> Value {
    let (keys, proxy, nonce, digest) = sandbox_event_parts(case);
    let request = sandbox_event_request(case, proxy, &nonce, &digest);
    json!({
        "proxy_public_identity": hx(&keys.public().encode()),
        "channel_key_sha256": hx(&sandbox::channel_key_digest(
            &array(case, "channel_ed25519_public"),
        )),
        "body_sha256": hx(&digest),
        "request_message": hx(
            &sign::signed_message(agent::LABEL_REQUEST, &agent::refs(&request.fields()))
                .expect("valid label"),
        ),
        "request_signature": hx(&agent::sign_request(&keys, &request).to_bytes()),
    })
}

fn sandbox_event_check(case: &Value) {
    let (keys, proxy, nonce, digest) = sandbox_event_parts(case);
    let request = sandbox_event_request(case, proxy, &nonce, &digest);
    let sig = sign::Signature::from_bytes(array(case, "request_signature"));
    agent::verify_request(keys.public(), &request, &sig).expect("request");
    // The body is covered: another reason does not verify.
    let other = agent::body_digest(br#"{"reason":"theft"}"#);
    let moved = agent::SignedRequest {
        body_digest: &other,
        ..request
    };
    assert!(agent::verify_request(keys.public(), &moved, &sig).is_err());
    // The digest of the channel key is the one the claim's body carries.
    let body: Value = serde_json::from_str(text(case, "body")).expect("body");
    if let Some(sent) = body.get("channel_key_sha256") {
        let sent = data_encoding::BASE64URL_NOPAD
            .decode(sent.as_str().expect("text").as_bytes())
            .expect("base64url");
        assert_eq!(
            sent,
            hex::decode(text(case, "channel_key_sha256")).expect("hex")
        );
    }
}

// ------------------------------------------------------ sandbox heartbeat --

/// The proxy's new store epoch (`sandbox.store_reset`) and its heartbeat
/// (ADR 0036 E3.3, spec §13.12): two more signed requests (§13.3), with
/// their bodies. The heartbeat carries the epoch the reset logged.
fn sandbox_heartbeat_inputs() -> Vec<Value> {
    let b64 = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let epoch = det::<16>("store epoch");
    let sandbox = crate::ids::SandboxId::from_bytes(det::<16>("sandbox id"));
    let reset = json!({ "store_epoch": b64(&epoch) });
    let heartbeat = json!({
        "v": 1,
        "store_epoch": b64(&epoch),
        "seq": 1,
        "sent_at_ms": 1_800_000_300_000u64,
        "sandboxes": [
            { "id": sandbox.to_string(), "connected": true, "last_seen_at": 1_800_000_290_000u64 }
        ],
    });
    [
        (
            "store_reset",
            "POST",
            "/v1/agent/sandboxes/epochs",
            reset,
            1_800_000_240_000u64,
        ),
        (
            "heartbeat",
            "PUT",
            "/v1/agent/sandboxes/state",
            heartbeat,
            1_800_000_300_000,
        ),
    ]
    .into_iter()
    .map(|(name, method, path, body, ts)| {
        json!({
            "name": name,
            "proxy_agent_id": hx(&det::<16>("proxy agent id")),
            "proxy_x25519_seed": hx(&det::<32>("proxy x25519")),
            "proxy_ed25519_seed": hx(&det::<32>("proxy ed25519")),
            "method": method,
            "path": path,
            "timestamp_ms": ts,
            "nonce": hx(&det::<16>(&format!("sandbox {name} nonce"))),
            "body": serde_json::to_string(&body).expect("serializes"),
        })
    })
    .collect()
}

fn sandbox_heartbeat_compute(case: &Value) -> Value {
    let (keys, proxy, nonce, digest) = sandbox_event_parts(case);
    let request = sandbox_event_request(case, proxy, &nonce, &digest);
    json!({
        "proxy_public_identity": hx(&keys.public().encode()),
        "body_sha256": hx(&digest),
        "request_message": hx(
            &sign::signed_message(agent::LABEL_REQUEST, &agent::refs(&request.fields()))
                .expect("valid label"),
        ),
        "request_signature": hx(&agent::sign_request(&keys, &request).to_bytes()),
    })
}

fn sandbox_heartbeat_check(case: &Value) {
    let (keys, proxy, nonce, digest) = sandbox_event_parts(case);
    let request = sandbox_event_request(case, proxy, &nonce, &digest);
    let sig = sign::Signature::from_bytes(array(case, "request_signature"));
    agent::verify_request(keys.public(), &request, &sig).expect("request");
    // The body is covered: another epoch or `seq` does not verify.
    let other = agent::body_digest(
        text(case, "body")
            .replace("\"seq\":1", "\"seq\":2")
            .as_bytes(),
    );
    let other = if other == digest {
        agent::body_digest(b"{}")
    } else {
        other
    };
    let moved = agent::SignedRequest {
        body_digest: &other,
        ..request
    };
    assert!(agent::verify_request(keys.public(), &moved, &sig).is_err());
    // So is the method: the same body under another verb does not verify.
    let moved = agent::SignedRequest {
        method: if text(case, "method") == "PUT" {
            "POST"
        } else {
            "PUT"
        },
        ..request
    };
    assert!(agent::verify_request(keys.public(), &moved, &sig).is_err());
}

// ----------------------------------------------------------------- sandbox --

/// The sandbox package (`ksb1_`, spec §13.10, ADR 0036 §4), the proxy pin
/// and the digest the proxy keeps instead of the secret.
fn sandbox_inputs() -> Vec<Value> {
    vec![json!({
        "name": "sandbox-package",
        "proxy_x25519_seed": hx(&det::<32>("proxy x25519")),
        "proxy_ed25519_seed": hx(&det::<32>("proxy ed25519")),
        "sandbox_id": hx(&det::<16>("sandbox id")),
        "secret": hx(&det::<32>("sandbox secret")),
        "expires_at_ms": 1_800_028_800_000u64,
        "url": "tls://proxy.example.com:8443",
    })]
}

fn sandbox_parts(case: &Value) -> (IdentityKeyPair, sandbox::SandboxPackage) {
    let proxy = IdentityKeyPair::from_secret_bytes(
        &array(case, "proxy_x25519_seed"),
        &array(case, "proxy_ed25519_seed"),
    );
    let package = sandbox::SandboxPackage {
        sandbox_id: SandboxId::from_bytes(array(case, "sandbox_id")),
        secret: sandbox::SandboxSecret::from_bytes(&array(case, "secret")),
        expires_at_ms: number(case, "expires_at_ms"),
        proxy_pin: sandbox::proxy_pin(proxy.public()),
        url: text(case, "url").to_owned(),
    };
    (proxy, package)
}

fn sandbox_compute(case: &Value) -> Value {
    let (proxy, package) = sandbox_parts(case);
    let text = sandbox::encode_package(&package).expect("encodes");
    let raw = data_encoding::BASE64URL_NOPAD
        .decode(
            text.strip_prefix(sandbox::PACKAGE_PREFIX)
                .expect("prefix")
                .as_bytes(),
        )
        .expect("base64url");
    let mut digest_input = super::encoding::Tuple::new(sandbox::LABEL_SECRET_DIGEST);
    digest_input
        .push(package.sandbox_id.as_bytes())
        .push(package.secret.expose());
    let enc = |b: &[u8]| {
        format!(
            "{}{}",
            sandbox::PACKAGE_PREFIX,
            data_encoding::BASE64URL_NOPAD.encode(b)
        )
    };
    let mut other_version = raw.clone();
    other_version[0] = 0x02;
    let mut trailing = raw.clone();
    trailing.push(0x00);
    let mut zero_expiry = raw.clone();
    zero_expiry[49..57].copy_from_slice(&[0; 8]);
    let mut long_len = raw.clone();
    long_len[89..93].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut bad_scheme = raw[..89].to_vec();
    let https = b"https://proxy.example.com:8443";
    bad_scheme.extend_from_slice(&u32::try_from(https.len()).expect("short").to_be_bytes());
    bad_scheme.extend_from_slice(https);
    json!({
        "proxy_public_identity": hx(&proxy.public().encode()),
        "proxy_spki": hx(&sandbox::ed25519_spki(proxy.public())),
        "proxy_pin": hx(&package.proxy_pin),
        "package_bytes": hx(&raw),
        "package": text.as_str(),
        "secret_digest_input": hx(digest_input.as_bytes()),
        "secret_digest": hx(&sandbox::secret_digest(package.sandbox_id, &package.secret)),
        "negative": [
            { "why": "another prefix", "package": format!("ksb2_{}", text.strip_prefix(sandbox::PACKAGE_PREFIX).expect("prefix")) },
            { "why": "another version", "package": enc(&other_version) },
            { "why": "trailing byte", "package": enc(&trailing) },
            { "why": "one byte short", "package": enc(&raw[..raw.len() - 1]) },
            { "why": "expiry 0", "package": enc(&zero_expiry) },
            { "why": "address length past the end", "package": enc(&long_len) },
            { "why": "address with another scheme", "package": enc(&bad_scheme) },
        ],
    })
}

fn sandbox_check(case: &Value) {
    let (proxy, _) = sandbox_parts(case);
    assert_eq!(
        sandbox::ed25519_spki(proxy.public()).to_vec(),
        bytes(case, "proxy_spki")
    );
    let package = sandbox::decode_package(text(case, "package")).expect("decodes");
    assert_eq!(
        package.sandbox_id.as_bytes(),
        &array::<16>(case, "sandbox_id")
    );
    assert_eq!(package.secret.expose(), &array::<32>(case, "secret"));
    assert_eq!(package.expires_at_ms, number(case, "expires_at_ms"));
    assert_eq!(package.proxy_pin, array::<32>(case, "proxy_pin"));
    assert_eq!(package.url, text(case, "url"));
    assert!(sandbox::secret_matches(
        &array(case, "secret_digest"),
        package.sandbox_id,
        &package.secret
    ));
    for bad in case["negative"].as_array().expect("negative cases") {
        assert!(
            sandbox::decode_package(text(bad, "package")).is_err(),
            "{}",
            text(bad, "why")
        );
    }
}

// ----------------------------------------------------- sandbox revocation --

/// The person's revocation of sandboxes (spec §13.11, ADR 0036 E3.3): one
/// sandbox, and every sandbox of the proxy.
fn sandbox_revoke_inputs() -> Vec<Value> {
    let base = json!({
        "account_x25519_seed": hx(&det::<32>("identity x25519")),
        "account_ed25519_seed": hx(&det::<32>("identity ed25519")),
        "account_id": hx(&det::<16>("account")),
        "proxy_agent_id": hx(&det::<16>("proxy agent id")),
        "at_ms": 1_800_000_000_000u64,
    });
    let with = |name: &str, scope: &str| {
        let mut case = base.clone();
        case["name"] = json!(name);
        case["scope"] = json!(scope);
        case
    };
    vec![
        with(
            "one-sandbox",
            hx(&det::<16>("sandbox id")).as_str().expect("hex"),
        ),
        with("all", "all"),
    ]
}

fn sandbox_revoke_parts(case: &Value) -> (IdentityKeyPair, sandbox::RevokeToSign) {
    let account = IdentityKeyPair::from_secret_bytes(
        &array(case, "account_x25519_seed"),
        &array(case, "account_ed25519_seed"),
    );
    let scope = match text(case, "scope") {
        "all" => sandbox::RevokeScope::All,
        _ => sandbox::RevokeScope::Sandbox(SandboxId::from_bytes(array(case, "scope"))),
    };
    let revoke = sandbox::RevokeToSign {
        account: AccountId::from_bytes(array(case, "account_id")),
        proxy: AgentId::from_bytes(array(case, "proxy_agent_id")),
        scope,
        at_ms: number(case, "at_ms"),
    };
    (account, revoke)
}

fn sandbox_revoke_compute(case: &Value) -> Value {
    let (account, revoke) = sandbox_revoke_parts(case);
    json!({
        "account_public_identity": hx(&account.public().encode()),
        "message": hx(&revoke.message()),
        "signature": hx(&sandbox::sign_revoke(&account, &revoke).to_bytes()),
    })
}

fn sandbox_revoke_check(case: &Value) {
    let (account, revoke) = sandbox_revoke_parts(case);
    let signature = sign::Signature::from_bytes(array(case, "signature"));
    sandbox::verify_revoke(account.public(), &revoke, &signature).expect("verifies");
    let other_scope = sandbox::RevokeToSign {
        scope: match revoke.scope {
            sandbox::RevokeScope::All => {
                sandbox::RevokeScope::Sandbox(SandboxId::from_bytes(det("sandbox id")))
            }
            sandbox::RevokeScope::Sandbox(_) => sandbox::RevokeScope::All,
        },
        ..revoke
    };
    assert!(sandbox::verify_revoke(account.public(), &other_scope, &signature).is_err());
    let later = sandbox::RevokeToSign {
        at_ms: revoke.at_ms + 1,
        ..revoke
    };
    assert!(sandbox::verify_revoke(account.public(), &later, &signature).is_err());
}

// --------------------------------------------------------- secret requests --

fn secret_request_inputs() -> Vec<Value> {
    let vault_id = VaultId::from_bytes(det("vault"));
    let project_id = ProjectId::from_bytes(det("project"));
    let item_id = ItemId::from_bytes(det("item"));
    let request_create = crate::ids::SecretRequestId::from_bytes(det("secret request create"));
    let request_outside = crate::ids::SecretRequestId::from_bytes(det("secret request outside"));
    let request_update = crate::ids::SecretRequestId::from_bytes(det("secret request update"));
    let agent_id = AgentId::from_bytes(det("agent id"));

    let create_proposal = serde_json::to_string(&crate::secret_request::SecretRequestProposal {
        v: 1,
        mode: crate::secret_request::SecretRequestMode::Create,
        kind: Some(crate::model::item::ItemKind::ApiKey),
        title: Some("Vercel AI Gateway".into()),
        vault_id: Some(vault_id),
        project_id: Some(project_id),
        target_item_id: None,
        field: "api_key".into(),
        placeholder: Some("vck_…".into()),
        setup_url: Some("https://vercel.com/dashboard/ai-gateway".into()),
        base_url: Some("https://ai-gateway.vercel.sh".into()),
        urls: Vec::new(),
        notes: Some("Used to generate narration".into()),
        proxy_proposal: Some(crate::secret_request::ProxyProposal {
            preset: None,
            profile: "vercel-ai".into(),
            upstream: "https://ai-gateway.vercel.sh".into(),
            header: "authorization".into(),
            prefix: "Bearer ".into(),
            methods: vec!["POST".into()],
            ask_methods: Vec::new(),
            path_prefixes: vec!["/v1".into()],
            rate_per_minute: Some(60),
        }),
    })
    .expect("proposal json");

    let create_decision_in_grant =
        serde_json::to_string(&crate::secret_request::SecretRequestDecision {
            v: 1,
            request_id: request_create,
            agent_id,
            status: crate::secret_request::SecretRequestStatus::Fulfilled,
            in_grant: true,
            vault_id: Some(vault_id),
            project_id: Some(project_id),
            item_id: Some(item_id),
            field: Some("api_key".into()),
            proxy_profile: Some("vercel-ai".into()),
        })
        .expect("decision json");

    let create_decision_outside_grant =
        serde_json::to_string(&crate::secret_request::SecretRequestDecision {
            v: 1,
            request_id: request_outside,
            agent_id,
            status: crate::secret_request::SecretRequestStatus::Fulfilled,
            in_grant: false,
            vault_id: None,
            project_id: None,
            item_id: None,
            field: Some("api_key".into()),
            proxy_profile: Some("vercel-ai".into()),
        })
        .expect("decision json");

    let update_proposal = serde_json::to_string(&crate::secret_request::SecretRequestProposal {
        v: 1,
        mode: crate::secret_request::SecretRequestMode::Update,
        kind: None,
        title: None,
        vault_id: None,
        project_id: None,
        target_item_id: Some(item_id),
        field: "api_key".into(),
        placeholder: None,
        setup_url: None,
        base_url: None,
        urls: Vec::new(),
        notes: None,
        proxy_proposal: None,
    })
    .expect("proposal json");

    let update_decision_denied =
        serde_json::to_string(&crate::secret_request::SecretRequestDecision {
            v: 1,
            request_id: request_update,
            agent_id,
            status: crate::secret_request::SecretRequestStatus::Denied,
            in_grant: false,
            vault_id: None,
            project_id: None,
            item_id: None,
            field: None,
            proxy_profile: None,
        })
        .expect("decision json");

    let base = json!({
        "account_x25519_seed": hx(&det::<32>("identity x25519")),
        "account_ed25519_seed": hx(&det::<32>("identity ed25519")),
        "account_id": hx(&det::<16>("account")),
        "agent_id": hx(agent_id.as_bytes()),
        "decided_at_ms": 1_800_000_000_500u64,
    });
    let make = |name: &str,
                req: crate::ids::SecretRequestId,
                ikm_label: &str,
                proposal: &str,
                decision: &str| {
        let mut c = base.clone();
        c["name"] = json!(name);
        c["request_id"] = json!(hx(req.as_bytes()));
        c["ikm_e"] = json!(hx(&det::<32>(ikm_label)));
        c["proposal"] = json!(proposal);
        c["decision"] = json!(decision);
        c
    };
    vec![
        make(
            "create-api-key-fulfilled-in-grant",
            request_create,
            "secret request ikm_e create",
            &create_proposal,
            &create_decision_in_grant,
        ),
        make(
            "create-api-key-fulfilled-outside-grant",
            request_outside,
            "secret request ikm_e outside",
            &create_proposal,
            &create_decision_outside_grant,
        ),
        make(
            "update-field-denied",
            request_update,
            "secret request ikm_e update",
            &update_proposal,
            &update_decision_denied,
        ),
    ]
}

fn secret_request_parts(
    case: &Value,
) -> (
    IdentityKeyPair,
    AccountId,
    AgentId,
    crate::ids::SecretRequestId,
) {
    let account = IdentityKeyPair::from_secret_bytes(
        &array(case, "account_x25519_seed"),
        &array(case, "account_ed25519_seed"),
    );
    let account_id = AccountId::from_bytes(array(case, "account_id"));
    let agent_id = AgentId::from_bytes(array(case, "agent_id"));
    let request_id = crate::ids::SecretRequestId::from_bytes(array(case, "request_id"));
    (account, account_id, agent_id, request_id)
}

fn secret_request_compute(case: &Value) -> Value {
    let (account, account_id, agent_id, request_id) = secret_request_parts(case);
    let proposal_bytes = text(case, "proposal").as_bytes();
    let decision_bytes = text(case, "decision").as_bytes();
    let digest = agent::body_digest(proposal_bytes);
    let blob = agent::seal_secret_request_with_rng(
        account.public(),
        account_id,
        agent_id,
        request_id,
        proposal_bytes,
        &mut FixedRng(bytes(case, "ikm_e")),
    )
    .expect("seal");
    let to_sign = agent::SecretRequestDecisionToSign {
        request: request_id,
        agent: agent_id,
        proposal_digest: &digest,
        decision: decision_bytes,
        decided_at_ms: number(case, "decided_at_ms"),
    };
    let sig = agent::sign_secret_request_decision(&account, &to_sign);
    json!({
        "account_public_identity": hx(&account.public().encode()),
        "proposal_digest": hx(&digest),
        "proposal_blob": hx(&blob),
        "decision_message": hx(&to_sign.message()),
        "decision_signature": hx(&sig.to_bytes()),
    })
}

fn secret_request_check(case: &Value) {
    let (account, account_id, agent_id, request_id) = secret_request_parts(case);
    let proposal_str = text(case, "proposal");
    let decision_str = text(case, "decision");
    let parsed_proposal: crate::secret_request::SecretRequestProposal =
        serde_json::from_str(proposal_str).expect("valid proposal json");
    parsed_proposal.validate().expect("valid proposal");
    let parsed_decision: crate::secret_request::SecretRequestDecision =
        serde_json::from_str(decision_str).expect("valid decision json");
    parsed_decision.validate().expect("valid decision");

    let blob = bytes(case, "proposal_blob");
    let opened = agent::open_secret_request(&account, account_id, agent_id, request_id, &blob)
        .expect("opens");
    assert_eq!(opened.as_slice(), proposal_str.as_bytes());
    let digest = array::<32>(case, "proposal_digest");
    assert_eq!(agent::body_digest(&opened), digest);

    // Tampering with the blob or context fails to open.
    let mut flipped = blob.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(
        agent::open_secret_request(&account, account_id, agent_id, request_id, &flipped).is_err()
    );
    assert!(
        agent::open_secret_request(
            &account,
            account_id,
            agent_id,
            crate::ids::SecretRequestId::from_bytes(det("other request")),
            &blob
        )
        .is_err()
    );

    let to_sign = agent::SecretRequestDecisionToSign {
        request: request_id,
        agent: agent_id,
        proposal_digest: &digest,
        decision: decision_str.as_bytes(),
        decided_at_ms: number(case, "decided_at_ms"),
    };
    let sig = sign::Signature::from_bytes(array(case, "decision_signature"));
    agent::verify_secret_request_decision(account.public(), &to_sign, &sig).expect("verifies");

    // Tampering with digest or timestamp fails verification.
    let mut bad_digest = digest;
    bad_digest[0] ^= 0x80;
    assert!(
        agent::verify_secret_request_decision(
            account.public(),
            &agent::SecretRequestDecisionToSign {
                proposal_digest: &bad_digest,
                ..to_sign
            },
            &sig,
        )
        .is_err()
    );
    assert!(
        agent::verify_secret_request_decision(
            account.public(),
            &agent::SecretRequestDecisionToSign {
                decided_at_ms: to_sign.decided_at_ms + 1,
                ..to_sign
            },
            &sig,
        )
        .is_err()
    );
}

// --------------------------------------------------------- vault-key sig --

fn vault_key_signature_inputs() -> Vec<Value> {
    vec![json!({
        "name": "owner-signs-shared-vault-key",
        "account_id": hx(&det::<16>("account")),
        "vault_id": hx(&det::<16>("vault")),
        "account_x25519_seed": hx(&det::<32>("account x25519")),
        "account_ed25519_seed": hx(&det::<32>("account ed25519")),
        "key": hx(&det::<32>("signed vault key")),
        "ikm_e": hx(&det::<32>("signed vault ikmE")),
    })]
}

fn vault_key_signature_parts(case: &Value) -> (IdentityKeyPair, VaultContext) {
    let account = IdentityKeyPair::from_secret_bytes(
        &array(case, "account_x25519_seed"),
        &array(case, "account_ed25519_seed"),
    );
    let ctx = VaultContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        vault: VaultId::from_bytes(array(case, "vault_id")),
    };
    (account, ctx)
}

fn vault_key_signature_compute(case: &Value) -> Value {
    let (account, ctx) = vault_key_signature_parts(case);
    let shared = share::seal_with_rng(
        account.public(),
        Kind::SharedVaultKey,
        &share::vault_info(&ctx, account.public()),
        &array(case, "key"),
        &mut FixedRng(bytes(case, "ikm_e")),
    )
    .expect("HPKE seals");
    let message = sign::signed_message(
        share::LABEL_VAULT_KEY_SIGNATURE,
        &[ctx.account.as_bytes(), ctx.vault.as_bytes(), &shared],
    )
    .expect("label");
    let signature = share::sign_vault_key(&account, &ctx, &shared).expect("signs");
    json!({
        "account_public_identity": hx(&account.public().encode()),
        "shared": hx(&shared),
        "message": hx(&message),
        "signature": hx(&signature.to_bytes()),
    })
}

fn vault_key_signature_check(case: &Value) {
    let (account, ctx) = vault_key_signature_parts(case);
    let public = PublicIdentity::decode(&bytes(case, "account_public_identity")).expect("decodes");
    let shared = bytes(case, "shared");
    let sig = sign::Signature::from_bytes(array(case, "signature"));
    share::verify_vault_key(&public, &ctx, &shared, &sig).expect("verifies");
    let opened = share::open_shared_vault_key(&account, &ctx, &shared).expect("opens");
    assert_eq!(*opened.secret_bytes(), array::<32>(case, "key"));
    // Any other blob for the same account and vault does not verify.
    let mut other = shared.clone();
    other[40] ^= 1;
    assert!(share::verify_vault_key(&public, &ctx, &other, &sig).is_err());
}

// ------------------------------------------------------------ RFC 9180 A.2 --

fn rfc9180_inputs() -> Vec<Value> {
    vec![json!({
        "name": "RFC 9180 A.2.1 (base), sequence 0",
        "ikm_e": "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
        "pk_rm": "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        "sk_rm": "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        "info": "4f6465206f6e2061204772656369616e2055726e",
        "pt": "4265617574792069732074727574682c20747275746820626561757479",
        "aad": "436f756e742d30",
    })]
}

fn rfc9180_compute(case: &Value) -> Value {
    let (enc, ct) = share::hpke_seal(
        &array(case, "pk_rm"),
        &bytes(case, "info"),
        &bytes(case, "aad"),
        &bytes(case, "pt"),
        &mut FixedRng(bytes(case, "ikm_e")),
    )
    .expect("HPKE seals");
    json!({"enc": hx(&enc), "ct": hx(&ct)})
}

fn rfc9180_check(case: &Value) {
    // Values copied from RFC 9180 (not generated by this code).
    assert_eq!(
        text(case, "enc"),
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
    );
    assert_eq!(
        text(case, "ct"),
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
    );
    use hpke::Deserializable;
    let sk = share::HpkePrivateKey::from_bytes(&bytes(case, "sk_rm")).expect("sk");
    let pt = share::hpke_open(
        &sk,
        &bytes(case, "enc"),
        &bytes(case, "info"),
        &bytes(case, "aad"),
        &bytes(case, "ct"),
    )
    .expect("opens");
    assert_eq!(*pt, bytes(case, "pt"));
}

// -------------------------------------------------------------- attachment --

fn attachment_inputs() -> Vec<Value> {
    let base = json!({
        "account_id": hx(&det::<16>("account")),
        "vault_id": hx(&det::<16>("vault")),
        "project_id": hx(&det::<16>("project")),
        "item_id": hx(&det::<16>("item")),
        "attachment_id": hx(&det::<16>("attachment")),
        "attachment_key": hx(&det::<32>("attachment key")),
        "chunk_size": 64,
    });
    [0usize, 64, 150]
        .into_iter()
        .map(|len| {
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            with_outputs(
                &base,
                json!({
                    "name": format!("{len}-bytes"),
                    "nonce_prefix": hx(&det::<19>(&format!("attachment prefix {len}"))),
                    "plaintext": hx(&plaintext),
                }),
            )
        })
        .collect()
}

fn attachment_ctx(case: &Value) -> AttachmentContext {
    item_ctx(case).attachment(AttachmentId::from_bytes(array(case, "attachment_id")))
}

fn attachment_compute(case: &Value) -> Value {
    let key = AttachmentKey::from_bytes(array(case, "attachment_key"));
    let ctx = attachment_ctx(case);
    let chunk_size = u32::try_from(number(case, "chunk_size")).expect("u32");
    let mut blob = Vec::new();
    attachment::encrypt_with(
        &key,
        &ctx,
        chunk_size,
        &array(case, "nonce_prefix"),
        &bytes(case, "plaintext")[..],
        &mut blob,
    )
    .expect("encrypts");
    let header: [u8; attachment::HEADER_LEN] =
        blob[..attachment::HEADER_LEN].try_into().expect("header");
    let mut tuple = super::encoding::Tuple::new(attachment::LABEL_ATTACHMENT);
    for id in [
        "account_id",
        "vault_id",
        "project_id",
        "item_id",
        "attachment_id",
    ] {
        tuple.push(&bytes(case, id));
    }
    json!({"aad": hx(&aad(&header, &tuple)), "ciphertext": hx(&blob)})
}

fn attachment_check(case: &Value) {
    let key = AttachmentKey::from_bytes(array(case, "attachment_key"));
    let plain = attachment::decrypt_attachment_bytes(
        &key,
        &attachment_ctx(case),
        &bytes(case, "ciphertext"),
    )
    .expect("decrypts");
    assert_eq!(*plain, bytes(case, "plaintext"));
}

// --------------------------------------------------------------- signature --

fn signature_inputs() -> Vec<Value> {
    vec![json!({
        "name": "two-fields",
        "x25519_seed": hx(&det::<32>("signer x25519")),
        "ed25519_seed": hx(&det::<32>("signer ed25519")),
        "label": "klav/v1/sig/test-vector",
        "fields": [hx(b"first field"), hx(&[0u8; 0]), hx(&det::<16>("signed id"))],
    })]
}

fn signature_fields(case: &Value) -> Vec<Vec<u8>> {
    case["fields"]
        .as_array()
        .expect("fields array")
        .iter()
        .map(|f| hex::decode(f.as_str().expect("hex")).expect("hex"))
        .collect()
}

fn signature_compute(case: &Value) -> Value {
    let keys = IdentityKeyPair::from_secret_bytes(
        &array(case, "x25519_seed"),
        &array(case, "ed25519_seed"),
    );
    let fields = signature_fields(case);
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let message = sign::signed_message(text(case, "label"), &refs).expect("label");
    let signature = sign::sign(&keys, text(case, "label"), &refs).expect("signs");
    json!({
        "public_identity": hx(&keys.public().encode()),
        "message": hx(&message),
        "signature": hx(&signature.to_bytes()),
    })
}

fn signature_check(case: &Value) {
    let public = PublicIdentity::decode(&bytes(case, "public_identity")).expect("decodes");
    let fields = signature_fields(case);
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    let sig = sign::Signature::from_bytes(array(case, "signature"));
    sign::verify(&public, text(case, "label"), &refs, &sig).expect("verifies");
}

// -------------------------------------------------------------------- meta --

fn meta_inputs() -> Vec<Value> {
    let ids = json!({
        "account_id": hx(&det::<16>("account")),
        "vault_id": hx(&det::<16>("vault")),
        "project_id": hx(&det::<16>("project")),
    });
    [
        ("vault-meta", r#"{"v":1,"name":"Trabajo"}"#, 1u64),
        (
            "project-meta",
            r#"{"v":1,"name":"acme-api","description":"API de Acme"}"#,
            2,
        ),
    ]
    .into_iter()
    .map(|(name, plaintext, version)| {
        with_outputs(
            &ids,
            json!({
                "name": name,
                "key": hx(&det::<32>(&format!("{name} key"))),
                "nonce": hx(&det::<24>(&format!("{name} nonce"))),
                "version": version,
                "plaintext": plaintext,
            }),
        )
    })
    .collect()
}

fn meta_parts(case: &Value) -> (Kind, super::encoding::Tuple) {
    let ctx = ProjectContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        vault: VaultId::from_bytes(array(case, "vault_id")),
        project: ProjectId::from_bytes(array(case, "project_id")),
    };
    let version = number(case, "version");
    match text(case, "name") {
        "vault-meta" => (
            Kind::VaultMeta,
            meta::vault_tuple(&ctx.vault_context(), version),
        ),
        "project-meta" => (Kind::ProjectMeta, meta::project_tuple(&ctx, version)),
        other => panic!("unknown meta case {other}"),
    }
}

fn meta_compute(case: &Value) -> Value {
    let (kind, tuple) = meta_parts(case);
    let blob = aead::seal_with_nonce(
        &array(case, "key"),
        kind,
        &tuple,
        &array(case, "nonce"),
        text(case, "plaintext").as_bytes(),
    );
    json!({"aad": hx(&aad(&kind.header(), &tuple)), "ciphertext": hx(&blob)})
}

fn meta_check(case: &Value) {
    let ctx = ProjectContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        vault: VaultId::from_bytes(array(case, "vault_id")),
        project: ProjectId::from_bytes(array(case, "project_id")),
    };
    let version = number(case, "version");
    let blob = bytes(case, "ciphertext");
    let plain = match text(case, "name") {
        "vault-meta" => meta::decrypt_vault_meta(
            &VaultKey::from_bytes(array(case, "key")),
            &ctx.vault_context(),
            version,
            &blob,
        ),
        _ => meta::decrypt_project_meta(
            &ProjectKey::from_bytes(array(case, "key")),
            &ctx,
            version,
            &blob,
        ),
    }
    .expect("metadata opens");
    assert_eq!(&*plain, text(case, "plaintext").as_bytes());
    crate::model::meta::Meta::decode(&plain).expect("valid metadata JSON");
}

// --------------------------------------------------------- password record --

fn record_inputs() -> Vec<Value> {
    vec![
        json!({
            "name": "password-record",
            "account_id": hx(&det::<16>("account")),
            "vault_id": hx(&det::<16>("vault")),
            "item_id": hx(&det::<16>("item")),
            "key": hx(&det::<32>("vault key")),
            "nonce": hx(&det::<24>("password record nonce")),
            "plaintext": r#"{"v":1,"history":[{"field":"password","value":"correct horse","from_ms":1800000000000,"to_ms":1800000500000}]}"#,
        }),
        json!({
            "name": "password-record-rotation",
            "account_id": hx(&det::<16>("account")),
            "vault_id": hx(&det::<16>("vault")),
            "item_id": hx(&det::<16>("item")),
            "key": hx(&det::<32>("vault key")),
            "nonce": hx(&det::<24>("password record rotation nonce")),
            "plaintext": r#"{"v":2,"history":[{"field":"password","value":"correct horse","from_ms":1800000000000,"to_ms":1800000500000},{"field":"password","value":"x7#Lq9vR2mWt8Kp4Zs1B","from_ms":1800000600000,"to_ms":1800000660000,"unconfirmed":true}],"pending":{"field":"password","value":"Hn3$Vd8qPz2Rk7Lw5Tb9","created_at_ms":1800000700000,"task_id":"0193c2a4-5b6d-4e7f-8a9b-0c1d2e3f4a5b","rotation_id":"0193c2a4-6c7d-4e8f-9a0b-1c2d3e4f5a6b"}}"#,
        }),
        json!({
            "name": "system-project",
            "vault_id": hx(&det::<16>("vault")),
        }),
    ]
}

fn record_compute(case: &Value) -> Value {
    if text(case, "name") == "system-project" {
        let vault = VaultId::from_bytes(array(case, "vault_id"));
        let id = crate::model::history::system_project_id(vault);
        return json!({"project_id": hx(id.as_bytes())});
    }
    let ctx = VaultContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        vault: VaultId::from_bytes(array(case, "vault_id")),
    };
    let item = ItemId::from_bytes(array(case, "item_id"));
    let tuple = record::record_tuple(&ctx, item);
    let blob = aead::seal_with_nonce(
        &array(case, "key"),
        Kind::PasswordRecord,
        &tuple,
        &array(case, "nonce"),
        text(case, "plaintext").as_bytes(),
    );
    json!({"aad": hx(&aad(&Kind::PasswordRecord.header(), &tuple)), "ciphertext": hx(&blob)})
}

fn record_check(case: &Value) {
    if text(case, "name") == "system-project" {
        return;
    }
    let ctx = VaultContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        vault: VaultId::from_bytes(array(case, "vault_id")),
    };
    let item = ItemId::from_bytes(array(case, "item_id"));
    let key = VaultKey::from_bytes(array(case, "key"));
    let blob = bytes(case, "ciphertext");
    let plain = record::decrypt_password_record(&key, &ctx, item, &blob).expect("record opens");
    assert_eq!(&*plain, text(case, "plaintext").as_bytes());
    let parsed = crate::model::record::PasswordRecord::decode(&plain).expect("valid record JSON");
    // The record reads back to the same bytes (version 1 stays version 1).
    assert_eq!(&*parsed.encode(), text(case, "plaintext").as_bytes());
    if text(case, "name") == "password-record-rotation" {
        assert_eq!(parsed.history().len(), 2);
        assert!(parsed.history()[1].unconfirmed);
        assert!(
            parsed
                .pending()
                .and_then(|p| p.rotation_id.as_ref())
                .is_some()
        );
    } else {
        assert_eq!(parsed.history().len(), 1);
    }
}

// ----------------------------------------------------------------- passkey --

fn passkey_inputs() -> Vec<Value> {
    vec![
        json!({
            "name": "passkey-key",
            "account_id": hx(&det::<16>("account")),
            "vault_id": hx(&det::<16>("vault")),
            "item_id": hx(&det::<16>("item")),
            "vault_key": hx(&det::<32>("vault key")),
            "nonce": hx(&det::<24>("passkey key nonce")),
            "scalar": hx(&det::<32>("passkey scalar")),
            "credential_id": hx(&det::<16>("passkey credential")),
            "rp_id": "example.com",
            "user_handle": hx(b"klav-user-0001"),
            "message": hx(b"klav test vector: message signed by a passkey"),
        }),
        json!({
            "name": "webauthn",
            "scalar": hx(&det::<32>("passkey scalar")),
            "credential_id": hx(&det::<16>("passkey credential")),
            "rp_id": "example.com",
            "origin": "https://login.example.com",
            "create_challenge": hx(&det::<32>("passkey create challenge")),
            "get_challenge": hx(&det::<32>("passkey get challenge")),
        }),
    ]
}

fn webauthn_compute(case: &Value) -> Value {
    use crate::passkey::webauthn;
    let key = passkey::PasskeyPrivateKey::from_scalar(&array(case, "scalar")).expect("in range");
    let rp_id = text(case, "rp_id");
    let origin = text(case, "origin");
    let reg = webauthn::register(&key, rp_id, &bytes(case, "credential_id"), true).expect("valid");
    let create_cdj = webauthn::client_data_json(
        webauthn::Ceremony::Create,
        &bytes(case, "create_challenge"),
        origin,
    );
    let get_cdj = webauthn::client_data_json(
        webauthn::Ceremony::Get,
        &bytes(case, "get_challenge"),
        origin,
    );
    let assertion = webauthn::assert(
        &key,
        rp_id,
        true,
        &webauthn::client_data_hash(get_cdj.as_bytes()),
    );
    json!({
        "aaguid": hx(&passkey::AAGUID),
        "public_key_cose": hx(&reg.public_key_cose),
        "create_client_data_json": create_cdj,
        "create_auth_data": hx(&reg.auth_data),
        "attestation_object": hx(&reg.attestation_object),
        "get_client_data_json": get_cdj,
        "get_auth_data": hx(&assertion.authenticator_data),
        "get_signature": hx(&assertion.signature),
    })
}

fn passkey_parts(case: &Value) -> (VaultContext, ItemId, Vec<u8>, Vec<u8>) {
    (
        VaultContext {
            account: AccountId::from_bytes(array(case, "account_id")),
            vault: VaultId::from_bytes(array(case, "vault_id")),
        },
        ItemId::from_bytes(array(case, "item_id")),
        bytes(case, "credential_id"),
        bytes(case, "user_handle"),
    )
}

fn passkey_compute(case: &Value) -> Value {
    if text(case, "name") == "webauthn" {
        return webauthn_compute(case);
    }
    let (ctx, item, credential, user) = passkey_parts(case);
    let binding = passkey::PasskeyBinding {
        credential_id: &credential,
        rp_id: text(case, "rp_id"),
        user_handle: &user,
    };
    let key = passkey::PasskeyPrivateKey::from_scalar(&array(case, "scalar")).expect("in range");
    let (blob, tuple) = passkey::seal_passkey_key_with_nonce(
        &VaultKey::from_bytes(array(case, "vault_key")),
        &ctx,
        item,
        &binding,
        &key,
        &array(case, "nonce"),
    );
    json!({
        "aad": hx(&aad(&Kind::PasskeyKey.header(), &tuple)),
        "sealed_key": hx(&blob),
        "public_key": hx(&key.public_key()),
        "public_key_spki": hx(&key.public_key_spki_der()),
        "signature": hx(&key.sign(&bytes(case, "message"))),
    })
}

fn passkey_check(case: &Value) {
    if text(case, "name") == "webauthn" {
        let key =
            passkey::PasskeyPrivateKey::from_scalar(&array(case, "scalar")).expect("in range");
        let mut message = bytes(case, "get_auth_data");
        message.extend_from_slice(&Sha256::digest(
            text(case, "get_client_data_json").as_bytes(),
        ));
        passkey::verify_es256(&key.public_key(), &message, &bytes(case, "get_signature"))
            .expect("assertion verifies");
        assert_eq!(bytes(case, "create_auth_data")[32], 0x5d);
        assert_eq!(bytes(case, "get_auth_data")[32], 0x1d);
        return;
    }
    let (ctx, item, credential, user) = passkey_parts(case);
    let binding = passkey::PasskeyBinding {
        credential_id: &credential,
        rp_id: text(case, "rp_id"),
        user_handle: &user,
    };
    let vault_key = VaultKey::from_bytes(array(case, "vault_key"));
    let blob = bytes(case, "sealed_key");
    assert_eq!(blob.len(), passkey::PASSKEY_KEY_BLOB_LEN);
    let key = passkey::open_passkey_key(&vault_key, &ctx, item, &binding, &blob).expect("opens");
    assert_eq!(*key.scalar(), array::<32>(case, "scalar"));
    passkey::verify_es256(
        &bytes(case, "public_key"),
        &bytes(case, "message"),
        &bytes(case, "signature"),
    )
    .expect("signature verifies");
    let other = passkey::PasskeyBinding {
        rp_id: "example.org",
        ..binding
    };
    assert!(passkey::open_passkey_key(&vault_key, &ctx, item, &other, &blob).is_err());
}

// ------------------------------------------------------------------- local --

fn local_inputs() -> Vec<Value> {
    let base = json!({
        "account_id": hx(&det::<16>("account")),
        "device_id": hx(&det::<16>("device")),
        "kek": hx(&det::<32>("kek")),
    });
    vec![
        with_outputs(
            &base,
            json!({
                "name": "local-identity",
                "x25519_seed": hx(&det::<32>("identity x25519")),
                "ed25519_seed": hx(&det::<32>("identity ed25519")),
                "nonce": hx(&det::<24>("local identity nonce")),
            }),
        ),
        with_outputs(
            &base,
            json!({
                "name": "local-data",
                "purpose": "session",
                "plaintext": "{\"refresh_token\":\"krt_example\"}",
                "nonce": hx(&det::<24>("local data nonce")),
            }),
        ),
        with_outputs(
            &base,
            json!({
                "name": "local-outbox",
                "plaintext": "{\"v\":1,\"generated\":[{\"value\":\"Zoologist-Goofiness-Tingling7\",\"created_at\":1800000000000,\"host\":\"github.com\"}]}",
                "nonce": hx(&det::<24>("local outbox nonce")),
            }),
        ),
    ]
}

fn local_ctx(case: &Value) -> local::LocalContext {
    local::LocalContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        device: DeviceId::from_bytes(array(case, "device_id")),
    }
}

fn local_compute(case: &Value) -> Value {
    let ctx = local_ctx(case);
    let key = local::derive_bytes(&array(case, "kek"), &ctx);
    let info = local::key_info(&ctx);
    let (kind, tuple, plaintext): (Kind, _, Vec<u8>) = match text(case, "name") {
        "local-identity" => {
            let keys = IdentityKeyPair::from_secret_bytes(
                &array(case, "x25519_seed"),
                &array(case, "ed25519_seed"),
            );
            let mut plain = keys.hpke_private_key_bytes().to_vec();
            plain.extend_from_slice(&array::<32>(case, "ed25519_seed"));
            (
                Kind::LocalIdentity,
                local::identity_tuple(&ctx, keys.public()),
                plain,
            )
        }
        "local-data" => (
            Kind::LocalData,
            local::data_tuple(&ctx, text(case, "purpose")),
            text(case, "plaintext").as_bytes().to_vec(),
        ),
        "local-outbox" => (
            Kind::LocalOutbox,
            local::outbox_tuple(&ctx),
            text(case, "plaintext").as_bytes().to_vec(),
        ),
        other => panic!("unknown local case {other}"),
    };
    let blob = aead::seal_with_nonce(&key, kind, &tuple, &array(case, "nonce"), &plaintext);
    json!({
        "local_key_info": hx(info.as_bytes()),
        "local_key": hx(key.as_ref()),
        "aad": hx(&aad(&kind.header(), &tuple)),
        "sealed": hx(&blob),
    })
}

fn local_check(case: &Value) {
    let ctx = local_ctx(case);
    let key = local::derive_local_key(&Kek::from_bytes(array(case, "kek")), &ctx);
    assert_eq!(key.secret_bytes(), &array::<32>(case, "local_key"));
    let key = LocalKey::from_bytes(array(case, "local_key"));
    let blob = bytes(case, "sealed");
    match text(case, "name") {
        "local-identity" => {
            let keys = IdentityKeyPair::from_secret_bytes(
                &array(case, "x25519_seed"),
                &array(case, "ed25519_seed"),
            );
            local::open_local_identity(&key, &ctx, keys.public(), &blob)
                .expect("local identity opens");
        }
        "local-outbox" => {
            let plain = local::open_local_outbox(&key, &ctx, &blob).expect("local outbox opens");
            assert_eq!(&*plain, text(case, "plaintext").as_bytes());
        }
        _ => {
            let plain = local::open_local_data(&key, &ctx, text(case, "purpose"), &blob)
                .expect("local data opens");
            assert_eq!(&*plain, text(case, "plaintext").as_bytes());
        }
    }
}

// ---------------------------------------------------------------- keystore --

fn point(label: &str) -> [u8; keystore::P256_POINT_LEN] {
    let mut p = [0u8; keystore::P256_POINT_LEN];
    p[0] = 0x04;
    p[1..].copy_from_slice(&det::<64>(label));
    p
}

fn keystore_inputs() -> Vec<Value> {
    vec![json!({
        "name": "keystore-wrap",
        "account_id": hx(&det::<16>("account")),
        "device_id": hx(&det::<16>("device")),
        "keystore_public": hx(&point("keystore public")),
        "ephemeral_public": hx(&point("ephemeral public")),
        "shared_secret": hx(&det::<32>("keystore shared secret")),
        "password_at_ms": 1_793_600_000_000u64,
        "boot_time_s": 1_793_500_000u64,
        "local_key": hx(&det::<32>("local key")),
        "nonce": hx(&det::<24>("keystore wrap nonce")),
    })]
}

fn keystore_binding<'a>(
    case: &Value,
    ks: &'a [u8],
    eph: &'a [u8],
) -> keystore::KeystoreBinding<'a> {
    keystore::KeystoreBinding {
        ctx: local_ctx(case),
        keystore_public: ks,
        ephemeral_public: eph,
        password_at_ms: number(case, "password_at_ms"),
        boot_time_s: number(case, "boot_time_s"),
    }
}

fn keystore_compute(case: &Value) -> Value {
    let (ks, eph) = (
        bytes(case, "keystore_public"),
        bytes(case, "ephemeral_public"),
    );
    let binding = keystore_binding(case, &ks, &eph);
    let wrap_key = keystore::wrapping_key(&array(case, "shared_secret"), &binding);
    let tuple = keystore::wrap_tuple(&binding);
    let blob = aead::seal_with_nonce(
        &wrap_key,
        Kind::KeystoreWrap,
        &tuple,
        &array(case, "nonce"),
        &array::<32>(case, "local_key"),
    );
    json!({
        "wrap_key_info": hx(keystore::key_info(&binding).as_bytes()),
        "wrap_key": hx(wrap_key.as_ref()),
        "aad": hx(&aad(&Kind::KeystoreWrap.header(), &tuple)),
        "sealed": hx(&blob),
    })
}

fn keystore_check(case: &Value) {
    let (ks, eph) = (
        bytes(case, "keystore_public"),
        bytes(case, "ephemeral_public"),
    );
    let binding = keystore_binding(case, &ks, &eph);
    let key = keystore::unwrap_local_key(
        &array(case, "shared_secret"),
        &binding,
        &bytes(case, "sealed"),
    )
    .expect("keystore wrap opens");
    assert_eq!(key.secret_bytes(), &array::<32>(case, "local_key"));
}

// ------------------------------------------------------------------ driver --

fn files() -> Vec<VectorFile> {
    vec![
        VectorFile {
            name: "secret-key",
            description: "Secret Key: checksum y forma de texto",
            spec: "§4.2",
            inputs: secret_key_inputs,
            compute: secret_key_compute,
            check: secret_key_check,
        },
        VectorFile {
            name: "mcp-gateway",
            description: "MCP gateway (ADR 0049): local client tokens (klc1_) and their digest, the argument digest, tool patterns and how a tool call is evaluated",
            spec: "§13.16",
            inputs: mcp_inputs,
            compute: mcp_compute,
            check: mcp_check,
        },
        VectorFile {
            name: "invite",
            description: "Invite codes: canonical spelling, other spellings, digest and codes to reject (ADR 0048)",
            spec: "§4.7",
            inputs: invite_inputs,
            compute: invite_compute,
            check: invite_check,
        },
        VectorFile {
            name: "kdf",
            description: "Contraseña maestra + Secret Key → KEK",
            spec: "§4.3",
            inputs: kdf_inputs,
            compute: kdf_compute,
            check: kdf_check,
        },
        VectorFile {
            name: "identidad",
            description: "Par de llaves de identidad y su sellado con la KEK",
            spec: "§6",
            inputs: identity_inputs,
            compute: identity_compute,
            check: identity_check,
        },
        VectorFile {
            name: "envoltura",
            description: "Envoltura simétrica de llaves de proyecto, elemento y adjunto",
            spec: "§5.2",
            inputs: wrap_inputs,
            compute: wrap_compute,
            check: wrap_check,
        },
        VectorFile {
            name: "elemento",
            description: "Cifrado de las secciones de un elemento",
            spec: "§7",
            inputs: item_inputs,
            compute: item_compute,
            check: item_check,
        },
        VectorFile {
            name: "compartir",
            description: "Llaves de bóveda y proyecto compartidas con HPKE",
            spec: "§8",
            inputs: share_inputs,
            compute: share_compute,
            check: share_check,
        },
        VectorFile {
            name: "llave-de-boveda",
            description: "Firma de la cuenta dueña sobre su llave de bóveda compartida (ADR 0030 §1)",
            spec: "§8.3",
            inputs: vault_key_signature_inputs,
            compute: vault_key_signature_compute,
            check: vault_key_signature_check,
        },
        VectorFile {
            name: "hpke-rfc9180",
            description: "Vector oficial RFC 9180 A.2.1 para la suite de Klav",
            spec: "§8.1",
            inputs: rfc9180_inputs,
            compute: rfc9180_compute,
            check: rfc9180_check,
        },
        VectorFile {
            name: "adjunto",
            description: "Adjuntos cifrados con STREAM",
            spec: "§10",
            inputs: attachment_inputs,
            compute: attachment_compute,
            check: attachment_check,
        },
        VectorFile {
            name: "metadatos",
            description: "Metadatos de bóvedas y proyectos",
            spec: "§7.2",
            inputs: meta_inputs,
            compute: meta_compute,
            check: meta_check,
        },
        VectorFile {
            name: "registro",
            description: "Registro de contraseñas de un elemento, sellado con la llave de bóveda, e ID del proyecto de sistema",
            spec: "§7.3",
            inputs: record_inputs,
            compute: record_compute,
            check: record_check,
        },
        VectorFile {
            name: "passkey",
            description: "Passkeys: llave privada P-256 sellada con la llave de bóveda, firma ES256 (RFC 6979, DER), y el registro y la aserción WebAuthn de Klav",
            spec: "§14",
            inputs: passkey_inputs,
            compute: passkey_compute,
            check: passkey_check,
        },
        VectorFile {
            name: "local",
            description: "Llave local del dispositivo, identidad local, datos locales y cola de salida local",
            spec: "§12.2",
            inputs: local_inputs,
            compute: local_compute,
            check: local_check,
        },
        VectorFile {
            name: "llavero",
            description: "Llave local envuelta por el almacén de llaves de la plataforma (Secure Enclave)",
            spec: "§12.3",
            inputs: keystore_inputs,
            compute: keystore_compute,
            check: keystore_check,
        },
        VectorFile {
            name: "firma",
            description: "Firmas Ed25519 con separación de dominio",
            spec: "§9",
            inputs: signature_inputs,
            compute: signature_compute,
            check: signature_check,
        },
        VectorFile {
            name: "item-grant",
            description: "Per-item grant: an item key shared with HPKE (kind 0x23) and a signed version 2 grant payload that carries it",
            spec: "§8.2, §13.4",
            inputs: item_grant_inputs,
            compute: item_grant_compute,
            check: item_grant_check,
        },
        VectorFile {
            name: "sandbox-grant",
            description: "Version 3 grants: the credential proxy's, with a sandbox issuer, and the issuer's, with its sandbox proxy and no projects, each signed by the account",
            spec: "§13.4",
            inputs: sandbox_grant_inputs,
            compute: sandbox_grant_compute,
            check: sandbox_grant_check,
        },
        VectorFile {
            name: "sandbox-events",
            description: "The credential proxy's signed requests for a sandbox's life (sandbox.issued, sandbox.claimed, sandbox.revoked): bodies, their section 13.3 messages and signatures, and the digest of the channel key",
            spec: "§13.3, §13.7, §13.10",
            inputs: sandbox_event_inputs,
            compute: sandbox_event_compute,
            check: sandbox_event_check,
        },
        VectorFile {
            name: "sandbox-heartbeat",
            description: "The credential proxy's signed requests for a new store epoch (sandbox.store_reset) and its heartbeat: bodies, their section 13.3 messages and signatures",
            spec: "§13.3, §13.7, §13.12",
            inputs: sandbox_heartbeat_inputs,
            compute: sandbox_heartbeat_compute,
            check: sandbox_heartbeat_check,
        },
        VectorFile {
            name: "sandbox",
            description: "Sandbox package (ksb1_), the proxy pin (SHA-256 of its Ed25519 SPKI) and the digest of the one-time secret the proxy keeps",
            spec: "§13.10",
            inputs: sandbox_inputs,
            compute: sandbox_compute,
            check: sandbox_check,
        },
        VectorFile {
            name: "sandbox-revoke",
            description: "The person's revocation of sandboxes, signed by the account: one sandbox, and every sandbox of the proxy (all)",
            spec: "§13.11",
            inputs: sandbox_revoke_inputs,
            compute: sandbox_revoke_compute,
            check: sandbox_revoke_check,
        },
        VectorFile {
            name: "secret-request",
            description: "Agent secret requests (ADR 0046): HPKE-sealed proposal blob (kind 0x25) and account-signed decisions (fulfilled in grant, fulfilled outside grant, denied)",
            spec: "§13.14",
            inputs: secret_request_inputs,
            compute: secret_request_compute,
            check: secret_request_check,
        },
        VectorFile {
            name: "agentes",
            description: "Agentes: palabras de emparejamiento, llave secreta del agente y firmas de peticiones, grants, aprobaciones, revocaciones, solicitudes de tarea y pausas",
            spec: "§13",
            inputs: agent_inputs,
            compute: agent_compute,
            check: agent_check,
        },
    ]
}

// ------------------------------------------------------------------ agents --

fn agent_inputs() -> Vec<Value> {
    vec![json!({
        "name": "agent",
        "agent_x25519_seed": hx(&det::<32>("agent x25519")),
        "agent_ed25519_seed": hx(&det::<32>("agent ed25519")),
        "account_x25519_seed": hx(&det::<32>("identity x25519")),
        "account_ed25519_seed": hx(&det::<32>("identity ed25519")),
        "account_id": hx(&det::<16>("account")),
        "agent_id": hx(&det::<16>("agent id")),
        "approval_id": hx(&det::<16>("approval id")),
        "method": "POST",
        "path": "/v1/agent/access",
        "timestamp_ms": 1_800_000_000_000u64,
        "nonce": hx(&det::<16>("request nonce")),
        "body": "{\"action\":\"fill\",\"reason\":\"log in to GitHub\"}",
        "grant_payload": "{\"v\":1,\"version\":1}",
        "grant_change": "{\"projects\":[\"web\"],\"policy\":{\"permissions\":[]},\"rotate_removed\":true}",
        "approval_request": "{\"permission\":\"reveal\"}",
        "lease_until_ms": 1_800_000_900_000u64,
        "decided_at_ms": 1_800_000_000_500u64,
        "revoked_at_ms": 1_800_000_001_000u64,
        "vault_id": hx(&det::<16>("vault")),
        "project_id": hx(&det::<16>("project")),
        "project_key": hx(&det::<32>("project key")),
        "labels_nonce": hx(&det::<24>("grant labels nonce")),
        "labels": "{\"vault\":\"Personal\",\"project\":\"web\"}",
        "audit_events": ["{\"v\":1,\"action\":\"agent.registered\"}", "{\"v\":1,\"action\":\"agent.access\"}"],
        "task_id": hx(&det::<16>("task id")),
        "task_request": task_request_json(),
        "task_decision": task_decision_json(),
        "task_denial": serde_json::to_string(&task::denial(
            TaskId::from_bytes(det::<16>("task id")),
            AgentId::from_bytes(det::<16>("agent id")),
        ))
        .expect("serializes"),
        "task_decided_at_ms": 1_800_000_060_000u64,
        "task_ended_at_ms": 1_800_003_600_000u64,
        "task_offer": task_offer_json(),
        "task_offer_decided_at_ms": 1_800_000_120_000u64,
        "pause_at_ms": 1_800_000_002_000u64,
        "pause_until_ms": 1_800_003_602_000u64,
        "resume_at_ms": 1_800_000_003_000u64,
    })]
}

/// The three pause decisions of the vectors (spec §13.9): every agent for
/// an hour, one agent with no end, and the resume of every agent.
fn agent_pauses(case: &Value) -> [(&'static str, agent::PauseToSign); 3] {
    let account = AccountId::from_bytes(array(case, "account_id"));
    let agent_id = AgentId::from_bytes(array(case, "agent_id"));
    [
        (
            "pause_all",
            agent::PauseToSign {
                account,
                scope: agent::PauseScope::All,
                pause: true,
                at_ms: number(case, "pause_at_ms"),
                until_ms: number(case, "pause_until_ms"),
            },
        ),
        (
            "pause_agent",
            agent::PauseToSign {
                account,
                scope: agent::PauseScope::Agent(agent_id),
                pause: true,
                at_ms: number(case, "pause_at_ms"),
                until_ms: 0,
            },
        ),
        (
            "resume",
            agent::PauseToSign {
                account,
                scope: agent::PauseScope::All,
                pause: false,
                at_ms: number(case, "resume_at_ms"),
                until_ms: 0,
            },
        ),
    ]
}

/// The task request of the vectors (ADR 0021 §1): AWS with `fill` and
/// Telmex with `fill` on a given host, for two hours.
fn task_request_value() -> task::TaskRequest {
    let vault = VaultId::from_bytes(det::<16>("vault"));
    let project = ProjectId::from_bytes(det::<16>("project"));
    task::TaskRequest {
        v: task::TASK_FORMAT_VERSION,
        task: "Descargar las facturas de octubre".into(),
        reason: "Conciliar los gastos del mes".into(),
        duration_secs: 7200,
        access: vec![
            task::TaskAccessRequest {
                vault_id: vault,
                project_id: project,
                item_id: ItemId::from_bytes(det::<16>("task item aws")),
                permissions: vec![Permission::Fill],
                domain: None,
            },
            task::TaskAccessRequest {
                vault_id: vault,
                project_id: project,
                item_id: ItemId::from_bytes(det::<16>("task item telmex")),
                permissions: vec![Permission::Fill],
                domain: Some("telmex.com".into()),
            },
        ],
    }
}

fn task_request_json() -> String {
    serde_json::to_string(&task_request_value()).expect("serializes")
}

/// The approval: both items, with `totp` added by Klav to AWS, until two
/// hours after the decision.
fn task_decision_json() -> String {
    let request = task_request_value();
    let mut access: Vec<task::TaskAccessDecision> = request
        .access
        .iter()
        .map(|a| task::TaskAccessDecision {
            vault_id: a.vault_id,
            project_id: a.project_id,
            item_id: a.item_id,
            permissions: a.permissions.clone(),
            domains: vec![
                a.domain
                    .clone()
                    .unwrap_or_else(|| "signin.aws.amazon.com".into()),
            ],
            added_by_klav: Vec::new(),
        })
        .collect();
    access[0].permissions.push(Permission::Totp);
    access[0].added_by_klav.push(Permission::Totp);
    serde_json::to_string(&task::TaskDecision {
        v: task::TASK_FORMAT_VERSION,
        task_id: TaskId::from_bytes(det::<16>("task id")),
        agent_id: AgentId::from_bytes(det::<16>("agent id")),
        revision: 1,
        expires_at_ms: 1_800_000_060_000 + 7_200_000,
        access,
        offer: None,
    })
    .expect("serializes")
}

/// A task the person offers (ADR 0022 §6): `rotate` on Telmex's login, on
/// its site, for an hour, with their title and reason.
fn task_offer_json() -> String {
    serde_json::to_string(&task::TaskDecision {
        v: task::TASK_FORMAT_VERSION,
        task_id: TaskId::from_bytes(det::<16>("offered task id")),
        agent_id: AgentId::from_bytes(det::<16>("agent id")),
        revision: 1,
        expires_at_ms: 1_800_000_120_000 + 3_600_000,
        access: vec![task::TaskAccessDecision {
            vault_id: VaultId::from_bytes(det::<16>("vault")),
            project_id: ProjectId::from_bytes(det::<16>("project")),
            item_id: ItemId::from_bytes(det::<16>("task item telmex")),
            permissions: vec![Permission::Rotate],
            domains: vec!["telmex.com".into()],
            added_by_klav: Vec::new(),
        }],
        offer: Some(task::TaskOffer {
            task: "Cambiar mis contraseñas repetidas".into(),
            reason: "Que cada sitio tenga la suya".into(),
        }),
    })
    .expect("serializes")
}

/// The offer as signed: no request (empty bytes).
fn task_offer_to_sign(case: &Value) -> agent::TaskDecisionToSign<'_> {
    let offer = text(case, "task_offer");
    let decision: task::TaskDecision = serde_json::from_str(offer).expect("task offer");
    agent::TaskDecisionToSign {
        task: decision.task_id,
        agent: AgentId::from_bytes(array(case, "agent_id")),
        request: &[],
        decision: offer.as_bytes(),
        approve: true,
        decided_at_ms: number(case, "task_offer_decided_at_ms"),
    }
}

fn task_decision_to_sign(case: &Value, approve: bool) -> agent::TaskDecisionToSign<'_> {
    agent::TaskDecisionToSign {
        task: TaskId::from_bytes(array(case, "task_id")),
        agent: AgentId::from_bytes(array(case, "agent_id")),
        request: text(case, "task_request").as_bytes(),
        decision: text(
            case,
            if approve {
                "task_decision"
            } else {
                "task_denial"
            },
        )
        .as_bytes(),
        approve,
        decided_at_ms: number(case, "task_decided_at_ms"),
    }
}

fn agent_keys(case: &Value, who: &str) -> IdentityKeyPair {
    IdentityKeyPair::from_secret_bytes(
        &array(case, &format!("{who}_x25519_seed")),
        &array(case, &format!("{who}_ed25519_seed")),
    )
}

fn agent_request<'a>(
    case: &'a Value,
    agent: AgentId,
    nonce: &'a [u8; 16],
    digest: &'a [u8; 32],
) -> agent::SignedRequest<'a> {
    agent::SignedRequest {
        agent,
        method: text(case, "method"),
        path: text(case, "path"),
        timestamp_ms: number(case, "timestamp_ms"),
        nonce,
        body_digest: digest,
    }
}

fn agent_approval(case: &Value) -> agent::ApprovalToSign<'_> {
    agent::ApprovalToSign {
        approval: ApprovalId::from_bytes(array(case, "approval_id")),
        agent: AgentId::from_bytes(array(case, "agent_id")),
        request: text(case, "approval_request").as_bytes(),
        approve: true,
        lease_until_ms: number(case, "lease_until_ms"),
        decided_at_ms: number(case, "decided_at_ms"),
    }
}

fn agent_labels_ctx(case: &Value) -> ProjectContext {
    ProjectContext {
        account: AccountId::from_bytes(array(case, "account_id")),
        vault: VaultId::from_bytes(array(case, "vault_id")),
        project: ProjectId::from_bytes(array(case, "project_id")),
    }
}

fn audit_chain(case: &Value) -> Vec<[u8; 32]> {
    let mut previous = super::audit::GENESIS;
    let mut out = Vec::new();
    for (i, event) in case["audit_events"]
        .as_array()
        .expect("events")
        .iter()
        .enumerate()
    {
        let seq = u64::try_from(i + 1).expect("seq");
        previous =
            super::audit::chain_hash(seq, &previous, event.as_str().expect("event").as_bytes());
        out.push(previous);
    }
    out
}

fn audit_hashes(case: &Value) -> Value {
    Value::Array(audit_chain(case).iter().map(|h| hx(h)).collect())
}

fn audit_last(case: &Value) -> [u8; 32] {
    *audit_chain(case).last().expect("events")
}

fn agent_compute(case: &Value) -> Value {
    let agent_keys_ = agent_keys(case, "agent");
    let account_keys = agent_keys(case, "account");
    let account = AccountId::from_bytes(array(case, "account_id"));
    let agent_id = AgentId::from_bytes(array(case, "agent_id"));
    let nonce: [u8; 16] = array(case, "nonce");
    let digest = agent::body_digest(text(case, "body").as_bytes());
    let request = agent_request(case, agent_id, &nonce, &digest);
    let grant = agent::GrantToSign {
        account,
        agent: agent_id,
        agent_public: agent_keys_.public(),
        payload: text(case, "grant_payload").as_bytes(),
    };
    json!({
        "agent_public_identity": hx(&agent_keys_.public().encode()),
        "agent_fingerprint": hx(&agent_keys_.public().fingerprint()),
        "pairing_words": agent::pairing_code(agent_keys_.public()),
        "agent_secret": agent::encode_agent_secret(&agent_keys_).as_str(),
        "account_public_identity": hx(&account_keys.public().encode()),
        "body_digest": hx(&digest),
        "grant_change_digest": agent::grant_change_digest(
            text(case, "grant_payload").as_bytes(),
            text(case, "grant_change").as_bytes(),
        ),
        "request_signature": hx(&agent::sign_request(&agent_keys_, &request).to_bytes()),
        "grant_signature": hx(&agent::sign_grant(&account_keys, &grant).to_bytes()),
        "approval_signature": hx(&agent::sign_approval(&account_keys, &agent_approval(case)).to_bytes()),
        "revocation_signature": hx(&agent::sign_revocation(
            &account_keys,
            account,
            agent_id,
            number(case, "revoked_at_ms"),
        )
        .to_bytes()),
        "audit_hashes": audit_hashes(case),
        "audit_head_signature": hx(&super::audit::sign_head(
            &account_keys,
            account,
            2,
            &audit_last(case),
        )
        .to_bytes()),
        "task_decision_signature": hx(&agent::sign_task_decision(
            &account_keys,
            &task_decision_to_sign(case, true),
        )
        .to_bytes()),
        "task_denial_signature": hx(&agent::sign_task_decision(
            &account_keys,
            &task_decision_to_sign(case, false),
        )
        .to_bytes()),
        "task_offer_signature": hx(&agent::sign_task_decision(
            &account_keys,
            &task_offer_to_sign(case),
        )
        .to_bytes()),
        "task_end_signature": hx(&agent::sign_task_end(
            &account_keys,
            account,
            TaskId::from_bytes(array(case, "task_id")),
            agent_id,
            number(case, "task_ended_at_ms"),
        )
        .to_bytes()),
        "pause_all_signature": hx(&agent::sign_pause(&account_keys, &agent_pauses(case)[0].1).to_bytes()),
        "pause_agent_signature": hx(&agent::sign_pause(&account_keys, &agent_pauses(case)[1].1).to_bytes()),
        "resume_signature": hx(&agent::sign_pause(&account_keys, &agent_pauses(case)[2].1).to_bytes()),
        "labels_blob": hx(&agent::seal_grant_labels_with_nonce(
            &ProjectKey::from_bytes(array(case, "project_key")),
            &agent_labels_ctx(case),
            agent_id,
            &array(case, "labels_nonce"),
            text(case, "labels").as_bytes(),
        )),
        "messages": agent_messages(case),
        "labels_aad": hx(&aad(
            &Kind::GrantLabels.header(),
            &agent::labels_tuple(&agent_labels_ctx(case), agent_id),
        )),
        "negative": agent_negative(case),
    })
}

/// The exact bytes each signature covers (`tuple(label, fields…)`, spec
/// §9), so that another implementation can check its encoding before the
/// signature.
fn agent_messages(case: &Value) -> Value {
    let account = AccountId::from_bytes(array(case, "account_id"));
    let agent_id = AgentId::from_bytes(array(case, "agent_id"));
    let agent_public = agent_keys(case, "agent").public().clone();
    let nonce: [u8; 16] = array(case, "nonce");
    let digest = agent::body_digest(text(case, "body").as_bytes());
    let request = agent_request(case, agent_id, &nonce, &digest);
    let grant = agent::GrantToSign {
        account,
        agent: agent_id,
        agent_public: &agent_public,
        payload: text(case, "grant_payload").as_bytes(),
    };
    let message = |label: &str, fields: &[&[u8]]| {
        hx(&sign::signed_message(label, fields).expect("valid label"))
    };
    let task = TaskId::from_bytes(array(case, "task_id"));
    json!({
        "request": message(agent::LABEL_REQUEST, &agent::refs(&request.fields())),
        "grant": message(agent::LABEL_GRANT, &agent::refs(&grant.fields())),
        "approval": message(agent::LABEL_APPROVAL, &agent::refs(&agent_approval(case).fields())),
        "revocation": message(
            agent::LABEL_REVOCATION,
            &[account.as_bytes(), agent_id.as_bytes(), &number(case, "revoked_at_ms").to_be_bytes()],
        ),
        "task_decision": message(
            agent::LABEL_TASK_DECISION,
            &agent::refs(&task_decision_to_sign(case, true).fields()),
        ),
        "task_denial": message(
            agent::LABEL_TASK_DECISION,
            &agent::refs(&task_decision_to_sign(case, false).fields()),
        ),
        "task_end": message(
            agent::LABEL_TASK_END,
            &[
                account.as_bytes(),
                task.as_bytes(),
                agent_id.as_bytes(),
                &number(case, "task_ended_at_ms").to_be_bytes(),
            ],
        ),
        "audit_head": message(
            super::audit::LABEL_HEAD,
            &[account.as_bytes(), &2u64.to_be_bytes(), &audit_last(case)],
        ),
        "pause_all": message(agent::LABEL_AGENT_PAUSE, &agent::refs(&agent_pauses(case)[0].1.fields())),
        "pause_agent": message(agent::LABEL_AGENT_PAUSE, &agent::refs(&agent_pauses(case)[1].1.fields())),
        "resume": message(agent::LABEL_AGENT_PAUSE, &agent::refs(&agent_pauses(case)[2].1.fields())),
    })
}

/// Inputs that must be refused: a labels blob of another format version,
/// of another kind or with its tag altered, and a grant signed under the
/// approval label.
fn agent_negative(case: &Value) -> Value {
    let blob = agent::seal_grant_labels_with_nonce(
        &ProjectKey::from_bytes(array(case, "project_key")),
        &agent_labels_ctx(case),
        AgentId::from_bytes(array(case, "agent_id")),
        &array(case, "labels_nonce"),
        text(case, "labels").as_bytes(),
    );
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = blob.clone();
        f(&mut b);
        hx(&b)
    };
    let agent_public = agent_keys(case, "agent").public().clone();
    let grant = agent::GrantToSign {
        account: AccountId::from_bytes(array(case, "account_id")),
        agent: AgentId::from_bytes(array(case, "agent_id")),
        agent_public: &agent_public,
        payload: text(case, "grant_payload").as_bytes(),
    };
    let wrong_label = sign::sign(
        &agent_keys(case, "account"),
        agent::LABEL_APPROVAL,
        &agent::refs(&grant.fields()),
    )
    .expect("valid label");
    let resume = agent_pauses(case)[2].1;
    let resume_as_pause = agent::sign_pause(&agent_keys(case, "account"), &resume);
    json!([
        { "name": "labels_blob, versión 0x02", "labels_blob": with(&|b| b[0] = 0x02) },
        { "name": "labels_blob, kind 0x15", "labels_blob": with(&|b| b[1] = 0x15) },
        { "name": "labels_blob, tag alterado", "labels_blob": with(&|b| {
            let last = b.len() - 1;
            b[last] ^= 0x01;
        }) },
        { "name": "grant firmado con la etiqueta de aprobación", "grant_signature": hx(&wrong_label.to_bytes()) },
        { "name": "reanudación presentada como pausa (mismo alcance y hora)", "pause_signature": hx(&resume_as_pause.to_bytes()) },
    ])
}

fn agent_check(case: &Value) {
    let agent_public =
        PublicIdentity::decode(&bytes(case, "agent_public_identity")).expect("agent");
    let account_public =
        PublicIdentity::decode(&bytes(case, "account_public_identity")).expect("account");
    let decoded = agent::decode_agent_secret(text(case, "agent_secret")).expect("agent secret");
    assert_eq!(decoded.public(), &agent_public);
    assert!(agent::pairing_code_matches(
        &agent_public,
        text(case, "pairing_words")
    ));
    let agent_id = AgentId::from_bytes(array(case, "agent_id"));
    let nonce: [u8; 16] = array(case, "nonce");
    let digest: [u8; 32] = array(case, "body_digest");
    let request = agent_request(case, agent_id, &nonce, &digest);
    let sig = |key: &str| sign::Signature::from_bytes(array(case, key));
    agent::verify_request(&agent_public, &request, &sig("request_signature")).expect("request");
    let grant = agent::GrantToSign {
        account: AccountId::from_bytes(array(case, "account_id")),
        agent: agent_id,
        agent_public: &agent_public,
        payload: text(case, "grant_payload").as_bytes(),
    };
    agent::verify_grant(&account_public, &grant, &sig("grant_signature")).expect("grant");
    let payload = text(case, "grant_payload").as_bytes();
    let change = text(case, "grant_change").as_bytes();
    let shown = text(case, "grant_change_digest");
    assert!(agent::grant_change_matches(payload, change, shown));
    assert!(agent::grant_change_matches(
        payload,
        change,
        &shown.to_uppercase()
    ));
    assert!(!agent::grant_change_matches(change, payload, shown));
    agent::verify_approval(
        &account_public,
        &agent_approval(case),
        &sig("approval_signature"),
    )
    .expect("approval");
    agent::verify_revocation(
        &account_public,
        grant.account,
        agent_id,
        number(case, "revoked_at_ms"),
        &sig("revocation_signature"),
    )
    .expect("revocation");
    let labels = agent::open_grant_labels(
        &ProjectKey::from_bytes(array(case, "project_key")),
        &agent_labels_ctx(case),
        agent_id,
        &bytes(case, "labels_blob"),
    )
    .expect("labels open");
    assert_eq!(&*labels, text(case, "labels").as_bytes());
    // Task request and decision (spec §13.8): the stored bytes parse,
    // follow the rules of ADR 0021 and the signatures verify.
    let request: task::TaskRequest =
        serde_json::from_str(text(case, "task_request")).expect("task request");
    request.validate().expect("valid task request");
    let decision: task::TaskDecision =
        serde_json::from_str(text(case, "task_decision")).expect("task decision");
    decision.validate(true).expect("valid task decision");
    decision
        .check_first(&request, number(case, "task_decided_at_ms"))
        .expect("decision answers the request");
    let denial: task::TaskDecision =
        serde_json::from_str(text(case, "task_denial")).expect("task denial");
    denial.validate(false).expect("valid denial");
    agent::verify_task_decision(
        &account_public,
        &task_decision_to_sign(case, true),
        &sig("task_decision_signature"),
    )
    .expect("task decision");
    agent::verify_task_decision(
        &account_public,
        &task_decision_to_sign(case, false),
        &sig("task_denial_signature"),
    )
    .expect("task denial");
    assert!(
        agent::verify_task_decision(
            &account_public,
            &agent::TaskDecisionToSign {
                approve: false,
                ..task_decision_to_sign(case, true)
            },
            &sig("task_decision_signature"),
        )
        .is_err()
    );
    // An offered task (ADR 0022 §6): signed over an empty request.
    let offer: task::TaskDecision =
        serde_json::from_str(text(case, "task_offer")).expect("task offer");
    offer.validate(true).expect("valid offer");
    offer
        .check_offered(number(case, "task_offer_decided_at_ms"))
        .expect("an offered task");
    agent::verify_task_decision(
        &account_public,
        &task_offer_to_sign(case),
        &sig("task_offer_signature"),
    )
    .expect("task offer");
    assert!(
        agent::verify_task_decision(
            &account_public,
            &agent::TaskDecisionToSign {
                request: text(case, "task_request").as_bytes(),
                ..task_offer_to_sign(case)
            },
            &sig("task_offer_signature"),
        )
        .is_err()
    );
    agent::verify_task_end(
        &account_public,
        grant.account,
        decision.task_id,
        agent_id,
        number(case, "task_ended_at_ms"),
        &sig("task_end_signature"),
    )
    .expect("task end");
    // Pauses and resume (spec §13.9).
    for (name, decision) in agent_pauses(case) {
        agent::verify_pause(
            &account_public,
            &decision,
            &sig(&format!("{name}_signature")),
        )
        .unwrap_or_else(|_| panic!("{name}"));
    }
    assert_eq!(audit_hashes(case), case["audit_hashes"]);
    // Each stored message is what its signature covers.
    let messages = &case["messages"];
    for (name, signer, signature) in [
        ("request", &agent_public, "request_signature"),
        ("grant", &account_public, "grant_signature"),
        ("approval", &account_public, "approval_signature"),
        ("revocation", &account_public, "revocation_signature"),
        ("task_decision", &account_public, "task_decision_signature"),
        ("task_denial", &account_public, "task_denial_signature"),
        ("task_end", &account_public, "task_end_signature"),
        ("audit_head", &account_public, "audit_head_signature"),
        ("pause_all", &account_public, "pause_all_signature"),
        ("pause_agent", &account_public, "pause_agent_signature"),
        ("resume", &account_public, "resume_signature"),
    ] {
        let message = hex::decode(messages[name].as_str().expect("message")).expect("hex");
        signer
            .verifying_key()
            .expect("key")
            .verify_strict(
                &message,
                &ed25519_dalek::Signature::from_bytes(&sig(signature).to_bytes()),
            )
            .unwrap_or_else(|_| panic!("{name}: the signature does not cover the message"));
    }
    let aad = bytes(case, "labels_aad");
    assert_eq!(&aad[..2], &Kind::GrantLabels.header());
    // The negative cases are refused.
    for negative in case["negative"].as_array().expect("negative") {
        if negative.get("labels_blob").is_some() {
            assert!(
                agent::open_grant_labels(
                    &ProjectKey::from_bytes(array(case, "project_key")),
                    &agent_labels_ctx(case),
                    agent_id,
                    &bytes(negative, "labels_blob"),
                )
                .is_err(),
                "{}",
                text(negative, "name")
            );
        }
        if negative.get("pause_signature").is_some() {
            // The resume's bytes say «resume»: read as a pause, they fail.
            let resume = agent_pauses(case)[2].1;
            assert!(
                agent::verify_pause(
                    &account_public,
                    &agent::PauseToSign {
                        pause: true,
                        ..resume
                    },
                    &sign::Signature::from_bytes(array(negative, "pause_signature")),
                )
                .is_err()
            );
        }
        if negative.get("grant_signature").is_some() {
            assert!(
                agent::verify_grant(
                    &account_public,
                    &grant,
                    &sign::Signature::from_bytes(array(negative, "grant_signature")),
                )
                .is_err()
            );
        }
    }
    super::audit::verify_head(
        &account_public,
        grant.account,
        2,
        &audit_last(case),
        &sig("audit_head_signature"),
    )
    .expect("audit head");
}

// ------------------------------------------------------------- mcp gateway --

/// The policy of ADR 0049 §5.3's example: the session rule (methods, no
/// tools), `allow`, `ask` and `deny` tool rules on one item and endpoint.
fn mcp_policy() -> crate::policy::Policy {
    use crate::policy::{Effect, Policy, Rule, Scope};
    let item = ItemId::from_bytes(det::<16>("mcp item"));
    let base = Scope {
        items: vec![item],
        domains: vec!["api.maple.dev".parse().expect("host")],
        path_prefixes: vec!["/mcp".parse().expect("prefix")],
        ..Scope::default()
    };
    let rule = |effect, methods: &[&str], tools: &[&str]| Rule {
        permission: Permission::Proxy,
        effect,
        scope: Scope {
            methods: methods.iter().map(|m| m.parse().expect("method")).collect(),
            mcp_tools: tools.iter().map(|t| t.parse().expect("pattern")).collect(),
            ..base.clone()
        },
        expires_at: None,
    };
    Policy {
        rules: vec![
            rule(Effect::Allow, &["POST", "GET", "DELETE"], &[]),
            rule(Effect::Allow, &[], &["get_*", "list_*", "query_*"]),
            rule(Effect::Ask, &[], &["create_*", "update_*", "delete_*"]),
            rule(Effect::Deny, &[], &["create_api_key", "get_api_key"]),
        ],
        expires_at: None,
    }
}

fn mcp_inputs() -> Vec<Value> {
    let agent = hx(&det::<16>("mcp proxy"));
    let item = hx(&det::<16>("mcp item"));
    vec![
        json!({"name": "token-zeros", "agent_id": agent, "token_bytes": hx(&[0u8; 32])}),
        json!({"name": "token-pseudo-random", "agent_id": agent, "token_bytes": hx(&det::<32>("mcp token"))}),
        json!({
            "name": "tokens-rejected",
            "invalid": [
                "",
                "klc1_",
                "klc2_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "KLC1_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "klc1_AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "klc1_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "klc1_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "klc1_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "klc1_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+A",
                " klc1_AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ],
        }),
        json!({
            "name": "args",
            "agent_id": agent, "item_id": item, "tool": "query_logs",
            "raw_arguments": "{\"query\":\"error\", \"limit\":10}",
        }),
        json!({
            "name": "args-reordered",
            "agent_id": agent, "item_id": item, "tool": "query_logs",
            "raw_arguments": "{\"limit\":10,\"query\":\"error\"}",
        }),
        json!({
            "name": "args-absent",
            "agent_id": agent, "item_id": item, "tool": "query_logs",
            "raw_arguments": "",
        }),
        json!({
            "name": "patterns",
            "patterns": ["get_*", "query_logs", "*", "G*"],
            "tools": ["get_logs", "get_", "Get_logs", "forget_logs", "query_logs", "query_logs2", "bad name", ""],
            "invalid_patterns": ["", "**", "*get", "get_**", "*_api_key", "ge*t", " get_*", "get *", "quéry"],
        }),
        json!({
            "name": "evaluation",
            "policy": serde_json::to_value(mcp_policy()).expect("policy"),
            "item_id": item,
            "tools": [null, "query_logs", "get_dashboard", "delete_dashboard", "get_api_key", "create_api_key", "run_query", "Get_logs", "DeleteService", "get logs"],
        }),
    ]
}

fn mcp_compute(case: &Value) -> Value {
    use super::mcp::{LocalClientToken, digest_text, local_client_digest, mcp_args_digest};
    if case.get("invalid").is_some() {
        return json!({});
    }
    if case.get("token_bytes").is_some() {
        let agent = AgentId::from_bytes(array::<16>(case, "agent_id"));
        let bytes = array::<32>(case, "token_bytes");
        return json!({
            "token": LocalClientToken::from_bytes(&bytes).expose(),
            "token_digest": hx(&local_client_digest(agent, &bytes)),
        });
    }
    if case.get("raw_arguments").is_some() {
        let agent = AgentId::from_bytes(array::<16>(case, "agent_id"));
        let item = ItemId::from_bytes(array::<16>(case, "item_id"));
        let digest = mcp_args_digest(
            agent,
            item,
            text(case, "tool"),
            text(case, "raw_arguments").as_bytes(),
        );
        return json!({"mcp_args_hex": hx(&digest), "mcp_args": digest_text(&digest)});
    }
    if case.get("patterns").is_some() {
        let tools: Vec<&str> = case["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .map(|t| t.as_str().expect("tool"))
            .collect();
        let matches: serde_json::Map<String, Value> = case["patterns"]
            .as_array()
            .expect("patterns")
            .iter()
            .map(|p| {
                let p = p.as_str().expect("pattern");
                let pattern: crate::policy::ToolPattern = p.parse().expect("valid pattern");
                let hit: Vec<&str> = tools
                    .iter()
                    .copied()
                    .filter(|t| pattern.matches(t))
                    .collect();
                (p.to_owned(), json!(hit))
            })
            .collect();
        return json!({"matches": matches});
    }
    // Evaluation.
    let policy: crate::policy::Policy =
        serde_json::from_value(case["policy"].clone()).expect("policy");
    let item = ItemId::from_bytes(array::<16>(case, "item_id"));
    let effects: Vec<Value> = case["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| {
            let request = crate::policy::Request {
                permission: Permission::Proxy,
                vault: crate::policy::Target {
                    id: VaultId::from_bytes([1; 16]),
                    name: String::new(),
                },
                project: crate::policy::Target {
                    id: ProjectId::from_bytes([2; 16]),
                    name: String::new(),
                },
                tags: Vec::new(),
                domain: Some("api.maple.dev".into()),
                item: Some(item),
                method: Some("POST".into()),
                path: Some("/mcp".into()),
                mcp_tool: t.as_str().map(str::to_owned),
                now: 0,
            };
            serde_json::to_value(crate::policy::evaluate(&policy, &request).effect).expect("effect")
        })
        .collect();
    json!({"effects": effects})
}

fn mcp_check(case: &Value) {
    use super::mcp::LocalClientToken;
    if let Some(invalid) = case.get("invalid") {
        for t in invalid.as_array().expect("invalid") {
            let t = t.as_str().expect("string");
            assert!(LocalClientToken::new(t).bytes().is_err(), "accepted {t:?}");
        }
        return;
    }
    if case.get("token_bytes").is_some() {
        let agent = AgentId::from_bytes(array::<16>(case, "agent_id"));
        let token = LocalClientToken::new(text(case, "token"));
        assert_eq!(
            *token.bytes().expect("parses"),
            array::<32>(case, "token_bytes")
        );
        assert!(token.matches(agent, &bytes(case, "token_digest")));
        return;
    }
    if case.get("raw_arguments").is_some() {
        assert!(super::mcp::digest_text_ok(text(case, "mcp_args")));
        return;
    }
    if let Some(invalid) = case.get("invalid_patterns") {
        for p in invalid.as_array().expect("invalid patterns") {
            let p = p.as_str().expect("string");
            assert!(
                p.parse::<crate::policy::ToolPattern>().is_err(),
                "accepted {p:?}"
            );
        }
    }
}

// ------------------------------------------------------------------ invite --

fn invite_inputs() -> Vec<Value> {
    vec![
        json!({"name": "zeros", "bytes": hx(&[0u8; 16])}),
        json!({"name": "ones", "bytes": hx(&[0xFFu8; 16])}),
        json!({
            "name": "pseudo-random",
            "bytes": hx(&det::<16>("invite")),
        }),
        json!({
            "name": "ones-and-zeros",
            "bytes": hx(&*super::invite::InviteCode::new("1010101010101010101010101O")
                .canonical()
                .expect("a valid code")),
        }),
        json!({
            "name": "rejected",
            "invalid": [
                "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZX",
                "KLAV-00000-00000-00000-00000-000001",
                "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZW",
                "KLAV-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZWW",
                "KLAV-UZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZW",
                "KLAV-ZZZZZ_ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZW",
                "XLAVZZZZZZZZZZZZZZZZZZZZZZZZZW",
                "",
            ],
        }),
    ]
}

/// Other spellings of a code that must canonicalize to the same bytes:
/// lowercase, without the prefix or the dashes, with spaces, and with the
/// `I`/`L`/`O` aliases where the code has `1` or `0`.
fn invite_spellings(code: &str) -> Vec<String> {
    let bare = code[super::invite::PREFIX.len()..].replace('-', "");
    let aliased: String = code[super::invite::PREFIX.len()..]
        .chars()
        .map(|c| match c {
            '1' => 'l',
            '0' => 'O',
            c => c,
        })
        .collect();
    vec![
        code.to_lowercase(),
        bare.clone(),
        format!(
            "klav {}",
            code[super::invite::PREFIX.len()..].replace('-', " ")
        ),
        format!("KLAV-{aliased}"),
    ]
}

fn invite_compute(case: &Value) -> Value {
    if case.get("invalid").is_some() {
        return json!({});
    }
    let bytes = array::<16>(case, "bytes");
    let code = super::invite::InviteCode::from_bytes(&bytes);
    json!({
        "code": code.expose(),
        "spellings": invite_spellings(code.expose()),
        "digest": hx(&super::invite::digest_bytes(&bytes)),
    })
}

fn invite_check(case: &Value) {
    if let Some(invalid) = case.get("invalid") {
        for text in invalid.as_array().expect("invalid") {
            let text = text.as_str().expect("string");
            assert!(
                super::invite::InviteCode::new(text).canonical().is_err(),
                "accepted {text:?}"
            );
        }
        return;
    }
    let digest = bytes(case, "digest");
    let mut spellings = vec![text(case, "code").to_owned()];
    for s in case["spellings"].as_array().expect("spellings") {
        spellings.push(s.as_str().expect("string").to_owned());
    }
    for spelling in spellings {
        let code = super::invite::InviteCode::new(spelling.clone());
        assert_eq!(
            code.canonical().ok().map(|b| *b),
            Some(array::<16>(case, "bytes")),
            "{spelling}"
        );
        assert_eq!(code.digest().ok().map(|d| d.to_vec()), Some(digest.clone()));
    }
}

fn render(file: &VectorFile) -> Value {
    let cases: Vec<Value> = (file.inputs)()
        .iter()
        .map(|i| with_outputs(i, (file.compute)(i)))
        .collect();
    json!({
        "description": file.description,
        "spec": format!("docs/especificacion-cripto.md {}", file.spec),
        "format_version": 1,
        "encoding": "Los campos binarios van en hexadecimal; las cadenas de texto en UTF-8.",
        "cases": cases,
    })
}

#[test]
fn vectors_match_spec() {
    let regenerate = std::env::var_os("KLAV_REGEN_VECTORS").is_some();
    for file in files() {
        let path = dir().join(format!("{}.json", file.name));
        if regenerate {
            let mut text = serde_json::to_string_pretty(&render(&file)).expect("serializes");
            text.push('\n');
            std::fs::write(&path, text).expect("writes vector file");
        }
        let stored: Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("missing {}", path.display())),
        )
        .expect("valid JSON");
        let cases = stored["cases"].as_array().expect("cases");
        assert!(!cases.is_empty(), "{}: no cases", file.name);
        for case in cases {
            let outputs = (file.compute)(case);
            for (key, value) in outputs.as_object().expect("object") {
                assert_eq!(
                    &case[key],
                    value,
                    "{} / {} / {key}",
                    file.name,
                    text(case, "name")
                );
            }
            (file.check)(case);
        }
    }
}
