//! Sign-up, log-in and unlock.

use klav_core::crypto::CryptoError;
use klav_core::crypto::identity::{IdentityKeyPair, PublicIdentity, open_identity, seal_identity};
use klav_core::crypto::kdf::{
    AccountKeys, KdfParams, MasterPassword, derive_account_keys, derive_kek,
};
use klav_core::crypto::keys::LocalKey;
use klav_core::crypto::local::{
    LocalContext, derive_local_key, open_local_identity, seal_local_identity,
};
use klav_core::crypto::opaque;
use klav_core::crypto::secret_key::{EmergencyKit, SecretKey};
use klav_core::ids::AccountId;
use klav_proto::Blob;
use klav_proto::auth::{
    DeviceInfo, DeviceKind, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, PreloginRequest, PreloginResponse, RegisterFinishRequest,
    RegisterFinishResponse, RegisterStartRequest, RegisterStartResponse,
};
use reqwest::{Method, StatusCode};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::api::{self, Api};
use crate::deletion::DeletionMarker;
use crate::error::{ClientError, ClientResult};
use crate::home::{Home, write_private};
use crate::session::Unlocked;
use crate::state::{AccountFile, Cache, Tokens};
use crate::url::ServerUrl;

/// Input of [`signup`].
pub struct SignupRequest {
    /// Server base URL (through the table of moves, ADR 0028 §4).
    pub server: String,
    /// Account e-mail.
    pub email: String,
    /// New master password (the caller asks for it twice).
    pub password: MasterPassword,
    /// Name of this device.
    pub device_name: String,
    /// Kind of this device.
    pub device_kind: DeviceKind,
}

/// Input of [`login`].
pub struct LoginRequest {
    /// Server base URL (through the table of moves, ADR 0028 §4).
    pub server: String,
    /// Account e-mail.
    pub email: String,
    /// Master password.
    pub password: MasterPassword,
    /// Secret Key (from the emergency kit).
    pub secret_key: SecretKey,
    /// Name of this device.
    pub device_name: String,
    /// Kind of this device.
    pub device_kind: DeviceKind,
}

fn normalise_email(email: &str) -> String {
    email.trim().to_lowercase()
}

fn refuse_existing(home: &Home) -> ClientResult<()> {
    match AccountFile::load(home) {
        Ok(a) => Err(ClientError::AlreadyLoggedIn(a.email)),
        Err(ClientError::NotLoggedIn) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Creates an account: generates the Secret Key, the KDF parameters and the
/// identity, registers with OPAQUE, logs this device in and creates the
/// "Personal" vault. Returns the unlocked account and the emergency kit
/// (which holds the Secret Key: show it to the user, never log it).
///
/// Prefer [`signup_with`], which hands the kit over before anything is
/// registered.
pub async fn signup(home: &Home, req: SignupRequest) -> ClientResult<(Unlocked, EmergencyKit)> {
    signup_with(home, req, |_| Ok(())).await
}

/// [`signup`], calling `deliver` with the emergency kit **before** the
/// account is registered: if it fails (say, the kit file cannot be
/// written), nothing exists on the server. Once registered, the account is
/// never lost for a later failure: the device state is saved, and a
/// "Personal" vault that cannot be created is a warning
/// (`klav vault create Personal`). `klav account kit` shows the kit again
/// from this device's files.
pub async fn signup_with(
    home: &Home,
    req: SignupRequest,
    deliver: impl FnOnce(&EmergencyKit) -> ClientResult<()>,
) -> ClientResult<(Unlocked, EmergencyKit)> {
    refuse_existing(home)?;
    let server = ServerUrl::parse(&crate::server::resolve(&req.server)?)?;
    let api = Api::new(server.clone())?;
    let email = normalise_email(&req.email);

    // Check whether the server advertises closed registration before delivering
    // the kit or deriving Argon2id keys (ADR 0028 §3). Servers without
    // `registration_open` fall through and let `/v1/auth/register/start` decide.
    if matches!(
        crate::server::registration_open(server.as_str()).await,
        Ok(Some(false))
    ) {
        return Err(ClientError::Invalid(
            crate::server::registration_closed_message(server.as_str()),
        ));
    }

    let account_id = AccountId::generate();
    let kit = EmergencyKit::new(
        email.clone(),
        account_id,
        server.as_str().to_owned(),
        SecretKey::generate(),
    );
    deliver(&kit)?;
    let secret_key = kit.secret_key();
    let params = KdfParams::generate();
    let keys = derive_account_keys(&req.password, secret_key, &params)?;
    let identity = IdentityKeyPair::generate();
    let sealed = seal_identity(keys.kek(), account_id, &identity);

    let (registration, request) = opaque::client_start_registration(keys.opaque_input())?;
    let start_res = api
        .send(
            Method::POST,
            "/v1/auth/register/start",
            None,
            Some(&RegisterStartRequest {
                email: email.clone(),
                registration_request: Blob::new(request),
                invite: None,
            }),
        )
        .await?;
    if start_res.status() == StatusCode::FORBIDDEN {
        return Err(ClientError::Invalid(
            crate::server::registration_closed_message(server.as_str()),
        ));
    }
    let start: RegisterStartResponse = api::json(start_res).await?;
    let upload =
        registration.finish(keys.opaque_input(), start.registration_response.as_bytes())?;
    let res = api
        .send(
            Method::POST,
            "/v1/auth/register/finish",
            None,
            Some(&RegisterFinishRequest {
                email: email.clone(),
                account_id,
                registration_upload: Blob::new(upload),
                kdf_params: Blob::new(params.encode()),
                public_identity: Blob::new(identity.public().encode().to_vec()),
                sealed_identity: Blob::new(sealed),
                invite: None,
            }),
        )
        .await?;
    if res.status() == StatusCode::FORBIDDEN {
        return Err(ClientError::Invalid(
            crate::server::registration_closed_message(server.as_str()),
        ));
    }
    if res.status() == StatusCode::CONFLICT {
        return Err(ClientError::Invalid(format!(
            "an account with {email} already exists on this server"
        )));
    }
    let _: RegisterFinishResponse = api::json(res).await?;

    let mut unlocked = finish_login(
        home,
        api,
        &email,
        keys,
        secret_key,
        &params,
        &req.device_name,
        req.device_kind,
    )
    .await?;
    if let Err(e) = unlocked.create_vault(crate::DEFAULT_VAULT).await {
        unlocked.push_warning(format!(
            "the account exists, but its \"{}\" vault was not created ({e}): \
             run `klav vault create {}`",
            crate::DEFAULT_VAULT,
            crate::DEFAULT_VAULT
        ));
    }
    Ok((unlocked, kit))
}

/// Logs this device in to an existing account and syncs it.
pub async fn login(home: &Home, req: LoginRequest) -> ClientResult<Unlocked> {
    refuse_existing(home)?;
    // An old emergency kit names an old URL: it goes through the table
    // of moves (ADR 0028 §4).
    let server = ServerUrl::parse(&crate::server::resolve(&req.server)?)?;
    let api = Api::new(server)?;
    let email = normalise_email(&req.email);
    let prelogin: PreloginResponse = api
        .call(
            Method::POST,
            "/v1/auth/prelogin",
            &PreloginRequest {
                email: email.clone(),
            },
        )
        .await?;
    // The production floor applies (threat T3): a server cannot make us
    // derive keys with weak parameters.
    let params = KdfParams::decode(prelogin.kdf_params.as_bytes())?;
    let keys = derive_account_keys(&req.password, &req.secret_key, &params)?;
    let mut unlocked = finish_login(
        home,
        api,
        &email,
        keys,
        &req.secret_key,
        &params,
        &req.device_name,
        req.device_kind,
    )
    .await?;
    unlocked.sync().await?;
    Ok(unlocked)
}

/// OPAQUE login with already derived keys, then persist everything.
#[allow(clippy::too_many_arguments)]
async fn finish_login(
    home: &Home,
    api: Api,
    email: &str,
    keys: AccountKeys,
    secret_key: &SecretKey,
    params: &KdfParams,
    device_name: &str,
    device_kind: DeviceKind,
) -> ClientResult<Unlocked> {
    let (kek, input) = keys.into_parts();
    let (client, ke1) = opaque::client_start_login(&input)?;
    let start: LoginStartResponse = api
        .call(
            Method::POST,
            "/v1/auth/login/start",
            &LoginStartRequest {
                email: email.to_owned(),
                credential_request: Blob::new(ke1),
            },
        )
        .await?;
    // A wrong password (or Secret Key) fails here, locally.
    let ke3 = client
        .finish(&input, start.credential_response.as_bytes())
        .map_err(|_| ClientError::WrongCredentials)?;
    let res = api
        .send(
            Method::POST,
            "/v1/auth/login/finish",
            None,
            Some(&LoginFinishRequest {
                login_id: start.login_id,
                credential_finalization: Blob::new(ke3),
                device: DeviceInfo {
                    id: None,
                    name: device_name.to_owned(),
                    kind: device_kind,
                },
            }),
        )
        .await?;
    if res.status() == StatusCode::UNAUTHORIZED {
        return Err(ClientError::WrongCredentials);
    }
    let body: LoginFinishResponse = api::json(res).await?;
    let keyset = body.account;
    // The e-mail is shown as the account's (`klav status`, the app): it
    // must be the one typed.
    if normalise_email(&keyset.email) != email {
        return Err(ClientError::Security(
            "the server answered with another account's e-mail".into(),
        ));
    }
    if KdfParams::decode(keyset.kdf_params.as_bytes())? != *params {
        return Err(ClientError::Invalid(
            "the server returned other KDF parameters than at pre-login".into(),
        ));
    }
    let public = PublicIdentity::decode(keyset.public_identity.as_bytes())?;
    // Opening the sealed identity proves the keyset is ours (threat T9).
    let identity = open_identity(
        &kek,
        keyset.account_id,
        &public,
        keyset.sealed_identity.as_bytes(),
    )?;

    let ctx = LocalContext {
        account: keyset.account_id,
        device: body.device_id,
    };
    let local_key = derive_local_key(&kek, &ctx);
    let account = AccountFile {
        v: 1,
        server: api.base().as_str().to_owned(),
        email: keyset.email,
        account_id: keyset.account_id,
        device_id: body.device_id,
        device_name: device_name.to_owned(),
        kdf_params: keyset.kdf_params,
        public_identity: keyset.public_identity,
        sealed_identity: keyset.sealed_identity,
        local_identity: Blob::new(seal_local_identity(&local_key, &ctx, &identity)),
    };
    home.ensure()?;
    let text = secret_key.to_text();
    let mut line = Zeroizing::new(text.expose_secret().as_bytes().to_vec());
    line.push(b'\n');
    write_private(&home.secret_key_path(), &line)?;
    let tokens = Tokens::from_wire(body.session);
    tokens.save(home, &local_key, &ctx)?;
    let cache = Cache::empty();
    cache.save(home, &local_key, &ctx)?;
    account.save(home)?;
    Ok(Unlocked::assemble(
        home.clone(),
        account,
        local_key,
        identity,
        api,
        tokens,
        cache,
    ))
}

pub(crate) fn read_secret_key(home: &Home) -> ClientResult<SecretKey> {
    let text = Zeroizing::new(
        std::fs::read_to_string(home.secret_key_path())
            .map_err(|_| ClientError::Corrupt("the secret-key file is missing".into()))?,
    );
    Ok(SecretKey::parse(text.trim())?)
}

pub(crate) fn open_rest(
    home: &Home,
    account: AccountFile,
    local_key: LocalKey,
    identity: IdentityKeyPair,
) -> ClientResult<Unlocked> {
    let ctx = account.local_context();
    let tokens = Tokens::load(home, &local_key, &ctx)?;
    let mut cache = Cache::load(home, &local_key, &ctx)?;
    let mut deletion = DeletionMarker::load(home, &local_key, &ctx);
    // A `cache.bin` written by a build that kept the deletion inside it:
    // the deletion moves to its own file, and the cache is written again
    // without it, so older readers open it (review finding 5).
    if let Some(legacy) = cache.legacy_deletion.take() {
        if deletion.asked.is_none() {
            deletion.asked = Some(legacy);
            deletion.save(home, &local_key, &ctx)?;
        }
        cache.save(home, &local_key, &ctx)?;
    }
    let api = Api::new(ServerUrl::parse(&account.server)?)?;
    let mut unlocked = Unlocked::assemble(
        home.clone(),
        account,
        local_key,
        identity,
        api,
        tokens,
        cache,
    );
    unlocked.deletion = deletion;
    Ok(unlocked)
}

/// Unlocks this device with the master password (offline: the server is
/// not contacted). Run [`Unlocked::sync`] afterwards.
pub fn unlock_with_password(home: &Home, password: &MasterPassword) -> ClientResult<Unlocked> {
    let account = AccountFile::load(home)?;
    let secret_key = read_secret_key(home)?;
    // Floor and ceiling apply to the locally stored parameters as well.
    let params = KdfParams::decode(account.kdf_params.as_bytes())?;
    let kek = derive_kek(password, &secret_key, &params)?;
    let public = PublicIdentity::decode(account.public_identity.as_bytes())?;
    let identity = open_identity(
        &kek,
        account.account_id,
        &public,
        account.sealed_identity.as_bytes(),
    )
    .map_err(|e| match e {
        CryptoError::Decryption => ClientError::WrongCredentials,
        other => other.into(),
    })?;
    let local_key = derive_local_key(&kek, &account.local_context());
    open_rest(home, account, local_key, identity)
}

/// Unlocks this device with its local key (from the platform keystore,
/// e.g. Touch ID).
pub fn unlock_with_local_key(home: &Home, local_key: LocalKey) -> ClientResult<Unlocked> {
    let account = AccountFile::load(home)?;
    let public = PublicIdentity::decode(account.public_identity.as_bytes())?;
    let identity = open_local_identity(
        &local_key,
        &account.local_context(),
        &public,
        account.local_identity.as_bytes(),
    )?;
    open_rest(home, account, local_key, identity)
}

/// Checks a master password against an unlocked session, as proof of
/// presence (ADR 0041 §2.3): the password counts only if, with this
/// device's Secret Key and the session's own parameters and context, it
/// derives the session's local key, which only that session holds.
///
/// [`unlock_with_password`] is no such proof: it opens whatever account the
/// files in the home describe, and a program of the person's user can put
/// a consistent set made under its own password there. Here the Secret Key
/// is the only input read from a file, and a replaced one derives another
/// key, so it is refused. A `klavd` holds one of these per session, apart
/// from the session itself, so a check needs no lock on the session.
pub struct PasswordCheck {
    home: Home,
    params: KdfParams,
    ctx: LocalContext,
    local_key: std::sync::Arc<LocalKey>,
}

impl PasswordCheck {
    /// `Ok` when `password` is this session's master password, else
    /// [`ClientError::WrongCredentials`]. Runs Argon2id once (about a
    /// second): keep it off the async workers.
    pub fn check(&self, password: &MasterPassword) -> ClientResult<()> {
        // Missing or unreadable: no proof, as for a wrong password.
        let secret_key = read_secret_key(&self.home).map_err(|_| ClientError::WrongCredentials)?;
        let matches = klav_core::crypto::local::password_derives_local_key(
            password,
            &secret_key,
            &self.params,
            &self.ctx,
            &self.local_key,
        )?;
        if matches {
            Ok(())
        } else {
            Err(ClientError::WrongCredentials)
        }
    }
}

impl Unlocked {
    /// What checks a master password against this session: see
    /// [`PasswordCheck`]. Its parameters and context are this session's,
    /// read when it unlocked, never the files' at the time of a check.
    pub fn password_check(&self) -> ClientResult<PasswordCheck> {
        Ok(PasswordCheck {
            home: self.home.clone(),
            params: KdfParams::decode(self.account.kdf_params.as_bytes())?,
            ctx: self.ctx,
            local_key: std::sync::Arc::clone(&self.local_key),
        })
    }
}

/// Files of an account on a device, as `forget_account` removes them.
pub(crate) const ACCOUNT_FILES: &[&str] = &[
    "account.json",
    "secret-key",
    "session.bin",
    "cache.bin",
    "session.lock",
    // Generated passwords not uploaded yet (ADR 0022 §2): sealed with this
    // account's local key, they would also make a later account on this
    // device fail to open its outbox.
    crate::history::OUTBOX_FILE,
    // Passkeys the iOS extension registered or used without network (ADR
    // 0020 §11): sealed with this local key too, they would make every
    // passkey use of a later sign-in on this device fail.
    crate::passkey_outbox::PASSKEY_OUTBOX_FILE,
    // (and any set-aside outbox, `outbox.unreadable-<ms>.bin`: below)
    // The audit head this account pinned (`klav log verify`).
    "audit-head.json",
    // The breach check's opt-in (ADR 0022 §4): a later account on this
    // device must turn it on itself before anything goes to HIBP. The
    // `health` feature's `SETTINGS_FILE`, named here for builds without it.
    "health.json",
    // The URL the account moved off (ADR 0028 §4): a later account on this
    // device was never there.
    crate::server::MOVED_FILE,
    // The signed pauses `klavd` last learned (ADR 0033 §7.2): of this
    // account only.
    crate::pause::SIGNED_PAUSES_FILE,
    // The audit chain this device downloaded (ADR 0033 §8.4), sealed with
    // this local key.
    crate::audit::CHAIN_FILE,
    // What this device knows of the account's deletion (ADR 0037 A3),
    // sealed with this local key.
    crate::deletion::DELETION_FILE,
    // The key changes a revocation still owes (ADR 0033, amendment of
    // 2026-11-10, F8): of this account only, sealed with this local key.
    crate::revoke::REVOCATIONS_FILE,
    // The proxy heartbeat watermarks (ADR 0036 E3.3): of this account
    // only, sealed with this local key.
    crate::sandboxes::SANDBOX_MARKS_FILE,
];

/// Removes this device's copy of the account (sign-out). The session must
/// already be ended on the server. Platform files (a biometric enrolment)
/// are the caller's.
pub fn forget_account(home: &Home) {
    for name in ACCOUNT_FILES {
        let _ = std::fs::remove_file(home.file(name));
    }
    for aside in crate::passkey_outbox::unreadable_outboxes(home) {
        let _ = std::fs::remove_file(aside);
    }
}

/// The account set up in `home`, if any (no secrets needed).
pub fn account(home: &Home) -> ClientResult<AccountFile> {
    AccountFile::load(home)
}

/// The emergency kit of the account on this device, rebuilt from what is
/// in `home` (spec §4.2) with the server it uses today (ADR 0028 §4). The
/// master password is checked first (offline), because the kit shows the
/// Secret Key: show it to the person, never log it.
pub fn emergency_kit(home: &Home, password: &MasterPassword) -> ClientResult<EmergencyKit> {
    let unlocked = unlock_with_password(home, password)?;
    let account = unlocked.account();
    Ok(EmergencyKit::new(
        account.email.clone(),
        account.account_id,
        account.server.clone(),
        read_secret_key(home)?,
    ))
}

/// Moves the account on this device to `server` by hand (ADR 0028 §4,
/// also the way out when the domain is down, §6).
///
/// Runs a full OPAQUE login against the new URL with the master password,
/// for this same device, and keeps the new URL only if the account ID, the
/// public identity, the KDF parameters and the device match the local
/// account. OPAQUE gives a fake server nothing to attack offline (T2), and
/// the current session's tokens never go to an unchecked host. The URL is
/// taken as typed: the table of moves does not apply, so the account can
/// go back to an old URL. Returns the canonical URL saved.
pub async fn set_server(
    home: &Home,
    password: &MasterPassword,
    server: &str,
    device_kind: DeviceKind,
) -> ClientResult<String> {
    let account = AccountFile::load(home)?;
    let secret_key = read_secret_key(home)?;
    let target = ServerUrl::parse(server)?;
    let api = Api::new(target.clone())?;
    let params = KdfParams::decode(account.kdf_params.as_bytes())?;
    let prelogin: PreloginResponse = api
        .call(
            Method::POST,
            "/v1/auth/prelogin",
            &PreloginRequest {
                email: account.email.clone(),
            },
        )
        .await?;
    // Another server's parameters would be a decoy (an unknown account):
    // nothing is derived with them.
    if KdfParams::decode(prelogin.kdf_params.as_bytes())? != params {
        return Err(ClientError::Invalid(format!(
            "{} does not have this account",
            target.as_str()
        )));
    }
    let keys = derive_account_keys(password, &secret_key, &params)?;
    let (kek, input) = keys.into_parts();
    let (client, ke1) = opaque::client_start_login(&input)?;
    let start: LoginStartResponse = api
        .call(
            Method::POST,
            "/v1/auth/login/start",
            &LoginStartRequest {
                email: account.email.clone(),
                credential_request: Blob::new(ke1),
            },
        )
        .await?;
    let ke3 = client
        .finish(&input, start.credential_response.as_bytes())
        .map_err(|_| ClientError::WrongCredentials)?;
    let res = api
        .send(
            Method::POST,
            "/v1/auth/login/finish",
            None,
            Some(&LoginFinishRequest {
                login_id: start.login_id,
                credential_finalization: Blob::new(ke3),
                device: DeviceInfo {
                    id: Some(account.device_id),
                    name: account.device_name.clone(),
                    kind: device_kind,
                },
            }),
        )
        .await?;
    if res.status() == StatusCode::UNAUTHORIZED {
        return Err(ClientError::WrongCredentials);
    }
    let body: LoginFinishResponse = api::json(res).await?;
    let keyset = &body.account;
    let same = keyset.account_id == account.account_id
        && keyset.public_identity == account.public_identity
        && KdfParams::decode(keyset.kdf_params.as_bytes())? == params
        && body.device_id == account.device_id;
    let public = PublicIdentity::decode(account.public_identity.as_bytes())?;
    // The sealed identity must open with our KEK too (T9).
    let opens = open_identity(
        &kek,
        account.account_id,
        &public,
        keyset.sealed_identity.as_bytes(),
    )
    .is_ok();
    if !(same && opens) {
        // Best effort: end the session this login opened over there.
        let _ = api
            .send::<()>(
                Method::POST,
                "/v1/auth/logout",
                Some(&body.session.access_token),
                None,
            )
            .await;
        return Err(ClientError::Security(format!(
            "{} answered for another account or device; the account stays on {}",
            target.as_str(),
            account.server
        )));
    }
    let ctx = account.local_context();
    let local_key = derive_local_key(&kek, &ctx);
    let _lock = home.lock()?;
    Tokens::from_wire(body.session).save(home, &local_key, &ctx)?;
    let mut moved = account;
    moved.server = target.as_str().to_owned();
    moved.save(home)?;
    Ok(moved.server)
}
