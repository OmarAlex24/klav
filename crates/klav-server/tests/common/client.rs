//! A minimal Klav client for tests: everything secret is derived and
//! encrypted here with `klav-core`, exactly like a real client would, and
//! only OPAQUE messages and ciphertext are sent to the server.

use klav_core::crypto::identity::{IdentityKeyPair, PublicIdentity, open_identity, seal_identity};
use klav_core::crypto::kdf::{KdfParams, MasterPassword, derive_account_keys};
use klav_core::crypto::opaque;
use klav_core::crypto::random;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::ids::{AccountId, DeviceId};
use klav_proto::Blob;
use klav_proto::auth::{
    DeviceInfo, DeviceKind, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, PreloginRequest, PreloginResponse, RegisterFinishRequest,
    RegisterStartRequest, RegisterStartResponse, SessionTokens,
};
use reqwest::{Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::TestServer;

/// What a person knows (password) and keeps (Secret Key, emergency kit).
pub struct Credentials {
    pub email: String,
    pub password: String,
    pub secret_key_text: String,
    pub account_id: AccountId,
}

/// A logged-in device with the unlocked identity.
pub struct Session {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub tokens: SessionTokens,
    pub identity: IdentityKeyPair,
}

fn fast_params() -> KdfParams {
    KdfParams::insecure_for_tests(64, 1, 1, random::array())
}

impl TestServer {
    pub async fn post_json<T: Serialize + ?Sized>(&self, path: &str, body: &T) -> Response {
        self.http
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .expect("request")
    }

    pub async fn post_ok<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> R {
        let res = self.post_json(path, body).await;
        let status = res.status();
        assert!(status.is_success(), "POST {path} -> {status}");
        res.json().await.expect("json body")
    }

    /// Signs up a new account with fast (test-only) KDF parameters.
    pub async fn signup(&self, email: &str, password: &str) -> Credentials {
        self.try_signup(email, password)
            .await
            .expect("sign-up succeeds")
    }

    /// Like [`TestServer::signup`], returning the status of
    /// `register/finish` on failure.
    pub async fn try_signup(&self, email: &str, password: &str) -> Result<Credentials, StatusCode> {
        self.try_signup_declaring(email, password, None).await
    }

    /// Signs up deriving the keys with fast parameters but sending
    /// `declared` (if any) as the account's `kdf_params`. The server cannot
    /// tell the difference, which lets the KDF floor test avoid a
    /// production-cost Argon2id run.
    pub async fn try_signup_declaring(
        &self,
        email: &str,
        password: &str,
        declared: Option<KdfParams>,
    ) -> Result<Credentials, StatusCode> {
        let secret_key = SecretKey::generate();
        let params = fast_params();
        let account_id = AccountId::generate();
        let keys = derive_account_keys(&MasterPassword::new(password), &secret_key, &params)
            .expect("derive");
        let identity = IdentityKeyPair::generate();
        let sealed = seal_identity(keys.kek(), account_id, &identity);

        let (state, request) =
            opaque::client_start_registration(keys.opaque_input()).expect("start");
        let start: RegisterStartResponse = self
            .post_ok(
                "/v1/auth/register/start",
                &RegisterStartRequest {
                    email: email.into(),
                    registration_request: Blob::new(request),
                    invite: None,
                },
            )
            .await;
        let upload = state
            .finish(keys.opaque_input(), start.registration_response.as_bytes())
            .expect("finish");
        let res = self
            .post_json(
                "/v1/auth/register/finish",
                &RegisterFinishRequest {
                    email: email.into(),
                    account_id,
                    registration_upload: Blob::new(upload),
                    kdf_params: Blob::new(declared.as_ref().unwrap_or(&params).encode()),
                    public_identity: Blob::new(identity.public().encode().to_vec()),
                    sealed_identity: Blob::new(sealed),
                    invite: None,
                },
            )
            .await;
        if res.status() != StatusCode::CREATED {
            return Err(res.status());
        }
        use secrecy::ExposeSecret;
        Ok(Credentials {
            email: email.into(),
            password: password.into(),
            secret_key_text: secret_key.to_text().expose_secret().to_owned(),
            account_id,
        })
    }

    /// Runs `register/start` with `invite` and builds the matching
    /// `register/finish` body (ADR 0048), without sending it. `Err` is the
    /// status of a refused start.
    pub async fn prepare_signup(
        &self,
        email: &str,
        password: &str,
        invite: Option<&str>,
    ) -> Result<RegisterFinishRequest, StatusCode> {
        use klav_core::crypto::invite::InviteCode;
        let secret_key = SecretKey::generate();
        let params = fast_params();
        let account_id = AccountId::generate();
        let keys = derive_account_keys(&MasterPassword::new(password), &secret_key, &params)
            .expect("derive");
        let identity = IdentityKeyPair::generate();
        let sealed = seal_identity(keys.kek(), account_id, &identity);
        let (state, request) =
            opaque::client_start_registration(keys.opaque_input()).expect("start");
        let res = self
            .post_json(
                "/v1/auth/register/start",
                &RegisterStartRequest {
                    email: email.into(),
                    registration_request: Blob::new(request),
                    invite: invite.map(InviteCode::new),
                },
            )
            .await;
        if res.status() != StatusCode::OK {
            return Err(res.status());
        }
        let start: RegisterStartResponse = res.json().await.expect("start body");
        let upload = state
            .finish(keys.opaque_input(), start.registration_response.as_bytes())
            .expect("finish");
        Ok(RegisterFinishRequest {
            email: email.into(),
            account_id,
            registration_upload: Blob::new(upload),
            kdf_params: Blob::new(params.encode()),
            public_identity: Blob::new(identity.public().encode().to_vec()),
            sealed_identity: Blob::new(sealed),
            invite: invite.map(InviteCode::new),
        })
    }

    /// Sends a prepared `register/finish`; the response.
    pub async fn finish_signup(&self, body: &RegisterFinishRequest) -> Response {
        self.post_json("/v1/auth/register/finish", body).await
    }

    /// Signs up with `invite`: the status of the first refused step, or
    /// the new account's ID.
    pub async fn signup_with_invite(
        &self,
        email: &str,
        invite: Option<&str>,
    ) -> Result<AccountId, StatusCode> {
        let body = self.prepare_signup(email, "pw", invite).await?;
        let res = self.finish_signup(&body).await;
        if res.status() == StatusCode::CREATED {
            Ok(body.account_id)
        } else {
            Err(res.status())
        }
    }

    /// Runs the OPAQUE login. Returns the raw `login/finish` response.
    pub async fn login_raw(
        &self,
        creds: &Credentials,
        password: &str,
        device: DeviceInfo,
    ) -> (Response, Option<klav_core::crypto::keys::Kek>) {
        let prelogin: PreloginResponse = self
            .post_ok(
                "/v1/auth/prelogin",
                &PreloginRequest {
                    email: creds.email.clone(),
                },
            )
            .await;
        let params = KdfParams::decode_insecure_for_tests(prelogin.kdf_params.as_bytes())
            .expect("kdf params");
        let secret_key = SecretKey::parse(&creds.secret_key_text).expect("secret key");
        let keys = derive_account_keys(&MasterPassword::new(password), &secret_key, &params)
            .expect("derive");
        let (kek, input) = keys.into_parts();
        let (client, ke1) = opaque::client_start_login(&input).expect("ke1");
        let start: LoginStartResponse = self
            .post_ok(
                "/v1/auth/login/start",
                &LoginStartRequest {
                    email: creds.email.clone(),
                    credential_request: Blob::new(ke1),
                },
            )
            .await;
        // With a wrong password the client cannot open the envelope; send
        // garbage so the server-side failure path is exercised too.
        let (ke3, kek) = match client.finish(&input, start.credential_response.as_bytes()) {
            Ok(ke3) => (ke3, Some(kek)),
            Err(_) => (vec![0u8; 64], None),
        };
        let res = self
            .post_json(
                "/v1/auth/login/finish",
                &LoginFinishRequest {
                    login_id: start.login_id,
                    credential_finalization: Blob::new(ke3),
                    device,
                },
            )
            .await;
        (res, kek)
    }

    /// Logs in as a new device and unlocks the identity.
    pub async fn login(&self, creds: &Credentials, device_name: &str) -> Session {
        self.login_device(creds, device_name, None).await
    }

    pub async fn login_device(
        &self,
        creds: &Credentials,
        device_name: &str,
        device_id: Option<DeviceId>,
    ) -> Session {
        let (res, kek) = self
            .login_raw(
                creds,
                &creds.password,
                DeviceInfo {
                    id: device_id,
                    name: device_name.into(),
                    kind: DeviceKind::Other,
                },
            )
            .await;
        assert_eq!(res.status(), StatusCode::OK, "login");
        let body: LoginFinishResponse = res.json().await.expect("login body");
        assert_eq!(body.account.account_id, creds.account_id);
        let public = PublicIdentity::decode(body.account.public_identity.as_bytes()).expect("pk");
        let identity = open_identity(
            &kek.expect("kek"),
            body.account.account_id,
            &public,
            body.account.sealed_identity.as_bytes(),
        )
        .expect("identity opens with the KEK");
        Session {
            account_id: body.account.account_id,
            device_id: body.device_id,
            tokens: body.session,
            identity,
        }
    }

    /// The first half of the reauthentication that deletes the account
    /// (ADR 0037 §1), with `password` and the kit's Secret Key, as a real
    /// client does: the KDF parameters come from `GET /v1/account`. Returns
    /// the handle and the KE3 to send, or the `start` response if it fails.
    /// With a wrong password the client cannot open the envelope; the KE3
    /// is garbage, so the server-side failure path runs too.
    // The caller reads the failed response as it came: a test helper.
    #[allow(clippy::result_large_err)]
    pub async fn reauth_start(
        &self,
        session: &Session,
        creds: &Credentials,
        password: &str,
    ) -> Result<(String, Vec<u8>), Response> {
        let account: klav_proto::auth::AccountKeyset = self
            .get_auth(session, "/v1/account")
            .send()
            .await
            .expect("request")
            .json()
            .await
            .expect("account");
        let params = KdfParams::decode_insecure_for_tests(account.kdf_params.as_bytes())
            .expect("kdf params");
        let secret_key = SecretKey::parse(&creds.secret_key_text).expect("secret key");
        let keys = derive_account_keys(&MasterPassword::new(password), &secret_key, &params)
            .expect("derive");
        let (client, ke1) = opaque::client_start_login(keys.opaque_input()).expect("ke1");
        let res = self
            .post_auth(session, "/v1/account/delete/start")
            .json(&klav_proto::auth::AccountDeleteStartRequest {
                credential_request: Blob::new(ke1),
            })
            .send()
            .await
            .expect("request");
        if res.status() != StatusCode::OK {
            return Err(res);
        }
        let start: klav_proto::auth::AccountDeleteStartResponse =
            res.json().await.expect("start body");
        let ke3 = client
            .finish(keys.opaque_input(), start.credential_response.as_bytes())
            .unwrap_or_else(|_| vec![0u8; 64]);
        Ok((start.handle, ke3))
    }

    /// The second half of the reauthentication.
    pub async fn reauth_finish(&self, session: &Session, handle: &str, ke3: &[u8]) -> Response {
        self.post_auth(session, "/v1/account/delete/finish")
            .json(&klav_proto::auth::AccountDeleteFinishRequest {
                handle: handle.into(),
                credential_finalization: Blob::new(ke3.to_vec()),
            })
            .send()
            .await
            .expect("request")
    }

    /// Asks to delete the account with the right password.
    pub async fn ask_deletion(
        &self,
        session: &Session,
        creds: &Credentials,
    ) -> klav_proto::auth::AccountDeletion {
        let (handle, ke3) = self
            .reauth_start(session, creds, &creds.password)
            .await
            .unwrap_or_else(|res| panic!("deletion start -> {}", res.status()));
        let res = self.reauth_finish(session, &handle, &ke3).await;
        assert_eq!(res.status(), StatusCode::ACCEPTED, "deletion finish");
        res.json().await.expect("deletion body")
    }

    /// Cancels the deletion; returns the status.
    pub async fn cancel_deletion(&self, session: &Session) -> StatusCode {
        self.post_auth(session, "/v1/account/delete/cancel")
            .send()
            .await
            .expect("request")
            .status()
    }

    pub fn get_auth(&self, session: &Session, path: &str) -> reqwest::RequestBuilder {
        self.http
            .get(self.url(path))
            .bearer_auth(&session.tokens.access_token)
    }

    pub fn post_auth(&self, session: &Session, path: &str) -> reqwest::RequestBuilder {
        self.http
            .post(self.url(path))
            .bearer_auth(&session.tokens.access_token)
    }

    pub fn put_auth(&self, session: &Session, path: &str) -> reqwest::RequestBuilder {
        self.http
            .put(self.url(path))
            .bearer_auth(&session.tokens.access_token)
    }

    pub fn delete_auth(&self, session: &Session, path: &str) -> reqwest::RequestBuilder {
        self.http
            .delete(self.url(path))
            .bearer_auth(&session.tokens.access_token)
    }
}
