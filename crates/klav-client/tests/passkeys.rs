//! Passkeys against the real server (ADR 0020): create in a new login,
//! sign in, the rules for the same account and `excludeCredentials`, the
//! hand-off to the browser, and a second device that signs with the
//! passkey the first created.

mod common;

use common::ServerProcess;
use klav_client::passkeys::{PasskeyCreateOutcome, PasskeyCreateRequest};
use klav_client::{ClientError, Home, ItemFilter, LoginRequest, SignupRequest, login, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::passkey::verify_es256;
use klav_core::crypto::secret_key::SecretKey;
use klav_core::passkey::webauthn::{client_data_hash, rp_id_hash};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const B64: data_encoding::Encoding = data_encoding::BASE64URL_NOPAD;

fn b64(text: &str) -> Vec<u8> {
    B64.decode(text.as_bytes()).expect("base64url")
}

fn request(user: &[u8], name: &str) -> PasskeyCreateRequest {
    PasskeyCreateRequest {
        origin: "https://login.shop.example".into(),
        rp_id: Some("shop.example".into()),
        rp_name: Some("Shop".into()),
        user_id: B64.encode(user),
        user_name: name.into(),
        user_display_name: Some("Ana".into()),
        challenge: B64.encode(b"create-challenge-0123456789"),
        ..PasskeyCreateRequest::default()
    }
}

fn created(outcome: PasskeyCreateOutcome) -> klav_client::passkeys::PasskeyRegistration {
    match outcome {
        PasskeyCreateOutcome::Created(r) => *r,
        other => panic!("expected a created passkey, got {other:?}"),
    }
}

/// Verifies an assertion the way a relying party does.
fn verify(public_key_spki: &[u8], assertion: &klav_client::passkeys::PasskeyAssertion) {
    let point = &public_key_spki[public_key_spki.len() - 65..];
    let client_data = b64(&assertion.client_data_json);
    let mut message = b64(&assertion.authenticator_data);
    message.extend_from_slice(&client_data_hash(&client_data));
    verify_es256(point, &message, &b64(&assertion.signature)).expect("assertion verifies");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_sign_in_and_a_second_device() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home_a = Home::at(dir.path().join("a"));
    let (mut a, kit) = signup(
        &home_a,
        SignupRequest {
            server: server.url.clone(),
            email: "pk@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let secret_key = kit.secret_key().to_text().expose_secret().to_owned();

    // Nothing yet for the site.
    let none = a
        .passkey_candidates(
            "https://login.shop.example/sign-in",
            Some("shop.example"),
            &[],
        )
        .unwrap();
    assert_eq!(none.rp_id.as_deref(), Some("shop.example"));
    assert!(none.candidates.is_empty());

    // Create: a new login, titled after rp.name, with the page and the rpId.
    let reg = created(
        a.passkey_create(&request(b"user-ana", "ana"), true)
            .await
            .unwrap(),
    );
    assert_eq!(reg.title, "Shop");
    assert_eq!(reg.public_key_algorithm, -7);
    assert_eq!(reg.transports, ["internal", "hybrid"]);
    assert_eq!(b64(&reg.credential_id).len(), 16);
    let auth_data = b64(&reg.authenticator_data);
    assert_eq!(&auth_data[..32], &rp_id_hash("shop.example"));
    assert_eq!(auth_data[32], 0x5d, "UP UV BE BS AT");
    let client_data: serde_json::Value =
        serde_json::from_slice(&b64(&reg.client_data_json)).unwrap();
    assert_eq!(client_data["type"], "webauthn.create");
    assert_eq!(client_data["origin"], "https://login.shop.example");
    assert_eq!(client_data["crossOrigin"], false);
    let attestation = b64(&reg.attestation_object);
    assert!(
        attestation
            .windows(auth_data.len())
            .any(|w| w == auth_data.as_slice())
    );
    let view = a.view_item(&reg.item.to_string(), false).unwrap();
    assert_eq!(
        view.summary.urls,
        ["https://login.shop.example", "https://shop.example"]
    );
    assert_eq!(view.summary.username.as_deref(), Some("ana"));
    let summary = view.summary.passkey.clone().expect("passkey summary");
    assert_eq!(summary.rp_id, "shop.example");
    assert_eq!(summary.credential_id, reg.credential_id);

    // Sign in: the candidate, then an assertion a relying party accepts.
    let found = a
        .passkey_candidates("https://shop.example", None, &[])
        .unwrap();
    assert_eq!(found.candidates.len(), 1);
    assert_eq!(found.candidates[0].item, reg.item);
    assert_eq!(found.candidates[0].user_name, "ana");
    let public_key = b64(&reg.public_key);
    let challenge = B64.encode(b"get-challenge-0123456789abcdef");
    let assertion = a
        .passkey_get(
            "https://shop.example",
            None,
            &challenge,
            &reg.item.to_string(),
            true,
        )
        .unwrap();
    verify(&public_key, &assertion);
    assert_eq!(b64(&assertion.user_handle), b"user-ana");
    assert_eq!(assertion.credential_id, reg.credential_id);
    let auth = b64(&assertion.authenticator_data);
    assert_eq!(auth.len(), 37);
    assert_eq!(auth[32], 0x1d);
    assert_eq!(&auth[33..], &[0, 0, 0, 0], "signCount stays 0");
    let cd: serde_json::Value = serde_json::from_slice(&b64(&assertion.client_data_json)).unwrap();
    assert_eq!(cd["type"], "webauthn.get");
    assert_eq!(cd["challenge"], challenge);
    assert_eq!(cd["origin"], "https://shop.example");
    // Without verification, UV is 0.
    let unverified = a
        .passkey_get(
            "https://shop.example",
            None,
            &challenge,
            &reg.item.to_string(),
            false,
        )
        .unwrap();
    assert_eq!(b64(&unverified.authenticator_data)[32], 0x19);

    // allowCredentials narrows; an unknown one leaves nothing.
    let other = B64.encode(&[9u8; 16]);
    assert!(
        a.passkey_candidates("https://shop.example", None, std::slice::from_ref(&other))
            .unwrap()
            .candidates
            .is_empty()
    );
    assert_eq!(
        a.passkey_candidates(
            "https://shop.example",
            None,
            std::slice::from_ref(&reg.credential_id)
        )
        .unwrap()
        .candidates
        .len(),
        1
    );

    // Another site, a lookalike or a parent domain: no candidate, no signature.
    for origin in ["https://shop.example.evil", "https://other.example"] {
        assert!(
            a.passkey_candidates(origin, None, &[])
                .unwrap()
                .candidates
                .is_empty()
        );
        assert!(matches!(
            a.passkey_get(origin, None, &challenge, &reg.item.to_string(), true),
            Err(ClientError::NotFound(_))
        ));
    }
    // A public suffix or an insecure origin: hand it to the browser.
    let browser = a
        .passkey_candidates("https://shop.example", Some("example"), &[])
        .unwrap();
    assert!(browser.rp_id.is_none() && browser.candidates.is_empty());
    assert!(
        a.passkey_candidates("http://shop.example", None, &[])
            .unwrap()
            .rp_id
            .is_none()
    );
    let mut public_suffix = request(b"user-ana", "ana");
    public_suffix.rp_id = Some("example".into());
    assert_eq!(
        a.passkey_create(&public_suffix, true).await.unwrap(),
        PasskeyCreateOutcome::Browser
    );
    assert!(matches!(
        a.passkey_get(
            "http://shop.example",
            None,
            &challenge,
            &reg.item.to_string(),
            true
        ),
        Err(ClientError::Denied(_))
    ));

    // The same account again: ask first; with `replace`, the login keeps
    // its ID and gets a new credential.
    let again = a
        .passkey_create(&request(b"user-ana", "ana"), true)
        .await
        .unwrap();
    assert_eq!(
        again,
        PasskeyCreateOutcome::Exists {
            item: reg.item,
            title: "Shop".into()
        }
    );
    let mut replace = request(b"user-ana", "ana");
    replace.replace = true;
    let replaced = created(a.passkey_create(&replace, true).await.unwrap());
    assert_eq!(replaced.item, reg.item);
    assert_ne!(replaced.credential_id, reg.credential_id);

    // excludeCredentials that Klav holds: InvalidStateError for the page.
    let mut excluded = request(b"user-bob", "bob");
    excluded.exclude_credentials = vec![replaced.credential_id.clone()];
    assert_eq!(
        a.passkey_create(&excluded, true).await.unwrap(),
        PasskeyCreateOutcome::Excluded
    );

    // Another account of the same site: another login, with a free title.
    let bob = created(
        a.passkey_create(&request(b"user-bob", "bob"), true)
            .await
            .unwrap(),
    );
    assert_ne!(bob.item, reg.item);
    assert_eq!(bob.title, "Shop (2)");
    let both = a
        .passkey_candidates("https://shop.example", None, &[])
        .unwrap();
    assert_eq!(both.candidates.len(), 2);
    // Bob's passkey does not go into Ana's login.
    let mut wrong = request(b"user-bob", "bob");
    wrong.item = Some(reg.item.to_string());
    assert!(matches!(
        a.passkey_create(&wrong, true).await,
        Err(ClientError::Invalid(_))
    ));

    // An existing login without a passkey can take one.
    let plain = a
        .create(&klav_client::ops::NewItem {
            kind: klav_core::model::item::ItemKind::Login,
            title: "Shop work".into(),
            vault: None,
            project: None,
            fields: vec![],
            urls: vec![],
            tags: vec![],
            notes: None,
            allow_duplicate: false,
        })
        .await
        .unwrap();
    let mut into = request(b"user-work", "work");
    into.item = Some(plain.id.to_string());
    let work = created(a.passkey_create(&into, true).await.unwrap());
    assert_eq!(work.item, plain.id);

    // A second device: logs in, syncs, sees the passkeys and signs with
    // Ana's (the key is sealed with the vault key, which it opens).
    let home_b = Home::at(dir.path().join("b"));
    let b = login(
        &home_b,
        LoginRequest {
            server: server.url.clone(),
            email: "pk@example.com".into(),
            password: MasterPassword::new(PASSWORD),
            secret_key: SecretKey::parse(&secret_key).unwrap(),
            device_name: "phone".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("log-in");
    assert_eq!(
        b.list_items(&ItemFilter::default())
            .unwrap()
            .iter()
            .filter(|s| s.passkey.is_some())
            .count(),
        3
    );
    let on_b = b
        .passkey_get(
            "https://shop.example",
            None,
            &challenge,
            &replaced.item.to_string(),
            true,
        )
        .unwrap();
    verify(&b64(&replaced.public_key), &on_b);
    // The old credential's public key no longer verifies.
    let point = &public_key[public_key.len() - 65..];
    let mut message = b64(&on_b.authenticator_data);
    message.extend_from_slice(&client_data_hash(&b64(&on_b.client_data_json)));
    assert!(verify_es256(point, &message, &b64(&on_b.signature)).is_err());
}
