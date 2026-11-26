//! Klav Cloud's enclave end to end (ADR 0051, layer 3), on any machine:
//! enclaves with a fake NSM (a test P-384 chain from `klav-core`'s
//! `nitro-testkit`), a mock of the repository's published manifests, and,
//! for the accounts, a real `klav-server`, the person's client and a real
//! `klav-forward`.
//!
//! The two "enclaves" of a hand-off are two [`Enclave`]s in this test
//! process, each with its own NSM, seed and API listener, talking over
//! loopback TCP exactly as two enclaves talk through their parents. No
//! build ever has a fake NSM outside a test.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use klav_client::issuers::IssuerSpec;
use klav_client::proxy_admin::PairingCheck;
use klav_client::{Home, SignupRequest, Unlocked, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::sandbox::{SandboxPackage, decode_package};
use klav_core::ids::{AccountId, AgentId};
use klav_core::model::item::{Item, ItemKind};
use klav_core::nitro::fake::{FakeAttestation, FakeNitro, FakeReleaseKey, test_pcrs};
use klav_core::nitro::{Pcr, derive_account_keys, hosted_service_keys, sign_hosted_registration};
use klav_forward::forward::{LEGACY_SERVER_NAME, Proxy as Forwarder, server_name_for};
use klav_proto::Blob;
use klav_proto::agent::{
    AgentStatus, HostedProxyStatus, HostedRegistrationProof, RegisterHostedAgent,
};
use klav_sdk::sandbox::{self as issuer_api, StartRequest};
use klav_sdk::{Agent, KeyStore, MemoryAgent, Registration};
use rustls::pki_types::ServerName;

use super::attest::FakeNsm;
use super::engine::{
    AttestAnswer, EnrollAnswer, EnrollRequest, HelloAnswer, HelloRequest, ManifestWire,
    SealRequest, StatusAnswer,
};
use super::registry::Enrollment;
use super::{Anchors, Enclave, EnclaveConfig, PublishedRepo, QuotaLimits, SignedManifest};
use crate::channel::ChannelLimits;
use crate::channel_e2e_tests::{Raw, claim_request, global_log, key, upstream_client};
use crate::e2e_tests::Upstream;
use crate::e2e_tests::common::ServerProcess;
use crate::transport::TcpAcceptor;

const ENDPOINT: &str = "proxy.klav.test";
const RELEASE: &str = "active";
const SECOND: Duration = Duration::from_secs(1);
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

fn now() -> u64 {
    super::now_ms()
}

// ------------------------------------------------------------- fixtures --

/// The PCR3 of Klav's instance role, in every approved manifest.
fn klav_role() -> Pcr {
    test_pcrs("klav instance role")[3]
}

/// An enclave image: its version and PCR0–3 (PCR3: the instance role it
/// runs under).
#[derive(Clone)]
struct Image {
    version: &'static str,
    pcrs: [Pcr; 4],
}

fn image(version: &'static str) -> Image {
    let mut pcrs = test_pcrs(&format!("image {version}"));
    pcrs[3] = klav_role();
    Image { version, pcrs }
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// A manifest in the ADR's field order, signed by `signer`, with `pad`
/// spaces at its end (two different byte strings for the same content).
fn manifest_with(
    seq: u64,
    images: &[(&Image, &str)],
    signer: &FakeReleaseKey,
    pad: usize,
) -> SignedManifest {
    let images: Vec<String> = images
        .iter()
        .map(|(img, status)| {
            format!(
                r#"{{"version":"{}","commit":"{}","arch":"aarch64","pcr0":"{}","pcr1":"{}","pcr2":"{}","status":"{status}"}}"#,
                img.version,
                hex(&img.pcrs[0][..20]),
                hex(&img.pcrs[0]),
                hex(&img.pcrs[1]),
                hex(&img.pcrs[2]),
            )
        })
        .collect();
    let json = format!(
        r#"{{"v":1,"seq":{seq},"seed_epoch":0,"issued_at_ms":{},"expires_at_ms":{},"endpoint":"{ENDPOINT}","server":"api.klav.dev","images":[{}],"parent_roles":["{}"],"egress":["203.0.113.10/32"]}}{}"#,
        now() - 60_000,
        now() + 20 * DAY_MS,
        images.join(","),
        hex(&klav_role()),
        " ".repeat(pad),
    );
    let bytes = json.into_bytes();
    SignedManifest {
        signature: signer.sign(&bytes),
        bytes,
    }
}

fn manifest(seq: u64, images: &[(&Image, &str)]) -> SignedManifest {
    manifest_with(seq, images, &FakeReleaseKey::new(RELEASE), 0)
}

/// The repository's files, by name.
type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// A mock of `raw.githubusercontent.com/…/deploy/nitro/manifests/`.
struct Repo {
    base: String,
    files: Files,
}

impl Repo {
    async fn start() -> Self {
        use axum::extract::{Path, State};
        let files: Files = Arc::default();
        let app = axum::Router::new()
            .route(
                "/manifests/{name}",
                axum::routing::get(
                    |State(files): State<Files>, Path(name): Path<String>| async move {
                        match files.lock().expect("lock").get(&name) {
                            Some(bytes) => (axum::http::StatusCode::OK, bytes.clone()),
                            None => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                        }
                    },
                ),
            )
            .with_state(Arc::clone(&files));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base: format!("http://{addr}/manifests/"),
            files,
        }
    }

    /// Commits `m` as `<seq>.json` and `<seq>.json.sig`.
    fn publish(&self, seq: u64, m: &SignedManifest) {
        let mut files = self.files.lock().expect("lock");
        files.insert(format!("{seq}.json"), m.bytes.clone());
        files.insert(
            format!("{seq}.json.sig"),
            format!("{}\n", m.signature_hex()).into_bytes(),
        );
    }
}

/// AWS, as the tests see it: one fake root for every enclave.
struct World {
    nitro: Arc<FakeNitro>,
    repo: Repo,
}

impl World {
    async fn new() -> Self {
        Self {
            nitro: Arc::new(FakeNitro::new("aws", now())),
            repo: Repo::start().await,
        }
    }

    fn config(&self, server: &str, limits: QuotaLimits) -> EnclaveConfig {
        EnclaveConfig {
            server: server.to_owned(),
            endpoint: ENDPOINT.into(),
            server_http: reqwest::Client::new(),
            upstream: upstream_client(),
            limits,
            channel_limits: ChannelLimits::default(),
        }
    }

    /// An enclave running `img` under this world's root.
    fn enclave_with(&self, img: &Image, server: &str, limits: QuotaLimits) -> Arc<Enclave> {
        Enclave::new(
            self.config(server, limits),
            Arc::new(FakeNsm {
                nitro: Arc::clone(&self.nitro),
                pcrs: img.pcrs,
            }),
            Anchors::test(self.nitro.root(), &[FakeReleaseKey::new(RELEASE).public()]),
            Arc::new(PublishedRepo::new(&self.repo.base, reqwest::Client::new()).expect("repo")),
        )
        .expect("enclave")
    }

    fn enclave(&self, img: &Image) -> Arc<Enclave> {
        self.enclave_with(img, "http://127.0.0.1:9", QuotaLimits::default())
    }
}

/// Serves the enclave's API on loopback; returns its base URL.
async fn api(enclave: &Arc<Enclave>) -> String {
    let listener = TcpAcceptor(
        tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind"),
    );
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(Arc::clone(enclave).serve_api(Box::new(listener)));
    format!("http://{addr}")
}

/// Serves the enclave's channel on loopback.
async fn channel(enclave: &Arc<Enclave>) -> SocketAddr {
    let listener = TcpAcceptor(
        tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind"),
    );
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(Arc::clone(enclave).serve_channel(Box::new(listener)));
    addr
}

fn enrollment(n: u8) -> Enrollment {
    Enrollment {
        account_id: AccountId::from_bytes([n; 16]),
        agent_id: AgentId::from_bytes([n + 100; 16]),
        generation: 0,
        email: format!("person{n}@example.com"),
        account_public_identity: Blob::new(
            klav_core::crypto::identity::IdentityKeyPair::generate()
                .public()
                .encode()
                .to_vec(),
        ),
        enrolled_at_ms: now(),
    }
}

/// An attestation for `account` through the API, and its `user_data`.
async fn attested_binding(base: &str, account: AccountId, nitro: &FakeNitro) -> Vec<u8> {
    let nonce = data_encoding::BASE64URL_NOPAD.encode(&[7; 32]);
    let answer: AttestAnswer =
        reqwest::get(format!("{base}/v1/attest?account={account}&nonce={nonce}"))
            .await
            .expect("attest")
            .json()
            .await
            .expect("json");
    let doc = klav_core::nitro::fake::verify_document_with(
        answer.document.as_bytes(),
        nitro.root(),
        now(),
    )
    .expect("verifies");
    assert_eq!(doc.nonce(), Some(&[7u8; 32][..]));
    doc.user_data().expect("user_data").to_vec()
}

// ------------------------------------------------------------- hand-off --

/// ADR 0051 §4.2 and §7.4: the seed and the enrollments move from an older
/// holder to a newer joiner (a rolling upgrade), and the joiner then
/// attests the same per-account keys; the other way round (a downgrade),
/// an image on someone else's role, a revoked image and an image nobody
/// listed get nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_seed_moves_only_to_an_approved_image_never_down() {
    let world = World::new().await;
    let old = image("0.12.0");
    let new = image("0.13.0");
    let m7 = manifest(7, &[(&new, "current"), (&old, "draining")]);
    world.repo.publish(7, &m7);

    let holder = world.enclave(&old);
    holder.start_fresh().expect("seed");
    assert_eq!(holder.load_manifest(m7.clone()), Ok(7));
    for n in [1, 2] {
        holder.enroll_for_test(enrollment(n)).expect("enroll");
    }
    let holder_api = api(&holder).await;
    let client = reqwest::Client::new();

    // Upgrade: the new image joins the old holder.
    let joiner = world.enclave(&new);
    joiner.join(&holder_api, &client).await.expect("join");
    assert!(joiner.has_seed());
    let mut names = joiner.channel_names();
    names.sort();
    let mut expected = holder.channel_names();
    expected.sort();
    assert_eq!(names, expected);
    assert_eq!(names.len(), 2);
    let joiner_api = api(&joiner).await;
    for n in [1, 2] {
        let account = enrollment(n).account_id;
        assert_eq!(
            attested_binding(&holder_api, account, &world.nitro).await,
            attested_binding(&joiner_api, account, &world.nitro).await,
            "both enclaves attest the same keys for account {n}"
        );
    }
    // A second hand-off to an enclave that already holds a seed: refused
    // before anything is asked.
    assert!(joiner.join(&holder_api, &client).await.is_err());

    // Downgrade: the old image asks a new holder.
    let new_holder = world.enclave(&new);
    new_holder.start_fresh().expect("seed");
    new_holder.load_manifest(m7.clone()).expect("manifest");
    let new_api = api(&new_holder).await;
    let down = world.enclave(&old);
    let err = down.join(&new_api, &client).await.expect_err("downgrade");
    assert!(err.contains("downgrade"), "{err}");
    assert!(!down.has_seed());

    // The approved image on someone else's instance role (PCR3).
    let mut elsewhere = new.clone();
    elsewhere.pcrs[3] = test_pcrs("another account's role")[3];
    let rogue = world.enclave(&elsewhere);
    let err = rogue.join(&holder_api, &client).await.expect_err("role");
    assert!(err.contains("parent_role"), "{err}");
    assert!(!rogue.has_seed());

    // An image nobody listed refuses itself before asking.
    let unlisted = world.enclave(&image("9.9.9"));
    let err = unlisted
        .join(&holder_api, &client)
        .await
        .expect_err("unlisted");
    assert!(err.contains("image_not_listed"), "{err}");

    // A revoked image: the holder serves a later manifest that revokes it.
    let m8 = manifest(8, &[(&new, "current"), (&old, "revoked")]);
    world.repo.publish(8, &m8);
    let current = world.enclave(&new);
    current.start_fresh().expect("seed");
    current.load_manifest(m8.clone()).expect("manifest");
    let current_api = api(&current).await;
    let revoked = world.enclave(&old);
    let err = revoked
        .join(&current_api, &client)
        .await
        .expect_err("revoked");
    assert!(err.contains("image_revoked"), "{err}");
    // And a holder never goes back to an older manifest.
    assert_eq!(current.load_manifest(m7), Err("manifest_rollback"));
}

/// A joiner's seal request against `holder`, with a document of `img` and
/// `manifest`; the refusal's `reason`, or `None` when it was sealed.
async fn seal_with(
    world: &World,
    holder_api: &str,
    img: &Image,
    manifest: &SignedManifest,
) -> Option<String> {
    let client = reqwest::Client::new();
    let hello: HelloAnswer = client
        .post(format!("{holder_api}/v1/handoff/hello"))
        .json(&HelloRequest {
            nonce: Blob::new(vec![3; 32]),
        })
        .send()
        .await
        .expect("hello")
        .json()
        .await
        .expect("json");
    let document = world.nitro.attest(&FakeAttestation {
        pcrs: &img.pcrs,
        timestamp_ms: now(),
        public_key: Some(&[9; 32]),
        user_data: None,
        nonce: Some(hello.nonce.as_bytes()),
    });
    let res = client
        .post(format!("{holder_api}/v1/handoff/seal"))
        .json(&SealRequest {
            session: hello.session,
            document: Blob::new(document),
            manifest: ManifestWire {
                manifest: String::from_utf8(manifest.bytes.clone()).expect("utf8"),
                signature: manifest.signature_hex(),
            },
        })
        .send()
        .await
        .expect("seal");
    if res.status().is_success() {
        return None;
    }
    assert_eq!(res.status(), 403);
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["error"], "klav_handoff_refused");
    Some(body["reason"].as_str().expect("reason").to_owned())
}

/// ADR 0051 §4.2 step 2: a manifest the release authority signed but did
/// not publish never moves the seed, nor one whose published copy differs
/// by a byte, nor a mutated one, nor an older one; the joiner refuses an
/// unpublished holder manifest too.
#[tokio::test(flavor = "multi_thread")]
async fn only_a_published_manifest_moves_the_seed() {
    let world = World::new().await;
    let old = image("0.12.0");
    let new = image("0.13.0");
    let m7 = manifest(7, &[(&new, "current"), (&old, "draining")]);
    world.repo.publish(7, &m7);
    let holder = world.enclave(&old);
    holder.start_fresh().expect("seed");
    holder.load_manifest(m7.clone()).expect("manifest");
    let holder_api = api(&holder).await;

    // The published one: sealed.
    assert_eq!(seal_with(&world, &holder_api, &new, &m7).await, None);

    // Signed, not published.
    let m9 = manifest(9, &[(&new, "current"), (&old, "draining")]);
    assert_eq!(
        seal_with(&world, &holder_api, &new, &m9).await.as_deref(),
        Some("unpublished")
    );
    // Published, but the repository's copy differs by a byte (both signed).
    let m10 = manifest_with(
        10,
        &[(&new, "current"), (&old, "draining")],
        &FakeReleaseKey::new(RELEASE),
        0,
    );
    let m10_other = manifest_with(
        10,
        &[(&new, "current"), (&old, "draining")],
        &FakeReleaseKey::new(RELEASE),
        1,
    );
    world.repo.publish(10, &m10_other);
    assert_eq!(
        seal_with(&world, &holder_api, &new, &m10).await.as_deref(),
        Some("unpublished")
    );
    // Mutated after signing.
    let mut mutated = m7.clone();
    let at = mutated.bytes.len() - 3;
    mutated.bytes[at] ^= 0x01;
    assert_eq!(
        seal_with(&world, &holder_api, &new, &mutated)
            .await
            .as_deref(),
        Some("manifest_signature")
    );
    // Signed by a key that is not the release authority's.
    let forged = manifest_with(11, &[(&new, "current")], &FakeReleaseKey::new("forger"), 0);
    world.repo.publish(11, &forged);
    assert_eq!(
        seal_with(&world, &holder_api, &new, &forged)
            .await
            .as_deref(),
        Some("manifest_signature")
    );
    // Older than the holder's own (a rollback), even if published.
    let m5 = manifest(5, &[(&new, "current"), (&old, "current")]);
    world.repo.publish(5, &m5);
    assert_eq!(
        seal_with(&world, &holder_api, &new, &m5).await.as_deref(),
        Some("manifest_rollback")
    );
    // A session serves one seal.
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{holder_api}/v1/handoff/seal"))
        .json(&SealRequest {
            session: Blob::new(vec![0; 16]),
            document: Blob::new(vec![0; 8]),
            manifest: ManifestWire {
                manifest: String::from_utf8(m7.bytes.clone()).expect("utf8"),
                signature: m7.signature_hex(),
            },
        })
        .send()
        .await
        .expect("seal");
    assert_eq!(res.status(), 403);

    // The joiner checks too: a holder serving an unpublished manifest.
    let m12 = manifest(12, &[(&new, "current"), (&old, "draining")]);
    let unpublished_holder = world.enclave(&old);
    unpublished_holder.start_fresh().expect("seed");
    unpublished_holder.load_manifest(m12).expect("manifest");
    let other_api = api(&unpublished_holder).await;
    let joiner = world.enclave(&new);
    let err = joiner
        .join(&other_api, &client)
        .await
        .expect_err("unpublished");
    assert!(err.contains("not published"), "{err}");
    assert!(!joiner.has_seed());
}

/// A manifest is served only when signed and listing the enclave's own
/// image; an attestation needs an enrolled account and a sane nonce.
#[tokio::test(flavor = "multi_thread")]
async fn the_api_serves_only_what_verifies() {
    let world = World::new().await;
    let img = image("0.12.0");
    let enclave = world.enclave(&img);
    let base = api(&enclave).await;
    let client = reqwest::Client::new();
    // No seed, no manifest yet.
    let res = client
        .get(format!("{base}/v1/manifest"))
        .send()
        .await
        .expect("get");
    assert_eq!(res.status(), 503);
    enclave.start_fresh().expect("seed");
    assert!(enclave.start_fresh().is_err(), "one seed per enclave");

    let push = |m: &SignedManifest| {
        let wire = ManifestWire {
            manifest: String::from_utf8(m.bytes.clone()).expect("utf8"),
            signature: m.signature_hex(),
        };
        let client = client.clone();
        let base = base.clone();
        async move {
            let res = client
                .post(format!("{base}/v1/manifest"))
                .json(&wire)
                .send()
                .await
                .expect("post");
            let status = res.status().as_u16();
            let body: serde_json::Value = res.json().await.expect("json");
            (status, body)
        }
    };
    let without_me = manifest(3, &[(&image("0.13.0"), "current")]);
    let (status, body) = push(&without_me).await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (403, Some("image_not_listed"))
    );
    let forged = manifest_with(3, &[(&img, "current")], &FakeReleaseKey::new("forger"), 0);
    let (status, body) = push(&forged).await;
    assert_eq!(
        (status, body["reason"].as_str()),
        (403, Some("manifest_signature"))
    );
    let m3 = manifest(3, &[(&img, "current")]);
    assert_eq!(push(&m3).await, (200, serde_json::json!({ "seq": 3 })));
    let served: ManifestWire = client
        .get(format!("{base}/v1/manifest"))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(served.manifest.as_bytes(), m3.bytes.as_slice());

    let unknown = AccountId::from_bytes([42; 16]);
    let nonce = data_encoding::BASE64URL_NOPAD.encode(&[1; 32]);
    let res = client
        .get(format!("{base}/v1/attest?account={unknown}&nonce={nonce}"))
        .send()
        .await
        .expect("attest");
    assert_eq!(res.status(), 404);
    assert_eq!(
        res.headers()
            .get("klav-error")
            .and_then(|v| v.to_str().ok()),
        Some("klav_hosted_not_enrolled")
    );
    enclave.enroll_for_test(enrollment(5)).expect("enroll");
    let account = enrollment(5).account_id;
    for bad in ["", "%%%", &data_encoding::BASE64URL_NOPAD.encode(&[0; 65])] {
        let res = client
            .get(format!("{base}/v1/attest?account={account}&nonce={bad}"))
            .send()
            .await
            .expect("attest");
        assert_eq!(res.status(), 400, "{bad:?}");
    }
    // The binding is the account's (spec §15.6), with its derived keys.
    let seed = enclave.seed_for_test().expect("seed");
    let e = enrollment(5);
    let keys = derive_account_keys(&seed, e.account_id, e.generation);
    assert_eq!(
        attested_binding(&base, account, &world.nitro).await,
        klav_core::nitro::enclave_binding(e.account_id, e.agent_id, keys.public(), e.generation)
    );
}

// -------------------------------------------------------------- accounts --

/// An account with a `Northflank` item holding `token`.
async fn account(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    email: &str,
    token: &str,
) -> Unlocked {
    let (mut person, _) = signup(
        &Home::at(dir.path().join(format!("device-{email}"))),
        SignupRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new("correct horse battery staple"),
            device_name: "laptop".into(),
            device_kind: klav_proto::auth::DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up");
    let vault = person.find_vault("Personal").expect("vault");
    let project = person.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, "Northflank").expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value(token)
        .expect("set");
    person
        .add_item(vault, project, &item)
        .await
        .expect("add item");
    person
}

/// Configures `server` with the Ed25519 half of `enclave`'s service key
/// (`[hosted_proxy] service_key`, what `KLAV_HOSTED_PROXY_SERVICE_KEY`
/// sets on `api.klav.dev`) and restarts it on the same port. Call it
/// before any account signs up.
fn key_server_for(server: &mut ServerProcess, enclave: &Enclave) {
    let seed = enclave.seed_for_test().expect("seed");
    let service = klav_core::nitro::hosted_service_keys(&seed);
    key_server_with(server, &hex(service.public().ed25519()));
}

/// Configures `server` with `service_key` (64 hex digits) as
/// `[hosted_proxy] service_key` and restarts it on the same port.
fn key_server_with(server: &mut ServerProcess, service_key: &str) {
    let path = server.dir.path().join("server.toml");
    let mut config = std::fs::read_to_string(&path).expect("config");
    config.push_str(&format!(
        "[hosted_proxy]\nservice_key = \"{service_key}\"\n"
    ));
    std::fs::write(&path, config).expect("config");
    server.restart();
}

/// `GET /v1/status` on the enclave at `api_base`: always `200`; its
/// `service_key`, and the raw body.
async fn status_of(api_base: &str) -> (Option<String>, String) {
    let res = reqwest::get(format!("{api_base}/v1/status"))
        .await
        .expect("status");
    assert_eq!(res.status().as_u16(), 200, "/v1/status answers 200");
    let body = res.text().await.expect("status body");
    let answer: StatusAnswer = serde_json::from_str(&body).unwrap_or_else(|_| panic!("{body}"));
    (answer.service_key, body)
}

/// `klav-server hosted-proxy <switch> <email>` against `server`'s database,
/// as the operator turns Klav Cloud's proxy on or off for an account (ADR
/// 0051 §8, Q6).
fn hosted_proxy_switch(server: &ServerProcess, switch: &str, email: &str) {
    let out = std::process::Command::new(crate::e2e_tests::common::server_binary())
        .args(["hosted-proxy", switch, email, "--config"])
        .arg(server.dir.path().join("server.toml"))
        .output()
        .expect("run klav-server hosted-proxy");
    assert!(
        out.status.success(),
        "klav-server hosted-proxy {switch} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Asks the enclave at `api_base` to enroll `person`'s account (§6.1 step
/// 2): the status, the `klav-error` code and the body.
async fn enroll(api_base: &str, person: &Unlocked, email: &str) -> (u16, Option<String>, String) {
    let signed = person.sign_hosted_proxy_enroll(0, now());
    let res = reqwest::Client::new()
        .post(format!("{api_base}/v1/enroll"))
        .json(&EnrollRequest {
            account_id: signed.account_id,
            email: email.into(),
            account_public_identity: signed.account_public_identity,
            generation: signed.generation,
            at_ms: signed.at_ms,
            signature: Blob::new(signed.signature.to_bytes().to_vec()),
        })
        .send()
        .await
        .expect("enroll");
    let status = res.status().as_u16();
    let code = res
        .headers()
        .get("klav-error")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    (status, code, res.text().await.expect("enroll answer"))
}

/// One account set up on the hosted proxy, with an issuer and a sandbox.
struct Hosted {
    person: Unlocked,
    account_id: AccountId,
    channel: String,
    package: SandboxPackage,
    issuer: Agent,
    email: String,
    token: String,
}

/// Enrolls `person` in `enclave` (§6.1), approves its hosted agent as the
/// account's proxy with `Northflank` granted, adds `t3-code` as its
/// issuer, and starts a sandbox.
async fn enroll_and_start(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
    enclave: &Arc<Enclave>,
    api_base: &str,
    email: &str,
    token: &str,
    upstream: &Upstream,
) -> Hosted {
    let mut person = account(server, dir, email, token).await;
    hosted_proxy_switch(server, "enable", email);
    let signed = person.sign_hosted_proxy_enroll(0, now());
    let (status, _, answer) = enroll(api_base, &person, email).await;
    assert_eq!(status, 200, "{answer}");
    let answer: EnrollAnswer = serde_json::from_str(&answer).unwrap_or_else(|_| panic!("{answer}"));
    assert_eq!(
        answer.channel,
        super::channel_name(answer.agent_id, ENDPOINT)
    );
    let prepared = person
        .prepare_proxy_use(Some(super::engine::AGENT_NAME))
        .await
        .expect("use");
    person.commit_proxy_use(prepared).await.expect("use");
    let mut credential = crate::sandbox_e2e_tests::credential_at(
        "northflank",
        &format!("https://upstream.test:{}", upstream.port),
    );
    credential.methods = vec!["GET".into(), "POST".into()];
    let prepared = person
        .prepare_proxy_grant("Northflank", &credential, PairingCheck::InPrompt)
        .await
        .expect("grant");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        person
            .commit_proxy_change(prepared)
            .await
            .expect("grant")
            .complete()
    );
    let (mut issuer, _) = Agent::register(
        &Home::at(dir.path().join(format!("issuer-{email}"))),
        Registration {
            name: "t3-code".into(),
            server: server.url.clone(),
            email: email.into(),
            note: None,
            key_store: KeyStore::File {
                path: dir.path().join(format!("issuer-{email}.key")),
            },
        },
    )
    .await
    .expect("issuer");
    let prepared = person
        .prepare_issuer_add(
            "t3-code",
            &IssuerSpec {
                profiles: vec!["northflank".into()],
                url: format!("tls://{}:443", answer.channel),
                max_live: Some(5),
                ..IssuerSpec::default()
            },
            PairingCheck::InPrompt,
        )
        .await
        .expect("issuer add");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        person
            .commit_issuer_change(prepared)
            .await
            .expect("add")
            .complete()
    );
    let account_id = signed.account_id;
    let port = enclave.issuer_port(account_id).await.expect("serving");
    let started = issuer_api::start(&mut issuer, port, &start("chat-1"))
        .await
        .expect("start");
    Hosted {
        person,
        account_id,
        channel: answer.channel,
        package: decode_package(&started.package).expect("package"),
        issuer,
        email: email.into(),
        token: token.into(),
    }
}

fn start(label: &str) -> StartRequest {
    StartRequest {
        label: label.into(),
        profiles: vec!["northflank".into()],
        ttl_secs: None,
    }
}

fn sni(channel: &str) -> ServerName<'static> {
    server_name_for(&format!("{channel}:443"))
}

/// A real forwarder for `package`, reaching the enclave at `addr` and
/// sending `name` as SNI, relaying calls from a loopback port it returns.
async fn forwarder(
    package: &SandboxPackage,
    addr: SocketAddr,
    name: ServerName<'static>,
) -> (Arc<Forwarder>, u16) {
    let fwd = Arc::new(
        Forwarder::new(
            &format!("tls://{addr}"),
            package.proxy_pin,
            klav_core::crypto::channel::TlsSigner::channel_key(),
        )
        .expect("forwarder")
        .with_server_name(name),
    );
    let local = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = local.local_addr().expect("addr").port();
    tokio::spawn(klav_forward::forward::serve(local, Arc::clone(&fwd)));
    (fwd, port)
}

async fn call(port: u16, path: &str) -> (u16, String) {
    let res = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}{path}"))
        .send()
        .await
        .expect("call");
    let status = res.status().as_u16();
    (status, res.text().await.unwrap_or_default())
}

/// ADR 0051 §3.1, §3.4 and §9, with a real server, two accounts on one
/// enclave and real forwarders:
/// - each account's sandbox reaches only its own credential, through the
///   key its SNI names;
/// - account A's package, pin and claim never reach account B's proxy,
///   grants or credential, whichever name or pin it tries;
/// - an older forwarder (the fixed name `klav-proxy`) fails closed with
///   `klav_proxy_unreachable`; the same forwarder still works against a
///   self-hosted proxy (the channel tests of `klav-forward` and every
///   channel test of this crate, which send the fixed name);
/// - nothing secret is logged: not the seed, not an account's derived
///   private keys, not a provider token, not an e-mail.
#[tokio::test(flavor = "multi_thread")]
async fn accounts_are_isolated_and_an_old_forwarder_fails_closed() {
    let log = global_log();
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let world = World::new().await;
    let img = image("0.12.0");
    let enclave = world.enclave_with(&img, &server.url, QuotaLimits::default());
    enclave.start_fresh().expect("seed");
    key_server_for(&mut server, &enclave);
    enclave
        .load_manifest(manifest(1, &[(&img, "current")]))
        .expect("manifest");
    let api_base = api(&enclave).await;
    let addr = channel(&enclave).await;
    let upstream = Upstream::start().await;

    let a = enroll_and_start(
        &server,
        &dir,
        &enclave,
        &api_base,
        "ana@example.com",
        "tok_live_account_a_0123456789abcdef",
        &upstream,
    )
    .await;
    let b = enroll_and_start(
        &server,
        &dir,
        &enclave,
        &api_base,
        "bo@example.com",
        "tok_live_account_b_fedcba9876543210",
        &upstream,
    )
    .await;
    assert_ne!(a.channel, b.channel);
    assert_ne!(a.package.proxy_pin, b.package.proxy_pin);

    // An older forwarder: the fixed name matches no account.
    let (legacy, _) = forwarder(
        &a.package,
        addr,
        ServerName::try_from(LEGACY_SERVER_NAME).expect("name"),
    )
    .await;
    let refused = legacy.claim(&a.package).await.expect_err("legacy");
    assert_eq!(refused.error, "klav_proxy_unreachable");
    // No SNI at all (an IP literal in the URL): the same.
    let (bare, _) = forwarder(&a.package, addr, server_name_for(&addr.to_string())).await;
    assert_eq!(
        bare.claim(&a.package).await.expect_err("no sni").error,
        "klav_proxy_unreachable"
    );
    // A's package with B's name: B's key is presented and A's pin refuses
    // it, before a byte of the claim leaves.
    let (crossed, _) = forwarder(&a.package, addr, sni(&b.channel)).await;
    assert_eq!(
        crossed.claim(&a.package).await.expect_err("crossed").error,
        "klav_proxy_unreachable"
    );

    // Each forwarder, with its own name: claimed, and its calls carry its
    // account's credential only.
    let (fwd_a, port_a) = forwarder(&a.package, addr, sni(&a.channel)).await;
    fwd_a.claim(&a.package).await.expect("claim A");
    let (fwd_b, port_b) = forwarder(&b.package, addr, sni(&b.channel)).await;
    fwd_b.claim(&b.package).await.expect("claim B");
    let (status, body) = call(port_a, "/northflank/v1/projects").await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call(port_b, "/northflank/v1/projects").await;
    assert_eq!(status, 200, "{body}");
    let seen = upstream.requests();
    let auths: Vec<&str> = seen
        .iter()
        .filter_map(|s| s.header("authorization"))
        .collect();
    assert_eq!(
        auths,
        [
            format!("Bearer {}", a.token).as_str(),
            format!("Bearer {}", b.token).as_str()
        ]
    );

    // A's claim secret on a connection to B (with B's pin, which is no
    // secret): B's proxy has no such sandbox.
    let mut to_b = Raw::named(&key(b.package.proxy_pin), addr, sni(&b.channel))
        .await
        .expect("handshake with B");
    to_b.send(&claim_request(&a.package)).await.expect("send");
    let (status, body) = to_b.answer(5 * SECOND).await.expect("answer");
    assert_ne!(status, 200, "{body}");
    // A call on that connection is refused: its key is bound to nothing
    // in B's proxy, and B's credential never moves.
    to_b.send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    if let Some((status, _)) = to_b.answer(5 * SECOND).await {
        assert_ne!(status, 200);
    }
    // A raw connection that names A with A's pin, but never claimed: no
    // call either.
    let mut unbound = Raw::named(&key(a.package.proxy_pin), addr, sni(&a.channel))
        .await
        .expect("handshake with A");
    unbound
        .send(b"GET /northflank/v1/projects HTTP/1.1\r\nhost: 127.0.0.1:8790\r\n\r\n")
        .await
        .expect("send");
    let (status, _) = unbound.answer(5 * SECOND).await.expect("answer");
    assert_eq!(status, 401);
    assert_eq!(
        upstream.requests().len(),
        2,
        "no other call reached a provider"
    );

    // Each account's proxy is its own agent with its own grant.
    let state_a = enclave.state_of(a.account_id).await.expect("A");
    let state_b = enclave.state_of(b.account_id).await.expect("B");
    assert!(!Arc::ptr_eq(&state_a, &state_b));
    assert_ne!(state_a.proxy_id().await, state_b.proxy_id().await);

    // Nothing secret in any line logged meanwhile, in any encoding.
    let seed = enclave.seed_for_test().expect("seed");
    let mut secrets: Vec<Vec<u8>> = vec![
        klav_core::nitro::fake::seed_bytes(&seed).to_vec(),
        a.token.as_bytes().to_vec(),
        b.token.as_bytes().to_vec(),
    ];
    for h in [&a, &b] {
        let e_keys = derive_account_keys(&seed, h.account_id, 0);
        let both = klav_core::nitro::fake::secret_bytes(&e_keys);
        secrets.push(both[..32].to_vec());
        secrets.push(both[32..].to_vec());
    }
    let service =
        klav_core::nitro::fake::secret_bytes(&klav_core::nitro::hosted_service_keys(&seed));
    secrets.push(service[..32].to_vec());
    secrets.push(service[32..].to_vec());
    let text = log.text();
    assert!(!text.is_empty(), "the log captured something");
    for secret in &secrets {
        for encoded in [
            data_encoding::HEXLOWER.encode(secret),
            data_encoding::HEXUPPER.encode(secret),
            data_encoding::BASE64.encode(secret),
            data_encoding::BASE64URL_NOPAD.encode(secret),
            String::from_utf8_lossy(secret).into_owned(),
        ] {
            assert!(!text.contains(&encoded), "a secret reached the log");
        }
    }
    for email in [&a.email, &b.email] {
        assert!(!text.contains(email.as_str()), "an e-mail reached the log");
    }
    drop((a.person, a.issuer, b.person, b.issuer));
}

/// ADR 0051 §8 against layer 4's server: the enclave registers each
/// account's agent with its service key's mark in
/// `RegisterHostedAgent.hosted`, and a real `klav-server` holding that key
/// accepts it only for an entitled account:
/// - an entitled account enrolls, and its hosted agent reads
///   `hosted_proxy: {entitled: true}` in `GET /v1/agent/me`;
/// - an account the operator didn't turn on is refused with `403`
///   (`klav_hosted_not_entitled`), and enrolls once it is turned on;
/// - an enclave whose service key isn't the server's, and a mark tampered
///   with on the way, are refused with `403`; nothing is stored or served.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_checks_the_registration_mark_and_the_entitlement() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let world = World::new().await;
    let img = image("0.12.0");
    let enclave = world.enclave_with(&img, &server.url, QuotaLimits::default());
    enclave.start_fresh().expect("seed");
    enclave
        .load_manifest(manifest(1, &[(&img, "current")]))
        .expect("manifest");
    key_server_for(&mut server, &enclave);
    let api_base = api(&enclave).await;
    let seed = enclave.seed_for_test().expect("seed");

    // Entitled: registered, and the enclave's agent (its keys derived from
    // the same seed) reads the entitlement.
    let mut ana = account(&server, &dir, "ana@example.com", "tok_account_a").await;
    hosted_proxy_switch(&server, "enable", "ana@example.com");
    let (status, code, body) = enroll(&api_base, &ana, "ana@example.com").await;
    assert_eq!((status, code), (200, None), "{body}");
    let answer: EnrollAnswer = serde_json::from_str(&body).expect("answer");
    let signed = ana.sign_hosted_proxy_enroll(0, now());
    let mut hosted_agent = Agent::in_memory(
        MemoryAgent {
            name: super::engine::AGENT_NAME.into(),
            agent_id: answer.agent_id,
            server: server.url.clone(),
            email: "ana@example.com".into(),
            account_id: signed.account_id,
            account_public_identity: signed.account_public_identity,
            http: reqwest::Client::new(),
        },
        derive_account_keys(&seed, signed.account_id, 0),
    )
    .expect("the enclave's agent");
    let me = hosted_agent.me().await.expect("me");
    assert_eq!(me.status, AgentStatus::Pending);
    assert_eq!(me.hosted_proxy, Some(HostedProxyStatus { entitled: true }));
    assert_eq!(agent_ids(&mut ana).await, vec![answer.agent_id]);

    // Not entitled: the same enclave and key, refused, nothing stored or
    // served; turned on, the same account enrolls.
    let mut bo = account(&server, &dir, "bo@example.com", "tok_account_b").await;
    let bo_id = bo.sign_hosted_proxy_enroll(0, now()).account_id;
    let (status, code, body) = enroll(&api_base, &bo, "bo@example.com").await;
    assert_eq!(
        (status, code.as_deref()),
        (403, Some("klav_hosted_not_entitled")),
        "{body}"
    );
    assert!(agent_ids(&mut bo).await.is_empty());
    assert!(enclave.issuer_port(bo_id).await.is_err());
    hosted_proxy_switch(&server, "enable", "bo@example.com");
    let (status, _, body) = enroll(&api_base, &bo, "bo@example.com").await;
    assert_eq!(status, 200, "{body}");

    // Another enclave's service key (a seed the server wasn't given), for
    // an entitled account: refused, nothing stored or served.
    let impostor = world.enclave_with(&img, &server.url, QuotaLimits::default());
    impostor.start_fresh().expect("seed");
    impostor
        .load_manifest(manifest(1, &[(&img, "current")]))
        .expect("manifest");
    let impostor_base = api(&impostor).await;
    let mut cy = account(&server, &dir, "cy@example.com", "tok_account_c").await;
    hosted_proxy_switch(&server, "enable", "cy@example.com");
    let cy_id = cy.sign_hosted_proxy_enroll(0, now()).account_id;
    let (status, code, body) = enroll(&impostor_base, &cy, "cy@example.com").await;
    assert_eq!(
        (status, code.as_deref()),
        (403, Some("klav_hosted_not_entitled")),
        "{body}"
    );
    assert!(agent_ids(&mut cy).await.is_empty());
    assert!(impostor.issuer_port(cy_id).await.is_err());

    // A mark tampered with on the way, sent straight to the server: the
    // body the enclave sends for cy, marked with the real service key, is
    // accepted; the same body with another generation, or with a bit of
    // the signature flipped, is refused with 403 and stores nothing.
    let service = hosted_service_keys(&seed);
    let agent_keys = derive_account_keys(&seed, cy_id, 0);
    let body_for = |agent: AgentId, generation: u32, flip: bool| {
        let mut signature =
            sign_hosted_registration(&service, cy_id, agent, agent_keys.public(), 0).to_bytes();
        if flip {
            signature[0] ^= 1;
        }
        RegisterHostedAgent {
            id: agent,
            email: "cy@example.com".into(),
            name: super::engine::AGENT_NAME.into(),
            public_identity: Blob::new(agent_keys.public().encode().to_vec()),
            note: None,
            hosted: Some(HostedRegistrationProof {
                account_id: cy_id,
                generation,
                signature: Blob::new(signature.to_vec()),
            }),
        }
    };
    let register = |body: RegisterHostedAgent| {
        let url = format!("{}/v1/agents/register", server.url);
        async move {
            reqwest::Client::new()
                .post(url)
                .json(&body)
                .send()
                .await
                .expect("register")
                .status()
                .as_u16()
        }
    };
    assert_eq!(register(body_for(AgentId::generate(), 1, false)).await, 403);
    assert_eq!(register(body_for(AgentId::generate(), 0, true)).await, 403);
    assert!(agent_ids(&mut cy).await.is_empty());
    let untouched = AgentId::generate();
    assert_eq!(register(body_for(untouched, 0, false)).await, 202);
    assert_eq!(agent_ids(&mut cy).await, vec![untouched]);
    drop((ana, bo, cy));
}

/// The IDs of the agents `person`'s account has, pending ones included.
async fn agent_ids(person: &mut Unlocked) -> Vec<AgentId> {
    person
        .agents()
        .await
        .expect("agents")
        .into_iter()
        .map(|a| a.id)
        .collect()
}

/// ADR 0051 §3.3: each per-account quota trips with its code: live
/// sandboxes on start, calls per minute, the request body, and the day's
/// egress (the last through the same middleware, on a router of its own).
#[tokio::test(flavor = "multi_thread")]
async fn each_quota_trips_cleanly() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let world = World::new().await;
    let img = image("0.12.0");
    let limits = QuotaLimits {
        live_sandboxes: 2,
        requests_per_minute: 3,
        max_body: 64,
        ..QuotaLimits::default()
    };
    let enclave = world.enclave_with(&img, &server.url, limits);
    enclave.start_fresh().expect("seed");
    key_server_for(&mut server, &enclave);
    enclave
        .load_manifest(manifest(1, &[(&img, "current")]))
        .expect("manifest");
    let api_base = api(&enclave).await;
    let addr = channel(&enclave).await;
    let upstream = Upstream::start().await;
    let mut h = enroll_and_start(
        &server,
        &dir,
        &enclave,
        &api_base,
        "ana@example.com",
        "tok_live_quota_0123456789abcdef",
        &upstream,
    )
    .await;

    // Live sandboxes: the issuer may have 5, the account 2.
    let port = enclave.issuer_port(h.account_id).await.expect("port");
    issuer_api::start(&mut h.issuer, port, &start("chat-2"))
        .await
        .expect("second");
    let Err(third) = issuer_api::start(&mut h.issuer, port, &start("chat-3")).await else {
        panic!("a third live sandbox started");
    };
    assert_eq!(third.code(), "klav_rate_limited");

    // The body cap: refused before it reaches the proxy's state.
    let (fwd, local) = forwarder(&h.package, addr, sni(&h.channel)).await;
    fwd.claim(&h.package).await.expect("claim");
    let res = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{local}/northflank/v1/upload"))
        .body(vec![b'x'; 65])
        .send()
        .await
        .expect("post");
    assert_eq!(res.status(), 413);
    assert_eq!(
        res.headers()
            .get("klav-error")
            .and_then(|v| v.to_str().ok()),
        Some("klav_upstream_blocked")
    );

    // Calls per minute: three, then `429` with `retry_after`.
    for _ in 0..3 {
        let (status, body) = call(local, "/northflank/v1/projects").await;
        assert_eq!(status, 200, "{body}");
    }
    let res = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{local}/northflank/v1/projects"))
        .send()
        .await
        .expect("call");
    assert_eq!(res.status(), 429);
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["error"], "klav_rate_limited");
    assert!(
        body["retry_after"]
            .as_u64()
            .is_some_and(|s| (1..=60).contains(&s))
    );
    assert!(enclave.egress_today(h.account_id) > 0, "egress is counted");
    drop(h.person);
}

/// The middleware alone, on a router of its own: the day's egress and the
/// SSE cap.
#[tokio::test]
async fn egress_and_stream_quotas_trip() {
    use axum::body::Body;
    use axum::routing::get;
    let quotas = Arc::new(super::quota::Quotas::new(QuotaLimits {
        egress_bytes_per_day: 2500,
        sse_streams: 1,
        ..QuotaLimits::default()
    }));
    let app = axum::Router::new()
        .route("/p/big", get(|| async { vec![b'x'; 1024] }))
        .route(
            "/p/sse",
            get(|| async {
                let ticks = futures_util::stream::unfold(0u32, |n| async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Some((Ok::<_, std::io::Error>(format!("data: {n}\n\n")), n + 1))
                });
                axum::response::Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(Body::from_stream(ticks))
                    .expect("response")
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&quotas),
            super::quota::enforce,
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let client = reqwest::Client::new();
    for _ in 0..3 {
        let res = client
            .get(format!("http://{addr}/p/big"))
            .send()
            .await
            .expect("get");
        assert_eq!(res.status(), 200);
        res.bytes().await.expect("body");
    }
    let res = client
        .get(format!("http://{addr}/p/big"))
        .send()
        .await
        .expect("get");
    assert_eq!(res.status(), 429);
    assert_eq!(
        res.headers()
            .get("klav-error")
            .and_then(|v| v.to_str().ok()),
        Some("klav_rate_limited")
    );

    let quotas = Arc::new(super::quota::Quotas::new(QuotaLimits {
        sse_streams: 1,
        ..QuotaLimits::default()
    }));
    let app = axum::Router::new()
        .route(
            "/p/sse",
            get(|| async {
                let ticks = futures_util::stream::unfold(0u32, |n| async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Some((Ok::<_, std::io::Error>(format!("data: {n}\n\n")), n + 1))
                });
                axum::response::Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(Body::from_stream(ticks))
                    .expect("response")
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&quotas),
            super::quota::enforce,
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let first = client
        .get(format!("http://{addr}/p/sse"))
        .send()
        .await
        .expect("sse");
    let mut first = first;
    assert!(first.chunk().await.expect("chunk").is_some());
    // A second stream: the first, the oldest, ends.
    let second = client
        .get(format!("http://{addr}/p/sse"))
        .send()
        .await
        .expect("sse");
    let mut second = second;
    assert!(second.chunk().await.expect("chunk").is_some());
    let ended = tokio::time::timeout(5 * SECOND, async {
        while let Ok(Some(_)) = first.chunk().await {}
    })
    .await;
    assert!(ended.is_ok(), "the oldest stream closed");
    assert!(
        second.chunk().await.expect("chunk").is_some(),
        "the newest goes on"
    );
    assert_eq!(quotas.open_streams(), 1);
}

// ------------------------------------------------------------ layer 3b --

/// A TCP hop in front of the enclaves, as the load balancer and the parents
/// are: [`Hop::switch`] sends new connections to another enclave and cuts
/// the open ones, as an enclave that stops does.
struct Hop {
    addr: SocketAddr,
    target: Arc<Mutex<SocketAddr>>,
    open: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Hop {
    async fn to(target: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let target = Arc::new(Mutex::new(target));
        let open: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let (t, o) = (Arc::clone(&target), Arc::clone(&open));
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                let to = *t.lock().expect("lock");
                let task = tokio::spawn(async move {
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(to).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
                o.lock().expect("lock").push(task.abort_handle());
            }
        });
        Self { addr, target, open }
    }

    fn switch(&self, to: SocketAddr) {
        *self.target.lock().expect("lock") = to;
        for task in self.open.lock().expect("lock").drain(..) {
            task.abort();
        }
    }
}

/// Fails when any of `secrets`, in any usual encoding, or any of `emails`
/// is in `text`.
fn assert_nothing_secret(text: &str, secrets: &[Vec<u8>], emails: &[&str]) {
    assert!(!text.is_empty(), "the log captured something");
    for secret in secrets {
        for encoded in [
            data_encoding::HEXLOWER.encode(secret),
            data_encoding::HEXUPPER.encode(secret),
            data_encoding::BASE64.encode(secret),
            data_encoding::BASE64URL_NOPAD.encode(secret),
            String::from_utf8_lossy(secret).into_owned(),
        ] {
            assert!(!text.contains(&encoded), "a secret reached the log");
        }
    }
    for email in emails {
        assert!(!text.contains(email), "an e-mail reached the log");
    }
}

/// ADR 0051 §4.2, §4.3 and §7.4, a rolling upgrade with no failed call:
/// account A enrolls on enclave 1 and its sandbox is claimed and calling;
/// enclave 2, a newer image the published manifest lists, takes the seed
/// and every account's live state through the attested hand-off; enclave 1
/// stops. A's sandbox goes on calling through enclave 2 with the same
/// forwarder and channel key: no new claim, enrollment, approval or grant,
/// the same agent, the same store epoch. Account B, on the same enclaves,
/// stays apart. Nothing secret is logged at TRACE.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_sandbox_goes_on_through_the_new_enclave_after_an_upgrade() {
    let log = global_log();
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let world = World::new().await;
    let old = image("0.12.0");
    let new = image("0.13.0");
    let m1 = manifest(1, &[(&new, "current"), (&old, "draining")]);
    world.repo.publish(1, &m1);

    let first = world.enclave_with(&old, &server.url, QuotaLimits::default());
    first.start_fresh().expect("seed");
    key_server_for(&mut server, &first);
    first.load_manifest(m1).expect("manifest");
    let first_api = api(&first).await;
    let first_addr = channel(&first).await;
    let upstream = Upstream::start().await;
    let mut a = enroll_and_start(
        &server,
        &dir,
        &first,
        &first_api,
        "ana@example.com",
        "tok_live_upgrade_a_0123456789abcdef",
        &upstream,
    )
    .await;
    let mut b = enroll_and_start(
        &server,
        &dir,
        &first,
        &first_api,
        "bo@example.com",
        "tok_live_upgrade_b_fedcba9876543210",
        &upstream,
    )
    .await;

    // Both forwarders reach the enclaves through one hop, as through the
    // load balancer, and claim on enclave 1.
    let hop = Hop::to(first_addr).await;
    let (fwd_a, port_a) = forwarder(&a.package, hop.addr, sni(&a.channel)).await;
    fwd_a.claim(&a.package).await.expect("claim A");
    let (fwd_b, port_b) = forwarder(&b.package, hop.addr, sni(&b.channel)).await;
    fwd_b.claim(&b.package).await.expect("claim B");
    for port in [port_a, port_b] {
        let (status, body) = call(port, "/northflank/v1/projects").await;
        assert_eq!(status, 200, "{body}");
    }
    let state_a1 = first.state_of(a.account_id).await.expect("A on 1");
    let proxy_a = state_a1.proxy_id().await;
    let epoch_a = state_a1.heartbeats().epoch().await;
    let agents_a = agent_ids(&mut a.person).await;
    let agents_b = agent_ids(&mut b.person).await;
    drop(state_a1);

    // Enclave 2, the newer image, joins; then enclave 1 stops, and the hop
    // sends everything to enclave 2 and cuts what was open.
    let second = world.enclave_with(&new, &server.url, QuotaLimits::default());
    second
        .join(&first_api, &reqwest::Client::new())
        .await
        .expect("hand-off");
    let second_addr = channel(&second).await;
    first.stop_for_test().await;
    hop.switch(second_addr);
    // Enclave 1 is gone: straight to it, A's name presents no key.
    let (direct, _) = forwarder(&a.package, first_addr, sni(&a.channel)).await;
    assert_eq!(
        direct.claim(&a.package).await.expect_err("stopped").error,
        "klav_proxy_unreachable"
    );

    // A's sandbox goes on, through enclave 2, with the same forwarder.
    let seen_before = upstream.requests().len();
    for _ in 0..3 {
        let (status, body) = call(port_a, "/northflank/v1/projects").await;
        assert_eq!(status, 200, "{body}");
    }
    let (status, body) = call(port_b, "/northflank/v1/projects").await;
    assert_eq!(status, 200, "{body}");
    let auths: Vec<String> = upstream.requests()[seen_before..]
        .iter()
        .filter_map(|s| s.header("authorization").map(str::to_owned))
        .collect();
    let bearer_a = format!("Bearer {}", a.token);
    let bearer_b = format!("Bearer {}", b.token);
    assert_eq!(
        auths,
        [&bearer_a, &bearer_a, &bearer_a, &bearer_b].map(String::as_str),
        "each account's calls carry its own credential only"
    );
    assert!(
        second.egress_today(a.account_id) > 0,
        "the calls went through enclave 2"
    );
    let state_a2 = second.state_of(a.account_id).await.expect("A on 2");
    assert_eq!(state_a2.proxy_id().await, proxy_a, "the same agent");
    let views = state_a2.sandboxes().views().await;
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].sandbox_id, a.package.sandbox_id);
    assert!(views[0].claimed, "still claimed: no new claim was needed");
    // The same store epoch, its reset already logged: no new reset, and
    // the heartbeat goes on from the holder's `seq`.
    let (epoch, logged, seq) = state_a2.heartbeats().epoch().await;
    assert_eq!(epoch, epoch_a.0, "the same store epoch");
    assert!(logged && epoch_a.1);
    assert!(seq >= epoch_a.2, "seq goes on: {} then {seq}", epoch_a.2);
    // No enrollment, approval or grant of the person in between.
    assert_eq!(agent_ids(&mut a.person).await, agents_a);
    assert_eq!(agent_ids(&mut b.person).await, agents_b);

    // B stays apart on enclave 2: A's package with B's name fails the pin,
    // and each account has its own proxy.
    let (crossed, _) = forwarder(&a.package, second_addr, sni(&b.channel)).await;
    assert_eq!(
        crossed.claim(&a.package).await.expect_err("crossed").error,
        "klav_proxy_unreachable"
    );
    let state_b2 = second.state_of(b.account_id).await.expect("B on 2");
    assert!(!Arc::ptr_eq(&state_a2, &state_b2));
    assert_ne!(state_b2.proxy_id().await, proxy_a);
    let views_b = state_b2.sandboxes().views().await;
    assert_eq!(views_b.len(), 1);
    assert_eq!(views_b[0].sandbox_id, b.package.sandbox_id);

    // Nothing secret in any line logged meanwhile.
    let seed = second.seed_for_test().expect("seed");
    let mut secrets: Vec<Vec<u8>> = vec![
        klav_core::nitro::fake::seed_bytes(&seed).to_vec(),
        a.token.as_bytes().to_vec(),
        b.token.as_bytes().to_vec(),
        a.package.secret.expose().to_vec(),
        b.package.secret.expose().to_vec(),
    ];
    for h in [&a, &b] {
        let both =
            klav_core::nitro::fake::secret_bytes(&derive_account_keys(&seed, h.account_id, 0));
        secrets.push(both[..32].to_vec());
        secrets.push(both[32..].to_vec());
    }
    let service = klav_core::nitro::fake::secret_bytes(&hosted_service_keys(&seed));
    secrets.push(service[..32].to_vec());
    secrets.push(service[32..].to_vec());
    assert_nothing_secret(&log.text(), &secrets, &[&a.email, &b.email]);
    drop((a.person, a.issuer, b.person, b.issuer));
}

/// ADR 0051 §18, blocker 2: the operator reads the service key's public
/// half from the enclave and sets it as `KLAV_HOSTED_PROXY_SERVICE_KEY`.
/// Before a seed, `GET /v1/status` answers `service_key: null`; after
/// genesis, 64 lowercase hex digits, and a real `klav-server` configured
/// with exactly that string accepts the enclave's registration marks. A
/// newer enclave that takes the seed through the hand-off serves the same
/// key, and the server accepts its marks too. The key is logged once per
/// enclave; no private key, seed, token or e-mail reaches the log at
/// TRACE or the status answer.
#[tokio::test(flavor = "multi_thread")]
async fn the_service_key_is_served_and_logged_and_only_its_public_half() {
    let log = global_log();
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let world = World::new().await;
    let old = image("0.12.0");
    let new = image("0.13.0");
    let m1 = manifest(1, &[(&new, "current"), (&old, "draining")]);
    world.repo.publish(1, &m1);

    // Genesis: no key before the seed, then the key.
    let first = world.enclave_with(&old, &server.url, QuotaLimits::default());
    let first_api = api(&first).await;
    assert_eq!(status_of(&first_api).await.0, None, "no seed, no key");
    assert_eq!(first.service_key(), None);
    first.start_fresh().expect("seed");
    first.load_manifest(m1).expect("manifest");
    let (served, first_body) = status_of(&first_api).await;
    let key = served.expect("a seeded enclave serves its service key");
    assert_eq!(key.len(), 64, "{key}");
    assert!(
        key.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase hex: {key}"
    );
    assert_eq!(first.service_key(), Some(key.as_str()));

    // The server takes exactly the served string, and accepts the marks.
    key_server_with(&mut server, &key);
    let ana = account(
        &server,
        &dir,
        "ana@example.com",
        "tok_service_key_a_0123456789",
    )
    .await;
    hosted_proxy_switch(&server, "enable", "ana@example.com");
    let (status, code, body) = enroll(&first_api, &ana, "ana@example.com").await;
    assert_eq!((status, code), (200, None), "{body}");

    // A newer enclave joins: no key before the hand-off, the same after.
    let second = world.enclave_with(&new, &server.url, QuotaLimits::default());
    let second_api = api(&second).await;
    assert_eq!(status_of(&second_api).await.0, None, "no seed, no key");
    second
        .join(&first_api, &reqwest::Client::new())
        .await
        .expect("hand-off");
    let (served, second_body) = status_of(&second_api).await;
    assert_eq!(
        served.as_deref(),
        Some(key.as_str()),
        "the same seed, the same key"
    );
    // Its marks pass the same server configuration.
    let bo = account(
        &server,
        &dir,
        "bo@example.com",
        "tok_service_key_b_9876543210",
    )
    .await;
    hosted_proxy_switch(&server, "enable", "bo@example.com");
    let (status, code, body) = enroll(&second_api, &bo, "bo@example.com").await;
    assert_eq!((status, code), (200, None), "{body}");

    // Logged, public half only.
    let text = log.text();
    assert!(text.contains(&key), "the service key is logged");
    let seed = second.seed_for_test().expect("seed");
    let mut secrets: Vec<Vec<u8>> = vec![
        klav_core::nitro::fake::seed_bytes(&seed).to_vec(),
        b"tok_service_key_a_0123456789".to_vec(),
        b"tok_service_key_b_9876543210".to_vec(),
    ];
    let service = klav_core::nitro::fake::secret_bytes(&hosted_service_keys(&seed));
    secrets.push(service[..32].to_vec());
    secrets.push(service[32..].to_vec());
    for person in [&ana, &bo] {
        let id = person.sign_hosted_proxy_enroll(0, now()).account_id;
        let both = klav_core::nitro::fake::secret_bytes(&derive_account_keys(&seed, id, 0));
        secrets.push(both[..32].to_vec());
        secrets.push(both[32..].to_vec());
    }
    assert_nothing_secret(&text, &secrets, &["ana@example.com", "bo@example.com"]);
    for body in [&first_body, &second_body] {
        assert_nothing_secret(body, &secrets, &["ana@example.com", "bo@example.com"]);
    }
    drop((ana, bo));
}

/// `klav-proxy enclave` as the image starts it, over loopback instead of
/// vsock and with a fake NSM: genesis serves the published manifest it
/// names, the hand-off only on the peer port; a joiner takes the seed and
/// the accounts from it; a joiner that finds no holder, and a genesis
/// whose manifest isn't published, give up with the reason.
#[tokio::test(flavor = "multi_thread")]
async fn the_enclave_command_starts_fresh_or_joins_a_peer() {
    use super::run::{Plan, Startup, loopback, serve};
    let world = World::new().await;
    let img = image("0.12.0");
    let m3 = manifest(3, &[(&img, "current")]);
    world.repo.publish(3, &m3);
    let startup = |plan: Plan| async {
        let (channel, _) = loopback().await;
        let (api, api_addr) = loopback().await;
        let (peer, peer_addr) = loopback().await;
        let startup = Startup {
            plan,
            config: world.config("http://127.0.0.1:9", QuotaLimits::default()),
            channel,
            api,
            peer: Some(peer),
            published: Arc::new(
                PublishedRepo::new(&world.repo.base, reqwest::Client::new()).expect("repo"),
            ),
            peer_client: reqwest::Client::new(),
            join_retry: Duration::from_millis(50),
        };
        (startup, api_addr, peer_addr)
    };
    let nsm = || -> Arc<FakeNsm> {
        Arc::new(FakeNsm {
            nitro: Arc::clone(&world.nitro),
            pcrs: img.pcrs,
        })
    };
    let anchors = || Anchors::test(world.nitro.root(), &[FakeReleaseKey::new(RELEASE).public()]);

    // Genesis, serving manifest 3.
    let (s, api_g, peer_g) = startup(Plan::Genesis {
        manifest_seq: Some(3),
    })
    .await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(serve(s, nsm(), anchors(), Some(tx)));
    let genesis = rx.await.expect("genesis ready");
    assert!(genesis.has_seed());
    let served: ManifestWire = reqwest::get(format!("http://{api_g}/v1/manifest"))
        .await
        .expect("manifest")
        .json()
        .await
        .expect("json");
    assert_eq!(served.manifest.as_bytes(), &m3.bytes[..]);
    // The hand-off is on the peer port only.
    let hello = |addr: SocketAddr| async move {
        reqwest::Client::new()
            .post(format!("http://{addr}/v1/handoff/hello"))
            .json(&HelloRequest {
                nonce: Blob::new(vec![1; 32]),
            })
            .send()
            .await
            .expect("hello")
            .status()
            .as_u16()
    };
    assert_eq!(hello(api_g).await, 404);
    assert_eq!(hello(peer_g).await, 200);
    for n in [1, 2] {
        genesis.enroll_for_test(enrollment(n)).expect("enroll");
    }

    // A joiner takes the seed and both accounts.
    let (s, _, _) = startup(Plan::Join {
        holder: format!("http://{peer_g}"),
        attempts: 3,
    })
    .await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(serve(s, nsm(), anchors(), Some(tx)));
    let joiner = rx.await.expect("joiner ready");
    assert!(joiner.has_seed());
    assert!(genesis.service_key().is_some());
    assert_eq!(joiner.service_key(), genesis.service_key());
    let mut names = joiner.channel_names();
    names.sort();
    let mut expected = genesis.channel_names();
    expected.sort();
    assert_eq!(names, expected);

    // No holder answers: it gives up after its attempts.
    let (s, _, _) = startup(Plan::Join {
        holder: "http://127.0.0.1:9".into(),
        attempts: 2,
    })
    .await;
    let err = serve(s, nsm(), anchors(), None)
        .await
        .expect_err("no holder");
    assert!(err.contains("no hand-off after 2 attempts"), "{err}");
    // A genesis whose manifest isn't published doesn't start.
    let (s, _, _) = startup(Plan::Genesis {
        manifest_seq: Some(99),
    })
    .await;
    let err = serve(s, nsm(), anchors(), None)
        .await
        .expect_err("unpublished");
    assert!(err.contains("manifest 99"), "{err}");
}

/// Writes `head` and then each of `chunks` as one HTTP chunk to `port`.
async fn chunked(port: u16, path: &str, chunks: &[Vec<u8>], end: bool) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let head = format!(
        "POST {path} HTTP/1.1\r\nhost: 127.0.0.1:{port}\r\ncontent-type: application/octet-stream\r\ntransfer-encoding: chunked\r\n\r\n"
    );
    s.write_all(head.as_bytes()).await.expect("head");
    for c in chunks {
        // The proxy may answer and close before every chunk is in.
        if s.write_all(format!("{:x}\r\n", c.len()).as_bytes())
            .await
            .is_err()
            || s.write_all(c).await.is_err()
            || s.write_all(b"\r\n").await.is_err()
        {
            break;
        }
    }
    if end {
        let _ = s.write_all(b"0\r\n\r\n").await;
    }
    s
}

/// The status and the `klav-error` of the answer on `s`.
async fn answer_of(s: &mut tokio::net::TcpStream) -> (u16, Option<String>) {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(10 * SECOND, async {
        while !buf.ends_with(b"\r\n\r\n") {
            if s.read(&mut byte).await.expect("read") == 0 {
                break;
            }
            buf.push(byte[0]);
        }
    })
    .await;
    assert!(read.is_ok(), "an answer came");
    let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let code = head
        .split("\r\n")
        .find_map(|l| l.strip_prefix("klav-error: "))
        .map(str::to_owned);
    (status, code)
}

/// Polls `check` until it holds (at most 5 s).
async fn eventually(what: &str, check: impl Fn() -> bool) {
    let begun = std::time::Instant::now();
    while !check() {
        assert!(begun.elapsed() < 5 * SECOND, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// ADR 0051 §3.3: the per-account cap on calls to providers at once and on
/// request bodies held in memory each trip with `503 klav_proxy_backlog`,
/// a call waits its turn while a slot frees up, and both give back what
/// they hold when the answer ends or the caller goes away mid-body; a body
/// sent in chunks without `Content-Length` past the body limit is cut and
/// refused with `413 klav_upstream_blocked`, and reaches no provider.
#[tokio::test(flavor = "multi_thread")]
async fn the_account_caps_trip_deterministically_and_release() {
    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let world = World::new().await;
    let img = image("0.12.0");
    let limits = QuotaLimits {
        upstream_calls: 2,
        queue_wait: 2 * SECOND,
        buffer_bytes: 1000,
        max_body: 512,
        ..QuotaLimits::default()
    };
    let enclave = world.enclave_with(&img, &server.url, limits);
    enclave.start_fresh().expect("seed");
    key_server_for(&mut server, &enclave);
    enclave
        .load_manifest(manifest(1, &[(&img, "current")]))
        .expect("manifest");
    let api_base = api(&enclave).await;
    let addr = channel(&enclave).await;
    let upstream = Upstream::start().await;
    let h = enroll_and_start(
        &server,
        &dir,
        &enclave,
        &api_base,
        "ana@example.com",
        "tok_live_caps_0123456789abcdef",
        &upstream,
    )
    .await;
    let (fwd, local) = forwarder(&h.package, addr, sni(&h.channel)).await;
    fwd.claim(&h.package).await.expect("claim");
    let state = enclave.state_of(h.account_id).await.expect("state");
    assert_eq!((state.free_slots(), state.free_buffer()), (2, 1000));

    // Calls at once: both of the account's slots held, as by two calls in
    // flight. A third waits its turn, then gets `503` with `retry_after`.
    let one = state.take_slots(None).await.expect("one");
    let two = state.take_slots(None).await.expect("two");
    let res = reqwest::get(format!("http://127.0.0.1:{local}/northflank/v1/projects"))
        .await
        .expect("call");
    assert_eq!(res.status(), 503);
    assert_eq!(
        res.headers()
            .get("klav-error")
            .and_then(|v| v.to_str().ok()),
        Some("klav_proxy_backlog")
    );
    assert_eq!(
        res.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    let body: serde_json::Value = res.json().await.expect("json");
    assert_eq!(body["retry_after"], 1);
    // While one waits its turn, a slot frees up: it goes through.
    let waiting = tokio::spawn(call(local, "/northflank/v1/projects"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(one);
    let (status, body) = waiting.await.expect("waited");
    assert_eq!(status, 200, "{body}");
    drop(two);
    eventually("every call slot came back", || state.free_slots() == 2).await;

    // Bodies held at once: 900 of the 1000 bytes held; a 200-byte body
    // doesn't fit, and fits once they are given back.
    let budget = Arc::clone(state.body_budget().expect("budget"));
    let held = Arc::clone(&budget)
        .try_acquire_many_owned(900)
        .expect("held");
    let post = || async {
        reqwest::Client::new()
            .post(format!("http://127.0.0.1:{local}/northflank/v1/upload"))
            .body(vec![b'x'; 200])
            .send()
            .await
            .expect("post")
    };
    let res = post().await;
    assert_eq!(res.status(), 503);
    assert_eq!(
        res.headers()
            .get("klav-error")
            .and_then(|v| v.to_str().ok()),
        Some("klav_proxy_backlog")
    );
    drop(held);
    let res = post().await;
    assert_eq!(res.status(), 200);
    eventually("the body's bytes came back", || state.free_buffer() == 1000).await;

    // A body that stops on the way holds its bytes only while its caller
    // is there.
    let stalled = chunked(local, "/northflank/v1/upload", &[vec![b'y'; 300]], false).await;
    eventually("the stalled body holds its bytes", || {
        state.free_buffer() == 700
    })
    .await;
    assert_eq!(state.free_slots(), 1);
    drop(stalled);
    eventually("the caller went away: its bytes and slot came back", || {
        state.free_buffer() == 1000 && state.free_slots() == 2
    })
    .await;

    // Chunked, no `Content-Length`, past the 512-byte limit: cut and
    // refused, nothing reaches the provider.
    let seen = upstream.requests().len();
    let mut over = chunked(
        local,
        "/northflank/v1/upload",
        &[vec![b'z'; 300], vec![b'z'; 300]],
        true,
    )
    .await;
    assert_eq!(
        answer_of(&mut over).await,
        (413, Some("klav_upstream_blocked".to_owned()))
    );
    assert_eq!(
        upstream.requests().len(),
        seen,
        "nothing reached the provider"
    );
    // A chunked body within the limit still goes through.
    let mut within = chunked(
        local,
        "/northflank/v1/upload",
        &[vec![b'z'; 100], vec![b'z'; 100]],
        true,
    )
    .await;
    assert_eq!(answer_of(&mut within).await.0, 200);
    eventually("everything came back", || {
        state.free_buffer() == 1000 && state.free_slots() == 2
    })
    .await;
    drop(h.person);
}

// ----------------------------------------------------- the person's side --

/// A manifest like [`manifest_with`], for the accounts of `server` (a
/// host name), valid from `issued` for `days`.
fn manifest_for(
    seq: u64,
    images: &[(&Image, &str)],
    signer: &FakeReleaseKey,
    server: &str,
    issued: u64,
    days: u64,
) -> SignedManifest {
    let images: Vec<String> = images
        .iter()
        .map(|(img, status)| {
            format!(
                r#"{{"version":"{}","commit":"{}","arch":"aarch64","pcr0":"{}","pcr1":"{}","pcr2":"{}","status":"{status}"}}"#,
                img.version,
                hex(&img.pcrs[0][..20]),
                hex(&img.pcrs[0]),
                hex(&img.pcrs[1]),
                hex(&img.pcrs[2]),
            )
        })
        .collect();
    let json = format!(
        r#"{{"v":1,"seq":{seq},"seed_epoch":0,"issued_at_ms":{issued},"expires_at_ms":{},"endpoint":"{ENDPOINT}","server":"{server}","images":[{}],"parent_roles":["{}"],"egress":["203.0.113.10/32"]}}"#,
        issued + days * DAY_MS,
        images.join(","),
        hex(&klav_role()),
    );
    let bytes = json.into_bytes();
    SignedManifest {
        signature: signer.sign(&bytes),
        bytes,
    }
}

/// What a parent in front of the enclave does to the person's requests.
#[derive(Default)]
struct Tamper {
    /// Serve this manifest instead of the enclave's.
    manifest: Option<ManifestWire>,
    /// Flip a bit of every attestation document.
    document: bool,
}

/// A parent host between the person's device and the enclave's API that
/// can lie (ADR 0051 §1.1, T276): it serves another manifest, or alters
/// the attestation. Returns its base URL.
async fn tampering_parent(enclave_api: String, tamper: Arc<Mutex<Tamper>>) -> String {
    use axum::extract::{RawQuery, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    type S = (String, Arc<Mutex<Tamper>>);
    async fn relay(res: reqwest::Response) -> axum::response::Response {
        let status = StatusCode::from_u16(res.status().as_u16()).expect("status");
        (status, res.bytes().await.expect("body").to_vec()).into_response()
    }
    let app = axum::Router::new()
        .route(
            "/v1/manifest",
            axum::routing::get(|State((base, t)): State<S>| async move {
                let forged = t.lock().expect("lock").manifest.clone();
                match forged {
                    Some(m) => axum::Json(m).into_response(),
                    None => {
                        relay(
                            reqwest::get(format!("{base}/v1/manifest"))
                                .await
                                .expect("enclave"),
                        )
                        .await
                    }
                }
            }),
        )
        .route(
            "/v1/attest",
            axum::routing::get(
                |State((base, t)): State<S>, RawQuery(q): RawQuery| async move {
                    let res = reqwest::get(format!("{base}/v1/attest?{}", q.unwrap_or_default()))
                        .await
                        .expect("enclave");
                    if !res.status().is_success() || !t.lock().expect("lock").document {
                        return relay(res).await;
                    }
                    let mut answer: AttestAnswer = res.json().await.expect("answer");
                    let mut bytes = answer.document.as_bytes().to_vec();
                    let at = bytes.len() / 2;
                    bytes[at] ^= 1;
                    answer.document = Blob::new(bytes);
                    axum::Json(answer).into_response()
                },
            ),
        )
        .route(
            "/v1/enroll",
            axum::routing::post(
                |State((base, _)): State<S>, body: axum::body::Bytes| async move {
                    relay(
                        reqwest::Client::new()
                            .post(format!("{base}/v1/enroll"))
                            .header("content-type", "application/json")
                            .body(body.to_vec())
                            .send()
                            .await
                            .expect("enclave"),
                    )
                    .await
                },
            ),
        )
        .with_state((enclave_api, tamper));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn wire(m: &SignedManifest) -> ManifestWire {
    ManifestWire {
        manifest: String::from_utf8(m.bytes.clone()).expect("utf-8"),
        signature: m.signature_hex(),
    }
}

/// Grants `item` to the account's proxy with the `northflank` profile.
async fn grant(
    person: &mut Unlocked,
    item: &str,
    upstream: &Upstream,
) -> klav_client::ClientResult<klav_client::item_grants::ItemGrantReport> {
    let mut credential = crate::sandbox_e2e_tests::credential_at(
        &item.to_ascii_lowercase(),
        &format!("https://upstream.test:{}", upstream.port),
    );
    credential.methods = vec!["GET".into()];
    let prepared = person
        .prepare_proxy_grant(item, &credential, PairingCheck::Typed(None))
        .await?;
    assert!(
        !prepared.view().first,
        "Klav Cloud's proxy has no words to compare"
    );
    prepared.require_updated_devices(true)?;
    person.commit_proxy_change(prepared).await
}

async fn add_item(person: &mut Unlocked, title: &str, value: &str) {
    let vault = person.find_vault("Personal").expect("vault");
    let project = person.find_project(vault, "General").expect("project");
    let mut item = Item::from_template(ItemKind::Login, title).expect("item");
    item.field_mut("password")
        .expect("password")
        .set_value(value)
        .expect("set");
    person
        .add_item(vault, project, &item)
        .await
        .expect("add item");
}

/// ADR 0051 layer 5, the person's device against layers 3 and 4: a real
/// `klav-server` with the enclave's service key, the enclave (fake NSM),
/// and a parent that can lie in front of its API.
///
/// - `use klav` refuses an account that isn't entitled, then enrolls,
///   verifies the attestation against the keys the server shows, and
///   writes `{mode: "klav", agent_id}`;
/// - a grant needs no words and goes out only after a fresh attestation;
/// - a forged manifest, a rolled-back one, an expired one, a revoked image
///   and an altered document each block the next grant, and the status
///   says it couldn't be verified; reading and what it holds stay;
/// - a reset enrolls generation 1, a new agent, moves the credentials to
///   it and revokes the old one;
/// - «Stop using it» revokes the agent, sets the proxy to none, and no grant
///   reaches the revoked agent afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn the_person_verifies_the_enclave_before_every_wrap() {
    use klav_client::hosted_proxy::HostedState;
    use klav_core::model::preferences::ProxyMode;

    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let world = World::new().await;
    let img = image("0.12.0");
    let enclave = world.enclave_with(&img, &server.url, QuotaLimits::default());
    enclave.start_fresh().expect("seed");
    key_server_for(&mut server, &enclave);
    let host = reqwest::Url::parse(&server.url)
        .expect("url")
        .host_str()
        .expect("host")
        .to_owned();
    let release = FakeReleaseKey::new(RELEASE);
    let seq1 = manifest_for(1, &[(&img, "current")], &release, &host, now() - 60_000, 20);
    enclave.load_manifest(seq1.clone()).expect("manifest");
    let tamper = Arc::new(Mutex::new(Tamper::default()));
    let parent = tampering_parent(api(&enclave).await, Arc::clone(&tamper)).await;
    let upstream = Upstream::start().await;

    let email = "cam@example.com";
    let mut person = account(&server, &dir, email, "tok_live_cam_0123456789abcdef").await;
    add_item(&mut person, "Second", "tok_live_cam_second_0123456789").await;
    add_item(&mut person, "Third", "tok_live_cam_third_0123456789").await;
    person
        .set_hosted_proxy_endpoint(Some(&parent))
        .expect("endpoint");
    person.set_hosted_proxy_test_anchors(world.nitro.root(), &[release.public()]);

    // Not entitled yet: nothing is enrolled or written.
    let refused = person
        .prepare_hosted_proxy_use()
        .await
        .expect_err("not entitled");
    assert!(refused.to_string().contains("isn't entitled"), "{refused}");
    assert_eq!(
        person.preferences().expect("prefs").proxy().mode,
        ProxyMode::None
    );
    hosted_proxy_switch(&server, "enable", email);

    // `use klav`: enrolled and verified, then written after "presence".
    let prepared = person.prepare_hosted_proxy_use().await.expect("prepare");
    assert_eq!(prepared.view.state, HostedState::Verified);
    let image_view = prepared.view.image.clone().expect("image");
    assert_eq!(image_view.version, "0.12.0");
    assert_eq!(image_view.pcr0, hex(&img.pcrs[0]));
    assert_eq!(prepared.view.generation, Some(0));
    let first_agent = prepared.agent_id;
    person
        .commit_hosted_proxy_use(prepared)
        .await
        .expect("commit");
    let setting = person.preferences().expect("prefs").proxy();
    assert_eq!(setting.mode, ProxyMode::Klav);
    assert_eq!(setting.agent_id, Some(first_agent));
    let status = person.proxy_status().await.expect("status");
    assert_eq!(status.agent_id, Some(first_agent));
    assert!(status.problems.is_empty(), "{:?}", status.problems);
    assert!(status.lost.is_empty());
    let hosted = status.hosted.expect("hosted view");
    assert_eq!(hosted.state, HostedState::Verified, "{}", hosted.message);
    assert_eq!(
        hosted.channel.as_deref(),
        Some(super::channel_name(first_agent, ENDPOINT).as_str())
    );

    // The first grant: no words, after a fresh attestation.
    assert!(
        grant(&mut person, "Northflank", &upstream)
            .await
            .expect("grant")
            .complete()
    );

    // Each lie of the parent blocks the next wrap, and only that.
    let other = FakeReleaseKey::new("not the release authority");
    let seq2 = manifest_for(2, &[(&img, "current")], &release, &host, now() - 60_000, 20);
    enclave.load_manifest(seq2).expect("seq 2");
    // This device now verifies seq 2: its watermark moves.
    assert_eq!(
        person
            .proxy_status()
            .await
            .expect("status")
            .hosted
            .expect("view")
            .manifest_seq,
        Some(2)
    );
    let lies: Vec<(&str, Tamper)> = vec![
        (
            "manifest_signature",
            Tamper {
                manifest: Some(wire(&manifest_for(
                    3,
                    &[(&img, "current")],
                    &other,
                    &host,
                    now() - 60_000,
                    20,
                ))),
                document: false,
            },
        ),
        (
            "manifest_rollback",
            Tamper {
                manifest: Some(wire(&seq1)),
                document: false,
            },
        ),
        (
            "manifest_expired",
            Tamper {
                manifest: Some(wire(&manifest_for(
                    4,
                    &[(&img, "current")],
                    &release,
                    &host,
                    now() - 25 * DAY_MS,
                    20,
                ))),
                document: false,
            },
        ),
        (
            "image_revoked",
            Tamper {
                manifest: Some(wire(&manifest_for(
                    5,
                    &[(&img, "revoked"), (&image("0.13.0"), "current")],
                    &release,
                    &host,
                    now() - 60_000,
                    20,
                ))),
                document: false,
            },
        ),
        (
            "other_server",
            Tamper {
                manifest: Some(wire(&manifest_for(
                    6,
                    &[(&img, "current")],
                    &release,
                    "api.klav.dev",
                    now() - 60_000,
                    20,
                ))),
                document: false,
            },
        ),
        (
            "signature",
            Tamper {
                manifest: None,
                document: true,
            },
        ),
    ];
    for (reason, lie) in lies {
        *tamper.lock().expect("lock") = lie;
        let refused = grant(&mut person, "Second", &upstream)
            .await
            .expect_err(reason);
        assert!(
            matches!(refused, klav_client::ClientError::Security(_)),
            "{reason}: {refused}"
        );
        let status = person.proxy_status().await.expect("status still reads");
        let view = status.hosted.expect("view");
        assert_eq!(view.state, HostedState::Unverified, "{reason}");
        assert!(view.state.needs_attention());
        if reason != "signature" {
            assert_eq!(view.reason.as_deref(), Some(reason));
        }
        // What it holds stays until the person acts (§6.3).
        assert_eq!(status.credentials.len(), 1, "{reason}");
    }
    // The revoked image's manifest (seq 5) was the highest verified: the
    // enclave's seq 2 is now a rollback for this device. The release
    // authority publishes a newer one, and the enclave serves it.
    *tamper.lock().expect("lock") = Tamper::default();
    let seq7 = manifest_for(7, &[(&img, "current")], &release, &host, now() - 60_000, 20);
    enclave.load_manifest(seq7).expect("seq 7");
    assert!(
        grant(&mut person, "Second", &upstream)
            .await
            .expect("an honest parent again")
            .complete()
    );

    // Reset: generation 1, a new agent, the credentials move, the old one
    // is revoked.
    let reset = person.prepare_hosted_proxy_reset().await.expect("reset");
    assert_eq!(reset.old_agent_id, Some(first_agent));
    assert_eq!(reset.new.view.generation, Some(1));
    assert_ne!(reset.new.agent_id, first_agent);
    assert_eq!(reset.credentials.len(), 2);
    let second_agent = reset.new.agent_id;
    let done = person
        .commit_hosted_proxy_reset(reset)
        .await
        .expect("reset commit");
    assert_eq!(done.share_failed, None);
    assert_eq!(done.shared.len(), 2);
    assert!(done.revoked.is_some());
    let status = person.proxy_status().await.expect("status");
    assert_eq!(status.agent_id, Some(second_agent));
    assert_eq!(status.credentials.len(), 2);
    let agents = person.agents().await.expect("agents");
    let old = agents.iter().find(|a| a.id == first_agent).expect("old");
    assert_eq!(old.status, AgentStatus::Revoked);

    // «Stop using it».
    let stopped = person.stop_hosted_proxy().await.expect("stop");
    assert!(stopped.revoked.is_some());
    assert_eq!(stopped.rotate_at_provider.len(), 2);
    assert_eq!(
        person.preferences().expect("prefs").proxy().mode,
        ProxyMode::None
    );
    let agents = person.agents().await.expect("agents");
    let gone = agents.iter().find(|a| a.id == second_agent).expect("agent");
    assert_eq!(gone.status, AgentStatus::Revoked);
    // A grant can't reach it any more: no proxy, and it was revoked here.
    assert!(grant(&mut person, "Third", &upstream).await.is_err());
}

/// Q5 (a): the person's own proxy stays beside Klav Cloud's. `use klav`
/// with an own proxy that holds a credential warns instead of refusing,
/// and the own proxy keeps its agent and its grant (it goes on serving the
/// local agents of its machine); new grants go to the hosted proxy.
#[tokio::test(flavor = "multi_thread")]
async fn the_own_proxy_keeps_its_credentials_beside_klav_cloud() {
    use klav_client::hosted_proxy::HostedState;
    use klav_core::model::preferences::ProxyMode;

    let mut server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let world = World::new().await;
    let img = image("0.12.0");
    let enclave = world.enclave_with(&img, &server.url, QuotaLimits::default());
    enclave.start_fresh().expect("seed");
    key_server_for(&mut server, &enclave);
    let host = reqwest::Url::parse(&server.url)
        .expect("url")
        .host_str()
        .expect("host")
        .to_owned();
    let release = FakeReleaseKey::new(RELEASE);
    let seq1 = manifest_for(1, &[(&img, "current")], &release, &host, now() - 60_000, 20);
    enclave.load_manifest(seq1).expect("manifest");
    let parent =
        tampering_parent(api(&enclave).await, Arc::new(Mutex::new(Tamper::default()))).await;
    let upstream = Upstream::start().await;

    let email = "dee@example.com";
    let mut person = account(&server, &dir, email, "tok_live_dee_0123456789abcdef").await;
    add_item(&mut person, "Second", "tok_live_dee_second_0123456789").await;
    person
        .set_hosted_proxy_endpoint(Some(&parent))
        .expect("endpoint");
    person.set_hosted_proxy_test_anchors(world.nitro.root(), &[release.public()]);

    // The person's own proxy, holding Northflank.
    let own = Agent::register(
        &Home::at(dir.path().join("agent-own")),
        Registration {
            name: "own-proxy".into(),
            server: server.url.clone(),
            email: email.into(),
            note: None,
            key_store: KeyStore::File {
                path: dir.path().join("own.key"),
            },
        },
    )
    .await
    .expect("register")
    .0;
    let prepared = person
        .prepare_proxy_use(Some("own-proxy"))
        .await
        .expect("use own");
    person.commit_proxy_use(prepared).await.expect("use own");
    let mut credential = crate::sandbox_e2e_tests::credential_at(
        "northflank",
        &format!("https://upstream.test:{}", upstream.port),
    );
    credential.methods = vec!["GET".into()];
    let prepared = person
        .prepare_proxy_grant("Northflank", &credential, PairingCheck::InPrompt)
        .await
        .expect("grant own");
    prepared.require_updated_devices(true).expect("ack");
    assert!(
        person
            .commit_proxy_change(prepared)
            .await
            .expect("grant own")
            .complete()
    );
    hosted_proxy_switch(&server, "enable", email);

    // `use klav`: a warning, not a refusal.
    let prepared = person.prepare_hosted_proxy_use().await.expect("prepare");
    assert_eq!(prepared.view.state, HostedState::Verified);
    assert!(
        prepared
            .warnings
            .iter()
            .any(|w| w.contains("own-proxy") && w.contains("keeps its credentials")),
        "{:?}",
        prepared.warnings
    );
    let hosted = prepared.agent_id;
    person
        .commit_hosted_proxy_use(prepared)
        .await
        .expect("commit");
    let setting = person.preferences().expect("prefs").proxy();
    assert_eq!(
        (setting.mode, setting.agent_id),
        (ProxyMode::Klav, Some(hosted))
    );

    // The own proxy is untouched: active, with Northflank in its grant.
    let own_view = person
        .agents()
        .await
        .expect("agents")
        .into_iter()
        .find(|a| a.id == own.id())
        .expect("own proxy listed");
    assert_eq!(own_view.status, AgentStatus::Active);
    let items = own_view.grant.expect("grant").items;
    assert_eq!(items.len(), 1, "{items:?}");

    // New grants go to Klav Cloud's proxy, after its check.
    assert!(
        grant(&mut person, "Second", &upstream)
            .await
            .expect("grant")
            .complete()
    );
    let status = person.proxy_status().await.expect("status");
    assert_eq!(status.agent_id, Some(hosted));
    assert_eq!(
        status.credentials.len(),
        1,
        "only Second, on the hosted proxy"
    );
}
