//! The app's calls after the server (or an edge in front of it) closed a
//! kept-alive connection while no call ran. `KlavCore`'s runtime runs only
//! inside a call, so nothing sees that close until the next call.

mod common;

use common::ServerProcess;
use std::time::Duration;

use klav_client::api::IDLE_CONNECTION_TIMEOUT;
use klav_client::{Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_ffi::KlavCore;
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
const EMAIL: &str = "ana@example.com";

/// An account made on the laptop, and the phone signed in to it through a
/// gate that can close its connections. Returns the gate (the phone needs
/// it alive) and the phone.
fn phone(
    server: &ServerProcess,
    dir: &tempfile::TempDir,
) -> (common::Gate, std::sync::Arc<KlavCore>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");
    let secret_key = rt.block_on(async {
        let (_, kit) = klav_client::signup(
            &Home::at(dir.path().join("laptop")),
            SignupRequest {
                server: server.url.clone(),
                email: EMAIL.into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: DeviceKind::Cli,
            },
        )
        .await
        .expect("sign-up");
        kit.secret_key().to_text().expose_secret().to_owned()
    });
    // Never production: this test's own server, on loopback.
    assert!(
        server.url.starts_with("http://127.0.0.1:"),
        "{}",
        server.url
    );
    let gate = common::Gate::start(&server.url);
    assert!(gate.url.starts_with("http://127.0.0.1:"), "{}", gate.url);
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).expect("core");
    core.sign_in(
        gate.url.clone(),
        EMAIL.into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .expect("sign in");
    (gate, core)
}

/// A call made longer than [`IDLE_CONNECTION_TIMEOUT`] after the last one,
/// whose kept-alive connection the server closed meanwhile while the app
/// ran nothing: the edge closing an idle connection, or the app suspended.
/// It gets a new connection instead of failing.
#[test]
fn a_call_long_after_the_last_never_meets_a_connection_closed_meanwhile() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (gate, core) = phone(&server, &dir);
    core.sync().expect("first sync");

    gate.drop_connections();
    // Time itself is what this is about: the pool drops a connection by
    // the clock, also while the app's runtime does not run.
    std::thread::sleep(IDLE_CONNECTION_TIMEOUT + Duration::from_secs(1));
    let next = core.sync();
    assert!(next.is_ok(), "the next call: {:?}", next.err());
}

/// A call well inside [`IDLE_CONNECTION_TIMEOUT`] of the last one, whose
/// kept-alive connection the server closed meanwhile while the app ran
/// nothing (an edge closing sooner than the pool forgets, or a device that
/// slept, whose pool clock stopped): its `GET /v1/sync` goes through on a
/// new connection instead of failing.
#[test]
fn a_call_soon_after_the_last_survives_a_connection_closed_meanwhile() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (gate, core) = phone(&server, &dir);
    core.sync().expect("first sync");

    gate.drop_connections();
    // Long enough for the close to reach this side, far from the pool's
    // idle timeout.
    std::thread::sleep(Duration::from_millis(500));
    let next = core.sync();
    assert!(next.is_ok(), "the next call: {:?}", next.err());
}
