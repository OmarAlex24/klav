//! The default server and the moves of its URL (ADR 0028), without the
//! real network: one local server reachable as `127.0.0.1` and as
//! `localhost` stands for an old URL and a new one, and canned responders
//! play hosts that answer for another account.

mod common;

use common::ServerProcess;
use klav_client::server::{self, take_move};
use klav_client::{
    ClientError, Home, SignupRequest, Unlocked, emergency_kit, set_server, signup,
    unlock_with_password,
};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::AccountId;
use klav_proto::auth::{AccountKeyset, DeviceKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PASSWORD: &str = "correct horse battery staple";

async fn sign_up(server: &str, home: &Home, email: &str) -> Unlocked {
    signup(
        home,
        SignupRequest {
            server: server.to_owned(),
            email: email.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
        },
    )
    .await
    .expect("sign-up")
    .0
}

/// The same server under its other loopback name.
fn other_name(url: &str) -> String {
    url.replace("127.0.0.1", "localhost")
}

fn server_in_file(home: &Home) -> String {
    klav_client::account(home).expect("account").server
}

/// A host that answers every request with `body` (200, JSON) and reports
/// the request lines it saw.
async fn canned(body: String) -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("addr").port()
    );
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 16 * 1024];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = tx.send(head);
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    (url, rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_account_moves_when_the_new_host_has_it() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("a"));
    let mut a = sign_up(&server.url, &home, "ana@example.com").await;
    let new = other_name(&server.url);
    let moves = [(server.url.as_str(), new.as_str())];

    assert_eq!(
        a.migrate_server_with(&moves).await.as_deref(),
        Some(new.as_str())
    );
    assert_eq!(server_in_file(&home), new);
    assert_eq!(a.account().server, new);
    // `klav status` says it once.
    assert_eq!(take_move(&home).as_deref(), Some("127.0.0.1"));
    assert_eq!(take_move(&home), None);
    // The account keeps working against the new URL, cache and marks
    // included.
    a.sync().await.expect("sync on the new URL");
    let mut again = unlock_with_password(&home, &MasterPassword::new(PASSWORD)).expect("unlock");
    assert_eq!(again.account().server, new);
    again.sync().await.expect("sync after reload");
    // Nothing more to move.
    assert_eq!(again.migrate_server_with(&moves).await, None);
    // The real table has nothing to do with a local server.
    assert_eq!(again.migrate_server().await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_move_to_a_host_without_the_account() {
    let old = ServerProcess::start(900);
    let other = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("a"));
    let mut a = sign_up(&old.url, &home, "ana@example.com").await;

    // Another server (another database): our token is unknown there (401).
    let moves = [(old.url.as_str(), other.url.as_str())];
    assert_eq!(a.migrate_server_with(&moves).await, None);
    assert_eq!(server_in_file(&home), old.url);

    // Nobody listening: nothing changes either.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://127.0.0.1:{}", l.local_addr().unwrap().port())
    };
    let moves = [(old.url.as_str(), closed.as_str())];
    assert_eq!(a.migrate_server_with(&moves).await, None);
    assert_eq!(server_in_file(&home), old.url);

    // A host that answers 200 for another account, or for this account
    // with another identity.
    let mine = a.account().clone();
    let theirs = AccountKeyset {
        account_id: AccountId::generate(),
        email: mine.email.clone(),
        kdf_params: mine.kdf_params.clone(),
        public_identity: mine.public_identity.clone(),
        sealed_identity: mine.sealed_identity.clone(),
    };
    let mut other_identity = mine.public_identity.as_bytes().to_vec();
    other_identity[0] ^= 1;
    let swapped = AccountKeyset {
        account_id: mine.account_id,
        email: mine.email.clone(),
        kdf_params: mine.kdf_params.clone(),
        public_identity: klav_proto::Blob::new(other_identity),
        sealed_identity: mine.sealed_identity.clone(),
    };
    for keyset in [theirs, swapped] {
        let (fake, mut seen) = canned(serde_json::to_string(&keyset).unwrap()).await;
        let moves = [(old.url.as_str(), fake.as_str())];
        assert_eq!(a.migrate_server_with(&moves).await, None);
        assert_eq!(server_in_file(&home), old.url);
        assert_eq!(a.account().server, old.url);
        // One request, with the access token only.
        let request = seen.recv().await.expect("the fake host was asked");
        assert!(request.starts_with("GET /v1/account HTTP/1.1"), "{request}");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer "),
            "{request}"
        );
        assert!(!request.contains("refresh"), "{request}");
    }
    assert_eq!(take_move(&home), None);
    a.sync().await.expect("still works on the old URL");
}

#[tokio::test(flavor = "multi_thread")]
async fn registration_open_is_known_before_any_password() {
    let open = ServerProcess::start(900);
    let closed = ServerProcess::start_closed();
    assert_eq!(
        server::registration_open(&open.url).await.unwrap(),
        Some(true)
    );
    assert_eq!(
        server::registration_open(&closed.url).await.unwrap(),
        Some(false)
    );
    let msg = server::registration_closed_message(&closed.url);
    assert!(msg.contains("127.0.0.1"), "{msg}");
    assert!(msg.contains(server::SELF_HOSTING_URL), "{msg}");
    // The default server is named as klav.dev.
    assert!(server::registration_closed_message(server::DEFAULT_SERVER).contains("klav.dev"));

    // signup_with refuses a closed server before delivering the kit or writing state.
    let dir = tempfile::tempdir().unwrap();
    let home_dir = dir.path().join("closed");
    let home = Home::at(&home_dir);
    let mut delivered = false;
    let err = klav_client::signup_with(
        &home,
        klav_client::SignupRequest {
            server: closed.url.clone(),
            email: "ana@example.com".into(),
            password: klav_core::crypto::kdf::MasterPassword::new("correct-horse-battery"),
            device_name: "Mac".into(),
            device_kind: klav_proto::auth::DeviceKind::Macos,
        },
        |_| {
            delivered = true;
            Ok(())
        },
    )
    .await
    .err()
    .expect("closed registration should fail");
    assert!(
        !delivered,
        "kit should not be delivered when registration is closed"
    );
    assert!(
        matches!(err, klav_client::ClientError::Invalid(ref m) if m == &msg),
        "unexpected error: {err:?}"
    );
    assert!(!home_dir.join("account.json").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn set_server_logs_in_there_and_keeps_only_the_same_account() {
    let server = ServerProcess::start(900);
    let other = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("a"));
    let a = sign_up(&server.url, &home, "ana@example.com").await;
    let device = a.account().device_id;
    drop(a);
    // The same e-mail on another server is another account.
    let other_dir = tempfile::tempdir().unwrap();
    drop(
        sign_up(
            &other.url,
            &Home::at(other_dir.path().join("b")),
            "ana@example.com",
        )
        .await,
    );
    let password = MasterPassword::new(PASSWORD);

    // Another server with the same e-mail: refused, nothing changes.
    let refused = set_server(&home, &password, &other.url, DeviceKind::Cli).await;
    assert!(refused.is_err());
    assert_eq!(server_in_file(&home), server.url);

    // A wrong password: refused.
    assert!(matches!(
        set_server(
            &home,
            &MasterPassword::new("wrong"),
            &other_name(&server.url),
            DeviceKind::Cli
        )
        .await,
        Err(ClientError::WrongCredentials)
    ));
    assert_eq!(server_in_file(&home), server.url);

    // The same server under another name: moved, same device.
    let new = other_name(&server.url);
    assert_eq!(
        set_server(&home, &password, &format!("{new}/"), DeviceKind::Cli)
            .await
            .unwrap(),
        new
    );
    let account = klav_client::account(&home).unwrap();
    assert_eq!(account.server, new);
    assert_eq!(account.device_id, device);
    let mut moved = unlock_with_password(&home, &password).expect("unlock");
    moved.sync().await.expect("sync with the new session");

    // Back to the old URL by hand: the table of moves does not apply.
    assert_eq!(
        set_server(&home, &password, &server.url, DeviceKind::Cli)
            .await
            .unwrap(),
        server.url
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_kit_is_rebuilt_with_todays_server_after_the_password() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(dir.path().join("a"));
    let mut a = sign_up(&server.url, &home, "ana@example.com").await;
    let new = other_name(&server.url);
    a.migrate_server_with(&[(server.url.as_str(), new.as_str())])
        .await
        .expect("moved");
    assert!(matches!(
        emergency_kit(&home, &MasterPassword::new("wrong")),
        Err(ClientError::WrongCredentials)
    ));
    let kit = emergency_kit(&home, &MasterPassword::new(PASSWORD)).expect("kit");
    assert_eq!(kit.server_url, new);
    assert_eq!(kit.email, "ana@example.com");
    assert_eq!(kit.account_id, a.account().account_id);
    let text = klav_client::kit::render(&kit);
    assert!(text.contains(&format!("Server:     {new}")));
}
