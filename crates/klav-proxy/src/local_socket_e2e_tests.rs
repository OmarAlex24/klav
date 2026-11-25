//! The local socket end to end (ADR 0036 E3.5, layer 11): a real
//! `klav-server`, a proxy bound with its socket, an issuer starting
//! sandboxes, and the person's client on the same machine listing and
//! revoking them through the socket without a signature. The ends are
//! `person_local` in the person's verified log, and the server bars those
//! sandboxes from then on.

use klav_client::local_proxy::{self, LocalProxyError, codes};
use klav_sdk::sandbox::{self as issuer_api, StartRequest};

use crate::app::{ControlSocket, ServeOptions, StartEnv, bind};
use crate::e2e_tests::common::ServerProcess;
use crate::sandbox_e2e_tests::setup;

fn request(label: &str) -> StartRequest {
    StartRequest {
        label: label.into(),
        profiles: vec!["northflank".into()],
        ttl_secs: None,
    }
}

/// The client is blocking: off the runtime's threads.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("join")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_person_lists_and_revokes_through_the_local_socket() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut ana, proxy, mut t3) = setup(&server, &dir).await;
    let proxy_id = proxy.id();
    drop(proxy);
    let socket = dir.path().join("p.sock");
    let bound = bind(ServeOptions {
        home: klav_client::Home::at(dir.path().join("agent-klav-proxy")),
        name: "klav-proxy".into(),
        port: 0,
        channel: None,
        max_body: crate::proxy::DEFAULT_MAX_BODY,
        request_timeout: crate::proxy::DEFAULT_REQUEST_TIMEOUT,
        no_local_calls: false,
        control_socket: ControlSocket::At(socket.clone()),
        env: StartEnv::from_lookup(|_| None),
    })
    .await
    .expect("bind");
    assert_eq!(bound.control_socket(), Some(socket.as_path()));
    let port = bound.port();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(bound.run(async {
        let _ = stopped.await;
    }));

    // A second proxy on the same socket is refused, and the first keeps it.
    let again = crate::local::LocalSocket::bind(&socket);
    assert!(
        matches!(again, Err(crate::local::BindError::Taken(_))),
        "{:?}",
        again.err()
    );

    let one = issuer_api::start(&mut t3, port, &request("chat-1"))
        .await
        .expect("start")
        .sandbox_id;
    let two = issuer_api::start(&mut t3, port, &request("chat-2"))
        .await
        .expect("start")
        .sandbox_id;

    // The list: metadata only, newest first, with the proxy's own ID and
    // port.
    let path = socket.clone();
    let listed = blocking(move || local_proxy::sandboxes(&path))
        .await
        .expect("list");
    assert_eq!(listed.proxy_id, proxy_id);
    assert_eq!(listed.port, port);
    assert!(listed.local_calls);
    assert!(!listed.channel);
    let ids: Vec<_> = listed.sandboxes.iter().map(|s| s.sandbox_id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&one) && ids.contains(&two));
    let first = listed
        .sandboxes
        .iter()
        .find(|s| s.sandbox_id == one)
        .expect("one");
    assert_eq!(
        (first.label.as_str(), first.profiles.as_slice()),
        ("chat-1", ["northflank".to_owned()].as_slice())
    );
    assert!(!first.claimed && !first.connected);
    let raw = serde_json::to_string(&listed).expect("json");
    assert!(!raw.contains("secret"), "{raw}");

    // A sandbox it does not have, and a scope that is not one.
    let path = socket.clone();
    let missing =
        blocking(move || local_proxy::revoke(&path, Some(klav_core::ids::SandboxId::generate())))
            .await;
    assert!(
        matches!(&missing, Err(LocalProxyError::Refused { code, .. }) if code == codes::NOT_FOUND),
        "{missing:?}"
    );

    // One, then all: ended at once, logged by the server.
    let path = socket.clone();
    let revoked = blocking(move || local_proxy::revoke(&path, Some(one)))
        .await
        .expect("revoke one");
    assert_eq!((revoked.revoked, revoked.logged), (vec![one], true));
    let left: Vec<_> = issuer_api::list(&t3, port)
        .await
        .expect("ls")
        .into_iter()
        .map(|s| s.sandbox_id)
        .collect();
    assert_eq!(left, [two]);
    let path = socket.clone();
    let revoked = blocking(move || local_proxy::revoke(&path, None))
        .await
        .expect("revoke all");
    assert_eq!((revoked.revoked, revoked.logged), (vec![two], true));
    let path = socket.clone();
    let revoked = blocking(move || local_proxy::revoke(&path, None))
        .await
        .expect("revoke all, none live");
    assert_eq!((revoked.revoked.len(), revoked.logged), (0, true));
    let path = socket.clone();
    let empty = blocking(move || local_proxy::sandboxes(&path))
        .await
        .expect("list");
    assert!(empty.sandboxes.is_empty());
    assert_eq!(empty.unsent_ends, 0);

    // In the person's verified log: two `person_local` ends.
    ana.verify_audit().await.expect("the chain verifies");
    let ends: Vec<Option<String>> = ana
        .audit_log(&klav_client::audit::LogFilter::default())
        .await
        .expect("log")
        .into_iter()
        .filter(|l| l.action == "sandbox.revoked")
        .map(|l| l.outcome)
        .collect();
    assert_eq!(
        ends,
        [
            Some("person_local".to_owned()),
            Some("person_local".to_owned())
        ]
    );

    // Stopped: the socket file goes with it.
    let _ = stop.send(());
    task.await.expect("join").expect("run");
    assert!(!socket.exists(), "the socket file is removed at the end");
}

/// A request that is not one is answered with an error line, and a peer
/// that never sends a line is closed without an answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_bad_line_gets_an_error_line() {
    use std::io::{BufRead, BufReader, Write};
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let (_ana, proxy, _t3) = setup(&server, &dir).await;
    drop(proxy);
    let socket = dir.path().join("p.sock");
    let bound = bind(ServeOptions {
        home: klav_client::Home::at(dir.path().join("agent-klav-proxy")),
        name: "klav-proxy".into(),
        port: 0,
        channel: None,
        max_body: crate::proxy::DEFAULT_MAX_BODY,
        request_timeout: crate::proxy::DEFAULT_REQUEST_TIMEOUT,
        no_local_calls: false,
        control_socket: ControlSocket::At(socket.clone()),
        env: StartEnv::from_lookup(|_| None),
    })
    .await
    .expect("bind");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(bound.run(async {
        let _ = stopped.await;
    }));
    let path = socket.clone();
    let answers = blocking(move || {
        let mut answers = Vec::new();
        for line in [
            "{\"v\":2,\"op\":\"sandboxes\"}\n",
            "{\"v\":1,\"op\":\"stop\"}\n",
            "{\"v\":1,\"op\":\"revoke\",\"scope\":\"chat-1\"}\n",
            "not json\n",
        ] {
            let mut stream = std::os::unix::net::UnixStream::connect(&path).expect("connect");
            stream.write_all(line.as_bytes()).expect("write");
            let mut answer = String::new();
            BufReader::new(stream).read_line(&mut answer).expect("read");
            answers.push(answer);
        }
        answers
    })
    .await;
    for answer in answers {
        let e = local_proxy::read_answer::<local_proxy::LocalRevoked>(&answer);
        assert!(
            matches!(&e, Err(LocalProxyError::Refused { code, .. }) if code == codes::BAD_REQUEST),
            "{answer}"
        );
    }
    let _ = stop.send(());
    task.await.expect("join").expect("run");
}
