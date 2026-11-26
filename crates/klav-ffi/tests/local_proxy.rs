//! The proxy on this Mac through its local socket (ADR 0036 E3.5, layer
//! 11), from `DaemonEngine`: a stand-in proxy answers the documented lines
//! on `<home>/agents/klav-proxy.sock`. No `klavd` runs: the socket needs
//! none, so the app can revoke while Klav is locked.

#![cfg(feature = "daemon")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

use klav_ffi::{DaemonEngine, KlavError, LocalProxyState};

const SANDBOX: &str = "0b9c2e5a-3d41-4f6e-8a7b-1c2d3e4f5a6b";
const ISSUER: &str = "6f1c2b8e-4d3a-4f5b-9c7d-1e2f3a4b5c6d";
const PROXY: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

/// Answers each connection's line with `answer(line)`, `count` times.
fn stand_in(
    listener: UnixListener,
    count: usize,
    answer: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
    std::thread::spawn(move || {
        let mut asked = Vec::new();
        for _ in 0..count {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            reader.read_line(&mut line).expect("read");
            let request: serde_json::Value = serde_json::from_str(&line).expect("json");
            let mut out = serde_json::to_vec(&answer(&request)).expect("json");
            out.push(b'\n');
            (&stream).write_all(&out).expect("write");
            asked.push(request);
        }
        asked
    })
}

#[test]
fn the_app_lists_and_revokes_through_the_proxys_socket() {
    let home = tempfile::tempdir().expect("home");
    let engine = DaemonEngine::new(home.path().to_string_lossy().into_owned()).expect("engine");

    // Nothing there, and nothing registered.
    assert!(matches!(
        engine.local_proxy(),
        LocalProxyState::NotRunning { registered: false }
    ));
    let agents = home.path().join("agents");
    std::fs::create_dir_all(&agents).expect("agents");
    std::fs::write(agents.join("klav-proxy.json"), b"{}").expect("registration");
    assert!(matches!(
        engine.local_proxy(),
        LocalProxyState::NotRunning { registered: true }
    ));

    let listener = UnixListener::bind(agents.join("klav-proxy.sock")).expect("bind");
    let proxy = stand_in(listener, 3, |req| match req["op"].as_str() {
        Some("sandboxes") => serde_json::json!({
            "v": 1, "proxy_id": PROXY, "port": 8790, "local_calls": true,
            "channel": false, "mcp_gateway": true, "mcp_profiles": ["maple"],
            "unsent_ends": 0,
            "sandboxes": [{
                "sandbox_id": SANDBOX, "issuer_id": ISSUER, "label": "chat-1",
                "profiles": ["northflank"], "issued_at": 1, "expires_at": 2,
                "claimed": true, "connected": true, "last_seen_at": 1,
            }],
        }),
        Some("revoke") if req["scope"] == SANDBOX => {
            serde_json::json!({"v": 1, "revoked": [SANDBOX], "logged": true})
        }
        _ => serde_json::json!({"v": 1, "error": "sandbox_not_found",
                                "message": "this proxy has no live sandbox with that ID"}),
    });

    let LocalProxyState::Running { info } = engine.local_proxy() else {
        panic!("running");
    };
    assert_eq!((info.proxy_id.as_str(), info.port), (PROXY, 8790));
    assert_eq!(info.mcp_profiles, ["maple"]);
    assert_eq!(info.sandboxes.len(), 1);
    let s = &info.sandboxes[0];
    assert_eq!(
        (s.sandbox_id.as_str(), s.label.as_str()),
        (SANDBOX, "chat-1")
    );
    assert!(s.connected && s.claimed);

    let revoked = engine
        .local_proxy_revoke(Some(SANDBOX.into()))
        .expect("revoke");
    assert_eq!(
        (revoked.revoked, revoked.logged),
        (vec![SANDBOX.to_owned()], true)
    );
    let missing = engine.local_proxy_revoke(None);
    assert!(
        matches!(missing, Err(KlavError::NotFound { .. })),
        "{missing:?}"
    );
    let asked = proxy.join().expect("proxy");
    assert_eq!(
        asked[1],
        serde_json::json!({"v": 1, "op": "revoke", "scope": SANDBOX})
    );
    assert_eq!(
        asked[2],
        serde_json::json!({"v": 1, "op": "revoke", "scope": "all"})
    );

    // Not a sandbox ID: refused before anything is asked.
    assert!(matches!(
        engine.local_proxy_revoke(Some("chat-1".into())),
        Err(KlavError::Invalid { .. })
    ));
}
