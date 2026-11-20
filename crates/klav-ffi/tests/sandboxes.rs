//! The person's sandboxes from the iPhone (`KlavCore`, ADR 0036 E2.1,
//! E2.3): the list from the verified log with the proxy's signed heartbeat,
//! and the revocation of one sandbox and of all of them, against a real
//! server and a proxy that signs its requests as `klav-proxy` does.

mod common;

use common::ServerProcess;
use common::sandboxes::{PASSWORD, setup};
use klav_ffi::{KlavCore, KlavError, SandboxRevokeInfo, SandboxStatusInfo};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
}

#[test]
fn the_phone_lists_and_revokes_the_accounts_sandboxes() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("phone");
    let made = runtime().block_on(setup(&server, &home, "ana@example.com"));
    let (proxy, claimed, waiting) = (
        made.proxy.to_string(),
        made.claimed.to_string(),
        made.waiting.to_string(),
    );

    let core = KlavCore::new(home.display().to_string()).expect("core");
    assert!(matches!(core.sandbox_list(false), Err(KlavError::Locked)));
    core.unlock_with_password(PASSWORD.into(), None)
        .expect("unlock");

    // The log's two sandboxes, and the proxy's heartbeat on the claimed one.
    let list = core.sandbox_list(false).expect("list");
    let view = list.proxy.expect("the account's proxy");
    assert_eq!(view.agent_id, proxy);
    assert_eq!(view.name.as_deref(), Some("klav-proxy"));
    assert_eq!(
        (view.no_signs, view.quiet, view.paused),
        (None, false, false)
    );
    assert!(!list.marks_unreadable);
    let rows: Vec<_> = list
        .sandboxes
        .iter()
        .map(|s| (s.sandbox_id.clone(), s.label.clone(), s.status, s.connected))
        .collect();
    assert_eq!(
        rows,
        [
            (
                claimed.clone(),
                "chat-1".to_owned(),
                SandboxStatusInfo::Active,
                Some(true)
            ),
            (
                waiting.clone(),
                "chat-2".to_owned(),
                SandboxStatusInfo::Waiting,
                None
            ),
        ]
    );
    assert_eq!(list.sandboxes[0].issuer_name.as_deref(), Some("t3-code"));

    // Revoking one: the server takes it, and the list says «Revoking…».
    let revoked = core
        .revoke_sandbox(proxy.clone(), claimed.clone())
        .expect("revoke");
    let SandboxRevokeInfo::Revoked {
        scope, sandbox_ids, ..
    } = revoked
    else {
        panic!("not applied: {revoked:?}");
    };
    assert_eq!(
        (scope, sandbox_ids),
        (claimed.clone(), vec![claimed.clone()])
    );
    let list = core.sandbox_list(false).expect("list");
    assert_eq!(list.sandboxes[0].status, SandboxStatusInfo::Revoking);
    assert_eq!(list.sandboxes[1].status, SandboxStatusInfo::Waiting);

    // Revoking all: it covers the other one too.
    let all = core
        .revoke_all_sandboxes(proxy.clone())
        .expect("revoke all");
    let SandboxRevokeInfo::Revoked {
        scope, sandbox_ids, ..
    } = all
    else {
        panic!("not applied: {all:?}");
    };
    assert_eq!(scope, "all");
    assert!(sandbox_ids.contains(&waiting));
    let list = core.sandbox_list(false).expect("list");
    assert!(
        list.sandboxes
            .iter()
            .all(|s| s.status == SandboxStatusInfo::Revoking)
    );

    // IDs that are not IDs are refused before anything is signed.
    for (p, s) in [("nope", claimed.as_str()), (proxy.as_str(), "nope")] {
        assert!(matches!(
            core.revoke_sandbox(p.into(), s.into()),
            Err(KlavError::Invalid { .. })
        ));
    }
    core.lock();
    assert!(matches!(
        core.revoke_all_sandboxes(proxy),
        Err(KlavError::Locked)
    ));
}
