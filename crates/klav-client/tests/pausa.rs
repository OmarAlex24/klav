//! The signed pauses a device takes from its own file before the first
//! sync (ADR 0033 §7.2, `Unlocked::remember_pauses`): only the ones this
//! account signed, for the scope and times they say.

mod common;

use common::ServerProcess;
use klav_client::{Home, SignupRequest, Unlocked, signup};
use klav_core::crypto::kdf::MasterPassword;
use klav_core::ids::AgentId;
use klav_proto::Blob;
use klav_proto::agent::AgentPause;
use klav_proto::auth::DeviceKind;

const PASSWORD: &str = "correct horse battery staple";

async fn sign_up(server: &ServerProcess, dir: &tempfile::TempDir, email: &str) -> Unlocked {
    signup(
        &Home::at(dir.path().join(email)),
        SignupRequest {
            server: server.url.clone(),
            email: email.into(),
            password: MasterPassword::new(PASSWORD),
            device_name: "laptop".into(),
            device_kind: DeviceKind::Cli,
            invite: None,
        },
    )
    .await
    .expect("sign-up")
    .0
}

/// `pause` as the server lists it.
fn listed(u: &Unlocked, agent: Option<AgentId>, at: i64) -> AgentPause {
    let signed = u.sign_pause(agent, true, at, 0);
    AgentPause {
        agent_id: agent,
        at: signed.at,
        until: signed.until,
        signature: signed.signature,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_pauses_this_account_signed_are_remembered() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut ana = sign_up(&server, &dir, "ana@example.com").await;
    let bob = sign_up(&server, &dir, "bob@example.com").await;
    assert!(ana.agent_pauses().is_empty());
    let agent = AgentId::generate();
    let at = 1_700_000_000_000;
    let valid = listed(&ana, Some(agent), at);
    let forged = AgentPause {
        signature: Blob::new(vec![7; 64]),
        ..valid.clone()
    };
    let short = AgentPause {
        signature: Blob::new(vec![7; 10]),
        ..valid.clone()
    };
    // Ana's signature, moved to every agent or to another time.
    let widened = AgentPause {
        agent_id: None,
        ..valid.clone()
    };
    let redated = AgentPause {
        at: at + 1,
        ..valid.clone()
    };
    // Bob's own account signed it, not Ana's.
    let foreign = listed(&bob, Some(agent), at);

    let bad = [forged, short, widened, redated, foreign];
    ana.remember_pauses(&bad);
    assert!(ana.agent_pauses().is_empty(), "{:?}", ana.agent_pauses());

    let mut mixed = bad.to_vec();
    mixed.insert(2, valid.clone());
    ana.remember_pauses(&mixed);
    assert_eq!(ana.agent_pauses(), std::slice::from_ref(&valid));

    // Once this device knows some (the sync replaces them), a later call
    // does not.
    ana.remember_pauses(&[listed(&ana, None, at)]);
    assert_eq!(ana.agent_pauses(), [valid]);
}
