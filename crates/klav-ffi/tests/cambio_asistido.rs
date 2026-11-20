//! Vault health and assisted password changes from the phone (ADR 0022
//! §4–6) against the real server:
//!
//! * the health report sees Invoices and Bank sharing a password, with no
//!   value in it, and the breach check stays off until the person turns it
//!   on (a local setting);
//! * «Fix my reused passwords»: the card lists both logins by host, a login
//!   without a website is refused before Face ID, and the offered task
//!   holds `rotate` (and `totp` added by Klav on Invoices);
//! * an agent changes Invoices through the person's other device (as
//!   `klavd` does) and confirms it; it starts Bank and stops. The phone
//!   follows each site (changed, then pending and started) and sees Bank's
//!   pending password, keeps the current one, and the new one goes to the
//!   history unconfirmed.

mod common;

use common::ServerProcess;
use klav_client::rotate::{PageRules, RotationStep};
use klav_client::{Home, SignupRequest, Unlocked};
use klav_core::crypto::agent::{self, SignedRequest};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::random;
use klav_core::ids::{AgentId, ItemId, TaskId};
use klav_core::model::item::{Item, ItemKind};
use klav_ffi::{ItemQuery, KlavCore, KlavError, OfferInput};
use klav_proto::Blob;
use klav_proto::agent::{
    HEADER_AGENT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, RegisterAgent,
};
use klav_proto::auth::DeviceKind;
use klav_proto::rotate::{AgentRequestProof, RotationStarted};
use secrecy::ExposeSecret;
use std::str::FromStr;

const PASSWORD: &str = "correct horse battery staple";
const TOTP: &str = "JBSWY3DPEHPK3PXP";
/// The password Invoices and Bank share.
const SHARED: &str = "MARKER-shared-ffi-password";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
}

fn login(title: &str, url: Option<&str>, password: &str, totp: bool) -> Item {
    let mut item = Item::from_template(ItemKind::Login, title).expect("test setup");
    item.field_mut("username")
        .expect("test setup")
        .set_value("ana")
        .expect("test setup");
    item.field_mut("password")
        .expect("test setup")
        .set_value(password)
        .expect("test setup");
    if totp {
        item.field_mut("totp")
            .expect("test setup")
            .set_value(TOTP)
            .expect("test setup");
    }
    if let Some(url) = url {
        item.add_url(url).expect("test setup");
    }
    item
}

/// Signs up on "the laptop" with Invoices and Bank (the same password),
/// Notes (the same password, no website) and Shop (its own). Returns the
/// laptop's session, which plays the person's `klavd`, and the Secret Key.
fn laptop(rt: &tokio::runtime::Runtime, server: &str, dir: &std::path::Path) -> (Unlocked, String) {
    rt.block_on(async {
        let (mut laptop, kit) = klav_client::signup(
            &Home::at(dir.join("laptop")),
            SignupRequest {
                server: server.to_owned(),
                email: "ana@example.com".into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: DeviceKind::Cli,
            },
        )
        .await
        .expect("test setup");
        let vault = laptop.find_vault("Personal").expect("test setup");
        let project = laptop.find_project(vault, "General").expect("test setup");
        for item in [
            login(
                "Invoices",
                Some("https://invoices.example.com/login"),
                SHARED,
                true,
            ),
            login(
                "Bank",
                Some("https://bank.example.com/login"),
                SHARED,
                false,
            ),
            login("Notes", None, SHARED, false),
            login(
                "Shop",
                Some("https://shop.example.com/"),
                "MARKER-unique-Xq9!vT2#pL7@wR4",
                false,
            ),
        ] {
            laptop
                .add_item(vault, project, &item)
                .await
                .expect("test setup");
        }
        (
            laptop,
            kit.secret_key().to_text().expose_secret().to_owned(),
        )
    })
}

/// An agent with its own key, signing its requests (spec §13.3).
struct Agent {
    id: AgentId,
    keys: IdentityKeyPair,
    server: String,
}

impl Agent {
    fn register(server: &str) -> (Self, String) {
        let agent = Self {
            id: AgentId::generate(),
            keys: IdentityKeyPair::generate(),
            server: server.to_owned(),
        };
        let status = runtime().block_on(async {
            reqwest::Client::new()
                .post(format!("{server}/v1/agents/register"))
                .json(&RegisterAgent {
                    id: agent.id,
                    email: "ana@example.com".into(),
                    name: "rotate-bot".into(),
                    public_identity: Blob::new(agent.keys.public().encode().to_vec()),
                    note: None,
                })
                .send()
                .await
                .expect("test setup")
                .status()
        });
        assert_eq!(status.as_u16(), 202);
        let words = agent::pairing_code(agent.keys.public());
        (agent, words)
    }

    /// A signed `POST`: (status, body, the request as proof for `klavd`).
    fn post(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> (u16, serde_json::Value, AgentRequestProof) {
        let bytes = serde_json::to_vec(body).expect("test setup");
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test setup")
            .as_millis();
        let timestamp = u64::try_from(timestamp).expect("test setup");
        let nonce = random::array::<16>();
        let signature = agent::sign_request(
            &self.keys,
            &SignedRequest {
                agent: self.id,
                method: "POST",
                path,
                timestamp_ms: timestamp,
                nonce: &nonce,
                body_digest: &agent::body_digest(&bytes),
            },
        );
        let proof = AgentRequestProof {
            method: "POST".into(),
            path: path.to_owned(),
            timestamp_ms: timestamp,
            nonce: Blob::new(nonce.to_vec()),
            body: Blob::new(bytes.clone()),
            signature: Blob::new(signature.to_bytes().to_vec()),
        };
        let (status, json) = runtime().block_on(async {
            let res = reqwest::Client::new()
                .post(format!("{}{path}", self.server))
                .header(HEADER_AGENT, self.id.to_string())
                .header(HEADER_TIMESTAMP, timestamp.to_string())
                .header(HEADER_NONCE, Blob::new(nonce.to_vec()).to_text())
                .header(
                    HEADER_SIGNATURE,
                    Blob::new(signature.to_bytes().to_vec()).to_text(),
                )
                .header("content-type", "application/json")
                .body(bytes)
                .send()
                .await
                .expect("test setup");
            let status = res.status().as_u16();
            (status, res.json().await.unwrap_or(serde_json::Value::Null))
        });
        (status, json, proof)
    }

    /// `rotate_password`: the server's half; returns the step for `klavd`.
    fn start(&self, task: TaskId, item: ItemId, host: &str) -> RotationStep {
        let (status, body, proof) = self.post(
            "/v1/agent/rotations",
            &serde_json::json!({
                "item_id": item,
                "reason": "Give the site a new password",
                "claims": { "domain": host },
                "task_id": task,
            }),
        );
        assert_eq!(status, 201, "{body}");
        let started: RotationStarted = serde_json::from_value(body).expect("rotation");
        RotationStep {
            agent_id: self.id,
            task_id: task,
            rotation_id: started.rotation.id,
            item_id: item,
            request: proof,
        }
    }

    /// `rotate_confirm`: the server's half; returns the step for `klavd`.
    fn confirm(&self, step: &RotationStep) -> RotationStep {
        let (status, body, proof) = self.post(
            &format!("/v1/agent/rotations/{}/confirm", step.rotation_id),
            &serde_json::json!({ "item_id": step.item_id, "reason": "The site took it" }),
        );
        assert_eq!(status, 200, "{body}");
        RotationStep {
            request: proof,
            ..step.clone()
        }
    }
}

/// Nothing the phone got may carry a password.
fn no_values(what: &impl std::fmt::Debug) {
    let text = format!("{what:?}");
    assert!(!text.contains("MARKER"), "a value leaked: {text}");
}

#[test]
fn the_phone_sees_the_health_offers_the_fix_and_settles_a_pending_password() {
    let rt = runtime();
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let (mut laptop, secret_key) = laptop(&rt, &server.url, dir.path());
    let phone_home = dir.path().join("phone");
    let core = KlavCore::new(phone_home.display().to_string()).unwrap();
    core.sign_in(
        server.url.clone(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key,
        "iPhone".into(),
        None,
    )
    .unwrap();
    let items = core.items(ItemQuery::default()).unwrap();
    let id_of = |title: &str| items.iter().find(|i| i.title == title).unwrap().clone();
    let (invoices, bank, notes) = (id_of("Invoices"), id_of("Bank"), id_of("Notes"));

    // The breach check: off by default, a local setting (never on in tests:
    // it would ask Have I Been Pwned).
    assert!(!core.health_settings().unwrap().breach_check);
    assert!(core.set_breach_check(true).unwrap().breach_check);
    assert!(core.health_settings().unwrap().breach_check);
    assert!(phone_home.join("health.json").exists());
    assert!(!core.set_breach_check(false).unwrap().breach_check);

    // The report: one group of three, no values.
    let health = core.vault_health().unwrap();
    no_values(&health);
    assert_eq!(health.items, 4);
    assert_eq!(health.passwords, 4);
    assert_eq!(health.breaches.status, "off");
    assert_eq!(health.reused.len(), 1);
    let mut titles: Vec<&str> = health.reused[0]
        .items
        .iter()
        .map(|i| i.title.as_str())
        .collect();
    titles.sort_unstable();
    assert_eq!(titles, ["Bank", "Invoices", "Notes"]);

    // The card needs an agent with a grant first.
    let offer = core.reused_offer(None).unwrap();
    assert!(offer.agents.is_empty() && offer.agent.is_none());
    let (agent, words) = Agent::register(&server.url);
    core.approve_agent(
        agent.id.to_string(),
        words,
        vec![invoices.project_id.clone()],
        None,
    )
    .unwrap();

    // The only agent is picked; logins sorted by host, the blocked one last.
    let offer = core.reused_offer(None).unwrap();
    no_values(&offer);
    assert_eq!(offer.agent.as_ref().unwrap().name, "rotate-bot");
    let rows: Vec<(&str, Option<&str>)> = offer
        .rows
        .iter()
        .map(|r| (r.title.as_str(), r.blocked.as_deref()))
        .collect();
    assert_eq!(
        rows,
        [
            ("Bank", None),
            ("Invoices", None),
            ("Notes", Some("no_site"))
        ]
    );
    assert_eq!(offer.rows[1].permissions, ["rotate", "totp"]);
    assert_eq!(offer.rows[0].group, Some(1));
    assert_eq!(offer.task, "Change passwords");

    // Checked before Face ID: nothing, or a login without a site, is refused.
    let input = |ids: Vec<String>| OfferInput {
        agent: agent.id.to_string(),
        items: ids,
        task: None,
        reason: None,
        duration_secs: Some(3600),
    };
    assert!(matches!(
        core.check_offer(input(vec![])),
        Err(KlavError::Invalid { .. })
    ));
    assert!(matches!(
        core.check_offer(input(vec![bank.id.clone(), notes.id.clone()])),
        Err(KlavError::Invalid { .. })
    ));
    assert!(core.tasks().unwrap().is_empty(), "nothing was sent");
    let both = vec![bank.id.clone(), invoices.id.clone()];
    assert_eq!(core.check_offer(input(both.clone())).unwrap(), 2);

    // Offered: approved at once, by the person, with `rotate`.
    let task = core.offer_task(input(both)).unwrap();
    assert_eq!(task.status, "approved");
    assert!(task.offered);
    assert_eq!(task.agent, "rotate-bot");
    for row in &task.rows {
        assert!(
            row.permissions
                .iter()
                .any(|p| p.permission == "rotate" && p.checked),
            "{row:?}"
        );
    }
    let listed = core.tasks().unwrap();
    assert!(listed.iter().any(|t| t.id == task.id && t.offered));
    let progress = core.task_progress(task.id.clone()).unwrap();
    assert_eq!(progress.sites.len(), 2);
    assert!(
        progress
            .sites
            .iter()
            .all(|s| s.state == "pending" && !s.started)
    );

    // Invoices: changed and confirmed through the laptop, as `klavd` does.
    // (The agent's requests block on their own runtime: never inside the
    // laptop's.)
    let task_id = TaskId::from_str(&task.id).unwrap();
    rt.block_on(laptop.sync()).unwrap();
    let step = agent.start(
        task_id,
        ItemId::from_str(&invoices.id).unwrap(),
        "invoices.example.com",
    );
    rt.block_on(async {
        let plan = laptop.rotation_begin(&step).await.unwrap();
        laptop
            .rotation_store_pending(&plan, &PageRules::default())
            .await
            .unwrap();
    });
    let done = agent.confirm(&step);
    rt.block_on(laptop.rotation_finish(&done, true)).unwrap();

    // Bank: started, the new password pending, and the agent stops.
    let step = agent.start(
        task_id,
        ItemId::from_str(&bank.id).unwrap(),
        "bank.example.com",
    );
    rt.block_on(async {
        let plan = laptop.rotation_begin(&step).await.unwrap();
        laptop
            .rotation_store_pending(&plan, &PageRules::default())
            .await
            .unwrap();
    });

    core.sync().unwrap();
    let progress = core.task_progress(task.id.clone()).unwrap();
    no_values(&progress);
    let site = |title: &str| {
        progress
            .sites
            .iter()
            .find(|s| s.title.as_deref() == Some(title))
            .unwrap()
    };
    assert_eq!(site("Invoices").state, "changed");
    assert_eq!(site("Bank").state, "pending");
    assert!(site("Bank").started);
    assert_eq!(site("Bank").hosts, ["bank.example.com"]);
    assert!(progress.card.as_ref().is_some_and(|c| c.offered));

    // Invoices has a new password; the shared one is its previous one.
    let changed = core
        .field_value(invoices.id.clone(), "password".into())
        .unwrap();
    assert_ne!(changed, SHARED);
    let history = core.password_history(invoices.id.clone()).unwrap();
    assert!(!history.pending);
    assert_eq!(history.entries.len(), 1);
    assert!(!history.entries[0].unconfirmed);
    assert_eq!(
        core.previous_password(invoices.id.clone(), 0).unwrap(),
        SHARED
    );

    // Bank: «Pending change: did the new password work?»
    let history = core.password_history(bank.id.clone()).unwrap();
    no_values(&history);
    assert!(history.pending);
    assert!(history.pending_since.is_some());
    assert!(history.entries.is_empty());

    // «Keep the current one»: the new one goes to the history, unconfirmed.
    let kept = core.resolve_pending(bank.id.clone(), false).unwrap();
    assert!(!kept.pending);
    assert_eq!(kept.entries.len(), 1);
    assert!(kept.entries[0].unconfirmed);
    assert_eq!(
        core.field_value(bank.id.clone(), "password".into())
            .unwrap(),
        SHARED
    );
    let unconfirmed = core.previous_password(bank.id.clone(), 0).unwrap();
    assert_ne!(unconfirmed, SHARED);
    // Decided: there is nothing left to decide.
    assert!(matches!(
        core.resolve_pending(bank.id.clone(), true),
        Err(KlavError::NotFound { .. })
    ));
    // The laptop sees the same.
    rt.block_on(async {
        laptop.sync().await.unwrap();
        let loc = laptop.find_item(&bank.id).unwrap();
        let view = laptop.password_history(loc).unwrap();
        assert!(!view.pending && view.entries[0].unconfirmed);
    });
}
