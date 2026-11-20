//! Task requests from the phone (ADR 0021 §8) against the real server: an
//! agent asks for a task, the phone sees the card Klav completed (titles
//! from the vault, `totp` added on a login with TOTP), leaves an item and
//! the added code out, shortens it and approves; a code outside the task
//! comes back as «Outside the task» and is added to it (revision 2, same
//! end); the person ends the task; another task is denied.

mod common;

use common::ServerProcess;
use klav_client::{Home, SignupRequest};
use klav_core::crypto::agent::{self, SignedRequest};
use klav_core::crypto::identity::IdentityKeyPair;
use klav_core::crypto::kdf::MasterPassword;
use klav_core::crypto::random;
use klav_core::ids::{AgentId, ItemId, ProjectId, VaultId};
use klav_core::model::item::{Item, ItemKind};
use klav_core::policy::Permission;
use klav_core::task::{TASK_FORMAT_VERSION, TaskAccessRequest, TaskRequest};
use klav_ffi::{
    ItemInfo, ItemQuery, KlavCore, KlavError, TaskChoiceEntry, TaskChoiceInput, TaskItem,
};
use klav_proto::Blob;
use klav_proto::agent::{
    HEADER_AGENT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP, PendingApproval, RegisterAgent,
};
use klav_proto::auth::DeviceKind;
use klav_proto::task::PendingTask;
use secrecy::ExposeSecret;
use std::str::FromStr;

const PASSWORD: &str = "correct horse battery staple";
const TOTP: &str = "JBSWY3DPEHPK3PXP";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup")
}

fn login(title: &str, url: &str, totp: bool) -> Item {
    let mut item = Item::from_template(ItemKind::Login, title).expect("test setup");
    item.field_mut("username")
        .expect("test setup")
        .set_value("ana")
        .expect("test setup");
    item.field_mut("password")
        .expect("test setup")
        .set_value("MARKER-ffi-task-password")
        .expect("test setup");
    if totp {
        item.field_mut("totp")
            .expect("test setup")
            .set_value(TOTP)
            .expect("test setup");
    }
    item.add_url(url).expect("test setup");
    item
}

/// Signs up on "the laptop" with Invoices (with TOTP) and Bank; returns
/// the Secret Key.
fn laptop(server: &str, dir: &std::path::Path) -> String {
    runtime().block_on(async {
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
            login("Invoices", "https://invoices.example.com/login", true),
            login("Bank", "https://bank.example.com/login", false),
        ] {
            laptop
                .add_item(vault, project, &item)
                .await
                .expect("test setup");
        }
        kit.secret_key().to_text().expose_secret().to_owned()
    })
}

/// An agent with its own key, signing its requests (spec §13.3).
struct Agent {
    id: AgentId,
    keys: IdentityKeyPair,
    server: String,
}

impl Agent {
    /// Registers, as `klav agent register` does; returns it and its words.
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
                    name: "invoices-bot".into(),
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

    /// A signed `POST` with a JSON body: (status, body).
    fn post(&self, path: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
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
        runtime().block_on(async {
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
        })
    }

    fn ask_task(&self, task: &str, access: Vec<TaskAccessRequest>) -> PendingTask {
        let request = TaskRequest {
            v: TASK_FORMAT_VERSION,
            task: task.into(),
            reason: "Reconcile the month's expenses".into(),
            duration_secs: 7200,
            access,
        };
        let (status, body) = self.post(
            "/v1/agent/tasks",
            &serde_json::to_value(&request).expect("test setup"),
        );
        assert_eq!(status, 202, "{body}");
        serde_json::from_value(body).expect("pending task")
    }
}

fn access(item: &ItemInfo, permissions: &[Permission]) -> TaskAccessRequest {
    TaskAccessRequest {
        vault_id: VaultId::from_str(&item.vault_id).expect("test setup"),
        project_id: ProjectId::from_str(&item.project_id).expect("test setup"),
        item_id: ItemId::from_str(&item.id).expect("test setup"),
        permissions: permissions.to_vec(),
        domain: None,
    }
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test setup")
            .as_millis(),
    )
    .expect("test setup")
}

/// The checked permissions of `item` on `card`.
fn checked(card: &TaskItem, item: &str) -> Vec<String> {
    card.rows
        .iter()
        .filter(|r| r.item_id == item)
        .flat_map(|r| r.permissions.iter().filter(|p| p.checked))
        .map(|p| p.permission.clone())
        .collect()
}

#[test]
fn a_phone_approves_a_task_adds_to_it_and_ends_it() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().unwrap();
    let secret_key = laptop(&server.url, dir.path());
    let core = KlavCore::new(dir.path().join("phone").display().to_string()).unwrap();
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
    let invoices = items.iter().find(|i| i.title == "Invoices").unwrap();
    let bank = items.iter().find(|i| i.title == "Bank").unwrap();

    // The agent joins with the default policy (`totp` asks).
    let (agent, words) = Agent::register(&server.url);
    core.approve_agent(
        agent.id.to_string(),
        words,
        vec![invoices.project_id.clone()],
        None,
    )
    .unwrap();
    assert!(core.tasks().unwrap().is_empty());

    // The card: titles from the vault and the code Klav added.
    let pending = agent.ask_task(
        "Download the October invoices",
        vec![
            access(invoices, &[Permission::Fill]),
            access(bank, &[Permission::Fill, Permission::Update]),
        ],
    );
    let tasks = core.tasks().unwrap();
    assert_eq!(tasks.len(), 1);
    let card = &tasks[0];
    assert_eq!(card.id, pending.pending_task_id.to_string());
    assert_eq!(card.status, "pending");
    assert_eq!(card.agent, "invoices-bot");
    assert_eq!(card.task, "Download the October invoices");
    assert_eq!(card.duration_secs, 7200);
    assert_eq!(card.revision, 0);
    let row = card.rows.iter().find(|r| r.item_id == invoices.id).unwrap();
    assert_eq!(row.title.as_deref(), Some("Invoices"));
    assert_eq!(row.username.as_deref(), Some("ana"));
    assert_eq!(row.domains, vec!["invoices.example.com".to_owned()]);
    let totp = row
        .permissions
        .iter()
        .find(|p| p.permission == "totp")
        .unwrap();
    assert!(totp.checked && totp.added_by_klav && !totp.asked);
    assert_eq!(checked(card, &bank.id), vec!["fill", "update"]);

    // Bad choices are refused before anything is signed.
    let entry = |item: &str, permission: Option<&str>| TaskChoiceEntry {
        item_id: item.to_owned(),
        permission: permission.map(str::to_owned),
    };
    assert!(matches!(
        core.decide_task(
            card.id.clone(),
            true,
            Some(TaskChoiceInput {
                without: vec![entry(&invoices.id, Some("bogus"))],
                ..TaskChoiceInput::default()
            }),
            card.request_digest.clone(),
        ),
        Err(KlavError::Invalid { .. })
    ));
    assert!(matches!(
        core.decide_task(
            card.id.clone(),
            true,
            Some(TaskChoiceInput {
                for_secs: Some(60),
                ..TaskChoiceInput::default()
            }),
            card.request_digest.clone(),
        ),
        Err(KlavError::Invalid { .. })
    ));
    assert!(
        core.decide_task(
            card.id.clone(),
            true,
            Some(TaskChoiceInput {
                without: vec![entry(&invoices.id, None), entry(&bank.id, None)],
                ..TaskChoiceInput::default()
            }),
            card.request_digest.clone(),
        )
        .is_err(),
        "nothing left to approve"
    );
    // A card other than the one the server serves now is not signed (ADR
    // 0030 §5): the task stays pending.
    assert!(matches!(
        core.decide_task(card.id.clone(), true, None, "00".repeat(32)),
        Err(KlavError::Security { .. })
    ));
    assert_eq!(core.tasks().unwrap()[0].status, "pending");

    // Without Bank and the added code, for 30 minutes.
    let before = now_ms();
    let approved = core
        .decide_task(
            card.id.clone(),
            true,
            Some(TaskChoiceInput {
                without: vec![entry(&bank.id, None), entry(&invoices.id, Some("totp"))],
                with: Vec::new(),
                for_secs: Some(1800),
            }),
            card.request_digest.clone(),
        )
        .unwrap();
    assert_eq!(approved.status, "approved");
    assert_eq!(approved.revision, 1);
    let expires_at = approved.expires_at.unwrap();
    assert!((before + 1_795_000..=now_ms() + 1_800_000).contains(&expires_at));
    assert_eq!(checked(&approved, &invoices.id), vec!["fill"]);
    assert!(checked(&approved, &bank.id).is_empty());
    let live = core.tasks().unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0], approved);

    // A code outside the task: «Outside the task», and it can be added.
    let (status, body) = agent.post(
        "/v1/agent/access",
        &serde_json::json!({
            "item_id": invoices.id,
            "permission": "totp",
            "reason": "the site asks for the code",
        }),
    );
    assert_eq!(status, 202, "{body}");
    let asked: PendingApproval = serde_json::from_value(body).unwrap();
    let approvals = core.approvals().unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].id, asked.pending_approval_id.to_string());
    let outside = approvals[0].task.clone().unwrap();
    assert_eq!(outside.id, approved.id);
    assert_eq!(outside.task, "Download the October invoices");
    assert_eq!(outside.expires_at, expires_at);
    assert!(outside.can_add);

    assert!(matches!(
        core.add_to_task("not-an-id".into(), approvals[0].request_digest.clone()),
        Err(KlavError::Invalid { .. })
    ));
    assert!(matches!(
        core.add_to_task(approvals[0].id.clone(), "00".repeat(32)),
        Err(KlavError::Security { .. })
    ));
    let added = core
        .add_to_task(approvals[0].id.clone(), approvals[0].request_digest.clone())
        .unwrap();
    assert_eq!(added.revision, 2);
    assert_eq!(added.expires_at, Some(expires_at), "the task is not longer");
    assert_eq!(added.created_at, approved.created_at);
    assert_eq!(checked(&added, &invoices.id), vec!["fill", "totp"]);
    assert!(core.approvals().unwrap().is_empty());

    // «End task»: ended by the person, and gone from the list.
    let ended = core.end_task(added.id.clone()).unwrap();
    assert_eq!(ended.status, "ended");
    assert_eq!(ended.ended_by.as_deref(), Some("person"));
    assert!(core.tasks().unwrap().is_empty());
    assert!(core.end_task(added.id).is_err(), "already ended");

    // Another task, denied (no choice needed).
    let other = agent.ask_task(
        "Check the bank",
        vec![access(invoices, &[Permission::Fill])],
    );
    let shown = core.tasks().unwrap()[0].request_digest.clone();
    let denied = core
        .decide_task(
            other.pending_task_id.to_string(),
            false,
            None,
            shown.clone(),
        )
        .unwrap();
    assert_eq!(denied.status, "denied");
    assert!(core.tasks().unwrap().is_empty());
    assert!(matches!(
        core.decide_task("nope".into(), false, None, shown),
        Err(KlavError::Invalid { .. })
    ));
}
