//! Environments on the phone through `KlavCore` (ADR 0032 §6, layer 4b),
//! against the real server: the list and one environment's variables with
//! no value, a development value shown without asking, Face ID every time
//! for a protected environment's value and for a login it points to,
//! lowering the protection and trashing a protected environment only after
//! the device's owner, and failing closed when the device cannot ask.
//! Values are compared with `==`, never printed.

mod common;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use common::ServerProcess;
use klav_client::{Home, SignupRequest};
use klav_core::crypto::kdf::MasterPassword;
use klav_ffi::{
    EnvironmentEditInput, FieldEdit, KeystoreError, KeystoreKey, KeystoreWrap, Kind, KlavCore,
    KlavError, NewItemInput, PlatformKeystore, VariableInput,
};
use klav_proto::auth::DeviceKind;
use secrecy::ExposeSecret;

const PASSWORD: &str = "correct horse battery staple";
/// The prompts' words, which the app gives in its language.
const SHOW: &str = "Show a value of “production”";
const LOWER: &str = "Lower the protection of “production”";
const OK: u8 = 0;
const CANCEL: u8 = 1;
const NO_PASSCODE: u8 = 2;

/// Only the device-owner check matters here; it counts its prompts.
struct Owner {
    answer: AtomicU8,
    prompts: Mutex<Vec<String>>,
}

impl Owner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            answer: AtomicU8::new(OK),
            prompts: Mutex::new(Vec::new()),
        })
    }

    fn asked(&self) -> usize {
        self.prompts.lock().expect("test setup").len()
    }

    fn last(&self) -> String {
        self.prompts
            .lock()
            .expect("test setup")
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

impl PlatformKeystore for Owner {
    fn available(&self) -> bool {
        true
    }
    fn create_key(&self) -> Result<KeystoreKey, KeystoreError> {
        Err(KeystoreError::Unavailable)
    }
    fn wrap(&self, _public_key: Vec<u8>) -> Result<KeystoreWrap, KeystoreError> {
        Err(KeystoreError::Unavailable)
    }
    fn unwrap(
        &self,
        _handle: Vec<u8>,
        _ephemeral_public: Vec<u8>,
        _reason: String,
    ) -> Result<Vec<u8>, KeystoreError> {
        Err(KeystoreError::Unavailable)
    }
    fn boot_time(&self) -> u64 {
        0
    }
    fn confirm_owner(&self, reason: String) -> Result<(), KeystoreError> {
        self.prompts.lock().expect("test setup").push(reason);
        match self.answer.load(Ordering::SeqCst) {
            CANCEL => Err(KeystoreError::Cancelled),
            NO_PASSCODE => Err(KeystoreError::Unavailable),
            _ => Ok(()),
        }
    }
}

/// An empty account made on a laptop; its Secret Key.
fn laptop(server: &str, dir: &std::path::Path) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test setup");
    rt.block_on(async {
        let (_, kit) = klav_client::signup(
            &Home::at(dir.join("laptop")),
            SignupRequest {
                server: server.to_owned(),
                email: "ana@example.com".into(),
                password: MasterPassword::new(PASSWORD),
                device_name: "laptop".into(),
                device_kind: DeviceKind::Cli,
                invite: None,
            },
        )
        .await
        .expect("test setup");
        kit.secret_key().to_text().expose_secret().to_owned()
    })
}

fn phone(server: &str, dir: &std::path::Path, secret_key: &str) -> Arc<KlavCore> {
    let core = KlavCore::new(dir.join("phone").display().to_string()).expect("test setup");
    core.sign_in(
        server.to_owned(),
        "ana@example.com".into(),
        PASSWORD.into(),
        secret_key.to_owned(),
        "phone".into(),
        None,
    )
    .expect("test setup");
    core
}

fn value(name: &str, value: &str) -> VariableInput {
    VariableInput {
        name: name.into(),
        value: Some(value.into()),
        reference: None,
    }
}

fn edit(create: bool, protected: Option<bool>, set: Vec<VariableInput>) -> EnvironmentEditInput {
    EnvironmentEditInput {
        create,
        must_be_new: create,
        protected,
        set,
        remove: Vec::new(),
    }
}

#[test]
fn the_phone_shows_environments_and_asks_for_the_protected_ones() {
    let server = ServerProcess::start(900);
    let dir = tempfile::tempdir().expect("test setup");
    let secret_key = laptop(&server.url, dir.path());
    let core = phone(&server.url, dir.path(), &secret_key);
    let owner = Owner::new();
    let keystore: Arc<dyn PlatformKeystore> = owner.clone();

    let github = core
        .create_item(NewItemInput {
            kind: Kind::Login,
            title: "GitHub".into(),
            vault_id: None,
            project_id: None,
            fields: vec![FieldEdit {
                name: "password".into(),
                value: "gh-secret".into(),
                kind: None,
            }],
            urls: vec!["https://github.com".into()],
            tags: Vec::new(),
            notes: None,
        })
        .expect("login");
    let project = github.project_id.clone();
    assert_eq!(core.value_protection(github.id.clone()).expect("ask"), None);

    // development: created, shown without asking.
    core.save_environment(
        project.clone(),
        "development".into(),
        edit(true, None, vec![value("DATABASE_URL", "postgres://dev")]),
        LOWER.into(),
        keystore.clone(),
    )
    .expect("development");
    // production: protected by its name, with a reference to GitHub.
    let saved = core
        .save_environment(
            project.clone(),
            "production".into(),
            edit(
                true,
                None,
                vec![
                    value("API_TOKEN", "prod-token"),
                    VariableInput {
                        name: "GITHUB_PASSWORD".into(),
                        value: None,
                        reference: Some(format!("{}/password", github.reference)),
                    },
                ],
            ),
            LOWER.into(),
            keystore.clone(),
        )
        .expect("production");
    assert!(saved.protected, "production protects itself");
    assert_eq!(saved.newly_protected, vec!["GitHub".to_owned()]);
    assert_eq!(owner.asked(), 0, "growing the protection asks nothing");

    let list = core.environments(Some(project.clone())).expect("list");
    let names: Vec<(String, u32, bool)> = list
        .iter()
        .map(|e| (e.name.clone(), e.variables, e.protected))
        .collect();
    assert_eq!(
        names,
        vec![
            ("development".to_owned(), 1, false),
            ("production".to_owned(), 2, true)
        ]
    );
    // Environments are listed by their own kind, never as notes, and the
    // login they point to says who protects it.
    let items = core.items(klav_ffi::ItemQuery::default()).expect("items");
    assert!(
        items
            .iter()
            .filter(|i| i.title == "production")
            .all(|i| i.kind == Kind::Environment)
    );
    assert_eq!(
        items
            .iter()
            .find(|i| i.id == github.id)
            .map(|i| i.protected_by.clone()),
        Some(vec!["production".to_owned()])
    );

    let dev = core
        .environment(project.clone(), "development".into())
        .expect("detail")
        .expect("development");
    assert_eq!(dev.variables.len(), 1);
    assert!(dev.variables[0].reference.is_none());
    let shown = core
        .variable_value(
            dev.variables[0].resolve.clone(),
            SHOW.into(),
            keystore.clone(),
        )
        .expect("dev value");
    assert!(shown == "postgres://dev");
    assert_eq!(owner.asked(), 0, "development asks nothing");

    let prod = core
        .environment(project.clone(), "production".into())
        .expect("detail")
        .expect("production");
    let github_var = prod
        .variables
        .iter()
        .find(|v| v.name == "GITHUB_PASSWORD")
        .expect("reference");
    assert!(
        github_var
            .target
            .as_deref()
            .is_some_and(|t| t.contains("GitHub"))
    );
    assert!(github_var.target_protected);
    let token = core
        .variable_value(
            prod.variables[0].resolve.clone(),
            SHOW.into(),
            keystore.clone(),
        )
        .expect("prod value");
    assert!(token == "prod-token");
    assert_eq!(owner.asked(), 1, "a protected value asks");
    assert_eq!(owner.last(), SHOW);
    let through = core
        .variable_value(github_var.resolve.clone(), SHOW.into(), keystore.clone())
        .expect("through the reference");
    assert!(through == "gh-secret");
    assert_eq!(owner.asked(), 2, "and asks every time");
    // The login the reference points to is protected too: the item page
    // asks before showing it.
    let reason = core
        .value_protection(github.id.clone())
        .expect("ask")
        .expect("protected");
    assert!(reason.contains("production"), "{reason}");
    // A development variable that points to the same login asks too: the
    // protection follows the item, not the environment it is read through.
    core.save_environment(
        project.clone(),
        "development".into(),
        edit(
            false,
            None,
            vec![VariableInput {
                name: "GITHUB_PASSWORD".into(),
                value: None,
                reference: Some(format!("{}/password", github.reference)),
            }],
        ),
        LOWER.into(),
        keystore.clone(),
    )
    .expect("development points to GitHub");
    assert_eq!(owner.asked(), 2, "pointing to it asks nothing");
    let dev = core
        .environment(project.clone(), "development".into())
        .expect("detail")
        .expect("development");
    let inherited = dev
        .variables
        .iter()
        .find(|v| v.name == "GITHUB_PASSWORD")
        .expect("reference");
    assert!(inherited.target_protected);
    let through = core
        .variable_value(inherited.resolve.clone(), SHOW.into(), keystore.clone())
        .expect("through development");
    assert!(through == "gh-secret");
    assert_eq!(owner.asked(), 3, "an inherited target asks");

    // Cancelling hands nothing out.
    owner.answer.store(CANCEL, Ordering::SeqCst);
    let cancelled = core.variable_value(
        prod.variables[0].resolve.clone(),
        SHOW.into(),
        keystore.clone(),
    );
    assert!(matches!(cancelled, Err(KlavError::BiometryFailed { .. })));
    // A device that cannot ask for its owner fails closed.
    owner.answer.store(NO_PASSCODE, Ordering::SeqCst);
    let closed = core.variable_value(
        prod.variables[0].resolve.clone(),
        SHOW.into(),
        keystore.clone(),
    );
    assert!(matches!(closed, Err(KlavError::BiometryUnavailable { .. })));
    // Only an environment's variable: a login's field is refused.
    owner.answer.store(OK, Ordering::SeqCst);
    let before = owner.asked();
    let refused = core.variable_value(
        format!("{}/password", github.reference),
        SHOW.into(),
        keystore.clone(),
    );
    assert!(matches!(refused, Err(KlavError::Denied { .. })));
    assert_eq!(
        owner.asked(),
        before,
        "nothing asked for a refused reference"
    );

    // Lowering the protection asks first; cancelled, nothing changes.
    owner.answer.store(CANCEL, Ordering::SeqCst);
    let lowered = core.save_environment(
        project.clone(),
        "production".into(),
        edit(false, Some(false), Vec::new()),
        LOWER.into(),
        keystore.clone(),
    );
    assert!(lowered.is_err());
    assert!(
        core.environments(Some(project.clone()))
            .expect("list")
            .iter()
            .any(|e| e.name == "production" && e.protected)
    );
    // Trashing a protected environment asks too.
    owner.answer.store(OK, Ordering::SeqCst);
    let before = owner.asked();
    core.trash_environment(
        project.clone(),
        "production".into(),
        LOWER.into(),
        keystore.clone(),
    )
    .expect("trash");
    assert_eq!(owner.asked(), before + 1);
    assert_eq!(owner.last(), LOWER);
    assert_eq!(core.environments(Some(project)).expect("list").len(), 1);
    assert_eq!(core.value_protection(github.id).expect("ask"), None);
}
