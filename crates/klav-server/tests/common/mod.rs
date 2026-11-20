//! Boots the real server on an ephemeral port for integration tests.
//!
//! Backend: a temporary SQLite file by default. When
//! `KLAV_TEST_DATABASE_URL` points to a Postgres server (admin URL, e.g.
//! `postgres://postgres@127.0.0.1:5432/postgres`), every test gets its own
//! fresh database on it, so tests can run in parallel.

#![allow(dead_code, unreachable_pub)]

pub mod agent;
pub mod client;
pub mod vault;

use std::net::SocketAddr;

use klav_server::{Config, Server};
use sqlx::any::AnyPoolOptions;
use tokio::sync::oneshot;

/// Where [`TestServer::call_dropped_at`] left a call.
#[derive(Debug, PartialEq, Eq)]
pub enum Dropped {
    /// Dropped at the wake asked for, before `changed` held. A commit
    /// already sent may still land after: see [`TestServer::settle`].
    Before,
    /// Dropped once `changed` held, before the handler saw its commit.
    After,
    /// It finished first, with this status.
    Finished(reqwest::StatusCode),
}

pub struct TestServer {
    pub base: String,
    handle: Server,
    pub http: reqwest::Client,
    pub database_url: String,
    pub data_dir: tempfile::TempDir,
    shutdown: Option<oneshot::Sender<()>>,
}

impl TestServer {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(customize: impl FnOnce(&mut Config)) -> Self {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let database_url = test_database_url(&data_dir).await;
        let mut config = Config {
            database_url: database_url.clone(),
            data_dir: data_dir.path().join("data"),
            ..Config::default()
        };
        // Tests log in many times from one IP; the rate-limit tests lower
        // these again.
        config.rate_limit.auth_ip_burst = 10_000;
        config.rate_limit.auth_email_burst = 10_000;
        // Test accounts use reduced Argon2id parameters to stay fast; the
        // KDF floor test turns this off again.
        config.insecure_accept_weak_kdf = true;
        customize(&mut config);
        let server = Server::new(config).await.expect("server starts");
        let handle = server.clone();
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            server
                .serve(listener, async {
                    let _ = rx.await;
                })
                .await
                .expect("serve");
        });
        Self {
            handle,
            base: format!("http://{addr}"),
            http: reqwest::Client::new(),
            database_url,
            data_dir,
            shutdown: Some(tx),
        }
    }

    /// The running server (for `purge_expired`).
    pub fn server_handle(&self) -> &Server {
        &self.handle
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// A raw connection to the server database, to inspect what is stored.
    pub async fn raw_db(&self) -> sqlx::AnyPool {
        sqlx::any::install_default_drivers();
        AnyPoolOptions::new()
            .max_connections(1)
            .connect(&self.database_url)
            .await
            .expect("raw db")
    }

    pub fn is_postgres(&self) -> bool {
        self.database_url.starts_with("postgres")
    }

    /// Sends `POST path` (as `session`, with a JSON `body`) through the
    /// router by hand, and drops the call as soon as `changed` holds, as
    /// hyper drops a handler whose client goes away. `None` when it was
    /// dropped there; the status if it finished first, which it can (see
    /// [`Self::call_dropped_at`]): run it inside [`until_dropped`].
    pub async fn call_dropped_once<F, Fut>(
        &self,
        session: Option<&client::Session>,
        path: &str,
        body: &impl serde::Serialize,
        changed: F,
    ) -> Option<reqwest::StatusCode>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        match self
            .call_dropped_at(session, path, body, None, changed)
            .await
        {
            Dropped::After => None,
            Dropped::Before => unreachable!("no wake to drop at"),
            Dropped::Finished(status) => Some(status),
        }
    }

    /// [`Self::call_dropped_once`], or dropped at the `wakes`-th wake of
    /// the call if `changed` does not hold by then.
    ///
    /// The call is polled only after a wake, and `changed` is read after
    /// each wake, before the next poll. When the handler's commit comes
    /// back between two polls, the call is dropped after its write commits
    /// and before the handler goes on. But a poll can also send the commit
    /// and read its reply before it returns (the database answered while
    /// the poll ran, or a wake for something else came while `changed` was
    /// being read), and then the call finishes in that poll: nothing
    /// outside the handler can stop that, so [`Dropped::Finished`] is a try
    /// without a drop, not a failure (see [`until_dropped`]).
    ///
    /// After [`Dropped::Before`], a commit already sent may still land:
    /// read what the call left only after [`Self::settle`].
    pub async fn call_dropped_at<F, Fut>(
        &self,
        session: Option<&client::Session>,
        path: &str,
        body: &impl serde::Serialize,
        wakes: Option<usize>,
        changed: F,
    ) -> Dropped
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        self.call_dropped_as(
            axum::http::Method::POST,
            session,
            path,
            body,
            wakes,
            changed,
        )
        .await
    }

    /// [`Self::call_dropped_once`] with any `method`: `None` when the call
    /// was dropped after `changed` held.
    pub async fn call_dropped_with<F, Fut>(
        &self,
        method: axum::http::Method,
        session: Option<&client::Session>,
        path: &str,
        body: &impl serde::Serialize,
        changed: F,
    ) -> Option<reqwest::StatusCode>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        match self
            .call_dropped_as(method, session, path, body, None, changed)
            .await
        {
            Dropped::After => None,
            Dropped::Before => unreachable!("no wake to drop at"),
            Dropped::Finished(status) => Some(status),
        }
    }

    /// [`Self::call_dropped_at`] with any `method`.
    pub async fn call_dropped_as<F, Fut>(
        &self,
        method: axum::http::Method,
        session: Option<&client::Session>,
        path: &str,
        body: &impl serde::Serialize,
        wakes: Option<usize>,
        changed: F,
    ) -> Dropped
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        use std::future::Future;
        use std::sync::Arc;
        use std::task::{Context, Poll, Waker};
        use tower::ServiceExt;

        /// Wakes the test's own task when the call can go on.
        struct Woken(tokio::sync::Notify);
        impl std::task::Wake for Woken {
            fn wake(self: Arc<Self>) {
                self.0.notify_one();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.notify_one();
            }
        }

        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header(axum::http::header::CONTENT_TYPE, "application/json");
        if let Some(session) = session {
            req = req.header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", session.tokens.access_token),
            );
        }
        let mut req = req
            .body(axum::body::Body::from(
                serde_json::to_vec(body).expect("test helper"),
            ))
            .expect("test helper");
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                40_000,
            ))));
        let call = self.handle.router().oneshot(req);
        let mut call = std::pin::pin!(call);
        let woken = Arc::new(Woken(tokio::sync::Notify::new()));
        let waker = Waker::from(Arc::clone(&woken));
        let mut cx = Context::from_waker(&waker);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut seen = 0;
        loop {
            if let Poll::Ready(res) = call.as_mut().poll(&mut cx) {
                let status = res.expect("infallible").status().as_u16();
                return Dropped::Finished(reqwest::StatusCode::from_u16(status).expect("status"));
            }
            tokio::time::timeout_at(deadline, woken.0.notified())
                .await
                .expect("the call never landed");
            seen += 1;
            if changed().await {
                return Dropped::After;
            }
            if wakes == Some(seen) {
                return Dropped::Before;
            }
        }
    }

    /// Waits until no transaction of a dropped call of `account` is still
    /// open: every person's write takes the account's row first, so this
    /// write on it waits for that transaction's commit or rollback (sqlx
    /// sends the rollback of a dropped transaction when its connection
    /// goes back to the pool).
    pub async fn settle(&self, db: &sqlx::AnyPool, account: klav_core::ids::AccountId) {
        sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
            .bind(account.to_string())
            .execute(db)
            .await
            .expect("settle");
    }

    /// From now on, the log refuses to append an event with `action`: the
    /// write that logs it must then fail as a whole.
    pub async fn refuse_audit_action(&self, action: &str) {
        assert!(
            action
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
            "a fixed action name"
        );
        let db = self.raw_db().await;
        let name = format!("klav_test_refuse_{}", action.replace('.', "_"));
        // `action` is checked above, so it is safe to interpolate.
        let statements = if self.is_postgres() {
            vec![
                "CREATE OR REPLACE FUNCTION klav_test_refuse() RETURNS trigger \
                 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test: append refused'; END $$"
                    .to_owned(),
                format!(
                    "CREATE TRIGGER {name} BEFORE INSERT ON audit_events \
                     FOR EACH ROW WHEN (NEW.action = '{action}') \
                     EXECUTE FUNCTION klav_test_refuse()"
                ),
            ]
        } else {
            vec![format!(
                "CREATE TRIGGER {name} BEFORE INSERT ON audit_events \
                 WHEN NEW.action = '{action}' \
                 BEGIN SELECT RAISE(ABORT, 'test: append refused'); END"
            )]
        };
        for sql in statements {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&db)
                .await
                .expect("test trigger");
        }
        db.close().await;
    }

    /// Undoes [`Self::refuse_audit_action`].
    pub async fn allow_audit_action(&self, action: &str) {
        assert!(
            action
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
            "a fixed action name"
        );
        let name = format!("klav_test_refuse_{}", action.replace('.', "_"));
        let sql = if self.is_postgres() {
            format!("DROP TRIGGER {name} ON audit_events")
        } else {
            format!("DROP TRIGGER {name}")
        };
        let db = self.raw_db().await;
        // `action` is checked above, so it is safe to interpolate.
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&db)
            .await
            .expect("test trigger");
        db.close().await;
    }

    /// From now on, every insert, update and delete of a row of `table`
    /// fails: the mirror of [`Self::refuse_audit_action`]. A route that
    /// appends its event in the write's own transaction then stores no
    /// event either; one that appended it in a transaction of its own
    /// before the write would leave it stored.
    pub async fn refuse_writes(&self, table: &str) {
        let statements = if self.is_postgres() {
            vec![
                "CREATE OR REPLACE FUNCTION klav_test_refuse_write() RETURNS trigger \
                 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test: write refused'; END $$"
                    .to_owned(),
                format!(
                    "CREATE TRIGGER klav_test_refuse_writes BEFORE INSERT OR UPDATE OR DELETE \
                     ON {} FOR EACH ROW EXECUTE FUNCTION klav_test_refuse_write()",
                    fixed_table(table)
                ),
            ]
        } else {
            ["insert", "update", "delete"]
                .map(|op| {
                    format!(
                        "CREATE TRIGGER klav_test_refuse_{op} BEFORE {op} ON {} \
                         BEGIN SELECT RAISE(ABORT, 'test: write refused'); END",
                        fixed_table(table)
                    )
                })
                .to_vec()
        };
        self.run_raw(statements).await;
    }

    /// Undoes [`Self::refuse_writes`].
    pub async fn allow_writes(&self, table: &str) {
        let statements = if self.is_postgres() {
            vec![format!(
                "DROP TRIGGER klav_test_refuse_writes ON {}",
                fixed_table(table)
            )]
        } else {
            ["insert", "update", "delete"]
                .map(|op| format!("DROP TRIGGER klav_test_refuse_{op}"))
                .to_vec()
        };
        self.run_raw(statements).await;
    }

    /// Postgres only: asserts that the row `id` of `table` and `account`'s
    /// latest event with `action` were last written by one transaction
    /// (their `xmin`). Call it right after the write, before anything else
    /// writes the row again.
    pub async fn assert_written_with(
        &self,
        db: &sqlx::AnyPool,
        account: klav_core::ids::AccountId,
        table: &str,
        id: &str,
        action: &str,
    ) {
        assert!(self.is_postgres(), "xmin is Postgres's");
        let row: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT xmin::text FROM {} WHERE id = $1",
            fixed_table(table)
        )))
        .bind(id)
        .fetch_one(db)
        .await
        .expect("the written row");
        let event: String = sqlx::query_scalar(
            "SELECT xmin::text FROM audit_events WHERE account_id = $1 AND action = $2 \
             ORDER BY seq DESC LIMIT 1",
        )
        .bind(account.to_string())
        .bind(action)
        .fetch_one(db)
        .await
        .expect("its event");
        assert_eq!(
            row, event,
            "the {table} row and its {action} were written by different transactions"
        );
    }

    /// Runs `statements` on a connection of its own.
    async fn run_raw(&self, statements: Vec<String>) {
        let db = self.raw_db().await;
        for sql in statements {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .execute(&db)
                .await
                .expect("test statement");
        }
        db.close().await;
    }

    /// The agent's stored status, read straight from the database.
    pub async fn agent_status(
        &self,
        db: &sqlx::AnyPool,
        agent: klav_core::ids::AgentId,
    ) -> Option<String> {
        sqlx::query_scalar("SELECT status FROM agents WHERE id = $1")
            .bind(agent.to_string())
            .fetch_optional(db)
            .await
            .expect("agent status")
    }

    /// Postgres only: holds the account's row lock while a person's write
    /// on `agent` (sent by `send`) waits for it, then takes the agent's row
    /// in the same transaction. A write that locks the agent before the
    /// account deadlocks with it, and one of the two is aborted.
    pub async fn assert_account_locked_before_agent<Fut>(
        &self,
        account: klav_core::ids::AccountId,
        agent: klav_core::ids::AgentId,
        send: Fut,
    ) -> reqwest::Response
    where
        Fut: std::future::Future<Output = reqwest::Result<reqwest::Response>> + Send + 'static,
    {
        self.assert_account_locked_first(
            account,
            "UPDATE agents SET status = status WHERE id = $1",
            agent.to_string(),
            send,
        )
        .await
    }

    /// [`Self::assert_account_locked_before_agent`] for any second row:
    /// `second` locks the row whose ID is `$1` (`id`).
    pub async fn assert_account_locked_first<Fut>(
        &self,
        account: klav_core::ids::AccountId,
        second: &'static str,
        id: String,
        send: Fut,
    ) -> reqwest::Response
    where
        Fut: std::future::Future<Output = reqwest::Result<reqwest::Response>> + Send + 'static,
    {
        assert!(self.is_postgres());
        let held = self.raw_db().await;
        let watch = self.raw_db().await;
        let mut tx = held.begin().await.expect("test");
        sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
            .bind(account.to_string())
            .execute(&mut *tx)
            .await
            .expect("test");
        let call = tokio::spawn(send);
        // Until the write waits on a lock: the account's, if it takes it
        // first; otherwise it already holds the second row.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity \
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(&watch)
            .await
            .expect("test");
            if waiting > 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the write never waited"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // Over Postgres's 1 s deadlock_timeout: a deadlock aborts one side.
        sqlx::query("SET LOCAL lock_timeout = '3s'")
            .execute(&mut *tx)
            .await
            .expect("test");
        sqlx::query(second)
            .bind(id)
            .execute(&mut *tx)
            .await
            .expect("the write held the second row while it waited for the account's");
        tx.commit().await.expect("test");
        held.close().await;
        watch.close().await;
        call.await.expect("test").expect("test")
    }
}

/// `table`, checked to be a plain table name, so it is safe to interpolate.
/// The refused writes' triggers have fixed names: one table at a time.
fn fixed_table(table: &str) -> &str {
    assert!(
        !table.is_empty() && table.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
        "a fixed table name"
    );
    table
}

/// How many tries [`until_dropped`] makes.
pub const DROP_TRIES: usize = 10;

/// Runs `attempt` (one try: a fresh fixture and one call through
/// [`TestServer::call_dropped_once`]) until its call is dropped after its
/// commit, and returns what that try set up. A try whose call finished
/// first, with a 2xx, did not drop and is tried again on a new fixture
/// (see [`TestServer::call_dropped_at`]); any other status fails.
///
/// After [`DROP_TRIES`] tries that all finished first, it returns the last
/// one and says so: no test code can force the drop (a call whose commit
/// is answered within the poll that sent it finishes in that poll), and a
/// loaded CI runner can answer that fast many times in a row. A finished
/// call leaves the same rows as one dropped after its commit, so the
/// caller's checks still hold, but they then prove nothing about the drop.
/// That the write and its event share one transaction is proved without
/// any race by each route's `…_that_cannot_be_logged_…` test (the log
/// refuses the event, and the write must not land), its
/// `…_that_cannot_be_stored_…` test (the database refuses the write, and no
/// event may be stored), and, on Postgres, its `…_share_one_transaction`
/// test (the written row and its event have one `xmin`); this helper adds
/// the client going away on top when it can. Each try prints its outcome, to
/// count over many runs how often a call finishes first.
///
/// So a caller must not undo what a finished try did before it returns
/// (the next try may clean it up instead).
#[allow(clippy::print_stderr)]
pub async fn until_dropped<T>(
    mut attempt: impl AsyncFnMut() -> (Option<reqwest::StatusCode>, T),
) -> T {
    let mut n = 1;
    loop {
        let (status, set_up) = attempt().await;
        match status {
            None => {
                eprintln!("dropped after its commit on try {n}");
                return set_up;
            }
            Some(status) => {
                assert!(
                    status.is_success(),
                    "try {n} finished with {status} before it was dropped"
                );
                if n == DROP_TRIES {
                    eprintln!(
                        "the call finished before it was dropped in all {DROP_TRIES} tries: \
                         checked as finished, the drop not exercised"
                    );
                    return set_up;
                }
            }
        }
        n += 1;
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn test_database_url(dir: &tempfile::TempDir) -> String {
    match std::env::var("KLAV_TEST_DATABASE_URL") {
        Ok(admin) if admin.starts_with("postgres") => fresh_postgres_database(&admin).await,
        _ => format!("sqlite://{}", dir.path().join("klav.db").display()),
    }
}

async fn fresh_postgres_database(admin: &str) -> String {
    sqlx::any::install_default_drivers();
    let name = format!(
        "klav_test_{}",
        klav_core::ids::VaultId::generate()
            .to_string()
            .replace('-', "")
    );
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(admin)
        .await
        .expect("connect to KLAV_TEST_DATABASE_URL");
    // `name` is a fixed prefix plus hex digits, so it is safe to interpolate.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&pool)
        .await
        .expect("create test database");
    pool.close().await;
    // Replace the database name (last path segment), keeping any query string.
    let (base, query) = match admin.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (admin, None),
    };
    let prefix = base.rsplit_once('/').map_or(base, |(p, _)| p);
    match query {
        Some(q) => format!("{prefix}/{name}?{q}"),
        None => format!("{prefix}/{name}"),
    }
}
