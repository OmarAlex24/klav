//! Database access through `sqlx::Any`, so one set of queries runs on both
//! SQLite (self-hosting) and Postgres (hosted plan).
//!
//! Portability rules for every query in this crate:
//!
//! * placeholders are `$1, $2, …` (both drivers accept them);
//! * IDs are `TEXT` (canonical UUID), timestamps are `BIGINT` Unix
//!   milliseconds, blobs are `BLOB`/`BYTEA`, flags are nullable timestamps;
//! * no booleans, no driver-specific types, no `ON CONFLICT` differences;
//! * a write transaction that touches a vault takes the vault row lock first
//!   (`UPDATE vaults … RETURNING revision`), which also turns the SQLite
//!   transaction into a writer immediately and avoids `SQLITE_BUSY` upgrades.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::AnyPool;
use sqlx::Executor;
use sqlx::any::AnyPoolOptions;

/// Which database the pool talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Sqlite,
    Postgres,
}

/// Connection pool plus the backend it targets.
#[derive(Clone)]
pub(crate) struct Db {
    pub(crate) pool: AnyPool,
}

/// Error raised while opening or migrating the database.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// The URL is neither `sqlite:` nor `postgres:`.
    #[error("unsupported database URL scheme (use sqlite:// or postgres://)")]
    UnsupportedScheme,
    /// Connecting failed.
    #[error("cannot connect to the database: {0}")]
    Connect(#[source] sqlx::Error),
    /// A migration failed.
    #[error("database migration failed: {0}")]
    Migrate(#[source] sqlx::migrate::MigrateError),
}

impl Db {
    /// Connects to `url` and applies pending migrations.
    pub(crate) async fn connect(url: &str) -> Result<Self, DbError> {
        sqlx::any::install_default_drivers();
        let backend = backend_of(url)?;
        let pool = match backend {
            Backend::Sqlite => {
                let url = with_create_mode(url);
                AnyPoolOptions::new()
                    .max_connections(8)
                    .after_connect(|conn, _meta| {
                        Box::pin(async move {
                            conn.execute("PRAGMA journal_mode = WAL").await?;
                            conn.execute("PRAGMA busy_timeout = 10000").await?;
                            conn.execute("PRAGMA foreign_keys = ON").await?;
                            conn.execute("PRAGMA synchronous = NORMAL").await?;
                            Ok(())
                        })
                    })
                    .connect(&url)
                    .await
            }
            Backend::Postgres => {
                AnyPoolOptions::new()
                    .max_connections(16)
                    .acquire_timeout(Duration::from_secs(10))
                    .connect(url)
                    .await
            }
        }
        .map_err(DbError::Connect)?;

        let mut migrator = migrator(backend);
        // A build older than its database still starts. After a rollback the
        // newer build's migrations stay recorded, and without this sqlx
        // refuses them (`VersionMissing`) and the server never comes up.
        // A changed checksum of a migration this build knows still fails.
        migrator.set_ignore_missing(true);
        migrator.run(&pool).await.map_err(DbError::Migrate)?;

        Ok(Self { pool })
    }

    /// Connects to a database the server already created and migrated, for
    /// the admin subcommands (`klav-server invite …`, ADR 0048 §1.4): never
    /// migrates and never creates a SQLite file, and refuses a schema older
    /// than this build's, so a newer CLI never changes the schema of an
    /// older running server.
    pub(crate) async fn connect_existing(url: &str) -> Result<Self, AdminDbError> {
        sqlx::any::install_default_drivers();
        let backend = backend_of(url).map_err(|_| AdminDbError::UnsupportedScheme)?;
        let pool = match backend {
            Backend::Sqlite => {
                let url = without_create_mode(url);
                AnyPoolOptions::new()
                    .max_connections(1)
                    .after_connect(|conn, _meta| {
                        Box::pin(async move {
                            // The server set WAL on the file already; the
                            // CLI waits for its writers instead of failing.
                            conn.execute("PRAGMA busy_timeout = 10000").await?;
                            conn.execute("PRAGMA foreign_keys = ON").await?;
                            Ok(())
                        })
                    })
                    .connect(&url)
                    .await
            }
            Backend::Postgres => {
                AnyPoolOptions::new()
                    .max_connections(2)
                    .acquire_timeout(Duration::from_secs(10))
                    .connect(url)
                    .await
            }
        }
        .map_err(AdminDbError::Connect)?;
        let applied: Vec<i64> = sqlx::query_scalar(
            "SELECT CAST(version AS BIGINT) FROM _sqlx_migrations WHERE success = TRUE",
        )
        .fetch_all(&pool)
        .await
        .map_err(|_| AdminDbError::SchemaBehind)?;
        let behind = migrator(backend)
            .iter()
            .filter(|m| m.migration_type.is_up_migration())
            .any(|m| !applied.contains(&m.version));
        if behind {
            return Err(AdminDbError::SchemaBehind);
        }
        Ok(Self { pool })
    }

    /// `SELECT 1`: used by the health check.
    pub(crate) async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
    }
}

/// Error raised while opening an existing database for an admin command.
#[derive(Debug, thiserror::Error)]
pub enum AdminDbError {
    /// The URL is neither `sqlite:` nor `postgres:`.
    #[error("unsupported database URL scheme (use sqlite:// or postgres://)")]
    UnsupportedScheme,
    /// Connecting failed (for SQLite, also: the file does not exist).
    #[error("cannot open the database: {0}")]
    Connect(#[source] sqlx::Error),
    /// The schema is older than this build's (or there is none).
    #[error(
        "the database schema is older than this klav-server: upgrade the server and start it \
         once (it migrates on start), then run this again. This command never migrates"
    )]
    SchemaBehind,
}

/// This build's migrations for `backend`.
fn migrator(backend: Backend) -> sqlx::migrate::Migrator {
    match backend {
        Backend::Sqlite => sqlx::migrate!("migrations/sqlite"),
        Backend::Postgres => sqlx::migrate!("migrations/postgres"),
    }
}

/// The SQLite file of `url`, if it names one (not `:memory:`).
pub(crate) fn sqlite_path(url: &str) -> Option<std::path::PathBuf> {
    let rest = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))?;
    let path = rest.split_once('?').map_or(rest, |(p, _)| p);
    (!path.is_empty() && !path.starts_with(':')).then(|| std::path::PathBuf::from(path))
}

fn backend_of(url: &str) -> Result<Backend, DbError> {
    if url.starts_with("sqlite:") {
        Ok(Backend::Sqlite)
    } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
        Ok(Backend::Postgres)
    } else {
        Err(DbError::UnsupportedScheme)
    }
}

/// SQLite only creates a missing database file with `mode=rwc`.
fn with_create_mode(url: &str) -> String {
    if url.contains("mode=") {
        url.to_owned()
    } else if url.contains('?') {
        format!("{url}&mode=rwc")
    } else {
        format!("{url}?mode=rwc")
    }
}

/// Opens an existing SQLite file read-write, never creating it.
fn without_create_mode(url: &str) -> String {
    if url.contains("mode=") {
        url.replace("mode=rwc", "mode=rw")
    } else if url.contains('?') {
        format!("{url}&mode=rw")
    } else {
        format!("{url}?mode=rw")
    }
}

/// Current time as Unix milliseconds (the only timestamp format we store).
pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_backend() {
        assert_eq!(backend_of("sqlite://x.db").ok(), Some(Backend::Sqlite));
        assert_eq!(backend_of("sqlite::memory:").ok(), Some(Backend::Sqlite));
        assert_eq!(backend_of("postgres://h/db").ok(), Some(Backend::Postgres));
        assert_eq!(
            backend_of("postgresql://h/db").ok(),
            Some(Backend::Postgres)
        );
        assert!(backend_of("mysql://h/db").is_err());
    }

    #[test]
    fn adds_create_mode() {
        assert_eq!(with_create_mode("sqlite://a.db"), "sqlite://a.db?mode=rwc");
        assert_eq!(
            with_create_mode("sqlite://a.db?cache=shared"),
            "sqlite://a.db?cache=shared&mode=rwc"
        );
        assert_eq!(
            with_create_mode("sqlite://a.db?mode=ro"),
            "sqlite://a.db?mode=ro"
        );
    }

    #[test]
    fn admin_urls_never_create_a_file() {
        assert_eq!(
            without_create_mode("sqlite://a.db"),
            "sqlite://a.db?mode=rw"
        );
        assert_eq!(
            without_create_mode("sqlite://a.db?mode=rwc"),
            "sqlite://a.db?mode=rw"
        );
        assert_eq!(
            sqlite_path("sqlite:///data/klav.db?mode=rwc"),
            Some(std::path::PathBuf::from("/data/klav.db"))
        );
        assert_eq!(
            sqlite_path("sqlite://data/klav.db"),
            Some(std::path::PathBuf::from("data/klav.db"))
        );
        assert_eq!(sqlite_path("sqlite::memory:"), None);
        assert_eq!(sqlite_path("postgres://h/db"), None);
    }

    #[tokio::test]
    async fn admin_connect_refuses_a_missing_or_older_database() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("t.db").display());
        // No file: not created.
        assert!(matches!(
            Db::connect_existing(&url).await,
            Err(AdminDbError::Connect(_))
        ));
        assert!(!dir.path().join("t.db").exists());
        // A file without the schema (or behind it): refused, not migrated.
        let empty = format!("sqlite://{}?mode=rwc", dir.path().join("e.db").display());
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(&empty).await.unwrap();
        sqlx::query("CREATE TABLE x (y INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let empty = format!("sqlite://{}", dir.path().join("e.db").display());
        assert!(matches!(
            Db::connect_existing(&empty).await,
            Err(AdminDbError::SchemaBehind)
        ));
        // Migrated by the server, then one migration "missing" (an older
        // server): refused.
        let db = Db::connect(&url).await.unwrap();
        Db::connect_existing(&url)
            .await
            .unwrap()
            .ping()
            .await
            .unwrap();
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 21")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(matches!(
            Db::connect_existing(&url).await,
            Err(AdminDbError::SchemaBehind)
        ));
        // The admin connection did not migrate it back.
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version = 21")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn connects_and_migrates_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("t.db").display());
        let db = Db::connect(&url).await.unwrap();
        db.ping().await.unwrap();
        // Migrations are idempotent.
        Db::connect(&url).await.unwrap();
    }

    #[tokio::test]
    async fn starts_on_a_database_a_newer_build_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("t.db").display());
        let db = Db::connect(&url).await.unwrap();
        // What a later build leaves behind: a migration this one never had.
        sqlx::query(
            "INSERT INTO _sqlx_migrations \
             (version, description, success, checksum, execution_time) \
             VALUES (9999, 'from a newer build', TRUE, X'00', 0)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        db.pool.close().await;

        let db = Db::connect(&url).await.unwrap();
        db.ping().await.unwrap();
    }
}
