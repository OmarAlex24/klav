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

        let mut migrator = match backend {
            Backend::Sqlite => sqlx::migrate!("migrations/sqlite"),
            Backend::Postgres => sqlx::migrate!("migrations/postgres"),
        };
        // A build older than its database still starts. After a rollback the
        // newer build's migrations stay recorded, and without this sqlx
        // refuses them (`VersionMissing`) and the server never comes up.
        // A changed checksum of a migration this build knows still fails.
        migrator.set_ignore_missing(true);
        migrator.run(&pool).await.map_err(DbError::Migrate)?;

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
