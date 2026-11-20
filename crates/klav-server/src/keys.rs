//! Long-term server secrets, generated on first start and kept in the
//! `server_state` table:
//!
//! * the OPAQUE server setup (OPRF seed + key-exchange key pair);
//! * the secret behind the decoy KDF parameters for unknown e-mails.
//!
//! Anyone with a copy of the database gets these too. That does not let them
//! brute-force passwords: the OPAQUE input mixes in the 128-bit Secret Key,
//! which the server never sees (spec §4.5, threat T1/T2).

use klav_core::crypto::opaque::ServerSetup;
use klav_core::crypto::random;
use zeroize::Zeroizing;

use crate::db::{Db, now_ms};

const OPAQUE_SETUP: &str = "opaque_server_setup_v1";
const DECOY_SECRET: &str = "decoy_kdf_secret_v1";

/// Server secrets loaded at start-up.
pub(crate) struct ServerKeys {
    pub(crate) opaque: ServerSetup,
    pub(crate) decoy_secret: Zeroizing<[u8; 32]>,
}

/// Error loading the server secrets.
#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    /// Database failure.
    #[error("cannot load server keys: {0}")]
    Db(#[from] sqlx::Error),
    /// A stored value is corrupt.
    #[error("stored server key {0} is corrupt")]
    Corrupt(&'static str),
}

/// Loads the server secrets, creating them on first start. Concurrent first
/// starts converge on whichever row was inserted first.
pub(crate) async fn load_or_create(db: &Db) -> Result<ServerKeys, KeysError> {
    let setup = get_or_insert(db, OPAQUE_SETUP, || ServerSetup::generate().to_bytes()).await?;
    let opaque = ServerSetup::from_bytes(&setup).map_err(|_| KeysError::Corrupt(OPAQUE_SETUP))?;

    let decoy = get_or_insert(db, DECOY_SECRET, || {
        Zeroizing::new(random::array::<32>().to_vec())
    })
    .await?;
    let decoy_secret: [u8; 32] = decoy
        .as_slice()
        .try_into()
        .map_err(|_| KeysError::Corrupt(DECOY_SECRET))?;
    Ok(ServerKeys {
        opaque,
        decoy_secret: Zeroizing::new(decoy_secret),
    })
}

async fn get_or_insert(
    db: &Db,
    key: &str,
    generate: impl FnOnce() -> Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, sqlx::Error> {
    let fresh = generate();
    sqlx::query(
        "INSERT INTO server_state (key, value, created_at) VALUES ($1, $2, $3) \
         ON CONFLICT (key) DO NOTHING",
    )
    .bind(key)
    .bind(fresh.to_vec())
    .bind(now_ms())
    .execute(&db.pool)
    .await?;
    let value: Vec<u8> = sqlx::query_scalar("SELECT value FROM server_state WHERE key = $1")
        .bind(key)
        .fetch_one(&db.pool)
        .await?;
    Ok(Zeroizing::new(value))
}
