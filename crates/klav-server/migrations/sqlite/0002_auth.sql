-- Accounts: OPAQUE record plus the encrypted keyset the client needs to unlock.
CREATE TABLE accounts (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    opaque_record   BLOB NOT NULL,
    kdf_params      BLOB NOT NULL,
    public_identity BLOB NOT NULL,
    sealed_identity BLOB NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- Client installations. Revoking one revokes all its sessions.
CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    kind         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    revoked_at   INTEGER
);
CREATE INDEX devices_account ON devices (account_id);

-- Sessions: only digests of the tokens are stored.
CREATE TABLE sessions (
    id                      TEXT PRIMARY KEY,
    account_id              TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id               TEXT NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    access_digest           BLOB NOT NULL UNIQUE,
    access_expires_at       INTEGER NOT NULL,
    refresh_digest          BLOB NOT NULL UNIQUE,
    previous_refresh_digest BLOB,
    refresh_expires_at      INTEGER NOT NULL,
    created_at              INTEGER NOT NULL,
    revoked_at              INTEGER
);
CREATE INDEX sessions_device ON sessions (device_id);
CREATE INDEX sessions_previous_refresh ON sessions (previous_refresh_digest);
