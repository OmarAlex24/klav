-- Vaults. `revision` is the vault's change counter: every change to the
-- vault or anything inside it increments it (strictly monotonic, never
-- reused). `meta_revision` is the revision of the last change to this row.
CREATE TABLE vaults (
    id               TEXT PRIMARY KEY,
    owner_account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    revision         INTEGER NOT NULL,
    version          INTEGER NOT NULL,
    meta             BLOB NOT NULL,
    meta_revision    INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    deleted_at       INTEGER
);
CREATE INDEX vaults_owner ON vaults (owner_account_id);

-- Who can open a vault: the vault key shared (HPKE, kind 0x20) with each
-- member. `member_type` is 'account' now; 'agent' arrives in fase 4.
CREATE TABLE vault_members (
    vault_id    TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    member_type TEXT NOT NULL,
    member_id   TEXT NOT NULL,
    role        TEXT NOT NULL,
    shared_key  BLOB NOT NULL,
    revision    INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    revoked_at  INTEGER,
    PRIMARY KEY (vault_id, member_type, member_id)
);
CREATE INDEX vault_members_member ON vault_members (member_type, member_id);

-- Projects: project key wrapped with the vault key (kind 0x02) and
-- encrypted metadata. Deleted projects stay as tombstones for sync.
CREATE TABLE projects (
    id          TEXT PRIMARY KEY,
    vault_id    TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    wrapped_key BLOB,
    meta        BLOB,
    revision    INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    deleted_at  INTEGER
);
CREATE INDEX projects_vault_revision ON projects (vault_id, revision);

-- Items: current version. Purged items keep a tombstone row without blobs.
CREATE TABLE items (
    id          TEXT PRIMARY KEY,
    vault_id    TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    project_id  TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    wrapped_key BLOB,
    overview    BLOB,
    details     BLOB,
    revision    INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    trashed_at  INTEGER,
    purged_at   INTEGER
);
CREATE INDEX items_vault_revision ON items (vault_id, revision);
CREATE INDEX items_project ON items (project_id);
CREATE INDEX items_trashed ON items (trashed_at);

-- Previous versions of each item (the current one lives in `items`).
CREATE TABLE item_versions (
    item_id     TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    project_id  TEXT NOT NULL,
    wrapped_key BLOB NOT NULL,
    overview    BLOB NOT NULL,
    details     BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (item_id, version)
);
