-- Vaults. `revision` is the vault's change counter: every change to the
-- vault or anything inside it increments it (strictly monotonic, never
-- reused). `meta_revision` is the revision of the last change to this row.
CREATE TABLE vaults (
    id               TEXT PRIMARY KEY,
    owner_account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    revision         BIGINT NOT NULL,
    version          BIGINT NOT NULL,
    meta             BYTEA NOT NULL,
    meta_revision    BIGINT NOT NULL,
    created_at       BIGINT NOT NULL,
    updated_at       BIGINT NOT NULL,
    deleted_at       BIGINT
);
CREATE INDEX vaults_owner ON vaults (owner_account_id);

-- Who can open a vault: the vault key shared (HPKE, kind 0x20) with each
-- member. `member_type` is 'account' now; 'agent' arrives in fase 4.
CREATE TABLE vault_members (
    vault_id    TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    member_type TEXT NOT NULL,
    member_id   TEXT NOT NULL,
    role        TEXT NOT NULL,
    shared_key  BYTEA NOT NULL,
    revision    BIGINT NOT NULL,
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL,
    revoked_at  BIGINT,
    PRIMARY KEY (vault_id, member_type, member_id)
);
CREATE INDEX vault_members_member ON vault_members (member_type, member_id);

-- Projects: project key wrapped with the vault key (kind 0x02) and
-- encrypted metadata. Deleted projects stay as tombstones for sync.
CREATE TABLE projects (
    id          TEXT PRIMARY KEY,
    vault_id    TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    version     BIGINT NOT NULL,
    wrapped_key BYTEA,
    meta        BYTEA,
    revision    BIGINT NOT NULL,
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL,
    deleted_at  BIGINT
);
CREATE INDEX projects_vault_revision ON projects (vault_id, revision);

-- Items: current version. Purged items keep a tombstone row without blobs.
CREATE TABLE items (
    id          TEXT PRIMARY KEY,
    vault_id    TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    project_id  TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    version     BIGINT NOT NULL,
    wrapped_key BYTEA,
    overview    BYTEA,
    details     BYTEA,
    revision    BIGINT NOT NULL,
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL,
    trashed_at  BIGINT,
    purged_at   BIGINT
);
CREATE INDEX items_vault_revision ON items (vault_id, revision);
CREATE INDEX items_project ON items (project_id);
CREATE INDEX items_trashed ON items (trashed_at);

-- Previous versions of each item (the current one lives in `items`).
CREATE TABLE item_versions (
    item_id     TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    version     BIGINT NOT NULL,
    project_id  TEXT NOT NULL,
    wrapped_key BYTEA NOT NULL,
    overview    BYTEA NOT NULL,
    details     BYTEA NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (item_id, version)
);
