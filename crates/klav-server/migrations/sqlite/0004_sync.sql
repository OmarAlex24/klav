-- Encrypted attachments (STREAM, kind 0x30). The ciphertext lives on disk
-- under <data_dir>/attachments/<vault_id>/<attachment_id>; this row holds the
-- wrapped attachment key (kind 0x04) and the sync metadata. `revision` stays
-- 0 until the upload completes, so unfinished uploads never reach other
-- devices.
CREATE TABLE attachments (
    id           TEXT PRIMARY KEY,
    vault_id     TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    item_id      TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    size         INTEGER NOT NULL,
    received     INTEGER NOT NULL,
    wrapped_key  BLOB,
    revision     INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    completed_at INTEGER,
    deleted_at   INTEGER
);
CREATE INDEX attachments_vault_revision ON attachments (vault_id, revision);
CREATE INDEX attachments_item ON attachments (item_id);
