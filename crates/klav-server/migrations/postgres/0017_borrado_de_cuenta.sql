-- Deleting an account from the apps (ADR 0037 §2): one row per account
-- whose deletion the person asked for. The hourly purge deletes the
-- account at `delete_at` (7 days after `requested_at`) unless a device
-- cancels it first, which removes the row. `device_id` is the device that
-- asked; it has no foreign key because devices are revoked, never deleted,
-- until the account goes, and the row goes with the account.
CREATE TABLE account_deletions (
    account_id   TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL,
    requested_at BIGINT NOT NULL,
    delete_at    BIGINT NOT NULL
);
CREATE INDEX account_deletions_due ON account_deletions (delete_at);
