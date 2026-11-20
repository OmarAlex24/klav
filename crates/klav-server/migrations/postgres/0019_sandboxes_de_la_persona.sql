-- The person's side of sandboxes (ADR 0036 E3.3, E5, layer 5a). Five new
-- tables, empty when created: nothing that exists is read, rewritten or
-- changed. Each row goes with its account (`ON DELETE CASCADE`); the
-- proxy and the sandboxes it names belong to the same account.

-- The person's revocations, signed by the account
-- (`klav/v1/sig/sandbox-revoke`, spec §13.11). `seq` is the position of
-- its `sandbox.revoke_requested` in the account's log, and the cursor of
-- `GET /v1/agent/sandboxes/revocations?since=`. `scope` is `all` or a
-- sandbox ID; `sandbox_ids` is the JSON list of the sandboxes it covers
-- (the one, or those of an `all` taken under the account's lock).
CREATE TABLE sandbox_revocations (
    account_id  TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    seq         BIGINT NOT NULL,
    proxy_id    TEXT NOT NULL,
    scope       TEXT NOT NULL,
    at_ms       BIGINT NOT NULL,
    signature   BYTEA NOT NULL,
    device_id   TEXT,
    sandbox_ids TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (account_id, seq)
);
-- A proxy's revocations after a cursor.
CREATE INDEX sandbox_revocations_proxy ON sandbox_revocations (proxy_id, seq);

-- One row per sandbox the person revoked, from the first revocation that
-- covered it: the access barrier checks it in one lookup.
CREATE TABLE sandbox_person_revoked (
    sandbox_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    proxy_id   TEXT NOT NULL,
    seq        BIGINT NOT NULL,
    at_ms      BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX sandbox_person_revoked_account ON sandbox_person_revoked (account_id);

-- The latest heartbeat of each proxy (`PUT /v1/agent/sandboxes/state`),
-- kept with its signed request (`proof`, the JSON of the request with its
-- body) and out of the log. `store_epoch`, `seq` and `sent_at_ms` are the
-- signed body's, copied out for the server's checks.
CREATE TABLE sandbox_heartbeats (
    proxy_id    TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    store_epoch BYTEA NOT NULL,
    seq         BIGINT NOT NULL,
    sent_at_ms  BIGINT NOT NULL,
    proof       BYTEA NOT NULL,
    received_at BIGINT NOT NULL
);
CREATE INDEX sandbox_heartbeats_account ON sandbox_heartbeats (account_id);

-- Every store epoch a proxy has used (`sandbox.store_reset`), so none is
-- used twice. `seq` is the position of its event in the log.
CREATE TABLE sandbox_store_epochs (
    proxy_id   TEXT NOT NULL,
    epoch      BYTEA NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    seq        BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (proxy_id, epoch)
);
CREATE INDEX sandbox_store_epochs_account ON sandbox_store_epochs (account_id);

-- Pushes about a sandbox already sent (`sandbox_theft`,
-- `sandbox_expiring`), so each goes once, and the hourly budget per
-- account.
CREATE TABLE sandbox_pushes (
    sandbox_id TEXT NOT NULL,
    kind       TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sent_at    BIGINT NOT NULL,
    PRIMARY KEY (sandbox_id, kind)
);
CREATE INDEX sandbox_pushes_account ON sandbox_pushes (account_id, kind, sent_at);
