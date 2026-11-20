-- Audit log (design §6, spec §13.7): one hash chain per account.
--
-- `event` are the exact JSON bytes of an `AuditEvent`; `hash` =
-- SHA-256(tuple("klav/v1/audit/event", seq, previous hash, event)). The
-- primary key serialises appends: two writers that read the same last
-- `seq` cannot both insert the next one (the loser retries).
CREATE TABLE audit_events (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    event      BLOB NOT NULL,
    hash       BLOB NOT NULL,
    at         INTEGER NOT NULL,
    agent_id   TEXT,
    item_id    TEXT,
    action     TEXT NOT NULL,
    PRIMARY KEY (account_id, seq)
);
CREATE INDEX audit_events_agent_item ON audit_events (agent_id, item_id);

-- Chain heads signed by the person's devices.
CREATE TABLE audit_heads (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    hash       BLOB NOT NULL,
    signature  BLOB NOT NULL,
    device_id  TEXT NOT NULL,
    signed_at  INTEGER NOT NULL
);
CREATE INDEX audit_heads_account ON audit_heads (account_id, signed_at);
