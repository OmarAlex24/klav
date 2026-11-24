-- Agent secret requests (ADR 0046): an agent asks the person to add a
-- missing item or update a secret field, sending HPKE-encrypted proposal
-- metadata (`proposal_blob`, kind `0x25`) without any secret value.
--
-- `proposal_blob` is held only while the request is pending; it is cleared
-- (`NULL`) immediately upon decision, revocation or expiry sweep.
-- `decision` are the exact signed JSON bytes of `SecretRequestDecision`
-- (spec §13.14).
CREATE TABLE secret_requests (
    id              TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    agent_id        TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    mode            TEXT NOT NULL,
    target_item_id  TEXT,
    reason          TEXT NOT NULL,
    proposal_digest BYTEA NOT NULL,
    proposal_blob   BYTEA,
    status          TEXT NOT NULL,
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    decided_at      BIGINT,
    decision        BYTEA,
    signature       BYTEA
);
CREATE INDEX secret_requests_account ON secret_requests (account_id, created_at);
CREATE INDEX secret_requests_agent ON secret_requests (agent_id, status);
