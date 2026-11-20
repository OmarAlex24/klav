-- Agents (fase 4, design §5): identities that register themselves and
-- that a person approves after comparing the 6-word pairing code.
--
-- `status`: pending | active | denied | revoked. A pending request lapses at
-- `expires_at`. The current grant is stored verbatim (`grant_payload` are
-- the exact signed JSON bytes, `grant_signature` the account's Ed25519
-- signature): the server parses it to enforce the policy, but never
-- re-serialises it.
CREATE TABLE agents (
    id                TEXT PRIMARY KEY,
    account_id        TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    note              TEXT,
    public_identity   BLOB NOT NULL,
    status            TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    approved_at       INTEGER,
    revoked_at        INTEGER,
    revocation_sig    BLOB,
    last_seen_at      INTEGER,
    grant_version     INTEGER NOT NULL,
    grant_payload     BLOB,
    grant_signature   BLOB,
    granted_at        INTEGER
);
CREATE INDEX agents_account ON agents (account_id);

-- Projects of the current grant (a copy of the payload's list, so access
-- checks need no JSON parsing).
CREATE TABLE agent_projects (
    agent_id   TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    vault_id   TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    PRIMARY KEY (agent_id, project_id)
);
CREATE INDEX agent_projects_vault ON agent_projects (vault_id);

-- Nonces of signed agent requests, kept past the clock-skew window to
-- reject replays (threat T25).
CREATE TABLE agent_nonces (
    agent_id   TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    nonce      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, nonce)
);
CREATE INDEX agent_nonces_expiry ON agent_nonces (expires_at);
