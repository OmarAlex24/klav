-- Approval requests (design §5.3): an agent action the policy sets to
-- `ask` waits here for the person.
--
-- `request` are the exact JSON bytes of `ApprovalRequest` the person signs
-- (spec §13.5). `status`: pending | approved | denied | expired. An approval
-- with `lease_until > decided_at` covers the same agent, permission and
-- item until then; with `lease_until = 0` it is spent on first use
-- (`used_at`). It only counts while the agent's grant is still
-- `grant_version`.
CREATE TABLE approvals (
    id            TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    status        TEXT NOT NULL,
    permission    TEXT NOT NULL,
    vault_id      TEXT NOT NULL,
    project_id    TEXT NOT NULL,
    item_id       TEXT,
    request       BLOB NOT NULL,
    grant_version INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    decided_at    INTEGER,
    lease_until   INTEGER,
    signature     BLOB,
    used_at       INTEGER
);
CREATE INDEX approvals_account ON approvals (account_id, created_at);
CREATE INDEX approvals_agent ON approvals (agent_id, status);
