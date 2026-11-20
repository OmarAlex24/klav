-- Task requests (ADR 0021): an agent asks for a set of items and
-- permissions at once; the person approves one card and the agent uses
-- that set until the task expires.
--
-- `request` are the exact bytes of the agent's signed POST body
-- (`TaskRequest`), and `decision` the exact bytes of the person's signed
-- `TaskDecision` in force (spec §13.8): nobody re-serializes them.
-- `status`: pending | approved | denied | expired | ended. An approved task
-- past `expires_at` is ended (`ended_by = 'expiry'`) the first time the
-- server notices.
CREATE TABLE tasks (
    id            TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    status        TEXT NOT NULL,
    request       BLOB NOT NULL,
    created_at    INTEGER NOT NULL,
    decide_by     INTEGER NOT NULL,
    decided_at    INTEGER,
    decision      BLOB,
    signature     BLOB,
    revision      INTEGER NOT NULL DEFAULT 0,
    expires_at    INTEGER,
    ended_at      INTEGER,
    ended_by      TEXT,
    end_signature BLOB
);
CREATE INDEX tasks_account ON tasks (account_id, created_at);
CREATE INDEX tasks_agent ON tasks (agent_id, status);
-- What an approved task covers: one row per (item, permission), keyed like
-- the approvals' `target_key` (ADR 0015 §1) without the domain and without
-- the grant version (a task re-evaluates the current grant on every use),
-- with the approved hosts as a JSON array.
CREATE TABLE task_targets (
    task_id    TEXT NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    target_key TEXT NOT NULL,
    hosts      TEXT NOT NULL,
    PRIMARY KEY (task_id, target_key)
);
CREATE INDEX task_targets_key ON task_targets (target_key);
