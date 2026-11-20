-- Pauses of agents (ADR 0033 §7, spec §13.9): the account's last signed
-- decision per scope. `scope` is `all` (every agent of the account,
-- including those approved later) or an agent ID; `state` is `pause` or
-- `resume`; `until_ms` is the end of a pause (Unix ms, 0: until the
-- person resumes). A new decision on a scope must be later (`at_ms`) than
-- the stored one, so an old resume cannot be replayed. The server checks
-- the pause on every signed agent request and again, under the account's
-- lock, when it logs an allowed agent action.
CREATE TABLE agent_pauses (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    scope      TEXT NOT NULL,
    state      TEXT NOT NULL,
    at_ms      INTEGER NOT NULL,
    until_ms   INTEGER NOT NULL,
    signature  BLOB NOT NULL,
    device_id  TEXT,
    PRIMARY KEY (account_id, scope)
);
