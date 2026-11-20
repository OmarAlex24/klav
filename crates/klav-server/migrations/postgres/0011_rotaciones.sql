-- Assisted password changes (ADR 0022 §5): one row per item an agent
-- starts changing inside a task. It only says where the change stands;
-- the passwords never reach the server (the person's klavd keeps the
-- pending one in the item's sealed password record).
--
-- `status`: started | confirmed | cancelled | abandoned. A started change
-- whose task is no longer running is marked abandoned the next time a
-- change of the same item starts: the person resolves the pending
-- password from the item.
CREATE TABLE rotations (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    task_id     TEXT NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    vault_id    TEXT NOT NULL,
    project_id  TEXT NOT NULL,
    item_id     TEXT NOT NULL,
    host        TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  BIGINT NOT NULL,
    finished_at BIGINT
);
CREATE INDEX rotations_agent ON rotations (agent_id, status);
-- At most one change in progress per item.
CREATE UNIQUE INDEX rotations_started_item ON rotations (item_id) WHERE status = 'started';
