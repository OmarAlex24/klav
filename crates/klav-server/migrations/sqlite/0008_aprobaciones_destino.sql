-- Approvals reused by a retry (ADR 0015): `target_key` is the action an
-- approval is for (grant version, permission, vault, project, item and
-- claimed domain), so a retry finds the approved or pending request instead
-- of creating another. Rows from before this migration have no key and are
-- never reused.
ALTER TABLE approvals ADD COLUMN target_key TEXT;
-- At most one pending request per agent and action: two concurrent
-- requests for the same thing get the same approval.
CREATE UNIQUE INDEX approvals_pending_target ON approvals (agent_id, target_key)
    WHERE status = 'pending';
CREATE INDEX approvals_agent_target ON approvals (agent_id, target_key, status);
