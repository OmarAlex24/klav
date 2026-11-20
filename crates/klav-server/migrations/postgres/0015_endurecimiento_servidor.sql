-- Layer 07 of the 2026-11 security round (server hardening).

-- Last activity of an attachment upload (declare or chunk): uploads left
-- unfinished for more than a day are removed by the purge. NULL on rows
-- created before this migration (the purge then uses created_at).
ALTER TABLE attachments ADD COLUMN updated_at BIGINT;

-- Unfinished uploads, for the clean-up and the per-account cap.
CREATE INDEX attachments_pending ON attachments (vault_id, created_at)
    WHERE completed_at IS NULL AND deleted_at IS NULL;

-- Lookups that scanned whole tables.
CREATE INDEX sessions_account ON sessions (account_id);
CREATE INDEX agent_projects_project ON agent_projects (project_id);
CREATE INDEX approvals_vault ON approvals (vault_id);
-- The periodic task sweep (every account): pending past decide_by,
-- approved past expires_at.
CREATE INDEX tasks_status_decide ON tasks (status, decide_by);
CREATE INDEX tasks_status_expiry ON tasks (status, expires_at);
