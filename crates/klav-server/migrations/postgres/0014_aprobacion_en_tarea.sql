-- «Add to the task» (ADR 0021 §6) approves the pending request once so the
-- agent's waiter exits; the approval is bound to that task (layer 06 of the
-- 2026-11 security round): it is never reused without being named, and a
-- named use needs the task to be running. NULL for every other approval.
ALTER TABLE approvals ADD COLUMN task_id TEXT;
