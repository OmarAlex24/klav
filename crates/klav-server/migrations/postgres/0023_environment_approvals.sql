-- One approval for an environment and the protected items it uses (ADR 0032
-- §3.1): `run_with_secrets` with an environment asks once for the
-- environment and every protected item its references point to. The
-- approval's signed request lists those items in `items`, and it serves one
-- access to each listed item: one row per item, the environment included,
-- spent one by one. The approval itself is spent (`approvals.used_at`) when
-- every row is, or lapses with the approve-once window. Approvals without
-- these rows work as before.
CREATE TABLE approval_items (
    approval_id TEXT NOT NULL REFERENCES approvals (id) ON DELETE CASCADE,
    item_id     TEXT NOT NULL,
    used_at     BIGINT,
    PRIMARY KEY (approval_id, item_id)
);
