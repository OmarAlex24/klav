-- Sandboxes a credential proxy started for an issuer (ADR 0036 §4, E3.3).
-- The proxy reports each step with a signed request, and the log keeps
-- what it signed (`sandbox.issued`, `sandbox.claimed`, `sandbox.revoked`);
-- this table only lets the server check that the steps come in order: a
-- claim or an end only after an issue by the same proxy, each only once,
-- and no more live sandboxes per issuer than the proxy's grant allows.
--
-- No secret, digest, package, label or profile is stored here: the label
-- and the profiles are in the event, and the secret never reaches the
-- server. `proxy_id` and `issuer_id` are agents of the same account,
-- so the row goes with `account_id` (agents are only ever deleted with
-- their account).
--
-- A new table only: no existing table changes.
CREATE TABLE sandboxes (
    id            TEXT PRIMARY KEY,
    account_id    TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    proxy_id      TEXT NOT NULL,
    issuer_id     TEXT NOT NULL,
    expires_at    BIGINT NOT NULL,
    issued_at     BIGINT NOT NULL,
    claimed_at    BIGINT,
    revoked_at    BIGINT,
    revoke_reason TEXT
);
-- Live sandboxes of one issuer at one proxy (`max_live`).
CREATE INDEX sandboxes_issuer ON sandboxes (proxy_id, issuer_id, revoked_at);
-- The account's sandboxes, for the cascade when an account is deleted.
CREATE INDEX sandboxes_account ON sandboxes (account_id);
