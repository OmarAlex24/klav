-- Registration invites (ADR 0048 §1.3): with `registration_mode = "invite"`
-- a sign-up needs one. Only the labelled digest of the code is stored
-- (`SHA-256(tuple("klav/v1/server/invite", canonical bytes))`, spec §4.7);
-- `id` is what `klav-server invite ls|revoke` use. Times are Unix ms.
--
-- The table belongs to the server, not to an account: deleting an account
-- leaves its invite (and its spent use) in place.
CREATE TABLE registration_invites (
    id          TEXT PRIMARY KEY,
    code_hash   BYTEA NOT NULL UNIQUE,
    bound_email TEXT,
    max_uses    BIGINT NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    used_count  BIGINT NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    expires_at  BIGINT,
    note        TEXT,
    created_at  BIGINT NOT NULL,
    revoked_at  BIGINT
);

-- Which accounts each invite created, for `klav-server invite ls`. The row
-- goes with the account (ADR 0037); the use is not given back.
CREATE TABLE registration_invite_uses (
    invite_id  TEXT NOT NULL REFERENCES registration_invites (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    used_at    BIGINT NOT NULL,
    PRIMARY KEY (invite_id, account_id)
);
CREATE INDEX registration_invite_uses_account ON registration_invite_uses (account_id);
