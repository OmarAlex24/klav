-- Push notifications (ADR 0018 §5): the APNs device token of each device
-- that asked for approvals on the phone. One per device; revoking the
-- device, logging it out or an "unregistered" answer from Apple removes it.
-- The token is a delivery address, not a secret, but it is never logged.
CREATE TABLE push_tokens (
    device_id   TEXT PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    account_id  TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    token       TEXT NOT NULL,
    environment TEXT NOT NULL,
    updated_at  BIGINT NOT NULL
);
CREATE INDEX push_tokens_account ON push_tokens (account_id);
CREATE INDEX push_tokens_token ON push_tokens (token);
