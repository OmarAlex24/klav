-- Server-wide key/value state (e.g. long-term protocol keys).
CREATE TABLE server_state (
    key        TEXT PRIMARY KEY,
    value      BYTEA NOT NULL,
    created_at BIGINT NOT NULL
);
