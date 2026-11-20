-- Server-wide key/value state (e.g. long-term protocol keys).
CREATE TABLE server_state (
    key        TEXT PRIMARY KEY,
    value      BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
