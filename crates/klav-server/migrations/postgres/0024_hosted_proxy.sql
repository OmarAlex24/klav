-- Klav Cloud's hosted proxy (ADR 0051 §3.5 and §8).
--
-- `accounts.hosted_proxy`: 1 while the account is entitled to the hosted
-- proxy, 0 (the default) otherwise. Only the operator sets it, with
-- `klav-server hosted-proxy enable|disable`; no route writes it.
-- `accounts.hosted_proxy_at`: when the operator last turned it on or off
-- (Unix ms); NULL if never.
ALTER TABLE accounts ADD COLUMN hosted_proxy BIGINT NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN hosted_proxy_at BIGINT;

-- `agents.hosted`: 1 for an agent Klav Cloud's hosted proxy registered with
-- a registration its service key signed, 0 (the default) for every other
-- agent. Server-side bookkeeping only: no client sees it, and it is not a
-- security boundary (the devices verify the enclave's attestation).
-- `agents.hosted_generation`: that registration's key generation (ADR
-- 0051 §3.2); NULL for every other agent.
ALTER TABLE agents ADD COLUMN hosted BIGINT NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN hosted_generation BIGINT;
