-- The MCP gateway (ADR 0049 §9 and §5.4).
--
-- `accounts.mcp_gateway_at`: when the person turned the account's
-- `mcp_gateway` switch on (Unix ms); NULL while it is off, the default.
-- Only `POST /v1/account/mcp-gateway` sets it, and nothing clears it. While
-- it is NULL the server refuses `claims.mcp_tool`, `claims.mcp_args` and
-- `local_client` with `400 mcp_gateway_off`.
ALTER TABLE accounts ADD COLUMN mcp_gateway_at INTEGER;

-- `approvals.lease_key`: for an MCP tool call, the target key without the
-- argument digest. «Once» matches `target_key` (the same tool with the same
-- arguments); a lease («for a while») also serves `lease_key` (the same tool
-- with any arguments). NULL for every other approval.
ALTER TABLE approvals ADD COLUMN lease_key TEXT;
CREATE INDEX approvals_agent_lease ON approvals (agent_id, lease_key)
    WHERE lease_key IS NOT NULL;
