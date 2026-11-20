-- Who wrote each version of an item (ADR 0030 §7, G8): the agent's ID, or
-- NULL for the person. Rows from before this migration count as the
-- person's. The hosts of the last version the person wrote are the
-- confirmed ones; those an agent added stay pending until she confirms them.
ALTER TABLE items ADD COLUMN author_agent_id TEXT;
ALTER TABLE item_versions ADD COLUMN author_agent_id TEXT;
