-- The owner's Ed25519 signature over its shared vault key (ADR 0030 §1,
-- spec §8.3): `tuple("klav/v1/sig/vault-key", account_id, vault_id,
-- shared_key)`. Clients reject a vault whose key the account did not sign.
-- NULL on rows from before this migration (the owner's devices sign them
-- once, TOFU, through `PUT /v1/vaults/{id}/signature`) and on agent rows.
ALTER TABLE vault_members ADD COLUMN shared_key_signature BYTEA;
