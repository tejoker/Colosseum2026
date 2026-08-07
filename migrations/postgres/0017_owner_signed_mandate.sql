-- Owner-signed mandate.
--
-- "This agent may do these things, up to this much" was previously the
-- operator's word: the server verified a session and stored whatever intent it
-- was handed, so whoever ran the server could invent authority for an agent and
-- nobody downstream could tell. The owner now signs that grant with the Ed25519
-- key `user_auth_with_key` already keeps in their own process, and the server
-- stores the signature plus a hash of the canonical mandate.
--
-- Empty on rows registered before this, and on deployments that have not turned
-- SAURON_REQUIRE_OWNER_MANDATE on.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS owner_mandate_sig_b64u TEXT NOT NULL DEFAULT '';
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS owner_mandate_hash TEXT NOT NULL DEFAULT '';
