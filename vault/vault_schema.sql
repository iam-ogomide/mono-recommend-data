-- PII vault schema for PostgreSQL.
-- NOT RUN against a live database yet: review it, and run it on a scratch database first.
-- It mirrors InMemoryVaultStore in vault.py, which is what the tests exercise.
--
-- Deployment rules this schema assumes (the database cannot enforce these alone):
--   1. Only the vault service connects as vault_app. No agent, no other service, no humans.
--   2. The database is not reachable from the agent network. The vault is its own service.
--   3. Erasure is only as permanent as your backups. Erase deletes the ciphertext and wrapped
--      keys from this database, but an older backup still holds them and the master key can
--      still decrypt them. Restoring that backup brings erased subscribers back. Decide with
--      compliance: keep backup retention short, and/or re-run every erasure after any restore.

CREATE TABLE vault_tokens (
    token        text        PRIMARY KEY,
    bvn_lookup   text        UNIQUE,          -- hex HMAC-SHA256 of the BVN. NULL after erasure.
    created_at   timestamptz NOT NULL,
    erased_at    timestamptz
);

CREATE TABLE vault_fields (
    token        text        NOT NULL REFERENCES vault_tokens (token),
    pii_field    text        NOT NULL CHECK (pii_field IN ('bvn', 'nin', 'phone')),
    ciphertext   bytea       NOT NULL,        -- 12-byte nonce + AES-256-GCM ciphertext and tag
    wrapped_dek  bytea       NOT NULL,        -- data key, wrapped by the master key
    kek_id       text        NOT NULL,        -- which master key wrapped it
    updated_at   timestamptz NOT NULL,
    PRIMARY KEY (token, pii_field)
);

-- Finds rows still on an old master key during rotation.
CREATE INDEX vault_fields_kek_idx ON vault_fields (kek_id);

-- Compare-and-swap rewrap, as used by Vault.rewrap_batch:
--   UPDATE vault_fields
--      SET wrapped_dek = $4, kek_id = $5
--    WHERE token = $1 AND pii_field = $2 AND wrapped_dek = $3;
--   -- rows affected = 1 means success, 0 means someone wrote a newer value first.

-- Atomic create (Vault.tokenize): insert the token and its fields in ONE transaction.
-- A unique violation on vault_tokens.bvn_lookup is the "TokenExists" case.

-- Erase (Vault.erase), one transaction:
--   DELETE FROM vault_fields WHERE token = $1;
--   UPDATE vault_tokens SET bvn_lookup = NULL, erased_at = COALESCE(erased_at, $2) WHERE token = $1;

-- ---------------------------------------------------------------------------
-- Audit. The vault does not store a separate audit table here. Every vault event goes to the
-- shared append-only, hash-chained PostgreSQL log in audit_logs/audit_schema.sql through
-- VaultAuditSink. Keep that audit database/schema separate from the vault data so a vault
-- database administrator cannot also edit the history of vault access.
-- ---------------------------------------------------------------------------
-- ---------------------------------------------------------------------------
-- Roles (names are placeholders)
-- ---------------------------------------------------------------------------
-- CREATE ROLE vault_app LOGIN;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON vault_tokens, vault_fields TO vault_app;
-- The audit writer uses a separate database role and connection to audit_logs.audit_log.
