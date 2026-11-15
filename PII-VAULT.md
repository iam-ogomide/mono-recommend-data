# PII Vault

## What it is

The PII (personally identifiable information) vault is a component that keeps
direct identifiers such as BVNs, NINs, and phone numbers separate from the rest
of the recommendation pipeline. The application stores a random subscriber
token (for example, `subtok_...`) on the subscriber record and uses that token
when it needs to refer to the person. A permitted caller can ask the vault to
resolve a token to a specific identifier for a specific purpose.

The vault is not a bureau client and does not make bureau calls. In this
repository it supplies the BVN lookup needed by the existing stored-report
adapter and recommendation runner.

## What it does

- **Normalizes identifiers.** BVNs and NINs must be 11 digits. Nigerian mobile
  phone formats are normalized to `+234...`.
- **Creates random tokens.** Tokens are not derived from BVNs. The same
  normalized BVN maps to the same token within a vault, using a keyed HMAC
  lookup value.
- **Encrypts stored values.** Each field is encrypted with AES-256-GCM using a
  fresh data-encryption key. That key is wrapped by a key-encryption key (KEK).
  Ciphertext is authenticated against the token and field, so moving encrypted
  data to another token or field is detected.
- **Applies explicit access grants.** Reads require a matching caller, field,
  and purpose. Grants can allow masked-only reads. Writers, erasers, and key
  rotators are separately listed. Access is denied by default.
- **Audits access.** Events record actions and outcomes without recording the
  identifier value. For successful reads, the audit write happens before the
  identifier is returned; if that audit write fails, the read fails closed.
- **Supports erasure and key rotation.** Erasure deletes encrypted fields and
  the BVN lookup hash but leaves a tombstone token. Key rotation rewraps data
  keys without re-encrypting the identifier values.

## How it is implemented here

### Vault logic

[`vault/vault.py`](./vault/vault.py) contains the core vault implementation:

- `Vault` implements tokenization, setting fields, resolving or masking fields,
  erasure, and key rewrapping.
- `PiiField`, `Grant`, and `VaultPolicy` define supported fields and access
  rules.
- `LocalKeyProvider` is a development key provider. It reads base64-encoded
  keys from environment variables and holds the master keys in process memory.
- `InMemoryVaultStore` and `InMemoryAudit` are for tests and local examples;
  they do not persist data across process restarts.

### MongoDB persistence

[`vault/mongo_store.py`](./vault/mongo_store.py) persists the encrypted token
records:

- Each token is one MongoDB document.
- The document stores the token, HMAC lookup value, timestamps, and encrypted
  field records (`ciphertext`, `wrapped_dek`, and `kek_id`).
- Token creation stores the token and its fields in one document insert.
- Erasure unsets encrypted fields and the lookup hash while retaining the
  tombstone.
- The unique partial index on `bvn_lookup` prevents two tokens from being
  created for the same BVN lookup hash.

The SQL schema in [`vault/vault_schema.sql`](./vault/vault_schema.sql) is a
PostgreSQL design reference for vault token/field storage. The current runner's
token store is MongoDB; audit events are stored separately in PostgreSQL.

### Shared audit log

[`audit_logs/audit_log.py`](./audit_logs/audit_log.py) scrubs and validates
events, appends them to a sequence-numbered SHA-256 hash chain, and provides
query and verification APIs. [`audit_logs/audit_schema.sql`](./audit_logs/audit_schema.sql)
adds PostgreSQL constraints and triggers that prevent updates/deletes and
reject inserts that do not extend the existing chain.

[`audit_logs/vault_bridge.py`](./audit_logs/vault_bridge.py) adapts vault events
to the shared log:

- `RESOLVE` and `READ_MASKED` become `UNMASK` events.
- Tokenization, field updates, erasure, and key rotation become `VAULT_ADMIN`
  events.
- The subject is the random subscriber token; the PII field and purpose are
  recorded as details. Identifier values are never sent to the audit log.
- A successful vault operation that returns sensitive data fails closed if
  the event cannot be durably appended. Denials remain denied if the audit
  store is unavailable.

The runner constructs `VaultAuditSink(PostgresAuditStore(...))` using
`AUDIT_DATABASE_URL`. This connection points to a PostgreSQL audit database
separate from the MongoDB vault data. The old MongoDB-specific vault audit
collection is no longer used.

### Runner integration

[`vault/vault_adapter.py`](./vault/vault_adapter.py) connects the core vault to
the recommendation runner:

- `migrate_subscribers()` reads existing BVNs, tokenizes valid values, and
  writes the resulting `pii_token` back to the subscriber record.
- `make_mongo_token_resolver()` reads a subscriber's token.
- `VaultLookup` implements the runner's BVN lookup interface. Missing or
  erased token data becomes the existing `BVN_NOT_FOUND` outcome. Access,
  audit, key, or decryption failures raise instead of silently falling back to
  plaintext.

[`runner.py`](./runner.py) constructs the development vault with MongoDB
collections in the main database. The default migration and run paths remain
unchanged: vault migration and lookup must be explicitly requested.

## Development setup and use

Run commands from the repository root with the project's virtual environment
active. Configure these values locally (for example, in the ignored `.env`
file):

- `VAULT_KEKS`: one or more `key-id:base64-key` entries. Each decoded KEK must
  be exactly 32 bytes.
- `VAULT_KEK_CURRENT`: the key ID from `VAULT_KEKS` to use for new encrypted
  fields.
- `VAULT_LOOKUP_KEY`: a base64-encoded key of at least 32 bytes, different
  from every KEK.
- `AUDIT_DATABASE_URL`: PostgreSQL connection URL for the shared audit log.
- Optional `VAULT_TOKENS_COLLECTION` name; its default is
  `runner_vault_tokens`.

Generate and store the keys securely; do not copy them into source control,
chat, or logs. **Keep the same keys backed up and available between runs.**
Changing or losing a KEK can make existing encrypted values unreadable.
Changing or losing the lookup key prevents the vault from finding existing
tokens from a BVN.

Before using the vault, apply [`audit_logs/audit_schema.sql`](./audit_logs/audit_schema.sql)
to the separate PostgreSQL audit database using an administrator/deployment
role. This change does not apply the schema to a live database. Configure the
application role with the read/insert operations required by the audit store,
and restrict schema changes and trigger management to a separate administrator.

First, preview the migration for one subscriber. This is read-only and does not
need vault keys:

```powershell
python runner.py --migrate-vault --only SUB-0001
```

If the preview is appropriate and the vault keys are configured, write the
token for that subscriber:

```powershell
python runner.py --migrate-vault --write-vault-migration --only SUB-0001
```

To explicitly authorize a write migration for all subscribers with BVNs, use
`--all-vault-migration` instead of `--only`:

```powershell
python runner.py --migrate-vault --write-vault-migration --all-vault-migration
```

After migration, run the recommendation pipeline through the vault:

```powershell
python runner.py --date 2026-09-22 --only SUB-0001 --use-vault
```

Migration **does not remove the plaintext `bvn` field** from subscriber
documents. Keep it until vault lookup has been validated and any separate
plaintext-removal change has been explicitly reviewed and approved.

## Important limitations

- **Development only:** `LocalKeyProvider` keeps KEKs in process memory, and
  the configured policy is constructed inside the runner. `Caller.name` is
  supplied by application code; it is not independently authenticated.
- **Not an isolated service:** the vault currently runs in the runner's
  process. The design does not by itself prevent other code with database
  access from reading vault documents or bypassing the vault.
- **PostgreSQL append-only guarantees depend on deployment controls.** Use
  separate database roles and keep database administration separate from the
  application writer. A superuser can disable triggers; preserve chain-head
  anchors outside the audit database and verify the chain.
- **Backups matter for erasure:** old database backups may still contain
  ciphertext and wrapped keys. Define backup retention and erasure-on-restore
  procedures before treating erasure as permanent.
- **Secrets require durable protection:** protect and back up the KEKs and
  lookup key independently of the database. Do not rotate or regenerate them
  without a planned key migration.
- **Python memory is not securely wiped.** Decrypted identifiers exist in
  process memory while being used.
- **Plaintext migration is gradual:** migrating a record adds `pii_token` but
  intentionally leaves its existing BVN in place.

Before production use, replace the local provider with a KMS-backed provider,
run the vault behind a service boundary with authenticated workload identity,
restrict database access to that service, and establish audit, backup, key
rotation, and erasure controls.
