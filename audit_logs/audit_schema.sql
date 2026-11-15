-- Audit log schema (PostgreSQL 14+). Tested on 16.
--
-- 1. Append only. UPDATE, DELETE and TRUNCATE are blocked by triggers, for every role,
--    including the table owner. A superuser can still drop the triggers or the table, so
--    also run the application as a role that has only INSERT and SELECT (see the end), and
--    save the chain head somewhere the DBA cannot write (see audit_log.py, "Limits").
-- 2. The database also checks the chain link on every insert: seq must be the previous seq + 1
--    and prev_hash must equal the previous row's hash. It does not recompute hashes; the
--    application does that and AuditLog.verify() re-checks them.
-- 3. No identifiers go in this table. The application scrubs before inserting.
-- 4. Plain table, no partitioning, no retention job. Retention is not specified yet. If rows
--    are ever archived, archive whole days and keep the hash of the last archived row so the
--    chain can still be verified from there.

CREATE TABLE IF NOT EXISTS audit_log (
    seq         bigint PRIMARY KEY CHECK (seq >= 1),
    at          timestamptz NOT NULL,
    event_type  text NOT NULL CHECK (event_type IN ('TOOL_CALL','APPROVAL','CONFIG_CHANGE','UNMASK','VAULT_ADMIN')),
    outcome     text NOT NULL CHECK (outcome IN ('ALLOWED','DENIED','ERROR')),
    actor       text NOT NULL CHECK (actor <> ''),
    actor_kind  text NOT NULL CHECK (actor_kind IN ('agent','service','human')),
    action      text NOT NULL CHECK (action <> ''),
    subject     text,
    tenant      text,
    run_id      text,
    trace_id    text,
    reason_code text,
    details     jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    scrubbed    boolean NOT NULL,
    prev_hash   char(64) NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    hash        char(64) NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS audit_log_at_idx       ON audit_log (at);
CREATE INDEX IF NOT EXISTS audit_log_denials_idx  ON audit_log (at, reason_code) WHERE outcome = 'DENIED';
CREATE INDEX IF NOT EXISTS audit_log_actor_idx    ON audit_log (actor, at);
CREATE INDEX IF NOT EXISTS audit_log_subject_idx  ON audit_log (subject) WHERE subject IS NOT NULL;
CREATE INDEX IF NOT EXISTS audit_log_run_idx      ON audit_log (run_id) WHERE run_id IS NOT NULL;

CREATE OR REPLACE FUNCTION audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% blocked)', TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_no_change   ON audit_log;
DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_change
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_is_append_only();
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_is_append_only();

-- Chain link check. Writers are serialised by the advisory lock taken in the application,
-- but the check here holds even if some other client forgets the lock: a second writer
-- loses with a primary key or chain error instead of forking the chain.
CREATE OR REPLACE FUNCTION audit_log_check_chain() RETURNS trigger AS $$
DECLARE
    last_seq  bigint;
    last_hash char(64);
BEGIN
    SELECT seq, hash INTO last_seq, last_hash FROM audit_log ORDER BY seq DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.seq <> 1 OR NEW.prev_hash <> repeat('0', 64) THEN
            RAISE EXCEPTION 'audit_log chain: first row must be seq 1 with the genesis hash';
        END IF;
    ELSIF NEW.seq <> last_seq + 1 OR NEW.prev_hash <> last_hash THEN
        RAISE EXCEPTION 'audit_log chain: row does not extend the current tail';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_chain ON audit_log;
CREATE TRIGGER audit_log_chain
    BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_check_chain();

-- Roles. Uncomment and adapt. The app role can add and read, nothing else.
--   REVOKE ALL ON audit_log FROM PUBLIC;
--   GRANT INSERT, SELECT ON audit_log TO audit_writer;   -- the service that appends
--   GRANT SELECT          ON audit_log TO audit_reader;   -- on-call, product review, alerts
