"""Runs against a real PostgreSQL 16 started in a temp directory (pixeltable-pgserver).
Skipped if that package is not installed. Set AUDIT_TEST_DSN to use your own server instead
(it must allow DROP TABLE and CREATE ROLE)."""
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

psycopg = pytest.importorskip("psycopg")

from audit_logs.audit_log import (  # noqa: E402
    AuditEvent, AuditLog, AuditQuery, AuditUnavailable, EventType, InMemoryAuditStore, Outcome,
    approval, config_change, tool_call,
)
from audit_logs.postgres_store import PostgresAuditStore  # noqa: E402

SCHEMA = (Path(__file__).parent / "audit_schema.sql").read_text()


@pytest.fixture(scope="session")
def dsn():
    if os.environ.get("AUDIT_TEST_DSN"):
        yield os.environ["AUDIT_TEST_DSN"]
        return
    pgserver = pytest.importorskip("pixeltable_pgserver")
    with tempfile.TemporaryDirectory() as d:
        srv = pgserver.get_server(d, cleanup_mode="stop")
        try:
            yield srv.get_uri()
        finally:
            srv.cleanup()


@pytest.fixture()
def db(dsn):
    """A fresh audit_log table for every test."""
    with psycopg.connect(dsn) as c:
        c.execute("DROP TABLE IF EXISTS audit_log CASCADE")
        c.execute(SCHEMA)
    return dsn


def log_for(dsn, **kw):
    return AuditLog(PostgresAuditStore(lambda: psycopg.connect(dsn, **kw)))


def ev(**over):
    base = dict(event_type=EventType.TOOL_CALL, outcome=Outcome.ALLOWED, actor="agent-1", action="get_report")
    base.update(over)
    return AuditEvent(**base)


def sql_error(dsn, sql, params=()):
    with pytest.raises(psycopg.Error) as e:
        with psycopg.connect(dsn) as c:
            c.execute(sql, params)
    return str(e.value)


class TestRoundTrip:
    def test_what_is_read_back_is_what_was_written_and_verifies(self, db):
        log = log_for(db)
        written = [
            log.append(tool_call("agent-a", "get_report", "DENIED", reason_code="NO_GRANT",
                                 tenant="t1", subject="subtok_ab12", note="naïve ☃ \"quoted\"", n=2**40, ok=True, none=None)),
            log.append(approval("amaka", "send_batch", ref="b-9")),
            log.append(config_change("tunde", "x.y", 1, 2, approved_by="amaka")),
        ]
        read = log.query(AuditQuery(newest_first=False))
        assert read == written
        assert log.verify().ok and log.verify(batch=2).checked == 3

    def test_verify_survives_a_non_utc_session_timezone(self, db):
        log = log_for(db, options="-c timezone=Asia/Tokyo")
        for _ in range(3):
            log.append(ev())
        assert log.verify().ok
        assert log_for(db, options="-c timezone=America/Sao_Paulo").verify().ok

    def test_microsecond_timestamps_survive(self, db):
        t = datetime(2026, 11, 8, 9, 0, 0, 123457, tzinfo=timezone.utc)
        log = AuditLog(PostgresAuditStore(lambda: psycopg.connect(db)), clock=lambda: t)
        log.append(ev())
        assert log.query()[0].at == t and log.verify().ok

    def test_head_and_anchor(self, db):
        log = log_for(db)
        assert log.head() is None
        log.append(ev())
        anchor = log.head()
        log.append(ev())
        assert anchor.seq == 1 and log.verify(anchor=anchor).ok


class TestAppendOnly:
    def test_update_delete_truncate_are_blocked(self, db):
        log_for(db).append(ev())
        for sql in ("UPDATE audit_log SET actor = 'x'", "DELETE FROM audit_log", "TRUNCATE audit_log"):
            assert "append-only" in sql_error(db, sql)
        assert log_for(db).verify().checked == 1

    def test_a_blocked_update_leaves_the_row_unchanged(self, db):
        log = log_for(db)
        log.append(ev(actor="honest"))
        sql_error(db, "UPDATE audit_log SET actor = 'mallory' WHERE seq = 1")
        assert log.query()[0].actor == "honest"

    def test_database_rejects_a_forked_or_skipped_chain_link(self, db):
        log = log_for(db)
        first = log.append(ev())
        cols = ("(seq, at, event_type, outcome, actor, actor_kind, action, scrubbed, prev_hash, hash)")
        vals = "VALUES (%s, now(), 'TOOL_CALL','ALLOWED','a','agent','b', false, %s, %s)"
        h = "a" * 64
        assert "chain" in sql_error(db, f"INSERT INTO audit_log {cols} {vals}", (2, "b" * 64, h))      # wrong prev
        assert "chain" in sql_error(db, f"INSERT INTO audit_log {cols} {vals}", (3, first.hash, h))    # skipped seq
        assert "chain" in sql_error(db, f"INSERT INTO audit_log {cols} {vals}", (1, "0" * 64, h))      # replay seq 1
        assert log.verify().checked == 1

    def test_first_row_must_be_genesis(self, db):
        cols = "(seq, at, event_type, outcome, actor, actor_kind, action, scrubbed, prev_hash, hash)"
        vals = "VALUES (%s, now(), 'TOOL_CALL','ALLOWED','a','agent','b', false, %s, %s)"
        assert "genesis" in sql_error(db, f"INSERT INTO audit_log {cols} {vals}", (5, "0" * 64, "c" * 64))
        assert "genesis" in sql_error(db, f"INSERT INTO audit_log {cols} {vals}", (1, "d" * 64, "c" * 64))

    def test_column_checks(self, db):
        base = "INSERT INTO audit_log (seq, at, event_type, outcome, actor, actor_kind, action, scrubbed, prev_hash, hash) VALUES "
        z, h = "0" * 64, "e" * 64
        assert sql_error(db, base + f"(1, now(), 'NOPE','ALLOWED','a','agent','b', false, '{z}', '{h}')")
        assert sql_error(db, base + f"(1, now(), 'TOOL_CALL','MAYBE','a','agent','b', false, '{z}', '{h}')")
        assert sql_error(db, base + f"(1, now(), 'TOOL_CALL','ALLOWED','','agent','b', false, '{z}', '{h}')")
        assert sql_error(db, base + f"(1, now(), 'TOOL_CALL','ALLOWED','a','agent','b', false, '{z}', 'XYZ')")


class TestTamperEvidence:
    def test_a_dba_who_disables_the_trigger_and_edits_is_caught(self, db):
        log = log_for(db)
        for _ in range(4):
            log.append(ev())
        anchor = log.head()
        with psycopg.connect(db) as c:   # superuser here: the scenario the hash chain exists for
            c.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change")
            c.execute("UPDATE audit_log SET outcome = 'ALLOWED', reason_code = 'EDITED' WHERE seq = 2")
            c.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_change")
        r = log.verify()
        assert (r.ok, r.problem, r.bad_seq) == (False, "HASH_MISMATCH", 2)
        assert not log.verify(anchor=anchor).ok

    def test_a_dba_who_deletes_the_tail_is_caught_only_with_an_anchor(self, db):
        log = log_for(db)
        for _ in range(4):
            log.append(ev())
        anchor = log.head()
        with psycopg.connect(db) as c:
            c.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change")
            c.execute("DELETE FROM audit_log WHERE seq > 2")
            c.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_change")
        assert log.verify().ok
        assert log.verify(anchor=anchor).problem == "ANCHOR_MISSING"


class TestConcurrency:
    def test_parallel_writers_produce_one_unbroken_chain(self, db):
        threads_n, each = 8, 20
        errors = []

        def work(i):
            log = log_for(db)
            try:
                for j in range(each):
                    log.append(ev(actor=f"agent-{i}", details={"j": j}))
            except Exception as e:  # pragma: no cover
                errors.append(e)

        ts = [threading.Thread(target=work, args=(i,)) for i in range(threads_n)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert not errors
        log = log_for(db)
        rows = log.query(AuditQuery(limit=10_000, newest_first=False))
        assert [r.seq for r in rows] == list(range(1, threads_n * each + 1))
        assert log.verify().ok
        per_actor = log.count(None, "actor")
        assert per_actor == {f"agent-{i}": each for i in range(threads_n)}

    def test_two_processes_without_the_lock_cannot_fork_the_chain(self, db):
        """Simulates a writer that skips the advisory lock: the DB trigger still refuses the fork."""
        log = log_for(db)
        log.append(ev())
        tail = log.head()
        cols = "(seq, at, event_type, outcome, actor, actor_kind, action, scrubbed, prev_hash, hash)"
        vals = "VALUES (%s, now(), 'TOOL_CALL','ALLOWED','a','agent','b', false, %s, %s)"
        with psycopg.connect(db) as c:
            c.execute(f"INSERT INTO audit_log {cols} {vals}", (2, tail.hash, "1" * 64))
        assert sql_error(db, f"INSERT INTO audit_log {cols} {vals}", (2, tail.hash, "2" * 64))
        assert log.head().seq == 2


class TestFailClosed:
    def test_unreachable_database_raises_audit_unavailable_with_no_detail(self, db):
        bad = AuditLog(PostgresAuditStore(lambda: psycopg.connect(
            "postgresql://nobody:secretpw@127.0.0.1:1/none", connect_timeout=1)))
        with pytest.raises(AuditUnavailable) as e:
            bad.append(ev())
        assert "secretpw" not in str(e.value) and "127.0.0.1" not in str(e.value)

    def test_failed_insert_rolls_back_and_leaves_no_gap(self, db):
        log = log_for(db)
        log.append(ev())
        with psycopg.connect(db) as c:
            c.execute("ALTER TABLE audit_log ADD CONSTRAINT boom CHECK (actor <> 'boom')")
        with pytest.raises(AuditUnavailable):
            log.append(ev(actor="boom"))
        log.append(ev())
        assert [r.seq for r in log.query(AuditQuery(newest_first=False))] == [1, 2] and log.verify().ok


class TestQueryParity:
    def events(self):
        return [
            tool_call("agent-a", "get_report", "ALLOWED", tenant="t1", subject="subtok_1", run_id="r1"),
            tool_call("agent-a", "get_report", "DENIED", tenant="t2", reason_code="CROSS_TENANT", run_id="r1"),
            tool_call("agent-a", "send_sms", "DENIED", reason_code="NO_GRANT", run_id="r2"),
            tool_call("agent-b", "send_sms", "DENIED", reason_code="NO_GRANT"),
            approval("amaka", "send_batch", ref="batch-9"),
            config_change("tunde", "autonomy.level", "A1", "A2", approved_by="amaka"),
        ]

    def both(self, db):
        def new_clock():
            t = [datetime(2026, 11, 8, 9, 0, tzinfo=timezone.utc)]

            def clock():
                t[0] += timedelta(seconds=1)
                return t[0]
            return clock

        pg = AuditLog(PostgresAuditStore(lambda: psycopg.connect(db)), new_clock())
        mem = AuditLog(InMemoryAuditStore(), new_clock())   # identical timestamps in both
        for e in self.events():
            pg.append(e)
            mem.append(e)
        return pg, mem

    def test_same_answers_as_the_in_memory_store(self, db):
        pg, mem = self.both(db)
        rows = pg.query(AuditQuery(newest_first=False))
        queries = [
            AuditQuery(), AuditQuery(outcome=Outcome.DENIED), AuditQuery(actor="agent-a", outcome=Outcome.DENIED),
            AuditQuery(event_type=EventType.APPROVAL), AuditQuery(subject="subtok_1"), AuditQuery(tenant="t2"),
            AuditQuery(run_id="r1"), AuditQuery(reason_code="NO_GRANT"), AuditQuery(limit=2),
            AuditQuery(limit=2, newest_first=False),
            AuditQuery(since=rows[1].at, until=rows[3].at, newest_first=False),
            AuditQuery(since=rows[2].at), AuditQuery(until=rows[2].at),
        ]
        for q in queries:
            assert pg.query(q) == mem.query(q), q
        for g in ("actor", "action", "reason_code", "outcome", "event_type", "tenant"):
            for q in (AuditQuery(), AuditQuery(outcome=Outcome.DENIED), AuditQuery(limit=1)):
                assert pg.count(q, g) == mem.count(q, g), (g, q)

    def test_denials_by_reason_for_product_review(self, db):
        pg, _ = self.both(db)
        assert pg.count(AuditQuery(outcome=Outcome.DENIED), "reason_code") == {"CROSS_TENANT": 1, "NO_GRANT": 2}

    def test_group_by_cannot_inject_sql(self, db):
        pg, _ = self.both(db)
        for bad in ("actor; DROP TABLE audit_log", "details", "1", "actor, hash"):
            with pytest.raises(ValueError):
                pg.count(None, bad)
        store = PostgresAuditStore(lambda: psycopg.connect(db))
        with pytest.raises(ValueError):
            store.count(AuditQuery(), "actor; DROP TABLE audit_log")
        assert pg.verify().checked == 6

    def test_filter_values_are_parameterised(self, db):
        pg, _ = self.both(db)
        assert pg.query(AuditQuery(actor="x' OR '1'='1")) == []
        assert pg.verify().ok


class TestRoles:
    def test_writer_role_can_append_and_read_but_nothing_else(self, db):
        with psycopg.connect(db) as c:
            c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='audit_writer') "
                      "THEN CREATE ROLE audit_writer NOLOGIN; END IF; END $$")
            c.execute("REVOKE ALL ON audit_log FROM PUBLIC")
            c.execute("GRANT INSERT, SELECT ON audit_log TO audit_writer")

        def as_writer():
            conn = psycopg.connect(db)
            conn.execute("SET ROLE audit_writer")
            return conn

        log = AuditLog(PostgresAuditStore(as_writer))
        log.append(ev())
        log.append(ev())
        assert log.verify().ok and len(log.query()) == 2

        for sql in ("UPDATE audit_log SET actor='x'", "DELETE FROM audit_log", "TRUNCATE audit_log",
                    "DROP TRIGGER audit_log_no_change ON audit_log",
                    "ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change",
                    "DROP TABLE audit_log"):
            with pytest.raises(psycopg.Error):
                with as_writer() as c:
                    c.execute(sql)
        assert log.verify().checked == 2
