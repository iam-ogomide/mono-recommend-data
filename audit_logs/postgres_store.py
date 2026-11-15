"""PostgreSQL store for the audit log. Works with psycopg 3.

    store = PostgresAuditStore(lambda: psycopg.connect(DSN))
    log = AuditLog(store)

Every call opens its own connection from the factory (use a pool's connection() in production).
Writers are serialised with a transaction-level advisory lock, so two processes cannot fork the
chain. The schema's chain trigger is the second line of defence.
"""
from __future__ import annotations

import json
from typing import Any, Callable

if __package__:
    from .audit_log import (
        GENESIS_HASH, GROUP_BY, AuditQuery, AuditRecord, AuditUnavailable,
    )
else:
    from audit_log import (
        GENESIS_HASH, GROUP_BY, AuditQuery, AuditRecord, AuditUnavailable,
    )

# Any fixed number. Change it only if another part of the system already uses this one.
CHAIN_LOCK_KEY = 0x41554449544C4F47  # "AUDITLOG"

_COLS = ("seq, at, event_type, outcome, actor, actor_kind, action, subject, tenant, run_id, "
         "trace_id, reason_code, details, scrubbed, prev_hash, hash")


def _row_to_record(row: tuple) -> AuditRecord:
    (seq, at, event_type, outcome, actor, actor_kind, action, subject, tenant, run_id,
     trace_id, reason_code, details, scrubbed, prev_hash, hash_) = row
    if isinstance(details, str):
        details = json.loads(details)
    return AuditRecord(
        seq=seq, at=at, event_type=event_type, outcome=outcome, actor=actor, actor_kind=actor_kind,
        action=action, subject=subject, tenant=tenant, run_id=run_id, trace_id=trace_id,
        reason_code=reason_code, details=details, scrubbed=scrubbed,
        prev_hash=prev_hash.strip(), hash=hash_.strip(),
    )


def _where(q: AuditQuery) -> tuple[str, list[Any]]:
    clauses, params = [], []
    for col in ("event_type", "outcome", "actor", "action", "subject", "tenant", "run_id", "reason_code"):
        value = getattr(q, col)
        if value is not None:
            clauses.append(f"{col} = %s")
            params.append(getattr(value, "value", value))
    if q.since is not None:
        clauses.append("at >= %s")
        params.append(q.since)
    if q.until is not None:
        clauses.append("at < %s")
        params.append(q.until)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


class PostgresAuditStore:
    def __init__(self, connect: Callable[[], Any]):
        self._connect = connect

    def append(self, build: Callable[[int, str], AuditRecord]) -> AuditRecord:
        # The connection context manager commits on success and rolls back on any error.
        with self._connect() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (CHAIN_LOCK_KEY,))
            last = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last[0] + 1, last[1].strip()) if last else (1, GENESIS_HASH)
            rec = build(seq, prev)
            conn.execute(
                f"INSERT INTO audit_log ({_COLS}) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)",
                (rec.seq, rec.at, rec.event_type.value, rec.outcome.value, rec.actor, rec.actor_kind.value,
                 rec.action, rec.subject, rec.tenant, rec.run_id, rec.trace_id, rec.reason_code,
                 json.dumps(rec.details), rec.scrubbed, rec.prev_hash, rec.hash),
            )
            return rec

    def tail(self) -> tuple[int, str] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1].strip()) if row else None

    def read(self, after_seq: int, limit: int) -> list[AuditRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_COLS} FROM audit_log WHERE seq > %s ORDER BY seq ASC LIMIT %s",
                (after_seq, limit)).fetchall()
        return [_row_to_record(r) for r in rows]

    def query(self, q: AuditQuery) -> list[AuditRecord]:
        where, params = _where(q)
        order = "DESC" if q.newest_first else "ASC"
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_COLS} FROM audit_log{where} ORDER BY seq {order} LIMIT %s",
                (*params, q.limit)).fetchall()
        return [_row_to_record(r) for r in rows]

    def count(self, q: AuditQuery, group_by: str) -> dict[str, int]:
        if group_by not in GROUP_BY:  # whitelist: the column name is interpolated into SQL
            raise ValueError(f"group_by must be one of {sorted(GROUP_BY)}")
        where, params = _where(q)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT COALESCE({group_by}, '(none)'), count(*) FROM audit_log{where} GROUP BY 1",
                params).fetchall()
        return {k: int(n) for k, n in rows}
