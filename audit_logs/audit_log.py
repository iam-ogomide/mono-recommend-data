"""Audit log
===========
The append-only record of what the system did and who allowed it: tool calls and their
denials, approvals, config changes, and unmask events (anything that reveals a real identifier).

What this module guarantees
  - Append only. There is no update or delete anywhere in this API.
  - Tamper evident. Every record carries the hash of the one before it, so an edit, a deleted
    row or a reordering is found by verify(). An edit that also recomputes every later hash
    is only found if you compare against an anchor saved somewhere the database admin cannot
    write (see "Limits").
  - Fail closed. append() raises AuditUnavailable if the record was not durably stored, and the
    caller must then not do the thing it was about to record.
  - No identifiers. Every string is checked for BVN, NIN, phone and email shapes before it is
    stored. A match is replaced with [REDACTED] and the record is flagged `scrubbed`. The log
    keeps the row instead of losing it. Records hold subscriber TOKENS, never real values.
  - The log sets the time and the sequence number. Callers cannot backdate or reorder.

Limits (read this)
  - The identifier check is a safety net, not a guarantee. It catches the common shapes. The
    real protection is that callers pass codes and tokens, never raw values.
  - The chain proves the log was not changed by someone who did not recompute it. Someone with
    full write access who rewrites the chain from some point on can recompute it. To catch that,
    save head() somewhere they cannot write (a separate account, a signed daily message, object
    storage with a retention lock) and pass it to verify(anchor=...). Without an anchor,
    deleting the last N rows is also invisible.
  - The chain is serialised: one writer at a time. Fine for a daily cycle and chat traffic. If
    volume grows past a few hundred events a second, shard the chain per source.
  - Because the log holds only tokens, erasing a subscriber in the vault leaves nothing here
    that can be linked back to them. The audit log never needs deleting for erasure requests.
    Retention is not specified in the architecture document and is not enforced here.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol

from pydantic import BaseModel, ConfigDict, Field

GENESIS_HASH = "0" * 64
MAX_FIELD = 64
MAX_VALUE = 200
MAX_DETAIL_KEYS = 20
REDACTED = "[REDACTED]"
NON_SCALAR = "[NON_SCALAR]"

GROUP_BY = frozenset({"actor", "action", "reason_code", "outcome", "event_type", "tenant"})


# ======================================================================
# EVENTS
# ======================================================================

class EventType(str, Enum):
    TOOL_CALL = "TOOL_CALL"          # an agent or service called a tool (denials are outcome=DENIED)
    APPROVAL = "APPROVAL"            # a human approved or rejected an action
    CONFIG_CHANGE = "CONFIG_CHANGE"  # a threshold, plan list or stop switch changed
    UNMASK = "UNMASK"                # a real identifier (or its last four) was revealed
    VAULT_ADMIN = "VAULT_ADMIN"      # tokenize, set field, erase, key rotation


class Outcome(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    ERROR = "ERROR"


class ActorKind(str, Enum):
    AGENT = "agent"
    SERVICE = "service"
    HUMAN = "human"


class AuditUnavailable(Exception):
    """The record could not be durably stored. Never carries content, only a code."""

    def __init__(self, reason: str = "AUDIT_STORE_UNAVAILABLE"):
        super().__init__(reason)
        self.reason = reason


class AuditEvent(BaseModel):
    """What a caller submits. The log adds the time, sequence number and hashes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_type: EventType
    outcome: Outcome
    actor: str = Field(min_length=1)
    actor_kind: ActorKind = ActorKind.SERVICE
    action: str = Field(min_length=1)            # tool name, "resolve", a config key, ...
    subject: str | None = None                   # subscriber TOKEN, never a real identifier
    tenant: str | None = None
    run_id: str | None = None
    trace_id: str | None = None
    reason_code: str | None = None               # short code such as NO_GRANT, not free text
    details: dict[str, Any] = {}                 # flat: str, int, bool, None. Floats become text.


class AuditRecord(BaseModel):
    """What is stored. Frozen: the only way to change a record is to write a new one."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int
    at: datetime
    event_type: EventType
    outcome: Outcome
    actor: str
    actor_kind: ActorKind
    action: str
    subject: str | None
    tenant: str | None
    run_id: str | None
    trace_id: str | None
    reason_code: str | None
    details: dict[str, str | int | bool | None]
    scrubbed: bool                               # True if anything was redacted, dropped or cut
    prev_hash: str
    hash: str

    def payload(self) -> str:
        """The exact text that is hashed. Changing this breaks every existing chain."""
        body = self.model_dump(mode="json", exclude={"hash"})
        body["at"] = self.at.astimezone(timezone.utc).isoformat(timespec="microseconds")
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def computed_hash(self) -> str:
        return hashlib.sha256(self.payload().encode()).hexdigest()


class Anchor(BaseModel):
    """A point in the chain, saved somewhere the database admin cannot write."""

    model_config = ConfigDict(frozen=True)
    seq: int
    hash: str


class VerifyReport(BaseModel):
    ok: bool
    checked: int
    problem: str | None = None   # SEQ_GAP PREV_HASH_MISMATCH HASH_MISMATCH ANCHOR_MISMATCH ANCHOR_MISSING
    bad_seq: int | None = None


class AuditQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: EventType | None = None
    outcome: Outcome | None = None
    actor: str | None = None
    action: str | None = None
    subject: str | None = None
    tenant: str | None = None
    run_id: str | None = None
    reason_code: str | None = None
    since: datetime | None = None    # inclusive
    until: datetime | None = None    # exclusive
    limit: int = Field(default=1000, ge=1, le=10_000)   # applies to query(), not count()
    newest_first: bool = True


# ======================================================================
# KEEPING IDENTIFIERS OUT
# ======================================================================

_KEY = re.compile(r"[a-z][a-z0-9_]{0,39}")
# 11 digits, optionally separated by single spaces or dashes (BVN, NIN, 0-prefixed phones).
# The boundary rules mean the hex digits inside a subtok_ token can never match.
_DIGITS_11 = re.compile(r"(?<![0-9A-Za-z])(?:\d[ -]?){10}\d(?![0-9A-Za-z])")
_PHONE_INTL = re.compile(r"(?<![0-9A-Za-z])\+?234[789]\d{9}(?![0-9A-Za-z])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SEPARATORS = re.compile(r"(?<=\d)[ ()\-.]+(?=[\d(])")


def looks_like_identifier(text: str) -> bool:
    if _DIGITS_11.search(text) or _EMAIL.search(text):
        return True
    return bool(_PHONE_INTL.search(_SEPARATORS.sub("", text)))


def _clean_text(value: Any, limit: int) -> tuple[str, bool]:
    text = str(value)
    if looks_like_identifier(text):
        return REDACTED, True
    if len(text) > limit:
        return text[:limit], True
    return text, False


def _clean_optional(value: str | None, limit: int = MAX_FIELD) -> tuple[str | None, bool]:
    return (None, False) if value is None else _clean_text(value, limit)


def scrub_details(details: dict[str, Any]) -> tuple[dict[str, str | int | bool | None], bool]:
    """Flat scalar dict only. Returns (clean, changed)."""
    clean: dict[str, str | int | bool | None] = {}
    changed = False
    items = list(details.items())
    if len(items) > MAX_DETAIL_KEYS:
        items, changed = items[:MAX_DETAIL_KEYS], True
    for key, value in items:
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            changed = True
            continue
        if value is None or isinstance(value, bool):
            clean[key] = value
        elif isinstance(value, int):
            if looks_like_identifier(str(value)):
                clean[key], changed = REDACTED, True
            else:
                clean[key] = value
        elif isinstance(value, (str, float)):
            clean[key], was = _clean_text(value, MAX_VALUE)
            changed = changed or was
        else:
            clean[key], changed = NON_SCALAR, True
    return clean, changed


# ======================================================================
# STORAGE
# ======================================================================

class AuditStore(Protocol):
    def append(self, build: Callable[[int, str], AuditRecord]) -> AuditRecord:
        """ATOMIC: read the tail, call build(next_seq, prev_hash) while no other writer can
        append, save the result, return it. Raise if it was not durably saved."""
        ...

    def tail(self) -> tuple[int, str] | None: ...
    def read(self, after_seq: int, limit: int) -> list[AuditRecord]: ...
    def query(self, q: AuditQuery) -> list[AuditRecord]: ...
    def count(self, q: AuditQuery, group_by: str) -> dict[str, int]: ...


def matches(rec: AuditRecord, q: AuditQuery) -> bool:
    return (
        (q.event_type is None or rec.event_type == q.event_type)
        and (q.outcome is None or rec.outcome == q.outcome)
        and (q.actor is None or rec.actor == q.actor)
        and (q.action is None or rec.action == q.action)
        and (q.subject is None or rec.subject == q.subject)
        and (q.tenant is None or rec.tenant == q.tenant)
        and (q.run_id is None or rec.run_id == q.run_id)
        and (q.reason_code is None or rec.reason_code == q.reason_code)
        and (q.since is None or rec.at >= q.since)
        and (q.until is None or rec.at < q.until)
    )


class InMemoryAuditStore:
    """Tests and demos. Same semantics as the Postgres store."""

    def __init__(self):
        self._lock = threading.Lock()
        self._rows: list[AuditRecord] = []

    def append(self, build: Callable[[int, str], AuditRecord]) -> AuditRecord:
        with self._lock:
            seq, prev = (self._rows[-1].seq + 1, self._rows[-1].hash) if self._rows else (1, GENESIS_HASH)
            rec = build(seq, prev)
            self._rows.append(rec)
            return rec

    def tail(self) -> tuple[int, str] | None:
        with self._lock:
            return (self._rows[-1].seq, self._rows[-1].hash) if self._rows else None

    def read(self, after_seq: int, limit: int) -> list[AuditRecord]:
        with self._lock:
            return [r for r in self._rows if r.seq > after_seq][:limit]

    def query(self, q: AuditQuery) -> list[AuditRecord]:
        with self._lock:
            hits = [r for r in self._rows if matches(r, q)]
        hits.sort(key=lambda r: r.seq, reverse=q.newest_first)
        return hits[: q.limit]

    def count(self, q: AuditQuery, group_by: str) -> dict[str, int]:
        with self._lock:
            hits = [r for r in self._rows if matches(r, q)]
        out: dict[str, int] = {}
        for r in hits:
            value = getattr(r, group_by)
            key = "(none)" if value is None else getattr(value, "value", value)
            out[key] = out.get(key, 0) + 1
        return out


# ======================================================================
# THE LOG
# ======================================================================

class AuditLog:
    def __init__(self, store: AuditStore, clock: Callable[[], datetime] | None = None):
        self._store = store
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def append(self, event: AuditEvent) -> AuditRecord:
        """Store one event. Raises AuditUnavailable if it was not durably saved."""
        changed = False
        text: dict[str, str | None] = {}
        for name in ("actor", "action", "subject", "tenant", "run_id", "trace_id", "reason_code"):
            text[name], was = _clean_optional(getattr(event, name))
            changed = changed or was
        details, was = scrub_details(event.details)
        changed = changed or was

        def build(seq: int, prev_hash: str) -> AuditRecord:
            draft = AuditRecord(
                seq=seq, at=self._clock().astimezone(timezone.utc),
                event_type=event.event_type, outcome=event.outcome, actor_kind=event.actor_kind,
                details=details, scrubbed=changed, prev_hash=prev_hash, hash="", **text,
            )
            return draft.model_copy(update={"hash": draft.computed_hash()})

        try:
            return self._store.append(build)
        except AuditUnavailable:
            raise
        except Exception:
            raise AuditUnavailable("AUDIT_STORE_UNAVAILABLE") from None

    def head(self) -> Anchor | None:
        """The current end of the chain. Save it somewhere the database admin cannot write."""
        tail = self._store.tail()
        return Anchor(seq=tail[0], hash=tail[1]) if tail else None

    def verify(self, anchor: Anchor | None = None, batch: int = 1000) -> VerifyReport:
        expected_seq, prev, checked, after = 1, GENESIS_HASH, 0, 0
        anchor_seen = anchor is None

        def bad(problem: str, seq: int | None) -> VerifyReport:
            return VerifyReport(ok=False, checked=checked, problem=problem, bad_seq=seq)

        while True:
            rows = self._store.read(after, batch)
            if not rows:
                break
            for rec in rows:
                if rec.seq != expected_seq:
                    return bad("SEQ_GAP", rec.seq)
                if rec.prev_hash != prev:
                    return bad("PREV_HASH_MISMATCH", rec.seq)
                if rec.hash != rec.computed_hash():
                    return bad("HASH_MISMATCH", rec.seq)
                if anchor is not None and rec.seq == anchor.seq:
                    if rec.hash != anchor.hash:
                        return bad("ANCHOR_MISMATCH", rec.seq)
                    anchor_seen = True
                prev, expected_seq, checked = rec.hash, expected_seq + 1, checked + 1
            after = rows[-1].seq
        if not anchor_seen:
            return bad("ANCHOR_MISSING", anchor.seq)
        return VerifyReport(ok=True, checked=checked)

    def query(self, q: AuditQuery | None = None) -> list[AuditRecord]:
        return self._store.query(q or AuditQuery())

    def count(self, q: AuditQuery | None, group_by: str) -> dict[str, int]:
        """For example denials by reason code in the last day, or by actor, to drive an alert."""
        if group_by not in GROUP_BY:
            raise ValueError(f"group_by must be one of {sorted(GROUP_BY)}")
        return self._store.count(q or AuditQuery(), group_by)


# ======================================================================
# CONSTRUCTORS FOR THE COMMON EVENTS
# ======================================================================

def tool_call(actor: str, tool: str, outcome: Outcome | str, *, actor_kind: ActorKind | str = ActorKind.AGENT,
              subject: str | None = None, tenant: str | None = None, run_id: str | None = None,
              trace_id: str | None = None, reason_code: str | None = None, **details: Any) -> AuditEvent:
    """An agent called a tool. Use outcome DENIED with a reason_code for a refusal."""
    return AuditEvent(event_type=EventType.TOOL_CALL, outcome=Outcome(outcome), actor=actor,
                      actor_kind=ActorKind(actor_kind), action=tool, subject=subject, tenant=tenant,
                      run_id=run_id, trace_id=trace_id, reason_code=reason_code, details=details)


def approval(approver: str, action: str, *, outcome: Outcome | str = Outcome.ALLOWED,
             subject: str | None = None, ref: str | None = None, run_id: str | None = None,
             trace_id: str | None = None, **details: Any) -> AuditEvent:
    """Who approved what. `approver` is the person, `action` is what they approved."""
    return AuditEvent(event_type=EventType.APPROVAL, outcome=Outcome(outcome), actor=approver,
                      actor_kind=ActorKind.HUMAN, action=action, subject=subject, run_id=run_id,
                      trace_id=trace_id, details={"ref": ref, **details} if ref else details)


def config_change(actor: str, key: str, old: Any, new: Any, *, approved_by: str | None = None,
                  reason_code: str | None = None, trace_id: str | None = None) -> AuditEvent:
    """A threshold, plan list or stop switch changed. Never put secrets in old or new."""
    return AuditEvent(event_type=EventType.CONFIG_CHANGE, outcome=Outcome.ALLOWED, actor=actor,
                      actor_kind=ActorKind.HUMAN, action=key, reason_code=reason_code, trace_id=trace_id,
                      details={"old": old, "new": new, "approved_by": approved_by})
