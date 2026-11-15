from datetime import datetime, timedelta, timezone

import pytest

from audit_logs.audit_log import (
    GENESIS_HASH, REDACTED, ActorKind, Anchor, AuditEvent, AuditLog, AuditQuery, AuditRecord,
    AuditUnavailable, EventType, InMemoryAuditStore, Outcome, approval, config_change,
    looks_like_identifier, scrub_details, tool_call,
)

T0 = datetime(2026, 11, 8, 9, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


def make():
    store = InMemoryAuditStore()
    return AuditLog(store, Clock()), store


def ev(**over):
    base = dict(event_type=EventType.TOOL_CALL, outcome=Outcome.ALLOWED, actor="agent-1", action="get_report")
    base.update(over)
    return AuditEvent(**base)


class TestAppend:
    def test_first_record_chains_from_genesis(self):
        log, _ = make()
        r = log.append(ev())
        assert (r.seq, r.prev_hash) == (1, GENESIS_HASH) and r.hash == r.computed_hash()

    def test_records_chain_and_log_sets_time(self):
        log, _ = make()
        a, b = log.append(ev()), log.append(ev())
        assert (b.seq, b.prev_hash) == (2, a.hash)
        assert b.at > a.at

    def test_caller_cannot_set_time_or_seq(self):
        with pytest.raises(Exception):
            AuditEvent(event_type="TOOL_CALL", outcome="ALLOWED", actor="a", action="b", seq=9)
        with pytest.raises(Exception):
            AuditEvent(event_type="TOOL_CALL", outcome="ALLOWED", actor="a", action="b", at=T0)

    def test_records_are_frozen(self):
        log, _ = make()
        r = log.append(ev())
        with pytest.raises(Exception):
            r.actor = "someone-else"

    def test_empty_actor_or_action_rejected(self):
        with pytest.raises(Exception):
            ev(actor="")
        with pytest.raises(Exception):
            ev(action="")

    def test_store_failure_fails_closed_without_leaking_content(self):
        class Broken(InMemoryAuditStore):
            def append(self, build):
                raise RuntimeError("connection to db at 10.0.0.5 refused")

        with pytest.raises(AuditUnavailable) as e:
            AuditLog(Broken()).append(ev())
        import traceback
        shown = "".join(traceback.format_exception(e.value))   # what a crash log would print
        assert "10.0.0.5" not in shown and "10.0.0.5" not in str(e.value)

    def test_failed_append_leaves_chain_intact(self):
        log, store = make()
        log.append(ev())
        orig = store.append
        store.append = lambda build: (_ for _ in ()).throw(RuntimeError("x"))
        with pytest.raises(AuditUnavailable):
            log.append(ev())
        store.append = orig
        log.append(ev())
        assert log.verify().ok and log.verify().checked == 2


class TestIdentifiers:
    @pytest.mark.parametrize("text", [
        "22123456789", "221 2345 6789", "221-2345-6789", "08031234567", "0803 123 4567",
        "+2348031234567", "2348031234567", "+234 803 123 4567", "+234-803-123-4567",
        "a@b.com", "amaka.o+x@mail.co.ng", "bvn 22123456789 end", "x=22123456789;",
    ])
    def test_detected(self, text):
        assert looks_like_identifier(text)

    @pytest.mark.parametrize("text", [
        "subtok_9f2c4e1a7b3d8c6e5a0b1c2d3e4f5a6b", "NO_GRANT", "run-2026-11-08", "score 580",
        "1234567890", "123456789012", "2026-11-08T09:00:00", "tool_get_report_v2",
        "subtok_22123456789abcdef0",
    ])
    def test_not_flagged(self, text):
        assert not looks_like_identifier(text)

    def test_every_text_field_is_scrubbed_and_flagged(self):
        log, _ = make()
        for name in ("actor", "action", "subject", "tenant", "run_id", "trace_id", "reason_code"):
            kw = {name: "22123456789"}
            r = log.append(ev(**kw))
            assert getattr(r, name) == REDACTED and r.scrubbed, name
            assert "22123456789" not in r.payload()

    def test_details_scrubbed_including_int_values_and_keys(self):
        d, changed = scrub_details({"bvn": 22123456789, "note": "call 08031234567", "ok": 5, "Bad Key": "x"})
        assert changed and d == {"bvn": REDACTED, "note": REDACTED, "ok": 5}

    def test_clean_record_is_not_flagged(self):
        log, _ = make()
        assert not log.append(ev(subject="subtok_abc", details={"n": 3, "flag": True, "x": None})).scrubbed

    def test_nested_and_unknown_types_are_not_stored(self):
        d, changed = scrub_details({"a": {"bvn": "22123456789"}, "b": [1], "c": object()})
        assert changed and set(d.values()) == {"[NON_SCALAR]"}
        assert "22123456789" not in str(d)

    def test_long_values_truncated_and_flagged(self):
        d, changed = scrub_details({"k": "x" * 500})
        assert changed and len(d["k"]) == 200

    def test_too_many_keys_capped(self):
        d, changed = scrub_details({f"k{i}": i for i in range(50)})
        assert changed and len(d) == 20

    def test_floats_become_text(self):
        d, _ = scrub_details({"score": 0.82})
        assert d == {"score": "0.82"}


class TestVerify:
    def fill(self, n=5):
        log, store = make()
        for i in range(n):
            log.append(ev(details={"i": i}))
        return log, store

    def test_clean_chain_ok(self):
        log, _ = self.fill()
        assert log.verify().ok and log.verify(batch=2).checked == 5

    def test_empty_log_ok(self):
        log, _ = make()
        assert log.verify().ok and log.head() is None

    def test_edited_record_detected(self):
        log, store = self.fill()
        store._rows[2] = store._rows[2].model_copy(update={"outcome": Outcome.DENIED})
        r = log.verify()
        assert (r.ok, r.problem, r.bad_seq) == (False, "HASH_MISMATCH", 3)

    def test_deleted_middle_record_detected(self):
        log, store = self.fill()
        del store._rows[2]
        assert log.verify().problem == "SEQ_GAP"

    def test_reordered_records_detected(self):
        log, store = self.fill()
        store._rows[1], store._rows[2] = store._rows[2], store._rows[1]
        assert not log.verify().ok

    def test_inserted_forged_record_detected(self):
        log, store = self.fill()
        forged = store._rows[1].model_copy(update={"actor": "mallory"})
        store._rows[1] = forged.model_copy(update={"hash": forged.computed_hash()})
        r = log.verify()
        assert (r.problem, r.bad_seq) == ("PREV_HASH_MISMATCH", 3)

    def test_full_rewrite_is_caught_only_by_an_anchor(self):
        log, store = self.fill()
        anchor = log.head()
        prev = GENESIS_HASH
        for i, rec in enumerate(store._rows):
            rec = rec.model_copy(update={"actor": "mallory", "prev_hash": prev})
            rec = rec.model_copy(update={"hash": rec.computed_hash()})
            store._rows[i], prev = rec, rec.hash
        assert log.verify().ok                                 # honest limit
        r = log.verify(anchor=anchor)
        assert (r.problem, r.bad_seq) == ("ANCHOR_MISMATCH", 5)

    def test_truncation_caught_only_by_an_anchor(self):
        log, store = self.fill()
        anchor = log.head()
        del store._rows[-2:]
        assert log.verify().ok
        assert log.verify(anchor=anchor).problem == "ANCHOR_MISSING"

    def test_anchor_still_valid_after_more_appends(self):
        log, _ = self.fill(3)
        anchor = log.head()
        log.append(ev())
        assert log.verify(anchor=anchor).ok

    def test_head_matches_last_record(self):
        log, store = self.fill()
        assert log.head() == Anchor(seq=5, hash=store._rows[-1].hash)

    def test_timestamp_is_covered_by_the_hash(self):
        log, store = self.fill(2)
        store._rows[0] = store._rows[0].model_copy(update={"at": store._rows[0].at + timedelta(days=1)})
        assert log.verify().problem == "HASH_MISMATCH"

    def test_details_are_covered_by_the_hash(self):
        log, store = self.fill(2)
        store._rows[0] = store._rows[0].model_copy(update={"details": {"i": 99}})
        assert log.verify().problem == "HASH_MISMATCH"

    def test_scrubbed_flag_is_covered_by_the_hash(self):
        log, store = self.fill(2)
        store._rows[0] = store._rows[0].model_copy(update={"scrubbed": True})
        assert log.verify().problem == "HASH_MISMATCH"


class TestQueryAndCount:
    def setup_method(self):
        self.log, _ = make()
        L = self.log
        L.append(tool_call("agent-a", "get_report", "ALLOWED", tenant="t1", subject="subtok_1"))
        L.append(tool_call("agent-a", "get_report", "DENIED", tenant="t2", reason_code="CROSS_TENANT"))
        L.append(tool_call("agent-a", "send_sms", "DENIED", reason_code="NO_GRANT"))
        L.append(tool_call("agent-b", "send_sms", "DENIED", reason_code="NO_GRANT"))
        L.append(approval("amaka", "send_batch", ref="batch-9"))
        L.append(config_change("tunde", "autonomy.level", "A1", "A2", approved_by="amaka"))

    def test_filters(self):
        q = self.log.query
        assert len(q(AuditQuery(outcome=Outcome.DENIED))) == 3
        assert len(q(AuditQuery(actor="agent-a", outcome=Outcome.DENIED))) == 2
        assert len(q(AuditQuery(event_type=EventType.APPROVAL))) == 1
        assert len(q(AuditQuery(subject="subtok_1"))) == 1
        assert len(q(AuditQuery(tenant="t2"))) == 1

    def test_time_window_since_inclusive_until_exclusive(self):
        rows = self.log.query(AuditQuery(newest_first=False))
        lo, hi = rows[1].at, rows[3].at
        got = self.log.query(AuditQuery(since=lo, until=hi, newest_first=False))
        assert [r.seq for r in got] == [2, 3]

    def test_order_and_limit(self):
        assert [r.seq for r in self.log.query(AuditQuery(limit=2))] == [6, 5]
        assert [r.seq for r in self.log.query(AuditQuery(limit=2, newest_first=False))] == [1, 2]

    def test_count_denials_by_reason_for_product_review(self):
        got = self.log.count(AuditQuery(outcome=Outcome.DENIED), "reason_code")
        assert got == {"CROSS_TENANT": 1, "NO_GRANT": 2}

    def test_count_by_actor_drives_the_spike_alert(self):
        got = self.log.count(AuditQuery(outcome=Outcome.DENIED), "actor")
        assert got == {"agent-a": 2, "agent-b": 1}

    def test_count_ignores_limit(self):
        assert sum(self.log.count(AuditQuery(limit=1), "outcome").values()) == 6

    def test_count_rejects_unknown_group(self):
        with pytest.raises(ValueError):
            self.log.count(None, "details")

    def test_missing_values_grouped_as_none(self):
        assert self.log.count(AuditQuery(event_type=EventType.APPROVAL), "tenant") == {"(none)": 1}

    def test_limit_bounds(self):
        for bad in (0, 10_001):
            with pytest.raises(Exception):
                AuditQuery(limit=bad)


class TestConstructors:
    def test_tool_call_denial(self):
        e = tool_call("a", "send_sms", "DENIED", reason_code="NO_GRANT", attempts=2)
        assert (e.event_type, e.outcome, e.action, e.details) == (EventType.TOOL_CALL, Outcome.DENIED, "send_sms", {"attempts": 2})

    def test_approval_records_who_what_when(self):
        log, _ = make()
        r = log.append(approval("amaka", "send_batch", ref="batch-9"))
        assert (r.actor, r.actor_kind, r.action, r.details["ref"]) == ("amaka", ActorKind.HUMAN, "send_batch", "batch-9")
        assert r.at == T0 + timedelta(seconds=1)

    def test_config_change_keeps_old_and_new_and_approver(self):
        log, _ = make()
        r = log.append(config_change("tunde", "threshold.low_score", 550, 560, approved_by="amaka"))
        assert r.details == {"old": 550, "new": 560, "approved_by": "amaka"} and r.event_type == EventType.CONFIG_CHANGE
