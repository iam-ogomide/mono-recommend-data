"""Verify the PII vault sends events to the shared audit log."""
import os

import pytest

from audit_logs.audit_log import AuditLog, AuditQuery, AuditUnavailable, EventType, InMemoryAuditStore, Outcome
from audit_logs.vault_bridge import VaultAuditSink
from vault import (  # noqa: E402
    Caller, Grant, LocalKeyProvider, InMemoryVaultStore, PiiField, Vault, VaultAccessDenied,
    VaultPolicy, VaultUnavailable,
)

BVN = "22123456789"
GW = Caller("creditchek-gateway", trace_id="trace-1")


def build(store=None):
    log = AuditLog(store or InMemoryAuditStore())
    vault = Vault(
        InMemoryVaultStore(), LocalKeyProvider({"v1": os.urandom(32)}, "v1"), os.urandom(32),
        VaultAuditSink(log),
        VaultPolicy(
            writers=frozenset({"onboarding"}), erasers=frozenset({"admin"}),
            grants=[Grant(caller="creditchek-gateway", fields=frozenset({PiiField.BVN}), purposes=frozenset({"bureau_pull"})),
                    Grant(caller="support", fields=frozenset({PiiField.BVN}), purposes=frozenset({"ticket"}), masked_only=True)]),
    )
    return vault, log


def rows(log):
    return log.query(AuditQuery(newest_first=False))


def test_full_lifecycle_lands_in_the_audit_log_and_the_chain_verifies():
    vault, log = build()
    token = vault.tokenize(Caller("onboarding"), bvn=BVN).token
    vault.resolve(GW, token, PiiField.BVN, purpose="bureau_pull")
    vault.read_masked(Caller("support"), token, PiiField.BVN, purpose="ticket")
    vault.erase(Caller("admin"), token, reason="DSAR_ERASURE")
    got = [(r.event_type, r.action, r.outcome, r.actor) for r in rows(log)]
    assert got == [
        (EventType.VAULT_ADMIN, "TOKENIZE", Outcome.ALLOWED, "onboarding"),
        (EventType.UNMASK, "RESOLVE", Outcome.ALLOWED, "creditchek-gateway"),
        (EventType.UNMASK, "READ_MASKED", Outcome.ALLOWED, "support"),
        (EventType.VAULT_ADMIN, "ERASE", Outcome.ALLOWED, "admin"),
    ]
    assert log.verify().ok


def test_unmask_event_records_who_why_which_field_and_trace_but_no_value():
    vault, log = build()
    token = vault.tokenize(Caller("onboarding"), bvn=BVN).token
    vault.resolve(GW, token, PiiField.BVN, purpose="bureau_pull")
    r = log.query(AuditQuery(event_type=EventType.UNMASK))[0]
    assert (r.subject, r.trace_id, r.details) == (token, "trace-1", {"pii_field": "bvn", "purpose": "bureau_pull"})
    assert not r.scrubbed                      # the vault already keeps values out; nothing needed redacting
    assert BVN not in "".join(x.payload() for x in rows(log))


def test_denied_attempts_are_recorded_with_reason():
    vault, log = build()
    token = vault.tokenize(Caller("onboarding"), bvn=BVN).token
    with pytest.raises(VaultAccessDenied):
        vault.resolve(Caller("recommendation-agent"), token, PiiField.BVN, purpose="bureau_pull")
    with pytest.raises(VaultAccessDenied):
        vault.resolve(Caller("support"), token, PiiField.BVN, purpose="ticket")   # masked_only grant
    denied = log.query(AuditQuery(outcome=Outcome.DENIED, newest_first=False))
    assert [(r.actor, r.action) for r in denied] == [("recommendation-agent", "RESOLVE"), ("support", "RESOLVE")]
    assert all(r.reason_code for r in denied)
    assert log.count(AuditQuery(outcome=Outcome.DENIED), "actor") == {"recommendation-agent": 1, "support": 1}


def test_if_the_audit_log_is_down_the_vault_returns_nothing():
    class Down(InMemoryAuditStore):
        broken = False

        def append(self, build):
            if self.broken:
                raise AuditUnavailable()
            return super().append(build)

    store = Down()
    vault, log = build(store)
    token = vault.tokenize(Caller("onboarding"), bvn=BVN).token
    store.broken = True
    with pytest.raises(VaultUnavailable):
        vault.resolve(GW, token, PiiField.BVN, purpose="bureau_pull")
    with pytest.raises(VaultUnavailable):
        vault.tokenize(Caller("onboarding"), bvn="22987654321")
    store.broken = False
    assert vault.resolve(GW, token, PiiField.BVN, purpose="bureau_pull") == BVN   # fine again once it is back


def test_a_denial_is_still_a_denial_when_the_log_is_down():
    class Down(InMemoryAuditStore):
        def append(self, build):
            raise AuditUnavailable()

    vault, _ = build(Down())
    with pytest.raises(VaultAccessDenied):
        vault.resolve(Caller("nobody"), "subtok_" + "0" * 32, PiiField.BVN, purpose="x")


def test_works_on_postgres_too():
    psycopg = pytest.importorskip("psycopg")
    pgserver = pytest.importorskip("pixeltable_pgserver")
    import tempfile
    from pathlib import Path
    from audit_logs.postgres_store import PostgresAuditStore
    with tempfile.TemporaryDirectory() as d:
        srv = pgserver.get_server(d, cleanup_mode="stop")
        try:
            dsn = srv.get_uri()
            with psycopg.connect(dsn) as c:
                c.execute((Path(__file__).parent / "audit_schema.sql").read_text())
            vault, log = build(PostgresAuditStore(lambda: psycopg.connect(dsn)))
            token = vault.tokenize(Caller("onboarding"), bvn=BVN).token
            vault.resolve(GW, token, PiiField.BVN, purpose="bureau_pull")
            assert [r.action for r in rows(log)] == ["TOKENIZE", "RESOLVE"] and log.verify().ok
        finally:
            srv.cleanup()
