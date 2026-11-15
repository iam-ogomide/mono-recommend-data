"""Runs the REAL recommendation runner with the vault behind it.

Needs your repo on the path and its dependencies installed (pymongo, python-dotenv, pydantic):
    RECO_ENGINE_DIR=/path/to/recommendation-engine python -m pytest test_integration_repo.py
Skipped when RECO_ENGINE_DIR is not set.

NOTE: on master, core.BureauSnapshot is missing `flags: list[str] = []`, which makes the runner's
own demo fail for every subscriber with AttributeError. These tests need that one-line fix.
"""
import os
import sys
import base64
from datetime import date, datetime

import pytest

REPO = os.environ.get("RECO_ENGINE_DIR")
if not REPO:
    pytest.skip("set RECO_ENGINE_DIR to run the repo integration tests", allow_module_level=True)
sys.path.insert(0, REPO)

runner = pytest.importorskip("runner")
credit = pytest.importorskip("credit")

from .test_adapter import FakeCollection  # noqa: E402
from .test_mongo_store import FakeMongoCollection  # noqa: E402
from audit_logs import AuditLog, InMemoryAuditStore  # noqa: E402
from vault import (  # noqa: E402
    Caller, Grant, InMemoryAudit, InMemoryVaultStore, LocalKeyProvider, PiiField, Vault,
    VaultPolicy,
)
from vault.vault_adapter import VaultLookup, make_mongo_token_resolver, migrate_subscribers  # noqa: E402

BVNS = {"SUB-A": "22123456789", "SUB-B": "22987654321", "SUB-E": "22555555555"}
RUN_DATE = date(2026, 10, 23)
GATEWAY = Caller("creditchek-gateway")


class SpyReportService:
    """Keyed by BVN like the real one, and remembers every BVN it was called with."""

    def __init__(self, reports):
        self._inner = runner.FakeReportService(reports)
        self.seen: list[str] = []

    def pull(self, bvn):
        self.seen.append(bvn)
        return self._inner.pull(bvn)


def build(grants=None, migrate=True):
    audit = InMemoryAudit()
    vault = Vault(
        InMemoryVaultStore(), LocalKeyProvider({"v1": os.urandom(32)}, "v1"), os.urandom(32), audit,
        VaultPolicy(
            writers=frozenset({"migration-job"}),
            grants=grants if grants is not None else [
                Grant(caller="creditchek-gateway", fields=frozenset({PiiField.BVN}),
                      purposes=frozenset({"bureau_pull"}))],
        ),
    )
    rows = [{"subscriber_id": sid, "plan": "PRO", "subscription_status": "active",
             "cycle_day": 23, "bvn": bvn} for sid, bvn in BVNS.items()]
    rows.append({"subscriber_id": "SUB-NEW", "plan": "PRO", "subscription_status": "active",
                 "cycle_day": 23})  # never had a BVN on file
    coll = FakeCollection(rows)
    if migrate:
        migrate_subscribers(coll, vault, Caller("migration-job"), write=True)

    snapshots = credit.InMemorySnapshotStore()
    from core import BureauSnapshot
    snapshots.save(BureauSnapshot(subscriber_id="SUB-A", bureau="FIRST_CENTRAL",
                                  snapshot_date=date(2026, 9, 23), score=650))
    report = SpyReportService({
        BVNS["SUB-A"]: {"score": 580, "non_performing_count": 0, "bureau": "FIRST_CENTRAL"},
        BVNS["SUB-B"]: {"score": 720, "non_performing_count": 1, "bureau": "FIRST_CENTRAL"},
        # SUB-E's report is missing on purpose, as in the repo's own demo
    })
    recs, log = runner.InMemoryRecommendationStore(), runner.InMemoryDecisionLog()
    deps = runner.RunnerDeps(
        subscribers=runner.FakeSubscriberSource([
            {k: v for k, v in r.items() if k != "bvn"} for r in rows]),  # Step 1 never sees a BVN
        lookup=VaultLookup(vault, make_mongo_token_resolver(coll), GATEWAY),
        report_service=report, snapshots=snapshots,
        repayments=runner.StubRepaymentSource({}),
        recommendations=recs, decision_log=log, llm=runner.FakeLLM(),
    )
    return deps, report, recs, audit, coll


def by_id(summary):
    return {r.subscriber_id: r for r in summary.rows}


def test_runner_works_unchanged_through_the_vault():
    deps, report, recs, audit, _ = build()
    summary = runner.run_daily(RUN_DATE, deps)
    rows = by_id(summary)
    assert rows["SUB-A"].outcome.value == "SENT"
    assert set(rows["SUB-A"].triggers_sent) == {"SCORE_DROP", "LOW_SCORE"}
    assert rows["SUB-B"].outcome.value == "SENT"
    assert rows["SUB-E"].reasons == ["REPORT_SERVICE_ERROR:RuntimeError"]  # bureau failure, not a vault one
    assert rows["SUB-NEW"].reasons == ["BVN_NOT_FOUND"]                   # same skip reason as before


def test_the_bureau_receives_the_real_bvn_and_only_the_gateway_path_resolves_it():
    deps, report, _, audit, _ = build()
    runner.run_daily(RUN_DATE, deps)
    assert sorted(report.seen) == sorted(BVNS.values())
    resolves = [e for e in audit.events if e.action == "RESOLVE"]
    assert resolves and {e.caller for e in resolves} == {"creditchek-gateway"}
    assert {e.purpose for e in resolves} == {"bureau_pull"}


def test_no_bvn_appears_in_anything_the_runner_saves_or_logs():
    deps, _, recs, audit, _ = build()
    summary = runner.run_daily(RUN_DATE, deps)
    assert len(recs.records) == 3  # guard: only meaningful if the runner really produced output
    assert summary.outcomes.get("SENT") == 2
    everything = (
        summary.model_dump_json()
        + "".join(r.model_dump_json() for r in recs.records)
        + "".join(e.model_dump_json() for e in audit.events)
    )
    for bvn in BVNS.values():
        assert bvn not in everything


def test_rerunning_the_same_day_still_creates_nothing_new():
    deps, _, recs, *_ = build()
    runner.run_daily(RUN_DATE, deps)
    first = len(recs.records)
    assert first == 3  # guard: the first run must have produced something to be idempotent about
    again = runner.run_daily(RUN_DATE, deps)
    assert len(recs.records) == first and again.outcomes.get("SENT", 0) == 0


def test_a_missing_grant_fails_loudly_per_subscriber_without_stopping_the_run():
    deps, report, recs, audit, _ = build(grants=[])  # nobody may resolve anything
    summary = runner.run_daily(RUN_DATE, deps)
    rows = by_id(summary)
    for sid in BVNS:
        assert rows[sid].outcome.value == "ERROR"
        assert rows[sid].reasons == ["UNEXPECTED_ERROR:VaultAccessDenied"]
    assert report.seen == [] and recs.records == []     # no BVN ever reached the bureau
    assert rows["SUB-NEW"].reasons == ["BVN_NOT_FOUND"]  # run kept going to the next subscriber
    assert any(e.outcome == "DENIED" for e in audit.events)


def test_before_migration_nobody_resolves():
    deps, report, *_ = build(migrate=False)
    summary = runner.run_daily(RUN_DATE, deps)
    assert {r.reasons[0] for r in summary.rows if r.subscriber_id in BVNS} == {"BVN_NOT_FOUND"}
    assert report.seen == []


def test_mongo_dependency_factory_can_resolve_through_vault_audited_in_shared_log(monkeypatch):
    monkeypatch.setenv(
        "VAULT_KEKS",
        "dev-v1:" + base64.b64encode(os.urandom(32)).decode("ascii"),
    )
    monkeypatch.setenv("VAULT_KEK_CURRENT", "dev-v1")
    monkeypatch.setenv("VAULT_LOOKUP_KEY", base64.b64encode(os.urandom(32)).decode("ascii"))

    subscribers = FakeCollection([
        {"subscriber_id": "SUB-A", "bvn": BVNS["SUB-A"], "plan": "PRO"},
    ])
    token_collection = FakeMongoCollection()
    names = runner.CollectionNames(report_source="reports")
    main_db = {
        names.subscribers: subscribers,
        names.vault_tokens: token_collection,
        names.snapshots: FakeMongoCollection(),
        names.recommendations: FakeMongoCollection(),
        names.decision_log: FakeMongoCollection(),
    }
    report_db = {"reports": FakeMongoCollection()}
    rebound_db = {names.rebound_schedules: FakeMongoCollection()}
    shared_audit = AuditLog(InMemoryAuditStore())
    monkeypatch.setattr(runner, "build_audit_log", lambda: shared_audit)

    vault = runner.build_vault(main_db, names)
    migrate_subscribers(subscribers, vault, Caller("migration-job"), write=True)
    deps = runner.build_mongo_deps(
        main_db, report_db, rebound_db, names, runner.FakeLLM(), use_vault=True
    )

    assert deps.lookup.get_bvn("SUB-A") == BVNS["SUB-A"]
    event = shared_audit.query()[0]
    assert event.action == "RESOLVE"
    assert event.details["purpose"] == "bureau_pull"
