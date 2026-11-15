import os

import pytest

from vault import (
    Caller, Grant, InMemoryAudit, InMemoryVaultStore, LocalKeyProvider, PiiField, Vault,
    VaultPolicy,
)
from vault.vault_adapter import VaultLookup, make_mongo_token_resolver, migrate_subscribers

BVN_A, BVN_B = "22123456789", "22987654321"
GATEWAY = Caller("creditchek-gateway")
MIGRATOR = Caller("migration-job")


class FakeCollection:
    """Understands ONLY the query shapes the adapter uses and raises on anything else,
    so a test cannot pass by accident against a query the fake silently ignored."""

    def __init__(self, docs):
        self.docs = docs

    def find(self, query, projection=None):
        assert set(query).issubset({"bvn", "subscriber_id"}), f"unsupported query {query}"
        cond = query["bvn"]
        assert cond == {"$exists": True, "$ne": None}, f"unsupported query {query}"
        allowed = query.get("subscriber_id", {}).get("$in")
        return [
            dict(d) for d in self.docs
            if d.get("bvn") is not None
            and (allowed is None or d.get("subscriber_id") in allowed)
        ]

    def find_one(self, query, projection=None):
        ((field, value),) = query.items()
        for d in self.docs:
            if d.get(field) == value:
                return {k: v for k, v in d.items() if projection is None or k in projection}
        return None

    def update_one(self, query, update):
        ((field, value),) = query.items()
        assert set(update) == {"$set"}, f"unsupported update {update}"
        for d in self.docs:
            if d.get(field) == value:
                d.update(update["$set"])
                return


def make_vault(**policy_over):
    policy = dict(
        writers=frozenset({"migration-job"}),
        erasers=frozenset({"admin"}),
        grants=[Grant(caller="creditchek-gateway", fields=frozenset({PiiField.BVN}),
                      purposes=frozenset({"bureau_pull"}))],
    )
    policy.update(policy_over)
    audit = InMemoryAudit()
    v = Vault(InMemoryVaultStore(), LocalKeyProvider({"v1": os.urandom(32)}, "v1"),
              os.urandom(32), audit, VaultPolicy(**policy))
    return v, audit


def subscribers():
    return FakeCollection([
        {"subscriber_id": "SUB-A", "bvn": BVN_A, "plan": "PRO", "phone": "08031234567"},
        {"subscriber_id": "SUB-B", "bvn": BVN_B, "plan": "BASIC", "phone": "not a phone"},
        {"subscriber_id": "SUB-C", "bvn": "123", "plan": "PRO"},          # invalid BVN
        {"subscriber_id": "SUB-D", "plan": "PRO"},                        # no BVN at all
    ])


class TestMigration:
    def test_dry_run_changes_nothing(self):
        vault, audit = make_vault()
        coll = subscribers()
        before = [dict(d) for d in coll.docs]
        rep = migrate_subscribers(coll, vault, MIGRATOR, write=False,
                                  extra_fields={PiiField.PHONE: "phone"})
        assert rep.dry_run and rep.scanned == 3 and rep.tokenized == 2
        assert rep.invalid_bvn == ["SUB-C"] and rep.dropped_extras == ["SUB-B:phone"]
        assert coll.docs == before and audit.events == []

    def test_write_tokenizes_and_never_deletes_the_plaintext(self):
        vault, _ = make_vault()
        coll = subscribers()
        rep = migrate_subscribers(coll, vault, MIGRATOR, write=True)
        assert (rep.tokenized, rep.already_tokenized) == (2, 0)
        a = next(d for d in coll.docs if d["subscriber_id"] == "SUB-A")
        assert a["pii_token"].startswith("subtok_") and a["bvn"] == BVN_A  # bvn still there on purpose
        assert "pii_token" not in next(d for d in coll.docs if d["subscriber_id"] == "SUB-C")

    def test_rerun_is_safe(self):
        vault, _ = make_vault()
        coll = subscribers()
        migrate_subscribers(coll, vault, MIGRATOR, write=True)
        tokens = {d["subscriber_id"]: d.get("pii_token") for d in coll.docs}
        again = migrate_subscribers(coll, vault, MIGRATOR, write=True)
        assert again.tokenized == 0 and again.already_tokenized == 2
        assert {d["subscriber_id"]: d.get("pii_token") for d in coll.docs} == tokens

    def test_write_can_be_limited_to_selected_subscribers(self):
        vault, _ = make_vault()
        coll = subscribers()
        rep = migrate_subscribers(
            coll, vault, MIGRATOR, write=True, subscriber_ids={"SUB-B"}
        )
        assert rep.scanned == 1 and rep.tokenized == 1
        assert "pii_token" not in next(d for d in coll.docs if d["subscriber_id"] == "SUB-A")
        assert "pii_token" in next(d for d in coll.docs if d["subscriber_id"] == "SUB-B")

    def test_report_never_contains_values(self):
        vault, _ = make_vault()
        rep = migrate_subscribers(subscribers(), vault, MIGRATOR, write=True,
                                  extra_fields={PiiField.PHONE: "phone"})
        dump = rep.model_dump_json()
        for secret in (BVN_A, BVN_B, "123", "08031234567", "not a phone"):
            assert secret not in dump

    def test_non_writer_cannot_migrate(self):
        vault, _ = make_vault(writers=frozenset())
        from vault import VaultAccessDenied
        with pytest.raises(VaultAccessDenied):
            migrate_subscribers(subscribers(), vault, MIGRATOR, write=True)

    def test_extra_phone_is_stored_normalised(self):
        vault, _ = make_vault(grants=[Grant(caller="support", fields=frozenset({PiiField.PHONE}),
                                            purposes=frozenset({"t"}), masked_only=True)])
        coll = subscribers()
        migrate_subscribers(coll, vault, MIGRATOR, write=True, extra_fields={PiiField.PHONE: "phone"})
        token = next(d for d in coll.docs if d["subscriber_id"] == "SUB-A")["pii_token"]
        assert vault.read_masked(Caller("support"), token, PiiField.PHONE, purpose="t") == "**********4567"


class TestLookup:
    def setup_method(self):
        self.vault, self.audit = make_vault()
        self.coll = subscribers()
        migrate_subscribers(self.coll, self.vault, MIGRATOR, write=True)
        self.lookup = VaultLookup(self.vault, make_mongo_token_resolver(self.coll), GATEWAY)

    def test_returns_bvn_for_a_migrated_subscriber(self):
        assert self.lookup.get_bvn("SUB-A") == BVN_A

    def test_unmigrated_unknown_and_no_bvn_subscribers_return_none(self):
        for sid in ("SUB-C", "SUB-D", "SUB-NOPE"):
            assert self.lookup.get_bvn(sid) is None

    def test_erased_subscriber_returns_none(self):
        token = make_mongo_token_resolver(self.coll)("SUB-A")
        self.vault.erase(Caller("admin"), token, reason="DSAR_ERASURE")
        assert self.lookup.get_bvn("SUB-A") is None

    def test_missing_grant_is_loud_not_silent(self):
        from vault import VaultAccessDenied
        bad = VaultLookup(self.vault, make_mongo_token_resolver(self.coll), Caller("recommendation-agent"))
        with pytest.raises(VaultAccessDenied):
            bad.get_bvn("SUB-A")

    def test_each_lookup_is_audited_with_purpose(self):
        self.lookup.get_bvn("SUB-A")
        ev = self.audit.events[-1]
        assert (ev.action, ev.outcome, ev.caller, ev.purpose) == (
            "RESOLVE", "ALLOWED", "creditchek-gateway", "bureau_pull")
