import copy
import os
from datetime import datetime, timezone

import pytest

from vault import (
    Caller,
    Grant,
    InMemoryAudit,
    LocalKeyProvider,
    PiiField,
    TokenErased,
    Vault,
    VaultPolicy,
)
from vault.mongo_store import MongoVaultStore


BVN = "22123456789"


def _value(document, path):
    value = document
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _set(document, path, value):
    parts = path.split(".")
    target = document
    for part in parts[:-1]:
        target = target.setdefault(part, {})
    target[parts[-1]] = value


def _matches(document, query):
    for key, expected in query.items():
        if key == "$or":
            if not any(_matches(document, option) for option in expected):
                return False
            continue
        actual = _value(document, key)
        if isinstance(expected, dict):
            if "$exists" in expected and (actual is not None) != expected["$exists"]:
                return False
            if "$ne" in expected and actual == expected["$ne"]:
                return False
            if "$in" in expected and actual not in expected["$in"]:
                return False
        elif actual != expected:
            return False
    return True


class FakeMongoCollection:
    def __init__(self):
        self.documents = []
        self.indexes = []

    def create_index(self, *args, **kwargs):
        self.indexes.append((args, kwargs))

    def insert_one(self, document):
        self.documents.append(copy.deepcopy(document))

    def find_one(self, query, projection=None):
        document = next((d for d in self.documents if _matches(d, query)), None)
        if document is None or projection is None:
            return copy.deepcopy(document)
        selected = {}
        for path, include in projection.items():
            if include and path != "_id":
                value = _value(document, path)
                if value is not None:
                    _set(selected, path, copy.deepcopy(value))
        return selected

    def find(self, query, projection=None):
        return [
            self.find_one({"_id": d["_id"]}, projection)
            for d in self.documents
            if _matches(d, query)
        ]

    def update_one(self, query, update):
        document = next((d for d in self.documents if _matches(d, query)), None)
        if document is None:
            return type("UpdateResult", (), {"matched_count": 0})()
        for path, value in update.get("$set", {}).items():
            _set(document, path, copy.deepcopy(value))
        for path in update.get("$unset", {}):
            parts = path.split(".")
            target = document
            for part in parts[:-1]:
                target = target.get(part, {})
            target.pop(parts[-1], None)
        return type("UpdateResult", (), {"matched_count": 1})()

    def find_one_and_update(self, query, update, projection=None, return_document=None):
        document = next((d for d in self.documents if _matches(d, query)), None)
        if document is None:
            return None
        before = copy.deepcopy(document)
        self.update_one({"_id": document["_id"]}, update)
        if projection:
            return self.find_one({"_id": document["_id"]}, projection) if return_document else before
        return before


def make_vault(token_collection, audit):
    keys = LocalKeyProvider({"dev-v1": os.urandom(32)}, "dev-v1")
    lookup_key = os.urandom(32)
    policy = VaultPolicy(
        writers=frozenset({"onboarding"}),
        grants=[
            Grant(
                caller="creditchek-gateway",
                fields=frozenset({PiiField.BVN}),
                purposes=frozenset({"bureau_pull"}),
            )
        ],
    )
    return Vault(
        MongoVaultStore(token_collection),
        keys,
        lookup_key,
        audit,
        policy,
    ), keys, lookup_key, policy


def test_vault_data_persists_across_instances_and_uses_the_shared_audit_sink():
    tokens, audit = FakeMongoCollection(), InMemoryAudit()
    vault, keys, lookup_key, policy = make_vault(tokens, audit)
    result = vault.tokenize(Caller("onboarding"), bvn=BVN)

    reopened = Vault(
        MongoVaultStore(tokens), keys, lookup_key, audit, policy
    )
    assert reopened.resolve(
        Caller("creditchek-gateway"), result.token, PiiField.BVN, purpose="bureau_pull"
    ) == BVN
    assert tokens.documents[0]["fields"]["bvn"]["ciphertext"] != BVN.encode()
    assert audit.events[-1].action == "RESOLVE"
    assert audit.events[-1].outcome == "ALLOWED"


def test_erase_removes_encrypted_fields_and_keeps_a_tombstone():
    tokens, audit = FakeMongoCollection(), InMemoryAudit()
    vault, *_ = make_vault(tokens, audit)
    result = vault.tokenize(Caller("onboarding"), bvn=BVN)

    erased = MongoVaultStore(tokens).erase(result.token, datetime.now(timezone.utc))
    assert erased == 1
    assert "fields" not in tokens.documents[0]
    assert "bvn_lookup" not in tokens.documents[0]
    assert tokens.documents[0]["erased_at"] is not None
    with pytest.raises(TokenErased):
        vault.resolve(
            Caller("creditchek-gateway"), result.token, PiiField.BVN, purpose="bureau_pull"
        )


def test_rewrap_is_compare_and_swap():
    tokens, audit = FakeMongoCollection(), InMemoryAudit()
    vault, *_ = make_vault(tokens, audit)
    result = vault.tokenize(Caller("onboarding"), bvn=BVN)
    store = MongoVaultStore(tokens)
    record = store.get_field(result.token, PiiField.BVN)
    assert store.rewrap_field(
        result.token, PiiField.BVN, record.wrapped_dek, b"new-wrapped-key", "dev-v2"
    )
    assert not store.rewrap_field(
        result.token, PiiField.BVN, record.wrapped_dek, b"stale-key", "dev-v3"
    )
