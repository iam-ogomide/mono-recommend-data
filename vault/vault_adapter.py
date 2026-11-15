"""Plugs the vault into the recommendation runner.

credit.create_bureau_snapshot() needs a SubscriberLookup: `get_bvn(subscriber_id) -> str | None`.
Today that is credit.make_mongo_lookup(), which reads a plaintext `bvn` field from the
subscribers collection. VaultLookup is a drop-in replacement:

    from vault_adapter import VaultLookup, make_mongo_token_resolver
    lookup = VaultLookup(
        vault,
        make_mongo_token_resolver(subscribers_collection),   # subscriber_id -> subtok_...
        Caller("creditchek-gateway", trace_id=run_id),
    )
    deps = RunnerDeps(lookup=lookup, ...)

Behaviour is kept the same where the runner depends on it:
  - subscriber has no token, or the token was erased, or has no BVN  ->  returns None, which
    credit.py already turns into the skip reason BVN_NOT_FOUND (not retryable).
  - anything else (access denied, vault or audit down, tampered data) RAISES. That is
    deliberate: a misconfigured policy should be loud. runner.py catches it per subscriber
    and records UNEXPECTED_ERROR:<ErrorName>, so one failure never stops the whole run.

Migration: migrate_subscribers() copies BVNs from the subscribers collection into the vault and
writes the token back as `pii_token`. It does NOT delete the plaintext `bvn` field. Do that as a
separate, deliberate step after you have checked a full run reads through the vault.
"""
from __future__ import annotations

from typing import Callable

from pydantic import BaseModel

from vault import (
    Caller, FieldNotSet, InvalidIdentifier, PiiField, TokenErased, TokenNotFound, Vault,
    normalize_identifier,
)


class VaultLookup:
    """Implements credit.SubscriberLookup."""

    def __init__(self, vault: Vault, token_for_subscriber: Callable[[str], str | None],
                 caller: Caller, purpose: str = "bureau_pull"):
        self._vault = vault
        self._token_for = token_for_subscriber
        self._caller = caller
        self._purpose = purpose

    def get_bvn(self, subscriber_id: str) -> str | None:
        token = self._token_for(subscriber_id)
        if not token:
            return None
        try:
            return self._vault.resolve(self._caller, token, PiiField.BVN, purpose=self._purpose)
        except (TokenNotFound, TokenErased, FieldNotSet):
            return None


def make_mongo_token_resolver(collection, field: str = "pii_token") -> Callable[[str], str | None]:
    """subscriber_id -> vault token, read from the subscriber document. Same pattern as
    rebound.make_user_ref_resolver. Reads one field and nothing else."""

    def resolve(subscriber_id: str) -> str | None:
        doc = collection.find_one({"subscriber_id": subscriber_id}, {field: 1, "_id": 0})
        value = doc.get(field) if doc else None
        return str(value) if value else None

    return resolve


class MigrationReport(BaseModel):
    dry_run: bool
    scanned: int = 0
    tokenized: int = 0                  # new tokens created
    already_tokenized: int = 0          # had a pii_token already, or the BVN was already in the vault
    invalid_bvn: list[str] = []         # subscriber_ids only, never values
    dropped_extras: list[str] = []      # "subscriber_id:field" where an optional value was invalid


def migrate_subscribers(
    collection,
    vault: Vault | None,
    caller: Caller,
    *,
    write: bool = False,
    subscriber_ids: set[str] | None = None,
    bvn_field: str = "bvn",
    token_field: str = "pii_token",
    extra_fields: dict[PiiField, str] | None = None,
) -> MigrationReport:
    """Dry run by default: validates every BVN and reports, changes nothing.

    `extra_fields` maps a vault field to the subscriber-document field that holds it, for
    example {PiiField.PHONE: "phone"}. Your repo only shows `bvn` on the subscriber document, so
    nothing else is assumed. An invalid optional value is dropped and reported; it never blocks
    the BVN. Needs `caller` to be in the vault policy's writers."""
    report = MigrationReport(dry_run=not write)
    extras = extra_fields or {}
    projection = {"subscriber_id": 1, bvn_field: 1, token_field: 1, "_id": 0,
                  **{doc_field: 1 for doc_field in extras.values()}}
    query = {bvn_field: {"$exists": True, "$ne": None}}
    if subscriber_ids is not None:
        query["subscriber_id"] = {"$in": sorted(subscriber_ids)}

    for doc in collection.find(query, projection):
        report.scanned += 1
        sid = str(doc.get("subscriber_id"))
        if doc.get(token_field):
            report.already_tokenized += 1
            continue
        try:
            clean_bvn = normalize_identifier(PiiField.BVN, doc[bvn_field])
        except InvalidIdentifier:
            report.invalid_bvn.append(sid)
            continue

        kwargs: dict[str, str] = {}
        for pii_field, doc_field in extras.items():
            raw = doc.get(doc_field)
            if raw in (None, ""):
                continue
            try:
                kwargs[pii_field.value] = normalize_identifier(pii_field, raw)
            except InvalidIdentifier:
                report.dropped_extras.append(f"{sid}:{pii_field.value}")

        if not write:
            report.tokenized += 1  # "would tokenize"
            continue
        if vault is None:
            raise ValueError("A vault instance is required when writing a migration.")
        result = vault.tokenize(caller, bvn=clean_bvn, purpose="migration", **kwargs)
        collection.update_one({"subscriber_id": doc.get("subscriber_id")},
                              {"$set": {token_field: result.token}})
        if result.created:
            report.tokenized += 1
        else:
            report.already_tokenized += 1
    return report
