"""MongoDB-backed vault storage for development deployments.

The token, lookup hash, and encrypted fields live in one MongoDB document so
token creation and erasure each use a single-document atomic write.
"""
from __future__ import annotations

from typing import Any

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

if __package__:
    from .vault import FieldRecord, PiiField, TokenExists, TokenRow, VaultUnavailable
else:
    from vault import FieldRecord, PiiField, TokenExists, TokenRow, VaultUnavailable


def _field_document(record: FieldRecord) -> dict[str, Any]:
    return {
        "token": record.token,
        "pii_field": record.pii_field.value,
        "ciphertext": record.ciphertext,
        "wrapped_dek": record.wrapped_dek,
        "kek_id": record.kek_id,
        "updated_at": record.updated_at,
    }


class MongoVaultStore:
    """Implements VaultStore using one document per token."""

    def __init__(self, collection):
        self._collection = collection

    def create_indexes(self) -> None:
        self._collection.create_index(
            "bvn_lookup",
            unique=True,
            partialFilterExpression={"bvn_lookup": {"$type": "string"}},
        )

    def create_token(self, row: TokenRow, records: list[FieldRecord]) -> None:
        document = {
            "_id": row.token,
            "token": row.token,
            "bvn_lookup": row.bvn_lookup,
            "created_at": row.created_at,
            "erased_at": row.erased_at,
            "fields": {
                record.pii_field.value: _field_document(record)
                for record in records
            },
        }
        try:
            self._collection.insert_one(document)
        except DuplicateKeyError:
            raise TokenExists() from None

    def token_for_lookup(self, bvn_lookup: str) -> str | None:
        doc = self._collection.find_one(
            {"bvn_lookup": bvn_lookup},
            {"token": 1, "_id": 0},
        )
        return str(doc["token"]) if doc else None

    def get_token(self, token: str) -> TokenRow | None:
        doc = self._collection.find_one(
            {"token": token},
            {"token": 1, "bvn_lookup": 1, "created_at": 1, "erased_at": 1, "_id": 0},
        )
        if doc is None:
            return None
        return TokenRow(
            token=doc["token"],
            bvn_lookup=doc.get("bvn_lookup"),
            created_at=doc["created_at"],
            erased_at=doc.get("erased_at"),
        )

    def get_field(self, token: str, pii_field: PiiField) -> FieldRecord | None:
        doc = self._collection.find_one(
            {"token": token},
            {f"fields.{pii_field.value}": 1, "_id": 0},
        )
        field = (doc or {}).get("fields", {}).get(pii_field.value)
        return FieldRecord.model_validate(field) if field else None

    def put_field(self, record: FieldRecord) -> None:
        result = self._collection.update_one(
            {"token": record.token, "erased_at": None},
            {"$set": {f"fields.{record.pii_field.value}": _field_document(record)}},
        )
        if result.matched_count != 1:
            raise VaultUnavailable("TOKEN_UNAVAILABLE")

    def erase(self, token: str, now) -> int:
        doc = self._collection.find_one_and_update(
            {"token": token, "erased_at": None},
            {
                "$set": {"erased_at": now},
                "$unset": {"bvn_lookup": "", "fields": ""},
            },
            projection={"fields": 1, "_id": 0},
            return_document=ReturnDocument.BEFORE,
        )
        if doc is None:
            return 0
        return len((doc.get("fields") or {}))

    def records_not_on_key(self, key_id: str, limit: int) -> list[FieldRecord]:
        if limit <= 0:
            return []
        fields = tuple(field.value for field in PiiField)
        query = {
            "$or": [
                {f"fields.{field}.kek_id": {"$exists": True, "$ne": key_id}}
                for field in fields
            ]
        }
        records: list[FieldRecord] = []
        for doc in self._collection.find(query, {"fields": 1, "_id": 0}):
            for record in (doc.get("fields") or {}).values():
                if record.get("kek_id") != key_id:
                    records.append(FieldRecord.model_validate(record))
                    if len(records) >= limit:
                        return records
        return records

    def rewrap_field(
        self,
        token: str,
        pii_field: PiiField,
        expected_wrapped_dek: bytes,
        new_wrapped_dek: bytes,
        new_kek_id: str,
    ) -> bool:
        result = self._collection.update_one(
            {
                "token": token,
                f"fields.{pii_field.value}.wrapped_dek": expected_wrapped_dek,
            },
            {
                "$set": {
                    f"fields.{pii_field.value}.wrapped_dek": new_wrapped_dek,
                    f"fields.{pii_field.value}.kek_id": new_kek_id,
                }
            },
        )
        return result.matched_count == 1
