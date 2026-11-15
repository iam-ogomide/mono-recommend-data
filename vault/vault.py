"""PII vault
===========
Maps a random subscriber token to direct identifiers (BVN, NIN, phone).
Everything else in the system carries the token; only callers with an explicit
grant can turn it back into a real value, and every attempt is audited.

What this module guarantees
  - Tokens are random. They are never derived from the identifier.
  - Values are encrypted with AES-256-GCM using a fresh data key per field. Each data
    key is wrapped by a master key (KEK) held by a KeyProvider (a KMS in production).
    Ciphertext is bound to its token and field, so rows cannot be swapped or replayed.
  - Access is deny-by-default and checked BEFORE any lookup, so an unauthorised
    caller learns nothing about whether a token exists.
  - The audit event is written BEFORE a value is returned. If the audit sink fails,
    the call fails (VaultUnavailable) and no value leaves.
  - Audit events and error messages never contain identifier values.
  - Erasure is cryptographic: ciphertext and wrapped keys are deleted, the BVN lookup
    hash is removed, and the token stays as a tombstone so old references fail cleanly.

What it does NOT do (read this)
  - `Caller.name` is asserted by the calling code. Inside one process that is a
    logic check, not a security boundary. Real enforcement needs the vault deployed
    as its own service, with the caller identity coming from workload identity or
    mTLS, and the database reachable only from that service.
  - LocalKeyProvider keeps the master key in process memory. Development only.
    Production needs a KMS-backed KeyProvider.
  - The BVN lookup key (HMAC) lets the vault find a token from a BVN. BVNs are 11
    digits, so if that key leaks they can be brute-forced. Protect it like the KEK.
  - Python cannot reliably wipe secrets from memory after use.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict

TOKEN_PREFIX = "subtok_"
_AAD_VERSION = "v1"
_NONCE_BYTES = 12


# ======================================================================
# FIELDS, ERRORS, NORMALISATION
# ======================================================================

class PiiField(str, Enum):
    BVN = "bvn"
    NIN = "nin"
    PHONE = "phone"


class VaultError(Exception):
    """Base error. `reason` is a stable code. Messages never contain identifier values."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class InvalidIdentifier(VaultError): ...
class VaultAccessDenied(VaultError): ...
class TokenNotFound(VaultError): ...
class TokenErased(VaultError): ...
class FieldNotSet(VaultError): ...
class DecryptionFailed(VaultError): ...
class VaultUnavailable(VaultError):
    """Audit sink or key service is down. The vault fails closed."""


class TokenExists(Exception):
    """Store-level: another caller created a token for this BVN first."""


def normalize_identifier(pii_field: PiiField, value: str) -> str:
    """Canonical form, so the same BVN always maps to the same token.
    Raises InvalidIdentifier without echoing the value."""
    text = str(value).strip()
    if pii_field in (PiiField.BVN, PiiField.NIN):
        text = re.sub(r"[\s-]", "", text)
        if not re.fullmatch(r"\d{11}", text):
            raise InvalidIdentifier(f"INVALID_{pii_field.name}")
        return text

    # Phone: accept +234..., 234..., 0... and store as +234XXXXXXXXXX
    digits = re.sub(r"[\s().-]", "", text).lstrip("+")
    if digits.startswith("234") and len(digits) == 13:
        national = digits[3:]
    elif digits.startswith("0") and len(digits) == 11:
        national = digits[1:]
    else:
        raise InvalidIdentifier("INVALID_PHONE")
    if not re.fullmatch(r"[789]\d{9}", national):
        raise InvalidIdentifier("INVALID_PHONE")
    return "+234" + national


def mask_value(value: str) -> str:
    """Everything but the last four characters."""
    return "*" * max(len(value) - 4, 0) + value[-4:]


# ======================================================================
# KEY PROVIDER (envelope encryption)
# ======================================================================

class KeyProvider(Protocol):
    current_key_id: str

    def wrap(self, dek: bytes, aad: bytes) -> bytes: ...
    def unwrap(self, wrapped: bytes, aad: bytes, key_id: str) -> bytes: ...


class LocalKeyProvider:
    """DEVELOPMENT ONLY. Master keys live in process memory, which defeats the point of a KMS.
    Replace with a provider that calls your KMS (wrap/unwrap are one API call each)."""

    def __init__(self, keys: dict[str, bytes], current: str):
        if current not in keys:
            raise ValueError("current key id is not in keys")
        if any(len(k) != 32 for k in keys.values()):
            raise ValueError("every master key must be exactly 32 bytes")
        self._keys = dict(keys)
        self.current_key_id = current

    def wrap(self, dek: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        return nonce + AESGCM(self._keys[self.current_key_id]).encrypt(nonce, dek, aad)

    def unwrap(self, wrapped: bytes, aad: bytes, key_id: str) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise DecryptionFailed("UNKNOWN_KEY_ID")
        try:
            return AESGCM(key).decrypt(wrapped[:_NONCE_BYTES], wrapped[_NONCE_BYTES:], aad)
        except InvalidTag:
            raise DecryptionFailed("BAD_WRAPPED_KEY") from None

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "LocalKeyProvider":
        """VAULT_KEKS="v1:<base64 32 bytes>,v2:<base64 32 bytes>"  VAULT_KEK_CURRENT="v2" """
        env = os.environ if environ is None else environ
        raw, current = env.get("VAULT_KEKS"), env.get("VAULT_KEK_CURRENT")
        if not raw or not current:
            raise ValueError("Set VAULT_KEKS and VAULT_KEK_CURRENT")
        keys: dict[str, bytes] = {}
        for item in raw.split(","):
            key_id, _, b64 = item.strip().partition(":")
            if not key_id or not b64:
                raise ValueError("VAULT_KEKS must look like id:base64,id:base64")
            keys[key_id] = base64.b64decode(b64)
        return cls(keys, current)


def lookup_key_from_env(environ: dict[str, str] | None = None) -> bytes:
    """VAULT_LOOKUP_KEY=<base64, at least 32 bytes>. Must be a DIFFERENT secret from the KEKs."""
    env = os.environ if environ is None else environ
    raw = env.get("VAULT_LOOKUP_KEY")
    if not raw:
        raise ValueError("Set VAULT_LOOKUP_KEY")
    return base64.b64decode(raw)


# ======================================================================
# STORAGE
# ======================================================================

class TokenRow(BaseModel):
    token: str
    bvn_lookup: str | None  # hex HMAC of the BVN. None once erased.
    created_at: datetime
    erased_at: datetime | None = None


class FieldRecord(BaseModel):
    token: str
    pii_field: PiiField
    ciphertext: bytes  # nonce (12 bytes) + AES-GCM ciphertext and tag
    wrapped_dek: bytes
    kek_id: str
    updated_at: datetime


class VaultStore(Protocol):
    def create_token(self, row: TokenRow, records: list[FieldRecord]) -> None:
        """Atomic: the token and its fields are saved together or not at all.
        Raises TokenExists if row.bvn_lookup is already taken."""
        ...

    def token_for_lookup(self, bvn_lookup: str) -> str | None: ...
    def get_token(self, token: str) -> TokenRow | None: ...
    def get_field(self, token: str, pii_field: PiiField) -> FieldRecord | None: ...
    def put_field(self, record: FieldRecord) -> None: ...

    def erase(self, token: str, now: datetime) -> int:
        """Delete every field, clear bvn_lookup, set erased_at. Returns fields deleted."""
        ...

    def records_not_on_key(self, key_id: str, limit: int) -> list[FieldRecord]: ...

    def rewrap_field(
        self, token: str, pii_field: PiiField, expected_wrapped_dek: bytes,
        new_wrapped_dek: bytes, new_kek_id: str,
    ) -> bool:
        """Compare-and-swap. Only updates if the row still has expected_wrapped_dek,
        so a rewrap can never overwrite a newer value written meanwhile."""
        ...


class InMemoryVaultStore:
    """Tests and demos. Same semantics the SQL schema in vault_schema.sql enforces."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tokens: dict[str, TokenRow] = {}
        self._by_lookup: dict[str, str] = {}
        self._fields: dict[tuple[str, PiiField], FieldRecord] = {}

    def create_token(self, row: TokenRow, records: list[FieldRecord]) -> None:
        with self._lock:
            if row.bvn_lookup in self._by_lookup:
                raise TokenExists()
            self._tokens[row.token] = row.model_copy()
            if row.bvn_lookup is not None:
                self._by_lookup[row.bvn_lookup] = row.token
            for rec in records:
                self._fields[(rec.token, rec.pii_field)] = rec.model_copy()

    def token_for_lookup(self, bvn_lookup: str) -> str | None:
        with self._lock:
            return self._by_lookup.get(bvn_lookup)

    def get_token(self, token: str) -> TokenRow | None:
        with self._lock:
            row = self._tokens.get(token)
            return row.model_copy() if row else None

    def get_field(self, token: str, pii_field: PiiField) -> FieldRecord | None:
        with self._lock:
            rec = self._fields.get((token, pii_field))
            return rec.model_copy() if rec else None

    def put_field(self, record: FieldRecord) -> None:
        with self._lock:
            self._fields[(record.token, record.pii_field)] = record.model_copy()

    def erase(self, token: str, now: datetime) -> int:
        with self._lock:
            row = self._tokens.get(token)
            if row is None:
                return 0
            if row.bvn_lookup is not None:
                self._by_lookup.pop(row.bvn_lookup, None)
            row.bvn_lookup = None
            row.erased_at = row.erased_at or now
            doomed = [k for k in self._fields if k[0] == token]
            for k in doomed:
                del self._fields[k]
            return len(doomed)

    def records_not_on_key(self, key_id: str, limit: int) -> list[FieldRecord]:
        with self._lock:
            out = [r.model_copy() for r in self._fields.values() if r.kek_id != key_id]
            return out[:limit]

    def rewrap_field(self, token, pii_field, expected_wrapped_dek, new_wrapped_dek, new_kek_id) -> bool:
        with self._lock:
            rec = self._fields.get((token, pii_field))
            if rec is None or rec.wrapped_dek != expected_wrapped_dek:
                return False
            rec.wrapped_dek, rec.kek_id = new_wrapped_dek, new_kek_id
            return True

    def raw_dump(self) -> list[bytes]:
        """Every stored byte string and text value. Tests use it to prove nothing is plaintext."""
        with self._lock:
            out: list[bytes] = []
            for t in self._tokens.values():
                out += [t.token.encode(), (t.bvn_lookup or "").encode()]
            for r in self._fields.values():
                out += [r.token.encode(), r.ciphertext, r.wrapped_dek, r.kek_id.encode()]
            return out


# ======================================================================
# AUDIT
# ======================================================================

class AuditEvent(BaseModel):
    """One row per attempt, allowed or not. Never holds an identifier value."""

    at: datetime
    action: str  # TOKENIZE | RESOLVE | READ_MASKED | SET_FIELD | ERASE | ROTATE
    outcome: str  # ALLOWED | DENIED | ERROR
    caller: str
    token: str | None = None
    pii_field: str | None = None
    purpose: str | None = None
    reason_code: str | None = None
    trace_id: str | None = None


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None:
        """MUST raise if the event was not durably recorded."""
        ...


class InMemoryAudit:
    def __init__(self):
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


# ======================================================================
# POLICY
# ======================================================================

@dataclass(frozen=True)
class Caller:
    name: str
    trace_id: str | None = None


class Grant(BaseModel):
    """Lets `caller` read `fields` for the listed purposes. masked_only = last four characters."""

    model_config = ConfigDict(frozen=True)
    caller: str
    fields: frozenset[PiiField]
    purposes: frozenset[str]
    masked_only: bool = False


class VaultPolicy(BaseModel):
    """Deny by default. Nothing is allowed unless it is listed here."""

    grants: list[Grant] = []
    writers: frozenset[str] = frozenset()   # may tokenize and set_field
    erasers: frozenset[str] = frozenset()   # may erase
    rotators: frozenset[str] = frozenset()  # may rewrap keys

    def read_grant(self, caller: str, pii_field: PiiField, purpose: str) -> Grant | None:
        for g in self.grants:
            if g.caller == caller and pii_field in g.fields and purpose in g.purposes:
                return g
        return None


# ======================================================================
# THE VAULT
# ======================================================================

class TokenizeResult(BaseModel):
    token: str
    created: bool


_REASON = re.compile(r"[A-Z0-9_]{1,40}")


def _safe(value: str | None) -> str | None:
    """Caller-supplied strings go into the audit log, so cap their size."""
    return None if value is None else str(value)[:64]


class Vault:
    def __init__(
        self,
        store: VaultStore,
        keys: KeyProvider,
        lookup_key: bytes,
        audit: AuditSink,
        policy: VaultPolicy,
        clock: Callable[[], datetime] | None = None,
    ):
        if len(lookup_key) < 32:
            raise ValueError("lookup_key must be at least 32 bytes")
        self._store, self._keys, self._lookup_key = store, keys, lookup_key
        self._audit_sink, self._policy = audit, policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ---------- internals ----------

    def _audit(self, action: str, outcome: str, caller: Caller, *, token: str | None = None,
               pii_field: PiiField | None = None, purpose: str | None = None,
               reason: str | None = None, strict: bool = True) -> None:
        event = AuditEvent(
            at=self._clock(), action=action, outcome=outcome, caller=_safe(caller.name) or "",
            token=_safe(token), pii_field=pii_field.value if pii_field else None,
            purpose=_safe(purpose), reason_code=reason, trace_id=_safe(caller.trace_id),
        )
        try:
            self._audit_sink.record(event)
        except Exception:
            if strict:
                raise VaultUnavailable("AUDIT_UNAVAILABLE") from None
            # A denial is still a denial if we could not log it.

    def _deny(self, action: str, caller: Caller, reason: str, exc: type[VaultError], **kw) -> VaultError:
        self._audit(action, "DENIED", caller, reason=reason, strict=False, **kw)
        return exc(reason)

    def _lookup(self, bvn: str) -> str:
        return hmac.new(self._lookup_key, b"bvn:" + bvn.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _aad(token: str, pii_field: PiiField) -> bytes:
        return f"{token}|{pii_field.value}|{_AAD_VERSION}".encode()

    def _seal(self, token: str, pii_field: PiiField, plaintext: str) -> FieldRecord:
        aad = self._aad(token, pii_field)
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = nonce + AESGCM(dek).encrypt(nonce, plaintext.encode(), aad)
        try:
            wrapped = self._keys.wrap(dek, aad)
        except Exception:
            raise VaultUnavailable("KEY_SERVICE_UNAVAILABLE") from None
        return FieldRecord(
            token=token, pii_field=pii_field, ciphertext=ciphertext, wrapped_dek=wrapped,
            kek_id=self._keys.current_key_id, updated_at=self._clock(),
        )

    def _open(self, rec: FieldRecord) -> str:
        aad = self._aad(rec.token, rec.pii_field)
        try:
            dek = self._keys.unwrap(rec.wrapped_dek, aad, rec.kek_id)
        except VaultError:
            raise
        except Exception:
            raise VaultUnavailable("KEY_SERVICE_UNAVAILABLE") from None
        try:
            return AESGCM(dek).decrypt(rec.ciphertext[:_NONCE_BYTES], rec.ciphertext[_NONCE_BYTES:], aad).decode()
        except InvalidTag:
            raise DecryptionFailed("BAD_CIPHERTEXT") from None

    # ---------- writes ----------

    def tokenize(self, caller: Caller, *, bvn: str, nin: str | None = None,
                 phone: str | None = None, purpose: str = "onboarding") -> TokenizeResult:
        """Get or create the token for a BVN. Idempotent. Never overwrites a stored NIN or
        phone for an existing token: use set_field for that."""
        if caller.name not in self._policy.writers:
            raise self._deny("TOKENIZE", caller, "NOT_A_WRITER", VaultAccessDenied, purpose=purpose)

        values = {PiiField.BVN: normalize_identifier(PiiField.BVN, bvn)}
        if nin is not None:
            values[PiiField.NIN] = normalize_identifier(PiiField.NIN, nin)
        if phone is not None:
            values[PiiField.PHONE] = normalize_identifier(PiiField.PHONE, phone)

        lookup = self._lookup(values[PiiField.BVN])
        existing = self._store.token_for_lookup(lookup)
        if existing:
            self._audit("TOKENIZE", "ALLOWED", caller, token=existing, purpose=purpose, reason="EXISTING")
            return TokenizeResult(token=existing, created=False)

        token = TOKEN_PREFIX + secrets.token_hex(12)
        self._audit("TOKENIZE", "ALLOWED", caller, token=token, purpose=purpose, reason="CREATED")
        records = [self._seal(token, f, v) for f, v in values.items()]
        row = TokenRow(token=token, bvn_lookup=lookup, created_at=self._clock())
        try:
            self._store.create_token(row, records)
        except TokenExists:
            winner = self._store.token_for_lookup(lookup)
            if winner is None:
                raise VaultUnavailable("TOKEN_RACE_UNRESOLVED") from None
            self._audit("TOKENIZE", "ALLOWED", caller, token=winner, purpose=purpose, reason="EXISTING_RACE")
            return TokenizeResult(token=winner, created=False)
        return TokenizeResult(token=token, created=True)

    def set_field(self, caller: Caller, token: str, pii_field: PiiField, value: str,
                  *, purpose: str = "update") -> None:
        """Replace a stored NIN or phone. The BVN cannot change: it is what identifies the person."""
        if caller.name not in self._policy.writers:
            raise self._deny("SET_FIELD", caller, "NOT_A_WRITER", VaultAccessDenied,
                             token=token, pii_field=pii_field, purpose=purpose)
        if pii_field is PiiField.BVN:
            raise self._deny("SET_FIELD", caller, "BVN_IMMUTABLE", VaultError,
                             token=token, pii_field=pii_field, purpose=purpose)
        clean = normalize_identifier(pii_field, value)
        row = self._store.get_token(token)
        if row is None:
            raise self._deny("SET_FIELD", caller, "NOT_FOUND", TokenNotFound,
                             token=token, pii_field=pii_field, purpose=purpose)
        if row.erased_at is not None:
            raise self._deny("SET_FIELD", caller, "ERASED", TokenErased,
                             token=token, pii_field=pii_field, purpose=purpose)
        self._audit("SET_FIELD", "ALLOWED", caller, token=token, pii_field=pii_field, purpose=purpose)
        self._store.put_field(self._seal(token, pii_field, clean))

    # ---------- reads ----------

    def _read(self, action: str, caller: Caller, token: str, pii_field: PiiField,
              purpose: str, masked: bool) -> str:
        kw = dict(token=token, pii_field=pii_field, purpose=purpose)

        # 1. Authorise first, so an unauthorised caller cannot probe which tokens exist.
        grant = self._policy.read_grant(caller.name, pii_field, purpose)
        if grant is None:
            raise self._deny(action, caller, "NO_GRANT", VaultAccessDenied, **kw)
        if grant.masked_only and not masked:
            raise self._deny(action, caller, "MASKED_ONLY", VaultAccessDenied, **kw)

        # 2. Then look the token up.
        row = self._store.get_token(token)
        if row is None:
            raise self._deny(action, caller, "NOT_FOUND", TokenNotFound, **kw)
        if row.erased_at is not None:
            raise self._deny(action, caller, "ERASED", TokenErased, **kw)
        rec = self._store.get_field(token, pii_field)
        if rec is None:
            self._audit(action, "ERROR", caller, reason="FIELD_NOT_SET", strict=False, **kw)
            raise FieldNotSet("FIELD_NOT_SET")

        # 3. Audit BEFORE the value leaves. No audit, no value.
        self._audit(action, "ALLOWED", caller, **kw)
        try:
            value = self._open(rec)
        except VaultError as exc:
            self._audit(action, "ERROR", caller, reason=exc.reason, strict=False, **kw)
            raise
        return mask_value(value) if masked else value

    def resolve(self, caller: Caller, token: str, pii_field: PiiField, *, purpose: str) -> str:
        """The real value. Needs a non-masked grant for this caller, field and purpose."""
        return self._read("RESOLVE", caller, token, pii_field, purpose, masked=False)

    def read_masked(self, caller: Caller, token: str, pii_field: PiiField, *, purpose: str) -> str:
        """Last four characters only. Any grant for this caller, field and purpose is enough."""
        return self._read("READ_MASKED", caller, token, pii_field, purpose, masked=True)

    # ---------- erasure and rotation ----------

    def erase(self, caller: Caller, token: str, *, reason: str) -> int:
        """Crypto-erase one person. `reason` is a short code such as DSAR_ERASURE, not free text.
        Safe to call twice. Returns how many fields were deleted."""
        if not _REASON.fullmatch(reason):
            raise ValueError("reason must be a short code like DSAR_ERASURE")
        if caller.name not in self._policy.erasers:
            raise self._deny("ERASE", caller, "NOT_AN_ERASER", VaultAccessDenied, token=token)
        row = self._store.get_token(token)
        if row is None:
            raise self._deny("ERASE", caller, "NOT_FOUND", TokenNotFound, token=token)
        self._audit("ERASE", "ALLOWED", caller, token=token,
                    reason="ALREADY_ERASED" if row.erased_at else reason)
        return self._store.erase(token, self._clock())

    def rewrap_batch(self, caller: Caller, *, limit: int = 100) -> int:
        """After adding a new master key and making it current, call this repeatedly until it
        returns 0. Only the small wrapped keys change, never the encrypted values."""
        if caller.name not in self._policy.rotators:
            raise self._deny("ROTATE", caller, "NOT_A_ROTATOR", VaultAccessDenied)
        done = 0
        for rec in self._store.records_not_on_key(self._keys.current_key_id, limit):
            aad = self._aad(rec.token, rec.pii_field)
            dek = self._keys.unwrap(rec.wrapped_dek, aad, rec.kek_id)
            try:
                new_wrapped = self._keys.wrap(dek, aad)
            except Exception:
                raise VaultUnavailable("KEY_SERVICE_UNAVAILABLE") from None
            if self._store.rewrap_field(rec.token, rec.pii_field, rec.wrapped_dek,
                                        new_wrapped, self._keys.current_key_id):
                done += 1
        self._audit("ROTATE", "ALLOWED", caller, reason=f"REWRAPPED_{done}")
        return done


# ======================================================================
# TRY IT (development keys, in-memory store, nothing leaves your machine)
#   python vault.py
# ======================================================================
if __name__ == "__main__":
    keys = LocalKeyProvider({"v1": os.urandom(32)}, "v1")
    audit = InMemoryAudit()
    store = InMemoryVaultStore()
    policy = VaultPolicy(
        writers=frozenset({"onboarding"}),
        grants=[
            Grant(caller="creditchek-gateway", fields=frozenset({PiiField.BVN}),
                  purposes=frozenset({"bureau_pull"})),
            Grant(caller="support-agent", fields=frozenset({PiiField.BVN, PiiField.PHONE}),
                  purposes=frozenset({"support_ticket"}), masked_only=True),
        ],
    )
    vault = Vault(store, keys, os.urandom(32), audit, policy)

    made = vault.tokenize(Caller("onboarding"), bvn="22123456789", phone="0803 123 4567")
    print("token:", made.token, "| created:", made.created)
    print("stored ciphertext (hex):", store.get_field(made.token, PiiField.BVN).ciphertext.hex()[:48], "...")
    print("gateway resolves BVN:", vault.resolve(Caller("creditchek-gateway"), made.token, PiiField.BVN, purpose="bureau_pull"))
    print("support sees phone:", vault.read_masked(Caller("support-agent"), made.token, PiiField.PHONE, purpose="support_ticket"))
    for attempt in (
        lambda: vault.resolve(Caller("support-agent"), made.token, PiiField.BVN, purpose="support_ticket"),
        lambda: vault.resolve(Caller("recommendation-agent"), made.token, PiiField.BVN, purpose="bureau_pull"),
    ):
        try:
            attempt()
        except VaultError as exc:
            print("denied:", exc.reason)
    print("\naudit trail (no values anywhere):")
    for e in audit.events:
        print(f"  {e.action:12} {e.outcome:8} caller={e.caller:20} field={e.pii_field} reason={e.reason_code}")
