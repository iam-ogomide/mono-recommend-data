import base64
import json
import os
import threading

import pytest

from vault import (
    AuditEvent, Caller, DecryptionFailed, Grant, InMemoryAudit, InMemoryVaultStore,
    InvalidIdentifier, LocalKeyProvider, PiiField, TokenErased, TokenNotFound, Vault,
    VaultAccessDenied, VaultError, VaultPolicy, VaultUnavailable, FieldNotSet,
    lookup_key_from_env, mask_value, normalize_identifier,
)

BVN = "22123456789"
BVN_2 = "22987654321"
NIN = "33111222333"
PHONE = "08031234567"
PHONE_NORM = "+2348031234567"

ONBOARD = Caller("onboarding", trace_id="t-1")
GATEWAY = Caller("creditchek-gateway", trace_id="t-2")
SUPPORT = Caller("support-agent")
AGENT = Caller("recommendation-agent")
ADMIN = Caller("compliance-admin")


def make_policy(**over):
    base = dict(
        writers=frozenset({"onboarding"}),
        erasers=frozenset({"compliance-admin"}),
        rotators=frozenset({"compliance-admin"}),
        grants=[
            Grant(caller="creditchek-gateway", fields=frozenset({PiiField.BVN}),
                  purposes=frozenset({"bureau_pull"})),
            Grant(caller="support-agent", fields=frozenset({PiiField.BVN, PiiField.PHONE}),
                  purposes=frozenset({"support_ticket"}), masked_only=True),
        ],
    )
    base.update(over)
    return VaultPolicy(**base)


@pytest.fixture
def parts():
    store, audit = InMemoryVaultStore(), InMemoryAudit()
    keys = LocalKeyProvider({"v1": os.urandom(32)}, "v1")
    lookup = os.urandom(32)
    vault = Vault(store, keys, lookup, audit, make_policy())
    return vault, store, audit, keys, lookup


def issue(vault, bvn=BVN, **kw):
    return vault.tokenize(ONBOARD, bvn=bvn, **kw).token


# ----------------------------------------------------------------- normalisation

class TestNormalisation:
    def test_bvn_accepts_spaces_and_dashes(self):
        assert normalize_identifier(PiiField.BVN, "2212 345-6789") == BVN

    @pytest.mark.parametrize("bad", ["", "123", "2212345678", "221234567890", "2212345678a"])
    def test_bvn_rejects_bad_shapes(self, bad):
        with pytest.raises(InvalidIdentifier):
            normalize_identifier(PiiField.BVN, bad)

    @pytest.mark.parametrize("raw", ["08031234567", "+2348031234567", "2348031234567", "0803 123 4567", "+234 (803) 123-4567"])
    def test_phone_variants_become_one_form(self, raw):
        assert normalize_identifier(PiiField.PHONE, raw) == PHONE_NORM

    @pytest.mark.parametrize("bad", ["0603123456", "08031234", "+2341234567890", "abc", "+4478091234567"])
    def test_phone_rejects_non_nigerian_mobile(self, bad):
        with pytest.raises(InvalidIdentifier):
            normalize_identifier(PiiField.PHONE, bad)

    def test_error_never_echoes_the_value(self):
        with pytest.raises(InvalidIdentifier) as exc:
            normalize_identifier(PiiField.BVN, "9999999999")
        assert "9999999999" not in str(exc.value) and "9999999999" not in repr(exc.value)

    def test_mask(self):
        assert mask_value(BVN) == "*******6789"
        assert mask_value("12") == "12"


# ----------------------------------------------------------------- tokens

class TestTokens:
    def test_round_trip(self, parts):
        vault, *_ = parts
        t = issue(vault, nin=NIN, phone=PHONE)
        assert vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull") == BVN

    def test_token_is_random_not_derived(self, parts):
        vault, *_ = parts
        t = issue(vault)
        assert t.startswith("subtok_") and BVN not in t
        other = Vault(InMemoryVaultStore(), LocalKeyProvider({"v1": os.urandom(32)}, "v1"),
                      os.urandom(32), InMemoryAudit(), make_policy())
        assert issue(other) != t  # same BVN, different vault, unrelated token

    def test_same_bvn_same_token_any_formatting(self, parts):
        vault, *_ = parts
        first = vault.tokenize(ONBOARD, bvn=BVN)
        again = vault.tokenize(ONBOARD, bvn="2212 345 6789")
        assert (again.token, again.created, first.created) == (first.token, False, True)

    def test_different_bvns_different_tokens(self, parts):
        vault, *_ = parts
        assert issue(vault, BVN) != issue(vault, BVN_2)

    def test_existing_token_does_not_overwrite_phone(self, parts):
        vault, *_ = parts
        t = issue(vault, phone=PHONE)
        vault.tokenize(ONBOARD, bvn=BVN, phone="08099999999")
        vault.set_field(ONBOARD, t, PiiField.PHONE, PHONE)  # no-op write, proves path works
        assert vault.read_masked(SUPPORT, t, PiiField.PHONE, purpose="support_ticket").endswith("4567")

    def test_concurrent_tokenize_makes_exactly_one_token(self, parts):
        vault, store, *_ = parts
        results, errors = [], []

        def work():
            try:
                results.append(vault.tokenize(ONBOARD, bvn=BVN))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=work) for _ in range(30)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert not errors
        assert len({r.token for r in results}) == 1
        assert sum(r.created for r in results) == 1

    def test_invalid_input_writes_nothing(self, parts):
        vault, store, audit, *_ = parts
        with pytest.raises(InvalidIdentifier):
            vault.tokenize(ONBOARD, bvn=BVN, phone="nonsense")
        assert store.raw_dump() == []


# ----------------------------------------------------------------- nothing readable at rest

class TestAtRest:
    def test_no_plaintext_anywhere_in_storage(self, parts):
        vault, store, *_ = parts
        issue(vault, nin=NIN, phone=PHONE)
        blob = b"|".join(store.raw_dump())
        for secret in (BVN, NIN, PHONE_NORM, PHONE, PHONE_NORM[1:]):
            assert secret.encode() not in blob

    def test_same_value_encrypts_differently_each_time(self, parts):
        vault, store, *_ = parts
        a = issue(vault, BVN, nin=NIN)
        b = issue(vault, BVN_2, nin=NIN)
        ra, rb = store.get_field(a, PiiField.NIN), store.get_field(b, PiiField.NIN)
        assert ra.ciphertext != rb.ciphertext and ra.wrapped_dek != rb.wrapped_dek

    def test_bvn_hash_is_keyed(self, parts):
        vault, store, audit, keys, _ = parts
        t = issue(vault)
        other = Vault(store, keys, os.urandom(32), audit, make_policy())
        # a vault with a different lookup key cannot find the existing token
        assert other.tokenize(ONBOARD, bvn=BVN).token != t


# ----------------------------------------------------------------- policy

class TestPolicy:
    def test_deny_by_default_empty_policy(self):
        store, audit = InMemoryVaultStore(), InMemoryAudit()
        v = Vault(store, LocalKeyProvider({"v1": os.urandom(32)}, "v1"), os.urandom(32), audit, VaultPolicy())
        with pytest.raises(VaultAccessDenied):
            v.tokenize(ONBOARD, bvn=BVN)
        with pytest.raises(VaultAccessDenied):
            v.resolve(GATEWAY, "subtok_x", PiiField.BVN, purpose="bureau_pull")

    def test_unlisted_caller_denied(self, parts):
        vault, *_ = parts
        t = issue(vault)
        with pytest.raises(VaultAccessDenied) as exc:
            vault.resolve(AGENT, t, PiiField.BVN, purpose="bureau_pull")
        assert exc.value.reason == "NO_GRANT"

    def test_wrong_purpose_denied(self, parts):
        vault, *_ = parts
        t = issue(vault)
        with pytest.raises(VaultAccessDenied):
            vault.resolve(GATEWAY, t, PiiField.BVN, purpose="marketing")

    def test_wrong_field_denied(self, parts):
        vault, *_ = parts
        t = issue(vault, nin=NIN)
        with pytest.raises(VaultAccessDenied):
            vault.resolve(GATEWAY, t, PiiField.NIN, purpose="bureau_pull")

    def test_masked_only_cannot_resolve_but_can_read_masked(self, parts):
        vault, *_ = parts
        t = issue(vault, phone=PHONE)
        with pytest.raises(VaultAccessDenied) as exc:
            vault.resolve(SUPPORT, t, PiiField.PHONE, purpose="support_ticket")
        assert exc.value.reason == "MASKED_ONLY"
        assert vault.read_masked(SUPPORT, t, PiiField.PHONE, purpose="support_ticket") == "**********4567"

    def test_only_writers_can_tokenize_or_set(self, parts):
        vault, *_ = parts
        with pytest.raises(VaultAccessDenied):
            vault.tokenize(GATEWAY, bvn=BVN)
        t = issue(vault)
        with pytest.raises(VaultAccessDenied):
            vault.set_field(GATEWAY, t, PiiField.PHONE, PHONE)

    def test_only_erasers_and_rotators(self, parts):
        vault, *_ = parts
        t = issue(vault)
        with pytest.raises(VaultAccessDenied):
            vault.erase(ONBOARD, t, reason="DSAR_ERASURE")
        with pytest.raises(VaultAccessDenied):
            vault.rewrap_batch(ONBOARD)

    def test_unauthorised_caller_cannot_probe_for_tokens(self, parts):
        vault, *_ = parts
        real = issue(vault)
        # Same error whether the token exists or not: no existence oracle.
        for token in (real, "subtok_doesnotexist"):
            with pytest.raises(VaultAccessDenied) as exc:
                vault.resolve(AGENT, token, PiiField.BVN, purpose="bureau_pull")
            assert exc.value.reason == "NO_GRANT"

    def test_authorised_caller_gets_not_found_for_unknown_token(self, parts):
        vault, *_ = parts
        with pytest.raises(TokenNotFound):
            vault.resolve(GATEWAY, "subtok_doesnotexist", PiiField.BVN, purpose="bureau_pull")

    def test_missing_field(self, parts):
        vault, *_ = parts
        t = issue(vault)  # no phone stored
        with pytest.raises(FieldNotSet):
            vault.read_masked(SUPPORT, t, PiiField.PHONE, purpose="support_ticket")

    def test_bvn_cannot_be_changed(self, parts):
        vault, *_ = parts
        t = issue(vault)
        with pytest.raises(VaultError) as exc:
            vault.set_field(ONBOARD, t, PiiField.BVN, BVN_2)
        assert exc.value.reason == "BVN_IMMUTABLE"


# ----------------------------------------------------------------- audit

class FailingAudit:
    def record(self, event: AuditEvent) -> None:
        raise ConnectionError("audit store down")


class TestAudit:
    def test_every_attempt_is_recorded_including_denials(self, parts):
        vault, _, audit, *_ = parts
        t = issue(vault)
        vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")
        with pytest.raises(VaultAccessDenied):
            vault.resolve(AGENT, t, PiiField.BVN, purpose="bureau_pull")
        got = [(e.action, e.outcome, e.caller) for e in audit.events]
        assert ("TOKENIZE", "ALLOWED", "onboarding") in got
        assert ("RESOLVE", "ALLOWED", "creditchek-gateway") in got
        assert ("RESOLVE", "DENIED", "recommendation-agent") in got

    def test_trace_id_and_purpose_recorded(self, parts):
        vault, _, audit, *_ = parts
        t = issue(vault)
        vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")
        ev = [e for e in audit.events if e.action == "RESOLVE"][0]
        assert (ev.trace_id, ev.purpose, ev.token, ev.pii_field) == ("t-2", "bureau_pull", t, "bvn")

    def test_audit_never_contains_values(self, parts):
        vault, _, audit, *_ = parts
        t = issue(vault, nin=NIN, phone=PHONE)
        vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")
        vault.read_masked(SUPPORT, t, PiiField.PHONE, purpose="support_ticket")
        vault.set_field(ONBOARD, t, PiiField.PHONE, "08051112222")
        with pytest.raises(VaultAccessDenied):
            vault.resolve(AGENT, t, PiiField.BVN, purpose="bureau_pull")
        vault.erase(ADMIN, t, reason="DSAR_ERASURE")
        dump = json.dumps([e.model_dump(mode="json") for e in audit.events])
        for secret in (BVN, NIN, PHONE, PHONE_NORM, "8051112222", "4567"):
            assert secret not in dump

    def test_resolve_fails_closed_when_audit_is_down(self, parts):
        vault, store, _, keys, lookup = parts
        t = issue(vault)
        broken = Vault(store, keys, lookup, FailingAudit(), make_policy())
        with pytest.raises(VaultUnavailable) as exc:
            broken.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")
        assert exc.value.reason == "AUDIT_UNAVAILABLE"

    def test_tokenize_writes_nothing_when_audit_is_down(self):
        store = InMemoryVaultStore()
        v = Vault(store, LocalKeyProvider({"v1": os.urandom(32)}, "v1"), os.urandom(32),
                  FailingAudit(), make_policy())
        with pytest.raises(VaultUnavailable):
            v.tokenize(ONBOARD, bvn=BVN)
        assert store.raw_dump() == []

    def test_denial_still_denied_when_audit_is_down(self, parts):
        vault, store, _, keys, lookup = parts
        t = issue(vault)
        broken = Vault(store, keys, lookup, FailingAudit(), make_policy())
        with pytest.raises(VaultAccessDenied):
            broken.resolve(AGENT, t, PiiField.BVN, purpose="bureau_pull")

    def test_hostile_token_string_is_truncated_in_audit(self, parts):
        vault, _, audit, *_ = parts
        with pytest.raises(TokenNotFound):
            vault.resolve(GATEWAY, "subtok_" + "A" * 5000, PiiField.BVN, purpose="bureau_pull")
        assert max(len(e.token or "") for e in audit.events) <= 64


# ----------------------------------------------------------------- tampering

class TestTampering:
    def test_flipped_ciphertext_byte_is_rejected(self, parts):
        vault, store, *_ = parts
        t = issue(vault)
        rec = store.get_field(t, PiiField.BVN)
        bad = bytearray(rec.ciphertext)
        bad[-1] ^= 1
        store.put_field(rec.model_copy(update={"ciphertext": bytes(bad)}))
        with pytest.raises(DecryptionFailed):
            vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")

    def test_ciphertext_swapped_between_subscribers_is_rejected(self, parts):
        vault, store, *_ = parts
        a, b = issue(vault, BVN), issue(vault, BVN_2)
        ra, rb = store.get_field(a, PiiField.BVN), store.get_field(b, PiiField.BVN)
        # Give subscriber A the whole encrypted record that belongs to B.
        store.put_field(ra.model_copy(update={"ciphertext": rb.ciphertext, "wrapped_dek": rb.wrapped_dek}))
        with pytest.raises(DecryptionFailed):
            vault.resolve(GATEWAY, a, PiiField.BVN, purpose="bureau_pull")

    def test_ciphertext_moved_to_another_field_is_rejected(self, parts):
        vault, store, *_ = parts
        t = issue(vault, nin=NIN)
        nin = store.get_field(t, PiiField.NIN)
        store.put_field(nin.model_copy(update={"pii_field": PiiField.BVN}))
        with pytest.raises(DecryptionFailed):
            vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")

    def test_unknown_key_id_is_rejected(self, parts):
        vault, store, *_ = parts
        t = issue(vault)
        rec = store.get_field(t, PiiField.BVN)
        store.put_field(rec.model_copy(update={"kek_id": "v-gone"}))
        with pytest.raises(DecryptionFailed):
            vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")

    def test_failed_decrypt_is_audited_as_error(self, parts):
        vault, store, audit, *_ = parts
        t = issue(vault)
        rec = store.get_field(t, PiiField.BVN)
        store.put_field(rec.model_copy(update={"ciphertext": rec.ciphertext[:-1] + b"\x00"}))
        with pytest.raises(DecryptionFailed):
            vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")
        assert audit.events[-1].outcome == "ERROR"


# ----------------------------------------------------------------- erasure

class TestErasure:
    def test_erase_removes_everything_readable(self, parts):
        vault, store, *_ = parts
        t = issue(vault, nin=NIN, phone=PHONE)
        before = [store.get_field(t, f) for f in (PiiField.BVN, PiiField.NIN, PiiField.PHONE)]
        lookup_hash = store.get_token(t).bvn_lookup
        assert all(before) and lookup_hash
        assert vault.erase(ADMIN, t, reason="DSAR_ERASURE") == 3
        with pytest.raises(TokenErased):
            vault.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")
        assert store.get_token(t).bvn_lookup is None  # no hash of the BVN is kept
        remaining = store.raw_dump()
        for rec in before:  # none of the encrypted material survives
            assert rec.ciphertext not in remaining and rec.wrapped_dek not in remaining
        assert lookup_hash.encode() not in remaining

    def test_erase_is_idempotent_and_audited(self, parts):
        vault, _, audit, *_ = parts
        t = issue(vault)
        assert vault.erase(ADMIN, t, reason="DSAR_ERASURE") == 1
        assert vault.erase(ADMIN, t, reason="DSAR_ERASURE") == 0
        erase_events = [e for e in audit.events if e.action == "ERASE"]
        assert [e.reason_code for e in erase_events] == ["DSAR_ERASURE", "ALREADY_ERASED"]

    def test_same_bvn_after_erasure_gets_a_new_unlinked_token(self, parts):
        vault, *_ = parts
        old = issue(vault)
        vault.erase(ADMIN, old, reason="DSAR_ERASURE")
        new = vault.tokenize(ONBOARD, bvn=BVN)
        assert new.created and new.token != old

    def test_cannot_write_to_erased_token(self, parts):
        vault, *_ = parts
        t = issue(vault)
        vault.erase(ADMIN, t, reason="DSAR_ERASURE")
        with pytest.raises(TokenErased):
            vault.set_field(ONBOARD, t, PiiField.PHONE, PHONE)

    def test_erase_unknown_token(self, parts):
        vault, *_ = parts
        with pytest.raises(TokenNotFound):
            vault.erase(ADMIN, "subtok_nope", reason="DSAR_ERASURE")

    @pytest.mark.parametrize("reason", ["free text with PII 22123456789", "", "lower_case", "X" * 41])
    def test_reason_must_be_a_short_code(self, parts, reason):
        vault, *_ = parts
        t = issue(vault)
        with pytest.raises(ValueError):
            vault.erase(ADMIN, t, reason=reason)


# ----------------------------------------------------------------- key rotation

class TestRotation:
    def test_rewrap_moves_everything_to_the_new_key(self, parts):
        vault, store, audit, _, lookup = parts
        k1, k2 = os.urandom(32), os.urandom(32)
        v1 = Vault(store, LocalKeyProvider({"v1": k1}, "v1"), lookup, audit, make_policy())
        tokens = [issue(v1, BVN, nin=NIN), issue(v1, BVN_2, phone=PHONE)]

        v2 = Vault(store, LocalKeyProvider({"v1": k1, "v2": k2}, "v2"), lookup, audit, make_policy())
        assert v2.resolve(GATEWAY, tokens[0], PiiField.BVN, purpose="bureau_pull") == BVN  # old data still reads
        assert v2.rewrap_batch(ADMIN, limit=2) == 2
        assert v2.rewrap_batch(ADMIN) == 2  # 4 fields total
        assert v2.rewrap_batch(ADMIN) == 0
        assert store.records_not_on_key("v2", 10) == []

        # The old master key can now be retired.
        v3 = Vault(store, LocalKeyProvider({"v2": k2}, "v2"), lookup, audit, make_policy())
        assert v3.resolve(GATEWAY, tokens[0], PiiField.BVN, purpose="bureau_pull") == BVN
        assert v3.resolve(GATEWAY, tokens[1], PiiField.BVN, purpose="bureau_pull") == BVN_2

    def test_rewrap_never_overwrites_a_newer_value(self, parts):
        vault, store, *_ = parts
        t = issue(vault, phone=PHONE)
        stale = store.get_field(t, PiiField.PHONE)
        vault.set_field(ONBOARD, t, PiiField.PHONE, "08051112222")  # someone updates it meanwhile
        assert store.rewrap_field(t, PiiField.PHONE, stale.wrapped_dek, b"x", "v2") is False
        assert vault.read_masked(SUPPORT, t, PiiField.PHONE, purpose="support_ticket").endswith("2222")


# ----------------------------------------------------------------- keys and config

class TestConfig:
    def test_short_lookup_key_rejected(self):
        with pytest.raises(ValueError):
            Vault(InMemoryVaultStore(), LocalKeyProvider({"v1": os.urandom(32)}, "v1"),
                  b"short", InMemoryAudit(), VaultPolicy())

    def test_master_key_must_be_32_bytes(self):
        with pytest.raises(ValueError):
            LocalKeyProvider({"v1": b"x" * 16}, "v1")
        with pytest.raises(ValueError):
            LocalKeyProvider({"v1": os.urandom(32)}, "v2")

    def test_from_env(self):
        k1, k2 = os.urandom(32), os.urandom(32)
        env = {
            "VAULT_KEKS": f"v1:{base64.b64encode(k1).decode()},v2:{base64.b64encode(k2).decode()}",
            "VAULT_KEK_CURRENT": "v2",
            "VAULT_LOOKUP_KEY": base64.b64encode(os.urandom(32)).decode(),
        }
        assert LocalKeyProvider.from_env(env).current_key_id == "v2"
        assert len(lookup_key_from_env(env)) == 32

    def test_from_env_missing(self):
        with pytest.raises(ValueError):
            LocalKeyProvider.from_env({})
        with pytest.raises(ValueError):
            lookup_key_from_env({})

    def test_key_service_outage_fails_closed(self, parts):
        vault, store, audit, _, lookup = parts
        t = issue(vault)

        class DownKms:
            current_key_id = "v1"
            def wrap(self, dek, aad): raise TimeoutError("kms")
            def unwrap(self, wrapped, aad, key_id): raise TimeoutError("kms")

        down = Vault(store, DownKms(), lookup, audit, make_policy())
        with pytest.raises(VaultUnavailable):
            down.resolve(GATEWAY, t, PiiField.BVN, purpose="bureau_pull")
        with pytest.raises(VaultUnavailable):
            down.tokenize(ONBOARD, bvn=BVN_2)
