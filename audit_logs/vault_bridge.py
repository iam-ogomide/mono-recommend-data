"""Connects the PII vault to the shared audit log.

    vault = Vault(store, keys, lookup_key, VaultAuditSink(audit_log), policy)

The vault calls record() before it returns anything. If the audit log cannot store the event,
record() raises, the vault turns that into VaultUnavailable, and no value leaves. (For denials
the vault carries on and still refuses, since refusing needs no audit to be safe.)

Mapping:
  RESOLVE, READ_MASKED  -> UNMASK       (a real value, or its last four digits, was asked for)
  everything else       -> VAULT_ADMIN  (TOKENIZE, SET_FIELD, ERASE, ROTATE)
The vault's own timestamp is ignored. The log stamps its own.

This module reads the vault's event by attribute name and does not import the vault, so the two
packages can be built and released separately.
"""
from __future__ import annotations

if __package__:
    from .audit_log import ActorKind, AuditEvent, AuditLog, EventType, Outcome
else:
    from audit_log import ActorKind, AuditEvent, AuditLog, EventType, Outcome

_UNMASK_ACTIONS = frozenset({"RESOLVE", "READ_MASKED"})


class VaultAuditSink:
    def __init__(self, log: AuditLog):
        self._log = log

    def record(self, event) -> None:
        details = {}
        if getattr(event, "pii_field", None):
            details["pii_field"] = event.pii_field
        if getattr(event, "purpose", None):
            details["purpose"] = event.purpose
        self._log.append(AuditEvent(
            event_type=EventType.UNMASK if event.action in _UNMASK_ACTIONS else EventType.VAULT_ADMIN,
            outcome=Outcome(event.outcome),
            actor=event.caller or "unknown",
            actor_kind=ActorKind.SERVICE,
            action=event.action,
            subject=event.token,
            trace_id=event.trace_id,
            reason_code=event.reason_code,
            details=details,
        ))  # raises AuditUnavailable on failure, which is what the vault needs
