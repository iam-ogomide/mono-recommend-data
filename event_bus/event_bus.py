"""Events bus (NATS JetStream)
============================
Carries tokenized events from Webhook ingress to the Orchestrator, queues quiet-hours batches,
and holds dead letters. Per the architecture doc: events are published with the webhook id as
Nats-Msg-Id (duplicates dropped), consumers are durable with explicit acks (a crash means
redelivery), and the bus never carries direct identifiers.

What this module does
  - BusEvent: the one event shape. Strict, versioned. No real identifiers: values that look like
    a BVN, NIN, phone or email are REJECTED, not redacted (ingress should have tokenized them).
  - EventPublisher: publishes with Nats-Msg-Id = event_id. Fails closed: if the bus did not
    confirm storage, it raises EventBusUnavailable and the caller must not treat the event as queued.
  - ensure_streams: creates or updates the streams (events, batch, usage, dead).
  - EventWorker: durable pull consumer. Acks only after the handler finishes. Retries with delay,
    sends poison and exhausted messages to the dead-letter stream, skips stale events per entity.
  - watch_max_deliveries: catches messages that ran out of deliveries because the worker kept
    crashing before it could dead-letter them.

What it does NOT do (read this)
  - Exactly-once. JetStream gives at-least-once. Dedupe on publish covers retries within the
    dedupe window only. Handlers MUST be idempotent: redelivery after a crash is normal.
  - Reorder. A stale event (older than what was already applied for the same entity_id) is
    skipped, not reordered. The skip decision needs a LastSeenStore; the in-memory one is
    for tests. In production back it with Postgres or Redis.
  - Catch missed webhooks. Ingress acknowledges CreditChek first, then publishes. If the publish
    fails after the 200, the event is lost unless the reconciliation job (not built here) finds it.
  - Name things for you. Stream names, retention and the dedupe window below are my defaults.
    Check them against Platform's NATS setup before use.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Literal, Protocol

import nats.errors
from nats.js.api import (
    AckPolicy, ConsumerConfig, RetentionPolicy, StorageType, StreamConfig,
)
from nats.js.errors import BadRequestError, NotFoundError
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Shared with the audit log so both use one definition of "looks like an identifier".
try:
    from audit_logs.audit_log import looks_like_identifier
except ModuleNotFoundError as exc:
    if exc.name != "audit_logs":
        raise
    from audit_log import looks_like_identifier

EVENTS_STREAM, BATCH_STREAM, USAGE_STREAM, DEAD_STREAM = "CCQ_EVENTS", "CCQ_BATCH", "CCQ_USAGE", "CCQ_DEAD"
EVENTS_PREFIX, BATCH_PREFIX, USAGE_PREFIX, DEAD_PREFIX = "ccq.events", "ccq.batch", "ccq.usage", "ccq.dead"

MAX_PAYLOAD_BYTES = 4096
MAX_PAYLOAD_KEYS = 30
MAX_VALUE = 200

_SAFE_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_KEY = re.compile(r"[a-z][a-z0-9_]{0,39}")


# ======================================================================
# ERRORS
# ======================================================================

class EventBusError(Exception):
    """Base. Messages are fixed codes, never event content."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class EventBusUnavailable(EventBusError):
    """The bus did not confirm that the event is stored."""


class IdentifierInEvent(EventBusError):
    """A value looks like a real identifier. Tokenize before publishing."""


class Reject(Exception):
    """Raise from a handler: this event can never succeed. Goes to dead letters, no retries."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = re.sub(r"[^A-Z0-9_]", "_", code.upper())[:40] or "REJECTED"


class RetryLater(Exception):
    """Raise from a handler: try again after `delay` seconds (counts as a delivery attempt)."""

    def __init__(self, delay: float | None = None):
        super().__init__("RETRY_LATER")
        self.delay = delay


# ======================================================================
# THE EVENT
# ======================================================================

class BusEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    event_id: str = Field(pattern=f"^{_SAFE_ID}$")      # the webhook id; becomes Nats-Msg-Id
    source: str = Field(pattern=r"^[a-z][a-z0-9_]{0,23}$")        # recova, income, credit ...
    type: str = Field(pattern=r"^[a-z][a-z0-9_.]{0,63}$")         # recova.collection.failed
    occurred_at: datetime                                          # when it happened at the source
    received_at: datetime                                          # when ingress got it
    subject_token: str | None = Field(default=None, pattern=r"^subtok_[0-9a-f]{24}$")
    tenant: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    # Opaque reference used to order events (for example a mandate id). Never a name, BVN or phone.
    entity_id: str | None = Field(default=None, pattern=f"^{_SAFE_ID}$")
    trace_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    payload: dict[str, str | int | bool | None] = {}

    @field_validator("occurred_at", "received_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must carry a timezone")
        return v.astimezone(timezone.utc)

    @field_validator("payload")
    @classmethod
    def _payload_ok(cls, v: dict) -> dict:
        if len(v) > MAX_PAYLOAD_KEYS:
            raise ValueError("payload has too many keys")
        for key, value in v.items():
            if not _KEY.fullmatch(key):
                raise ValueError("payload keys must be snake_case")
            if isinstance(value, str) and len(value) > MAX_VALUE:
                raise ValueError("payload value too long")
        if len(json.dumps(v)) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload too large")
        return v

    def assert_no_identifiers(self) -> None:
        """Raises IdentifierInEvent. Checks payload values, tenant and token, not the opaque ids."""
        values = [self.tenant, self.subject_token, *self.payload.values()]
        for v in values:
            if v is not None and looks_like_identifier(str(v)):
                raise IdentifierInEvent("IDENTIFIER_IN_EVENT")

    @property
    def subject(self) -> str:
        return f"{EVENTS_PREFIX}.{self.source}"


def dead_subject(original_subject: str) -> str:
    """ccq.events.recova -> ccq.dead.events.recova"""
    return f"{DEAD_PREFIX}.{original_subject.removeprefix('ccq.')}"


# ======================================================================
# STREAMS
# ======================================================================

@dataclass(frozen=True)
class BusConfig:
    replicas: int = 1                        # use 3 in production
    dedupe_window_s: float = 24 * 3600       # how long a repeated Nats-Msg-Id is dropped
    events_max_age_s: float = 7 * 24 * 3600
    usage_max_age_s: float = 90 * 24 * 3600
    dead_max_age_s: float = 30 * 24 * 3600

    def __post_init__(self):
        ages = (self.events_max_age_s, self.usage_max_age_s, self.dead_max_age_s)
        if self.dedupe_window_s <= 0 or min(ages) <= 0 or not 1 <= self.replicas <= 5:
            raise ValueError("BusConfig: windows must be positive and replicas between 1 and 5")
        if self.dedupe_window_s > min(ages):        # the server refuses this, so fail before connecting
            raise ValueError("BusConfig: dedupe_window_s cannot be longer than any stream's max age")


def stream_configs(cfg: BusConfig) -> list[StreamConfig]:
    common = dict(storage=StorageType.FILE, num_replicas=cfg.replicas, duplicate_window=cfg.dedupe_window_s)
    return [
        StreamConfig(name=EVENTS_STREAM, subjects=[f"{EVENTS_PREFIX}.>"], retention=RetentionPolicy.LIMITS,
                     max_age=cfg.events_max_age_s, **common),
        # Work waits here until quiet hours. WORK_QUEUE removes an item once it is acked.
        StreamConfig(name=BATCH_STREAM, subjects=[f"{BATCH_PREFIX}.>"], retention=RetentionPolicy.WORK_QUEUE,
                     max_age=cfg.events_max_age_s, **common),
        StreamConfig(name=USAGE_STREAM, subjects=[f"{USAGE_PREFIX}.>"], retention=RetentionPolicy.LIMITS,
                     max_age=cfg.usage_max_age_s, **common),
        StreamConfig(name=DEAD_STREAM, subjects=[f"{DEAD_PREFIX}.>"], retention=RetentionPolicy.LIMITS,
                     max_age=cfg.dead_max_age_s, **common),
    ]


async def ensure_streams(js, cfg: BusConfig | None = None) -> None:
    """Create each stream, or update it if it exists. Safe to run on every start."""
    for sc in stream_configs(cfg or BusConfig()):
        try:
            await js.add_stream(sc)
        except BadRequestError:
            await js.update_stream(sc)


# ======================================================================
# PUBLISHING
# ======================================================================

@dataclass(frozen=True)
class PublishResult:
    stream: str
    seq: int
    duplicate: bool


class EventPublisher:
    def __init__(self, js, *, timeout: float = 2.0):
        self._js = js
        self._timeout = timeout

    async def publish(self, event: BusEvent) -> PublishResult:
        """Store the event. A duplicate (same event_id inside the dedupe window) is not an error:
        it returns duplicate=True and nothing new is stored."""
        event.assert_no_identifiers()
        return await self._send(event.subject, event.model_dump_json().encode(), event.event_id)

    async def publish_to(self, subject: str, event: BusEvent) -> PublishResult:
        """For batch and usage subjects (ccq.batch.*, ccq.usage.*)."""
        event.assert_no_identifiers()
        return await self._send(subject, event.model_dump_json().encode(), event.event_id)

    async def dead_letter(self, *, subject: str, data: bytes, stream: str, seq: int, deliveries: int, reason: str) -> None:
        headers = {
            "Nats-Msg-Id": f"dead-{stream}-{seq}",          # dead-lettering twice stores once
            "Ccq-Dead-Reason": reason,
            "Ccq-Orig-Subject": subject,
            "Ccq-Orig-Stream": stream,
            "Ccq-Orig-Seq": str(seq),
            "Ccq-Deliveries": str(deliveries),
        }
        await self._send(dead_subject(subject), data, None, headers)

    async def _send(self, subject: str, data: bytes, msg_id: str | None, headers: dict | None = None) -> PublishResult:
        h = dict(headers or {})
        if msg_id:
            h["Nats-Msg-Id"] = msg_id
        try:
            ack = await self._js.publish(subject, data, headers=h or None, timeout=self._timeout)
        except Exception:
            raise EventBusUnavailable("BUS_PUBLISH_FAILED") from None
        return PublishResult(stream=ack.stream, seq=ack.seq, duplicate=bool(ack.duplicate))


# ======================================================================
# ORDERING
# ======================================================================

class LastSeenStore(Protocol):
    """Remembers the newest occurred_at applied per entity. Must survive restarts in production."""

    def last(self, key: str) -> datetime | None: ...
    def mark(self, key: str, at: datetime) -> None: ...


class InMemoryLastSeen:
    def __init__(self):
        self._d: dict[str, datetime] = {}

    def last(self, key: str) -> datetime | None:
        return self._d.get(key)

    def mark(self, key: str, at: datetime) -> None:
        if key not in self._d or at > self._d[key]:
            self._d[key] = at


def ordering_key(event: BusEvent) -> str | None:
    return f"{event.source}:{event.entity_id}" if event.entity_id else None


# ======================================================================
# CONSUMING
# ======================================================================

Handler = Callable[[BusEvent], Awaitable[None]]


@dataclass(frozen=True)
class WorkerConfig:
    batch: int = 10
    fetch_timeout: float = 1.0
    ack_wait: float = 30.0                       # must exceed the slowest handler
    max_deliver: int = 5
    retry_delays: tuple[float, ...] = (1.0, 5.0, 30.0, 120.0)


@dataclass
class RunStats:
    processed: int = 0
    retried: int = 0
    dead: int = 0
    stale: int = 0
    gated: bool = False


@dataclass(frozen=True)
class Lag:
    pending: int          # in the stream, not yet delivered
    ack_pending: int      # delivered, waiting for ack
    redelivered: int


class EventWorker:
    def __init__(self, js, *, stream: str, durable: str, subject: str, handler: Handler,
                 publisher: EventPublisher, config: WorkerConfig | None = None,
                 ordering: LastSeenStore | None = None, gate: Callable[[], bool] | None = None):
        self._js, self._stream, self._durable, self._subject = js, stream, durable, subject
        self._handler, self._pub = handler, publisher
        self._cfg = config or WorkerConfig()
        self._ordering, self._gate = ordering, gate
        self._sub = None

    async def start(self) -> None:
        self._sub = await self._js.pull_subscribe(
            self._subject, durable=self._durable, stream=self._stream,
            config=ConsumerConfig(
                ack_policy=AckPolicy.EXPLICIT, ack_wait=self._cfg.ack_wait,
                max_deliver=self._cfg.max_deliver, filter_subject=self._subject),
        )

    async def lag(self) -> Lag:
        info = await self._js.consumer_info(self._stream, self._durable)
        return Lag(info.num_pending, info.num_ack_pending, info.num_redelivered)

    async def run_once(self) -> RunStats:
        """Fetch one batch and handle it. If a gate is set and closed, fetch nothing (quiet hours)."""
        stats = RunStats()
        if self._gate is not None and not self._gate():
            stats.gated = True
            return stats
        try:
            msgs = await self._sub.fetch(self._cfg.batch, timeout=self._cfg.fetch_timeout)
        except nats.errors.TimeoutError:
            return stats
        for msg in msgs:
            await self._handle(msg, stats)
        return stats

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.run_once()

    async def _handle(self, msg, stats: RunStats) -> None:
        meta = msg.metadata
        deliveries, seq = meta.num_delivered, meta.sequence.stream
        last_try = deliveries >= self._cfg.max_deliver

        try:
            event = BusEvent.model_validate_json(msg.data)
        except Exception:
            return await self._dead(msg, seq, deliveries, "POISON_INVALID_EVENT", stats)

        key = ordering_key(event)
        if self._ordering is not None and key is not None:
            seen = self._ordering.last(key)
            if seen is not None and event.occurred_at < seen:
                await self._ack(msg)                  # older than what we already applied: nothing to do
                stats.stale += 1
                return

        try:
            await self._handler(event)
        except Reject as r:
            return await self._dead(msg, seq, deliveries, r.code, stats)
        except RetryLater as r:
            return await self._retry(msg, seq, deliveries, last_try, "RETRY_LATER", r.delay, stats)
        except Exception as e:                        # the class name only: messages may hold content
            return await self._retry(msg, seq, deliveries, last_try, f"HANDLER_ERROR:{type(e).__name__}"[:40], None, stats)

        if self._ordering is not None and key is not None:
            self._ordering.mark(key, event.occurred_at)
        await self._ack(msg)
        stats.processed += 1

    async def _ack(self, msg) -> None:
        """Wait for the server to confirm the ack. If the confirmation is lost the message comes
        back after ack_wait, which is safe because handlers are idempotent."""
        try:
            await msg.ack_sync(timeout=self._cfg.fetch_timeout + 2)
        except Exception:
            pass

    async def _retry(self, msg, seq, deliveries, last_try, code, delay, stats) -> None:
        if last_try:
            return await self._dead(msg, seq, deliveries, f"MAX_DELIVERIES:{code}"[:60], stats)
        if delay is None:
            idx = min(deliveries - 1, len(self._cfg.retry_delays) - 1)
            delay = self._cfg.retry_delays[idx]
        await msg.nak(delay=delay)
        stats.retried += 1

    async def _dead(self, msg, seq, deliveries, reason, stats) -> None:
        try:
            await self._pub.dead_letter(subject=msg.subject, data=msg.data, stream=self._stream,
                                        seq=seq, deliveries=deliveries, reason=reason)
        except EventBusUnavailable:
            await msg.nak(delay=self._cfg.retry_delays[0])   # could not park it: keep it, never drop it
            return
        await msg.term()
        stats.dead += 1


# ======================================================================
# MESSAGES THAT RAN OUT OF DELIVERIES
# ======================================================================

async def watch_max_deliveries(nc, js, *, stream: str, durable: str, publisher: EventPublisher):
    """If a worker keeps crashing, JetStream eventually stops redelivering and the message is
    stranded. JetStream announces that on an advisory subject. This listener copies such messages
    to the dead-letter stream. Advisories are not stored: run this as a long-lived process, and
    know that any advisory sent while it was down is missed. The server sends the advisory the
    next time a consumer polls after the last delivery expired, so it appears as soon as any
    worker for that durable is running. Returns the subscription."""

    async def on_advisory(msg) -> None:
        try:
            adv = json.loads(msg.data)
            seq = int(adv["stream_seq"])
            raw = await js.get_msg(stream, seq)
            await publisher.dead_letter(subject=raw.subject, data=raw.data, stream=stream, seq=seq,
                                        deliveries=int(adv.get("deliveries", 0)), reason="MAX_DELIVERIES:UNACKED")
        except (NotFoundError, EventBusUnavailable, KeyError, ValueError):
            pass   # message already gone, or bus down; the next sweep or an operator picks it up

    return await nc.subscribe(f"$JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES.{stream}.{durable}", cb=on_advisory)
