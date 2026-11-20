"""Publish and consume usage receipts on the repository's NATS usage stream."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Mapping

from event_bus import (
    USAGE_PREFIX,
    USAGE_STREAM,
    BusEvent,
    EventPublisher,
    EventWorker,
    IdentifierInEvent,
    Reject,
)
from audit_logs.audit_log import looks_like_identifier

from .consumer import handle_safely
from .db import get_connection
from .enforce import load_budgets
from .pricing import load_prices
from .redis_client import get_redis
from .usage_event import UsageEvent

USAGE_EVENT_TYPE = "usage.receipt"
USAGE_DURABLE = "cost-tracker"


def usage_to_bus_event(
    receipt: UsageEvent | Mapping[str, Any],
    *,
    received_at: datetime | None = None,
) -> BusEvent:
    event = UsageEvent.model_validate(receipt)
    event = BusEvent(
        event_id=event.event_id,
        source=event.source,
        type=USAGE_EVENT_TYPE,
        occurred_at=event.occurred_at,
        received_at=received_at or datetime.now(timezone.utc),
        subject_token=event.subscriber_ref,
        payload={
            "tier": event.tier,
            "item": event.item,
            "quantity": str(event.quantity),
            "unit": event.unit,
            "plan": event.plan,
            "agent": event.agent,
        },
    )
    event.assert_no_identifiers()
    return event


async def publish_usage_receipt(publisher: EventPublisher, receipt: UsageEvent | Mapping[str, Any]):
    event = usage_to_bus_event(receipt)
    return await publisher.publish_to(f"{USAGE_PREFIX}.{event.source}", event)


def usage_receipt_from_bus_event(event: BusEvent) -> dict[str, Any]:
    if event.type != USAGE_EVENT_TYPE:
        raise Reject("UNSUPPORTED_USAGE_EVENT")
    invalid_identifier = False
    try:
        event.assert_no_identifiers()
    except IdentifierInEvent:
        invalid_identifier = True
    payload = {}
    for key, value in event.payload.items():
        if value is not None and looks_like_identifier(str(value)):
            payload[key] = "[HIDDEN]"
            invalid_identifier = True
            continue
        payload[key] = value
    receipt = {
        "event_id": event.event_id,
        "occurred_at": event.occurred_at,
        "source": event.source,
        "subscriber_ref": event.subject_token,
        **payload,
    }
    if invalid_identifier:
        receipt["_identifier_rejected"] = True
    return receipt


def make_usage_worker(
    js,
    *,
    prices: dict | None = None,
    budgets: dict | None = None,
    usd_to_ngn: Decimal | str | int,
    connection_factory: Callable = get_connection,
    redis_client=None,
    publisher: EventPublisher | None = None,
) -> EventWorker:
    prices = prices if prices is not None else load_prices()
    budgets = budgets if budgets is not None else load_budgets()
    redis_client = redis_client if redis_client is not None else get_redis()
    publisher = publisher if publisher is not None else EventPublisher(js)

    async def handle(event: BusEvent) -> None:
        receipt = usage_receipt_from_bus_event(event)
        with connection_factory() as connection:
            handle_safely(receipt, prices, budgets, connection, redis_client, usd_to_ngn)

    return EventWorker(
        js,
        stream=USAGE_STREAM,
        durable=USAGE_DURABLE,
        subject=f"{USAGE_PREFIX}.>",
        handler=handle,
        publisher=publisher,
    )
