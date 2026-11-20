from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace

import pytest
from event_bus import BusEvent, EventPublisher, Reject

from cost_tracker.counters import add_to_counters, day_key, event_key, quota_key
from cost_tracker.bad_receipts import redact_identifiers
from cost_tracker import consumer
from cost_tracker.enforce import load_budgets
from cost_tracker.event_consumer import (
    USAGE_EVENT_TYPE,
    publish_usage_receipt,
    usage_receipt_from_bus_event,
    usage_to_bus_event,
)
from cost_tracker.pricing import load_prices

OCCURRED_AT = datetime(2026, 11, 15, 8, 0, tzinfo=timezone.utc)
SUBSCRIBER_TOKEN = "subtok_" + "ab12" * 6


def receipt(**changes):
    value = {
        "event_id": "usage-1",
        "occurred_at": OCCURRED_AT,
        "source": "model_gateway",
        "tier": "external",
        "item": "external-llm:input",
        "quantity": 1200,
        "unit": "tokens",
        "plan": "standard",
        "subscriber_ref": SUBSCRIBER_TOKEN,
        "agent": "concierge",
    }
    return {**value, **changes}


def test_default_config_files_load_from_package_directory():
    assert "external-llm:input" in load_prices()
    assert "company" in load_budgets()


def test_usage_receipt_round_trips_through_the_existing_usage_stream_contract():
    bus_event = usage_to_bus_event(receipt(), received_at=OCCURRED_AT)
    assert bus_event.type == USAGE_EVENT_TYPE
    assert bus_event.subject == "ccq.events.model_gateway"
    assert bus_event.subject_token == SUBSCRIBER_TOKEN
    assert bus_event.payload["quantity"] == "1200.0"

    result = usage_receipt_from_bus_event(bus_event)
    assert result == {
        **receipt(),
        "quantity": "1200.0",
    }


@pytest.mark.asyncio
async def test_publisher_routes_receipts_to_the_existing_usage_stream():
    class JetStream:
        async def publish(self, subject, data, headers=None, timeout=None):
            self.published = (subject, data, headers, timeout)
            return SimpleNamespace(stream="CCQ_USAGE", seq=1, duplicate=False)

    js = JetStream()
    result = await publish_usage_receipt(EventPublisher(js), receipt())
    subject, raw, headers, _ = js.published

    assert subject == "ccq.usage.model_gateway"
    assert headers["Nats-Msg-Id"] == "usage-1"
    assert result.stream == "CCQ_USAGE"
    assert BusEvent.model_validate_json(raw).type == USAGE_EVENT_TYPE


def test_usage_stream_consumer_rejects_non_receipt_events():
    event = BusEvent(
        event_id="not-a-receipt",
        source="model_gateway",
        type="model.response",
        occurred_at=OCCURRED_AT,
        received_at=OCCURRED_AT,
        subject_token=SUBSCRIBER_TOKEN,
    )
    with pytest.raises(Reject, match="UNSUPPORTED_USAGE_EVENT"):
        usage_receipt_from_bus_event(event)


def test_usage_receipt_rejects_identifiers_in_subscriber_reference():
    with pytest.raises(ValueError, match="identifier"):
        usage_to_bus_event(receipt(subscriber_ref="08031234567"))


def test_bus_receipt_with_identifier_is_sanitized_and_set_aside():
    event = usage_to_bus_event(receipt())
    unsafe_event = event.model_copy(update={"payload": {**event.payload, "agent": "a@b.com"}})

    sanitized = usage_receipt_from_bus_event(unsafe_event)
    assert sanitized["agent"] == "[HIDDEN]"
    assert sanitized["_identifier_rejected"] is True
    assert "a@b.com" not in str(sanitized)


def test_bad_receipt_sanitizer_redacts_nested_identifier_values():
    assert redact_identifiers({
        "subscriber_ref": "08031234567",
        "22123456789": 1,
        "nested": ["safe", "a@b.com", 22123456789],
    }) == {
        "subscriber_ref": "[HIDDEN]",
        "[HIDDEN]": 1,
        "nested": ["safe", "[HIDDEN]", "[HIDDEN]"],
    }


class FakeRedis:
    def __init__(self):
        self.seen = set()
        self.values = {}

    def eval(self, script, key_count, spend, quota, marker, cost, quantity):
        assert "SET" in script and "INCRBY" in script
        assert key_count == 3
        if marker in self.seen:
            return 0
        self.seen.add(marker)
        self.values[spend] = self.values.get(spend, 0) + int(cost)
        self.values[quota] = self.values.get(quota, 0) + int(quantity)
        return 1


def test_counter_updates_are_idempotent_for_jetstream_redelivery():
    client = FakeRedis()
    row = {
        "event_id": "usage-1",
        "occurred_at": OCCURRED_AT,
        "subscriber_ref": SUBSCRIBER_TOKEN,
        "unit": "tokens",
        "cost_ngn": Decimal("12.3456"),
        "quantity": Decimal("1200"),
    }

    add_to_counters(client, row)
    add_to_counters(client, row)

    assert client.values == {
        day_key(OCCURRED_AT): 123456,
        quota_key(SUBSCRIBER_TOKEN, OCCURRED_AT, "tokens"): 1_200_000,
    }
    assert event_key("usage-1") in client.seen


def test_duplicate_ledger_receipt_repairs_counters_from_persisted_values(monkeypatch):
    client = FakeRedis()
    persisted = {}

    def write_row(connection, row):
        assert connection is not None
        if row["event_id"] in persisted:
            return False
        persisted[row["event_id"]] = row
        return True

    def saved_counters(connection, event_id):
        assert connection is not None
        row = persisted[event_id]
        return {
            key: row[key]
            for key in ("event_id", "occurred_at", "quantity", "unit", "subscriber_ref", "cost_ngn")
        }

    def fake_price(event, prices, rate):
        assert event.event_id == "usage-1" and prices == {} and rate == 1
        return {"cost_ngn": Decimal("12.3456")}

    monkeypatch.setattr(consumer, "price_event", fake_price)
    monkeypatch.setattr(
        consumer,
        "build_ledger_row",
        lambda event, priced: {
            "event_id": event.event_id,
            "occurred_at": event.occurred_at,
            "quantity": Decimal(str(event.quantity)),
            "unit": event.unit,
            "subscriber_ref": event.subscriber_ref,
            "cost_ngn": priced["cost_ngn"],
        },
    )
    monkeypatch.setattr(consumer, "write_ledger_row", write_row)
    monkeypatch.setattr(consumer, "load_ledger_counters", saved_counters)

    raw = receipt()
    assert consumer.handle_receipt(raw, {}, {}, object(), client, 1)["status"] == "recorded"
    assert consumer.handle_receipt(
        {**raw, "quantity": 2400}, {}, {}, object(), client, 1
    )["status"] == "duplicate"
    assert client.values[quota_key(SUBSCRIBER_TOKEN, OCCURRED_AT, "tokens")] == 1_200_000
