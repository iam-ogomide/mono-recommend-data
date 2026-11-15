import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from event_bus import (
    BusConfig, BusEvent, EventBusUnavailable, EventPublisher, EventWorker, IdentifierInEvent,
    InMemoryLastSeen, Reject, RetryLater, WorkerConfig, dead_subject, ensure_streams, stream_configs,
    watch_max_deliveries,
)

T0 = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)
FAST = WorkerConfig(batch=20, fetch_timeout=0.3, ack_wait=1.0, max_deliver=3, retry_delays=(0.05, 0.05, 0.05))


def event(i=1, **over):
    base = dict(event_id=f"wh-{i}", source="recova", type="recova.collection.failed",
                occurred_at=T0 + timedelta(seconds=i), received_at=T0 + timedelta(seconds=i, milliseconds=50),
                subject_token="subtok_" + "ab12" * 6, tenant="creditchek", entity_id="mandate-77",
                payload={"attempt": 2, "reason": "INSUFFICIENT_FUNDS"})
    base.update(over)
    return BusEvent(**base)


async def stream_msgs(js, stream):
    return (await js.stream_info(stream)).state.messages


async def dead_msgs(js):
    out, seq = [], 1
    info = await js.stream_info("CCQ_DEAD")
    for s in range(info.state.first_seq, info.state.last_seq + 1):
        try:
            out.append(await js.get_msg("CCQ_DEAD", s))
        except Exception:
            pass
    return out


async def make_worker(js, handler, *, durable="orch", cfg=FAST, **kw):
    w = EventWorker(js, stream="CCQ_EVENTS", durable=durable, subject="ccq.events.recova",
                    handler=handler, publisher=EventPublisher(js), config=cfg, **kw)
    await w.start()
    return w


# ---------------------------------------------------------------- the event contract

class TestContract:
    def test_valid_event_round_trips(self):
        e = event()
        assert BusEvent.model_validate_json(e.model_dump_json()) == e and e.subject == "ccq.events.recova"

    @pytest.mark.parametrize("over", [
        {"occurred_at": datetime(2026, 1, 1)},                       # naive time
        {"event_id": "has space"}, {"event_id": ""}, {"source": "Recova"}, {"type": "A.B"},
        {"subject_token": "22123456789"}, {"subject_token": "subtok_short"},
        {"payload": {"Bad Key": 1}}, {"payload": {"k": "x" * 201}},
        {"payload": {f"k{i}": i for i in range(31)}}, {"payload": {"k": {"nested": 1}}},
        {"schema_version": 2}, {"unknown_field": "x"},
    ])
    def test_bad_events_are_rejected(self, over):
        with pytest.raises(Exception):
            event(**over)

    def test_payload_size_cap(self):
        with pytest.raises(Exception):
            event(payload={f"k{i}": "x" * 190 for i in range(25)})

    def test_frozen(self):
        with pytest.raises(Exception):
            event().type = "x"

    @pytest.mark.parametrize("bad", ["22123456789", "08031234567", "+2348031234567", "a@b.com", "call 0803 123 4567"])
    def test_identifiers_in_payload_or_tenant_are_refused(self, bad):
        with pytest.raises(IdentifierInEvent):
            event(payload={"note": bad}).assert_no_identifiers()

    @pytest.mark.parametrize("bad", ["22123456789", "08031234567", "a@b.com"])
    def test_a_tenant_field_holding_an_identifier_is_refused(self, bad):
        e = event()
        object.__setattr__(e, "tenant", bad)          # the tenant pattern normally blocks '@'; test the guard itself
        with pytest.raises(IdentifierInEvent):
            e.assert_no_identifiers()

    def test_int_payload_value_that_is_a_bvn_is_refused(self):
        with pytest.raises(IdentifierInEvent):
            event(payload={"n": 22123456789}).assert_no_identifiers()

    def test_opaque_reference_ids_may_be_numeric(self):
        event(entity_id="22123456789", event_id="22123456789").assert_no_identifiers()   # not PII, just a reference

    def test_clean_event_passes(self):
        event().assert_no_identifiers()


# ---------------------------------------------------------------- streams

class TestStreams:
    async def test_ensure_streams_is_repeatable_and_updates_changes(self, bus):
        _, js = bus
        await ensure_streams(js, BusConfig())
        await ensure_streams(js, BusConfig(events_max_age_s=48 * 3600))
        info = await js.stream_info("CCQ_EVENTS")
        assert info.config.max_age == 48 * 3600 and info.config.duplicate_window == 24 * 3600
        assert [s.name for s in stream_configs(BusConfig())] == ["CCQ_EVENTS", "CCQ_BATCH", "CCQ_USAGE", "CCQ_DEAD"]

    @pytest.mark.parametrize("kw", [
        {"events_max_age_s": 3600},                    # shorter than the 24h dedupe window: server would refuse
        {"dedupe_window_s": 0}, {"replicas": 0}, {"replicas": 6}, {"dead_max_age_s": -1},
    ])
    def test_bad_config_is_refused_before_connecting(self, kw):
        with pytest.raises(ValueError):
            BusConfig(**kw)

    def test_dead_subject(self):
        assert dead_subject("ccq.events.recova") == "ccq.dead.events.recova"


# ---------------------------------------------------------------- publishing

class TestPublish:
    async def test_stores_the_event(self, bus):
        _, js = bus
        r = await EventPublisher(js).publish(event())
        assert (r.stream, r.seq, r.duplicate) == ("CCQ_EVENTS", 1, False)
        raw = await js.get_msg("CCQ_EVENTS", 1)
        assert BusEvent.model_validate_json(raw.data) == event()
        assert raw.headers["Nats-Msg-Id"] == "wh-1"

    async def test_same_webhook_id_is_stored_once(self, bus):
        _, js = bus
        pub = EventPublisher(js)
        first, again = await pub.publish(event()), await pub.publish(event())
        assert (first.duplicate, again.duplicate) == (False, True) and again.seq == first.seq
        assert await stream_msgs(js, "CCQ_EVENTS") == 1

    async def test_different_webhook_ids_are_both_stored(self, bus):
        _, js = bus
        pub = EventPublisher(js)
        await pub.publish(event(1)); await pub.publish(event(2))
        assert await stream_msgs(js, "CCQ_EVENTS") == 2

    async def test_event_with_an_identifier_is_refused_and_nothing_is_stored(self, bus):
        _, js = bus
        with pytest.raises(IdentifierInEvent):
            await EventPublisher(js).publish(event(payload={"note": "bvn 22123456789"}))
        assert await stream_msgs(js, "CCQ_EVENTS") == 0

    async def test_no_stream_for_the_subject_fails_closed_without_detail(self, bus):
        _, js = bus
        with pytest.raises(EventBusUnavailable) as e:
            await EventPublisher(js, timeout=0.5).publish_to("nowhere.at.all", event())
        assert str(e.value) == "BUS_PUBLISH_FAILED" and e.value.__suppress_context__

    async def test_closed_connection_fails_closed(self, nats_url):
        import nats
        nc = await nats.connect(nats_url)
        js = nc.jetstream()
        await nc.close()
        with pytest.raises(EventBusUnavailable):
            await EventPublisher(js, timeout=0.5).publish(event())


# ---------------------------------------------------------------- consuming

class TestConsume:
    async def test_handled_event_is_acked_and_lag_clears(self, bus):
        _, js = bus
        pub, seen = EventPublisher(js), []

        async def handler(e): seen.append(e.event_id)

        w = await make_worker(js, handler)
        for i in range(5):
            await pub.publish(event(i))
        assert (await w.lag()).pending == 5
        stats = await w.run_once()
        lag = await w.lag()
        assert stats.processed == 5 and seen == [f"wh-{i}" for i in range(5)]
        assert (lag.pending, lag.ack_pending) == (0, 0)

    async def test_nothing_is_acked_until_the_handler_finishes(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event())
        gate, states = asyncio.Event(), {}

        async def handler(e):
            await gate.wait()

        w = await make_worker(js, handler, cfg=WorkerConfig(batch=5, fetch_timeout=0.3, ack_wait=30, max_deliver=3))
        task = asyncio.create_task(w.run_once())
        await asyncio.sleep(0.4)
        lag = await w.lag()
        assert (lag.ack_pending, lag.pending) == (1, 0)          # delivered, still unacked
        gate.set()
        await task
        assert (await w.lag()).ack_pending == 0

    async def test_a_crash_before_ack_means_redelivery(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event())
        # a worker takes the message and dies without acking
        crashed = await make_worker(js, lambda e: None, cfg=FAST)
        msgs = await crashed._sub.fetch(1, timeout=1)
        assert msgs[0].metadata.num_delivered == 1
        await asyncio.sleep(1.3)                                  # ack_wait is 1s
        seen = []

        async def handler(e): seen.append(e.event_id)

        survivor = await make_worker(js, handler, cfg=FAST)
        stats = await survivor.run_once()
        assert stats.processed == 1 and seen == ["wh-1"]

    async def test_transient_failure_is_retried_then_succeeds(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event())
        calls = []

        async def handler(e):
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("db hiccup")

        w = await make_worker(js, handler, cfg=WorkerConfig(batch=5, fetch_timeout=0.3, ack_wait=1, max_deliver=5, retry_delays=(0.05,)))
        total = 0
        for _ in range(10):
            total += (await w.run_once()).processed
            if total:
                break
        assert len(calls) == 3 and total == 1 and await stream_msgs(js, "CCQ_DEAD") == 0

    async def test_exhausted_retries_go_to_dead_letters_with_a_code_and_no_content(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event())

        async def handler(e):
            raise ValueError("secret 22123456789 leaked in an error message")

        w = await make_worker(js, handler)
        dead = 0
        for _ in range(10):
            dead += (await w.run_once()).dead
            if dead:
                break
        assert dead == 1
        (m,) = await dead_msgs(js)
        assert m.subject == "ccq.dead.events.recova"
        assert m.headers["Ccq-Dead-Reason"] == "MAX_DELIVERIES:HANDLER_ERROR:ValueError"
        assert (m.headers["Ccq-Orig-Subject"], m.headers["Ccq-Orig-Seq"], m.headers["Ccq-Deliveries"]) == ("ccq.events.recova", "1", "3")
        assert BusEvent.model_validate_json(m.data) == event()          # original preserved for replay
        assert "22123456789" not in str(m.headers) + m.data.decode()
        lag = await w.lag()
        assert (lag.pending, lag.ack_pending) == (0, 0)                 # not stuck in the live consumer

    async def test_reject_goes_straight_to_dead_letters(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event())
        calls = []

        async def handler(e):
            calls.append(1)
            raise Reject("unknown event type")

        w = await make_worker(js, handler)
        stats = await w.run_once()
        (m,) = await dead_msgs(js)
        assert (stats.dead, len(calls), m.headers["Ccq-Dead-Reason"], m.headers["Ccq-Deliveries"]) == (1, 1, "UNKNOWN_EVENT_TYPE", "1")

    async def test_retry_later_uses_the_delay_and_counts_as_an_attempt(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event())
        times = []

        async def handler(e):
            times.append(asyncio.get_running_loop().time())
            if len(times) == 1:
                raise RetryLater(0.5)

        w = await make_worker(js, handler)
        await w.run_once()
        await asyncio.sleep(0.2)
        assert len(times) == 1                                         # not redelivered early
        for _ in range(5):
            if (await w.run_once()).processed:
                break
        assert len(times) == 2 and times[1] - times[0] >= 0.45

    async def test_poison_message_is_parked_and_the_good_ones_still_flow(self, bus):
        _, js = bus
        pub, seen = EventPublisher(js), []
        await js.publish("ccq.events.recova", b"{not json at all 22123456789")
        await js.publish("ccq.events.recova", json.dumps({"event_id": "x"}).encode())   # valid JSON, wrong shape
        await pub.publish(event(9))

        async def handler(e): seen.append(e.event_id)

        w = await make_worker(js, handler)
        stats = await w.run_once()
        dead = await dead_msgs(js)
        assert (stats.processed, stats.dead, seen) == (1, 2, ["wh-9"])
        assert {m.headers["Ccq-Dead-Reason"] for m in dead} == {"POISON_INVALID_EVENT"}

    async def test_if_dead_lettering_fails_the_message_is_kept_not_dropped(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event())

        async def handler(e): raise Reject("BAD")

        w = await make_worker(js, handler)
        real = w._pub.dead_letter

        async def broken(**kw): raise EventBusUnavailable("BUS_PUBLISH_FAILED")

        w._pub.dead_letter = broken
        stats = await w.run_once()
        assert stats.dead == 0 and await stream_msgs(js, "CCQ_DEAD") == 0
        w._pub.dead_letter = real
        await asyncio.sleep(0.1)
        stats = await w.run_once()
        assert stats.dead == 1 and await stream_msgs(js, "CCQ_DEAD") == 1

    async def test_dead_lettering_the_same_message_twice_stores_it_once(self, bus):
        _, js = bus
        pub = EventPublisher(js)
        for _ in range(2):
            await pub.dead_letter(subject="ccq.events.recova", data=b"{}", stream="CCQ_EVENTS", seq=7, deliveries=3, reason="X")
        assert await stream_msgs(js, "CCQ_DEAD") == 1

    async def test_a_restarted_worker_resumes_without_reprocessing(self, bus):
        _, js = bus
        pub, seen = EventPublisher(js), []
        for i in range(3):
            await pub.publish(event(i))

        async def handler(e): seen.append(e.event_id)

        await (await make_worker(js, handler)).run_once()
        for i in range(3, 5):
            await pub.publish(event(i))
        await (await make_worker(js, handler)).run_once()          # same durable name, new process
        assert seen == [f"wh-{i}" for i in range(5)]

    async def test_two_workers_share_the_load_and_each_event_is_handled_once(self, bus):
        _, js = bus
        pub, seen = EventPublisher(js), []
        for i in range(40):
            await pub.publish(event(i))

        async def handler(e):
            seen.append(e.event_id)
            await asyncio.sleep(0.005)

        cfg = WorkerConfig(batch=5, fetch_timeout=0.3, ack_wait=10, max_deliver=3)
        a, b = await make_worker(js, handler, cfg=cfg), await make_worker(js, handler, cfg=cfg)
        stop = asyncio.Event()
        ta, tb = asyncio.create_task(a.run_forever(stop)), asyncio.create_task(b.run_forever(stop))
        for _ in range(100):
            if len(seen) >= 40:
                break
            await asyncio.sleep(0.1)
        stop.set()
        await asyncio.gather(ta, tb)
        assert len(seen) == 40 and len(set(seen)) == 40


# ---------------------------------------------------------------- ordering

class TestOrdering:
    async def test_an_older_event_for_the_same_entity_is_skipped(self, bus):
        _, js = bus
        pub, seen = EventPublisher(js), []
        await pub.publish(event(2, event_id="late-arrival-of-newer", type="recova.mandate.paused"))
        await pub.publish(event(1, event_id="older-but-arrives-second", type="recova.collection.failed"))

        async def handler(e): seen.append(e.event_id)

        w = await make_worker(js, handler, ordering=InMemoryLastSeen())
        stats = await w.run_once()
        assert seen == ["late-arrival-of-newer"] and (stats.processed, stats.stale) == (1, 1)

    async def test_different_entities_do_not_block_each_other(self, bus):
        _, js = bus
        pub, seen = EventPublisher(js), []
        await pub.publish(event(5, entity_id="m-1")); await pub.publish(event(1, entity_id="m-2"))

        async def handler(e): seen.append(e.event_id)

        stats = await (await make_worker(js, handler, ordering=InMemoryLastSeen())).run_once()
        assert stats.processed == 2 and stats.stale == 0

    async def test_events_without_an_entity_id_are_never_skipped(self, bus):
        _, js = bus
        pub, seen = EventPublisher(js), []
        await pub.publish(event(5, entity_id=None)); await pub.publish(event(1, entity_id=None))

        async def handler(e): seen.append(e.event_id)

        assert (await (await make_worker(js, handler, ordering=InMemoryLastSeen())).run_once()).processed == 2

    async def test_a_failed_event_does_not_advance_the_marker(self, bus):
        _, js = bus
        pub, seen, fail = EventPublisher(js), [], [True]
        await pub.publish(event(2))

        async def handler(e):
            if fail[0]:
                raise RuntimeError("x")
            seen.append(e.event_id)

        store = InMemoryLastSeen()
        w = await make_worker(js, handler, ordering=store)
        await w.run_once()
        assert store.last("recova:mandate-77") is None
        fail[0] = False
        await asyncio.sleep(0.1)
        assert (await w.run_once()).processed == 1 and seen == ["wh-2"]     # retry not mistaken for stale

    async def test_redelivery_of_an_already_applied_event_runs_again_and_must_be_idempotent(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event(3))
        store = InMemoryLastSeen()
        store.mark("recova:mandate-77", event(3).occurred_at)     # same time as the event: not stale
        seen = []

        async def handler(e): seen.append(1)

        assert (await (await make_worker(js, handler, ordering=store)).run_once()).processed == 1


# ---------------------------------------------------------------- quiet hours, batch, advisories

class TestQuietHoursAndBatch:
    async def test_closed_gate_fetches_nothing_and_open_gate_drains(self, bus):
        _, js = bus
        await EventPublisher(js).publish(event())
        open_, seen = [False], []

        async def handler(e): seen.append(1)

        w = await make_worker(js, handler, gate=lambda: open_[0])
        stats = await w.run_once()
        assert stats.gated and seen == [] and (await w.lag()).pending == 1
        open_[0] = True
        assert (await w.run_once()).processed == 1 and (await w.lag()).pending == 0

    async def test_batch_stream_removes_work_once_acked(self, bus):
        _, js = bus
        await EventPublisher(js).publish_to("ccq.batch.answer_pack", event(source="batch", type="batch.answer_pack.build"))
        assert await stream_msgs(js, "CCQ_BATCH") == 1
        seen = []

        async def handler(e): seen.append(e.type)

        w = EventWorker(js, stream="CCQ_BATCH", durable="batcher", subject="ccq.batch.answer_pack", handler=handler,
                        publisher=EventPublisher(js), config=FAST)
        await w.start()
        await w.run_once()
        assert seen == ["batch.answer_pack.build"] and await stream_msgs(js, "CCQ_BATCH") == 0

    async def test_a_worker_that_keeps_crashing_still_ends_up_in_dead_letters(self, bus):
        nc, js = bus
        await EventPublisher(js).publish(event())
        pub = EventPublisher(js)
        cfg = WorkerConfig(batch=1, fetch_timeout=0.3, ack_wait=1.0, max_deliver=2)
        w = await make_worker(js, lambda e: None, cfg=cfg)
        sub = await watch_max_deliveries(nc, js, stream="CCQ_EVENTS", durable="orch", publisher=pub)
        for _ in range(2):                                      # take it twice and die each time, never acking
            assert len(await w._sub.fetch(1, timeout=2)) == 1
            await asyncio.sleep(1.3)
        with pytest.raises(Exception):                          # the next worker to poll triggers the server's advisory
            await w._sub.fetch(1, timeout=1)
        for _ in range(30):
            if await stream_msgs(js, "CCQ_DEAD"):
                break
            await asyncio.sleep(0.2)
        (m,) = await dead_msgs(js)
        assert m.headers["Ccq-Dead-Reason"] == "MAX_DELIVERIES:UNACKED" and BusEvent.model_validate_json(m.data) == event()
        await sub.unsubscribe()
