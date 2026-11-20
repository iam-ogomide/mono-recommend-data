"""Run the JetStream usage-receipt consumer."""
from __future__ import annotations

import asyncio
import os
from decimal import Decimal, InvalidOperation

import nats
from dotenv import load_dotenv
from event_bus import ensure_streams

from .event_consumer import make_usage_worker
from .enforce import load_budgets
from .pricing import load_prices
from .redis_client import get_redis

load_dotenv()


def _required_fx_rate() -> Decimal:
    raw = os.getenv("USD_TO_NGN")
    if not raw:
        raise RuntimeError("Set USD_TO_NGN to the current naira-per-dollar rate.")
    try:
        rate = Decimal(raw)
    except InvalidOperation as error:
        raise ValueError("USD_TO_NGN must be a positive decimal number.") from error
    if not rate.is_finite() or rate <= 0:
        raise ValueError("USD_TO_NGN must be a positive decimal number.")
    return rate


async def serve() -> None:
    nats_url = os.getenv("NATS_URL")
    if not nats_url:
        raise RuntimeError("Set NATS_URL to the NATS server used by event_bus.")
    usd_to_ngn = _required_fx_rate()
    redis_client = get_redis()
    nc = None
    try:
        nc = await nats.connect(servers=nats_url)
        js = nc.jetstream()
        await ensure_streams(js)
        worker = make_usage_worker(
            js,
            prices=load_prices(),
            budgets=load_budgets(),
            usd_to_ngn=usd_to_ngn,
            redis_client=redis_client,
        )
        await worker.start()
        await worker.run_forever(asyncio.Event())
    finally:
        redis_client.close()
        if nc is not None:
            await nc.drain()


if __name__ == "__main__":
    asyncio.run(serve())
