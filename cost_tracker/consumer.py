"""Receipt processing for the PostgreSQL ledger and Redis counters.

It has two entry points:
- handle_receipt: takes one receipt through the whole line.
- handle_safely: does the same, but saves a bad receipt in the
  bad_receipts table so it cannot stop the line.
"""

from .bad_receipts import save_bad_receipt
from .counters import add_to_counters
from .enforce import check_limits, send_signal
from .ledger import build_ledger_row, load_ledger_counters, write_ledger_row
from .pricing import price_event, UnknownItemError
from .usage_event import UsageEvent

# The business says there is no daily budget, only pay-as-you-go
# from the user's wallet. So the limit check is switched OFF.
# Change this to True if limits are ever wanted again.
CHECK_LIMITS = False


def handle_receipt(raw, prices, budgets, connection, redis_client, usd_to_ngn):
    # Step 1: check the receipt is filled in properly.
    # A bad receipt stops here with an error.
    event = UsageEvent.model_validate(raw)

    # Step 2: price it in naira.
    priced = price_event(event, prices, usd_to_ngn)

    # Step 3: write it in the ledger (the official record).
    row = build_ledger_row(event, priced)
    is_new = write_ledger_row(connection, row)

    # Redis may have failed after the ledger commit on an earlier delivery.
    # Use persisted values and an atomic event marker to make repair safe.
    counter_row = row if is_new else load_ledger_counters(connection, event.event_id)
    add_to_counters(redis_client, counter_row)

    # Steps 5 and 6: check the limits and tell the gateway.
    # These only run when CHECK_LIMITS is True.
    limits = None
    if CHECK_LIMITS and is_new:
        limits = check_limits(redis_client, budgets, event.subscriber_ref, event.plan)
        send_signal(limits)

    if not is_new:
        return {"status": "duplicate", "event_id": event.event_id}

    return {
        "status": "recorded",
        "event_id": event.event_id,
        "cost_ngn": row["cost_ngn"],
        "limits": limits,
    }


def handle_safely(raw, prices, budgets, connection, redis_client, usd_to_ngn):
    # Same as handle_receipt, but one bad receipt cannot stop the line.
    try:
        return handle_receipt(
            raw, prices, budgets, connection, redis_client, usd_to_ngn
        )
    except (ValueError, UnknownItemError) as error:
        # The receipt itself is wrong. Save it in the bad_receipts table
        # and carry on with the next one.
        connection.rollback()  # clear any half-finished database work first
        save_bad_receipt(connection, raw, str(error))
        return {"status": "set_aside"}
    # Other errors, like the database being down, are NOT caught here,
    # so they are not hidden and the receipt can be tried again later.

