"""
counters.py

The tally keeper. She keeps quick running totals on the whiteboard (Redis).
The ledger (PostgreSQL) is still the official record.
If Redis is ever lost, the totals can be rebuilt from the ledger.
"""

from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP

# Every key starts with this, so we never mix with other projects' keys.
PREFIX = "cost_tracker"

# Redis adds whole numbers exactly, so we store money and amounts as
# whole numbers: money in 1/10,000 of a naira, amounts in thousandths.
MONEY_SCALE = 10_000
QUANTITY_SCALE = 1_000

_ADD_COUNTERS_ONCE = """
if redis.call("SET", KEYS[3], "1", "NX") then
    redis.call("INCRBY", KEYS[1], ARGV[1])
    redis.call("INCRBY", KEYS[2], ARGV[2])
    return 1
end
return 0
"""


def to_whole(value, scale):
    # Turn an exact Decimal into a whole number, e.g. 300 naira -> 3000000.
    return int((Decimal(value) * scale).to_integral_value(rounding=ROUND_HALF_UP))


def from_whole(number, scale):
    # Turn the whole number back into a normal Decimal.
    return Decimal(number) / scale


def day_key(when):
    # The label for the company's spend on one day.
    return f"{PREFIX}:spend:day:{when:%Y-%m-%d}"


def quota_key(subscriber_ref, when, unit):
    # The label for one person's usage of one unit in one month.
    return f"{PREFIX}:quota:{subscriber_ref}:{when:%Y-%m}:{unit}"


def event_key(event_id):
    return f"{PREFIX}:processed:{event_id}"


def add_to_counters(client, row):
    """Add a ledger row once, even when JetStream redelivers its receipt."""
    when = row["occurred_at"]
    client.eval(
        _ADD_COUNTERS_ONCE,
        3,
        day_key(when),
        quota_key(row["subscriber_ref"], when, row["unit"]),
        event_key(row["event_id"]),
        to_whole(row["cost_ngn"], MONEY_SCALE),
        to_whole(row["quantity"], QUANTITY_SCALE),
    )


def get_day_spend(client, when):
    # How much naira has the company spent on this day?
    raw = client.get(day_key(when))
    return from_whole(int(raw), MONEY_SCALE) if raw else Decimal("0")


def get_quota_used(client, subscriber_ref, when, unit):
    # How much of this unit has this person used this month?
    raw = client.get(quota_key(subscriber_ref, when, unit))
    return from_whole(int(raw), QUANTITY_SCALE) if raw else Decimal("0")