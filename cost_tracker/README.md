# Cost Tracker

The tracker consumes cost receipts from the repository's NATS JetStream
`CCQ_USAGE` stream, prices them in naira, writes the official ledger to
PostgreSQL, and updates Redis spend/quota counters. It does not charge users.

The architecture HTML in the repository describes this as a gateway-to-Cost
Tracker flow. The recommendation runner currently reads bureau reports that
have already been stored, so those reads are not counted as new bureau pulls.
Gateways should publish receipts when billable usage actually occurs.

## Run the consumer

From the repository root, set these values in the environment or `.env`:

- `NATS_URL`
- `USD_TO_NGN` (current naira-per-dollar rate)
- `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` (and optional `DB_PORT`,
  `DB_SSLMODE`)
- `REDIS_HOST`, `REDIS_PASSWORD` (and optional `REDIS_PORT`,
  `REDIS_USERNAME`, `REDIS_SSL`)

Apply the SQL files in `cost_tracker/sql/` to the PostgreSQL database, then run:

```powershell
python -m cost_tracker.run_worker
```

The worker uses the existing `event_bus` stream and consumer machinery. A
gateway can publish a `UsageEvent` with `publish_usage_receipt`; the anonymous
subscriber reference must be the vault's `subtok_...` token, never a BVN, name,
phone, email, or raw subscriber identifier.

Example receipt:

```python
from cost_tracker import publish_usage_receipt
from cost_tracker.usage_event import UsageEvent
from event_bus import EventPublisher

receipt = UsageEvent(
    source="model_gateway",
    tier="external",
    item="external-llm:input",
    quantity=1200,
    unit="tokens",
    plan="standard",
    subscriber_ref="subtok_ab12ab12ab12ab12ab12ab12",
)
await publish_usage_receipt(EventPublisher(js), receipt)
```

JetStream redelivers unacknowledged messages. PostgreSQL deduplicates ledger
rows by `event_id`, and Redis uses an atomic event marker so a replay cannot
double-count totals; a redelivery also repairs counters if Redis failed after
the ledger commit. Redis event markers persist; agree on a retention/rebuild
policy before scaling the tracker to high-volume traffic.

## Configuration and limits

`config/prices.yaml` and `config/budgets.yaml` are placeholders and must be
replaced with approved prices, plans, budgets, and current exchange-rate
operations before production use. The tracker currently keeps budget
enforcement disabled (`CHECK_LIMITS = False`) per the original business
decision; the enforcement helper is not a wallet debit or gateway control.

Dependencies are already listed in the repository's root `requirements.txt`.
