"""
bad_receipts.py

The home of the bad pile. A receipt that can never be processed
is saved here with the reason, so a person can look at it later.
"""

from psycopg.types.json import Jsonb

from audit_logs.audit_log import looks_like_identifier


def redact_identifiers(value):
    if isinstance(value, (str, int)) and not isinstance(value, bool):
        return "[HIDDEN]" if looks_like_identifier(str(value)) else value
    if isinstance(value, dict):
        return {
            "[HIDDEN]" if looks_like_identifier(str(key)) else key: redact_identifiers(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_identifiers(item) for item in value]
    return value


def save_bad_receipt(connection, raw, error):
    safe_raw = redact_identifiers(raw)
    safe_error = redact_identifiers(error)
    event_id = raw.get("event_id") if isinstance(raw, dict) else None

    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO bad_receipts (event_id, raw_receipt, error) "
            "VALUES (%s, %s, %s)",
            (event_id, Jsonb(safe_raw), safe_error),
        )
    connection.commit()