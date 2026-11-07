"""DocSentinel fault telemetry package.

Re-exports the public fault-event API from :mod:`docsentinel.telemetry.events`, so
callers keep importing from ``docsentinel.telemetry``. See
``docs/specs/fault-event-contract.md`` for the cross-tool event contract.
"""

from docsentinel.telemetry.events import (
    OUTCOME_VOCABULARY,
    SCHEMA_VERSION,
    TIER_VOCABULARY,
    FaultEvent,
    to_json_dict,
    utc_now_iso,
)

__all__ = [
    "FaultEvent",
    "to_json_dict",
    "utc_now_iso",
    "SCHEMA_VERSION",
    "TIER_VOCABULARY",
    "OUTCOME_VOCABULARY",
]
