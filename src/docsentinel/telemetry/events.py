"""Fault events mirroring ``docs/specs/fault-event-contract.md``.

The open tier vocabulary is ``deterministic`` / ``heuristic``; outcomes are
``pass``, ``rejected``, ``escalated``, ``suppressed``, and ``advisory``.
``escalated`` is reserved for a future human-in-the-loop hop, not produced by
DocSentinel v1. Domain and fault class are free strings, never closed enums.
The vocabulary constants document the contract without enforcing membership.
"""

import dataclasses
import datetime
from typing import Final, Mapping, Optional, Union

SCHEMA_VERSION: Final[str] = "1.0"
TIER_VOCABULARY: Final[frozenset[str]] = frozenset({"deterministic", "heuristic"})
OUTCOME_VOCABULARY: Final[frozenset[str]] = frozenset({"pass", "rejected", "escalated", "suppressed", "advisory"})


@dataclasses.dataclass(frozen=True, kw_only=True)
class FaultEvent:
    """A rule evaluation event following the cross-tool fault contract.

    :ivar ts: Event creation time as RFC-3339 UTC with a trailing ``Z``.
    :ivar domain: Free string naming the producing tool's content domain.
    :ivar fault_class: Free fault-class string, serialized under ``class``.
    :ivar tier: Open tier vocabulary value.
    :ivar rule: Producing rule code.
    :ivar outcome: Open outcome vocabulary value.
    :ivar model: Invoker-supplied generator model id, or ``None`` if unknown.
    :ivar schema_version: Cross-tool event contract version, not report version.
    :ivar details: Shallow JSON-primitive context, not deep-validated here.
        Producers must exclude raw document text, matched snippets, secrets,
        and PII; only codes, counts, and already-public values belong here.
    """

    ts: str
    domain: str
    fault_class: str
    tier: str
    rule: str
    outcome: str
    model: Optional[str]
    schema_version: str = SCHEMA_VERSION
    details: Mapping[str, Optional[Union[str, int, float, bool]]] = dataclasses.field(default_factory=dict)


def to_json_dict(event: FaultEvent) -> dict[str, object]:
    """Serialize an event, renaming only ``fault_class`` to ``class``.

    :param event: Event to serialize.
    :returns: A dictionary using the agreed wire keys.
    """
    data = dataclasses.asdict(event)
    data["class"] = data.pop("fault_class")
    return data


def utc_now_iso() -> str:
    """Return the current UTC event-creation timestamp.

    :returns: An RFC-3339 timestamp with a trailing ``Z``.
    """
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")
