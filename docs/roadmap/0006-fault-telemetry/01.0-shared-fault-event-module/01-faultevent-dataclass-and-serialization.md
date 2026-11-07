# Task 01 — `FaultEvent` dataclass, serialization, and conformance tripwire

**Parent story:** [Story 01.0](/docs/roadmap/0006-fault-telemetry/01.0-shared-fault-event-module/README.md)  
**Proposed source:** `src/docsentinel/telemetry/`

## Required contract

Define a frozen, `kw_only` dataclass (justification for dataclass over `TypedDict`
is in [ADR 0002](/docs/adr/0002-fault-telemetry-event-emission.md); the wire shape
is fixed by [the contract spec](/docs/specs/fault-event-contract.md)):

```
@dataclass(frozen=True, kw_only=True)
class FaultEvent:
    ts: str                        # RFC-3339 UTC with 'Z' suffix
    domain: str                    # free string, NOT an enum ("docs", "code", ...)
    fault_class: str               # serialised under JSON key "class"
    tier: str                      # "deterministic" | "heuristic"
    rule: str
    outcome: str                   # see vocabulary below
    model: str | None
    schema_version: str = SCHEMA_VERSION
    details: Mapping[str, str | int | float | bool | None] = field(default_factory=dict)
```

- Provide a module-level `SCHEMA_VERSION = "1.0"` constant and default
  `schema_version` from it.
- Provide `to_json_dict(event: FaultEvent) -> dict[str, object]` that renames
  `fault_class` to the wire key `"class"` and preserves all other keys verbatim.
  This is the only place the keyword-collision rename happens.
- Provide a small `utc_now_iso() -> str` helper (`datetime.now(timezone.utc)`
  rendered with a trailing `Z`) so callers never hand-format timestamps.

## Vocabulary (documented in module docstring, mirrored from the spec, not enforced as an enum)

- `tier`: `"deterministic"` | `"heuristic"`.
- `outcome`: `"pass"` | `"rejected"` | `"escalated"` | `"suppressed"` |
  `"advisory"`. `"escalated"` is reserved for a future HITL hop and is not produced
  by DocSentinel v1.
- `domain` and `fault_class` are free strings, never closed enums.

## Conformance tripwire (drift control)

Add literal references the tripwire test (Story 04.0) will check, so DocSentinel's
own shape cannot silently drift from the spec:

- The event field set, the `tier`/`outcome` vocabularies, and `SCHEMA_VERSION` are
  the machine mirror of [the spec](/docs/specs/fault-event-contract.md) §1–§3. Keep
  them in the same module so a bump touches code and spec in one change.

## Constraints

- stdlib-only (`dataclasses`, `datetime`, `json`, `typing`); **no cross-repo
  import** and no shared/path-referenced module.
- `details` values are restricted to JSON primitives; the dataclass does not
  deep-validate, but the adapter (Story 03.0) must never place raw document text or
  matched snippets there (no-secrets/no-PII rule, ADR 0002 / spec §4).

## Tests (for `testing-expert`)

- Unit: construct a `FaultEvent`; assert `to_json_dict` produces `"class"` (not
  `"fault_class"`) and every other agreed key; assert `json.loads(json.dumps(...))`
  round-trips.
- Unit: `schema_version` defaults to `SCHEMA_VERSION`; `model=None` serialises to
  JSON `null`.
- Unit (conformance tripwire): the event field names, the `tier`/`outcome`
  vocabularies, and `SCHEMA_VERSION` equal literals transcribed from the spec; a
  deliberate change to one without the other fails.
