# Story 01.0 — Contract spec, local event type/Protocol, and conformance tripwire

**Category:** infrastructure / prerequisite · **Proposed sources:** `docs/specs/fault-event-contract.md`, `src/docsentinel/telemetry/`  
**Depends on:** nothing in DocSentinel internals — by design.

> **Slug note:** this directory keeps the `shared-fault-event-module` slug for link
> stability. Per [ADR 0002](/docs/adr/0002-fault-telemetry-event-emission.md) there
> is **no shared module**: the only thing shared with FlakeForge is the written
> contract spec; DocSentinel owns its event type and Protocol.

## Goal

Land the **written cross-tool contract** and the smallest **stdlib-only**
DocSentinel-local implementation of the fault-telemetry event and its sink
Protocol, with a conformance tripwire that keeps the code aligned to the spec.
Nothing here imports FlakeForge and nothing is path-referenced across repos.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0006-fault-telemetry/01.0-shared-fault-event-module/01-faultevent-dataclass-and-serialization.md) | `FaultEvent` frozen dataclass, `to_json_dict`, `SCHEMA_VERSION`, and the conformance tripwire against the spec |
| [02](/docs/roadmap/0006-fault-telemetry/01.0-shared-fault-event-module/02-sink-protocol-and-default-sinks.md) | `FaultEventSink` PEP 544 Protocol and `NullSink` |

## Definition of done

- [docs/specs/fault-event-contract.md](/docs/specs/fault-event-contract.md) is the
  canonical contract (already drafted by the architect); the code matches its
  literals.
- `FaultEvent` is a frozen, `kw_only` dataclass matching the ADR 0002 / spec shape;
  `to_json_dict` renames `fault_class` -> `"class"` and emits the agreed keys.
- `FaultEventSink` is a `@runtime_checkable` Protocol with `emit(event) -> None`;
  `NullSink` satisfies it.
- A conformance tripwire test compares the event field set, the `tier`/`outcome`
  vocabularies, and `schema_version` to literals copied from the spec and fails on
  drift.
- stdlib-only; no cross-repo import; no shared/path-referenced module.
