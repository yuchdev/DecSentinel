# Task 02 — Docs, roadmap index, and FlakeForge adoption note

**Parent story:** [Story 04.0](/docs/roadmap/0006-fault-telemetry/04.0-tests-docs-and-extraction-readiness/README.md)  
**Proposed sources:** `docs/architecture/README.md`, `CLAUDE.md`, `docs/roadmap/README.md`, `docs/adr/README.md`, `docs/README.md`, sample config

## Required documentation

- **`docs/architecture/README.md`:** a telemetry section describing the design —
  the written cross-tool contract
  ([docs/specs/fault-event-contract.md](/docs/specs/fault-event-contract.md)), the
  DocSentinel-local `FaultEvent`/`FaultEventSink` Protocol and pluggable sinks in
  `telemetry/`, the single `engine.scan()` call site, the event schema, the
  `tier`/`outcome`/`class` vocabulary, and the default-off / observational
  guarantee. State clearly there is **no shared or extracted module**.
- **`CLAUDE.md`:** a short architecture note that `engine.scan()` optionally emits
  fault-telemetry events from one call site (reusing the assembled findings, never a
  second analyzer run); that `telemetry/` owns DocSentinel's independent event
  type, `FaultEventSink` Protocol, reference sinks (`JsonlSink`/`LoggingSink`/
  `SqliteSink`/`NullSink`), the `build_sink` selector factory, and the adapter; and
  that the event `schema_version` (string) is distinct from
  `ScanResult.schema_version` (int).
- **`docs/roadmap/README.md`:** add/refresh the Milestone 0006 row.
- **`docs/adr/README.md` and `docs/README.md`:** keep the ADR 0002 and spec index
  lines current.
- **Sample config:** show the three options (`telemetry_enabled`, `telemetry_sink`,
  `generated_by_model`) with defaults and a one-line CI example, e.g.
  `docsentinel scan --telemetry --telemetry-sink sqlite:events.db --generated-by-model <id>`
  and `--telemetry-sink file:events.jsonl` / `--telemetry-sink logging`.

## FlakeForge adoption note

Record (in the architecture section) exactly how the sibling FlakeForge project
aligns, so the two stay in lockstep without shared code:

- **Shared:** only [the written contract spec](/docs/specs/fault-event-contract.md)
  — the event fields/types, the `tier`/`outcome` vocabulary, `schema_version` and
  its bump policy, and the `FaultEventSink` Protocol *shape*.
- **Implemented independently per tool:** each repo has its **own** `FaultEvent`
  dataclass, its own `FaultEventSink` Protocol, its own sinks, and its own adapter
  (FlakeForge sets `domain="code"`, maps its `X`-codes, may emit `"escalated"` for
  its HITL hop). Nothing is imported across repos; nothing is path-referenced.
- **Lockstep rule:** any event-schema change is a coordinated `schema_version` bump
  in both repos plus the collector; ADR 0002, the spec, and FlakeForge's mirror ADR
  are the migration anchor. DocSentinel's conformance tripwire catches local drift;
  cross-repo alignment is a review discipline against the spec.

## Constraints

- Keep `/link-check` green on all touched docs.
- Update [docs/roadmap/0006-fault-telemetry/status.md](/docs/roadmap/0006-fault-telemetry/status.md)
  as stories actually close; do not infer completion from this specification.
