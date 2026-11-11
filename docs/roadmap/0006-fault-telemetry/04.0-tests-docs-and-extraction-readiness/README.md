# Story 04.0 — Tests, docs, and conformance (drift-control) readiness

**Category:** quality / release · **Proposed sources:** `tests/`, `docs/`, `CLAUDE.md`, `docs/roadmap/README.md`  
**Depends on:** Stories 01.0–03.0.

> **Slug note:** this directory keeps the `tests-docs-and-extraction-readiness`
> slug for link stability. Per [ADR 0002](/docs/adr/0002-fault-telemetry-event-emission.md)
> there is no module to extract; "extraction readiness" is now **conformance /
> drift-control readiness** against the written spec.

## Goal

Lock the behaviour with a full test matrix, document the feature, and prove
DocSentinel stays aligned to the written contract (the conformance tripwire plus
the mapping-coverage gate). Do not close Milestone 0006 while any registered rule
lacks a fault-class row.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0006-fault-telemetry/04.0-tests-docs-and-extraction-readiness/01-cross-surface-tests-and-mapping-gate.md) | Cross-surface tests, mapping-coverage gate, conformance tripwire, no-PII assertion, per-sink tests |
| [02](/docs/roadmap/0006-fault-telemetry/04.0-tests-docs-and-extraction-readiness/02-docs-and-flakeforge-adoption.md) | Docs, roadmap index, and FlakeForge adoption note |

## Definition of done

- CLI, library API, and pytest-plugin paths all emit identical events (one engine
  call site proven by test).
- A mapping-coverage test fails if any registered rule code is missing from both
  `fault-classes.md` and the adapter dict, or if the two disagree.
- A conformance tripwire test fails if the event shape, `tier`/`outcome`
  vocabularies, or `schema_version` drift from the spec's literals.
- Per-sink tests cover `JsonlSink` (stdout + append file), `LoggingSink` (captured
  via `caplog`), `SqliteSink` (row round-trip), `NullSink`, and the
  `python:<module>:<callable>` custom-sink loader.
- A no-PII test asserts `details` and emitted events never carry document text,
  including through the persisting `sqlite`/`logging` sinks.
- Docs updated: `docs/architecture/README.md` telemetry section, `CLAUDE.md`
  architecture note, `docs/roadmap/README.md` milestone table, sample config.
- FlakeForge adoption note records exactly what each tool implements independently
  and what the shared spec fixes.
