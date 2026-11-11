# Milestone 0006 — completion status

**Planning state:** 📝 Specification only (0 of 4 stories implemented). ADR 0002
is `Accepted` (ratified 2026-10-27); implementation in progress.

## Current status

| Story | Name | State | Tests executed |
|---|---|---|---|
| 01.0 | Contract spec + local event type/Protocol + tripwire | 🔶 In progress (1/2 tasks) | Task 01: 10 unit tests; full suite 2626 passed |
| 02.0 | Pluggable sinks and config/CLI surface | ⬜ Not started | — |
| 03.0 | Adapter and engine emission | ⬜ Not started | — |
| 04.0 | Tests, docs, conformance readiness | ⬜ Not started | — |

## Tracking rules

- Only mark a story complete when its source code, tests, documentation updates,
  and CI are merged — not from an already-written specification.
- Do not close 0006 while any registered rule code lacks a fault-class row in
  [`docs/specs/fault-classes.md`](/docs/specs/fault-classes.md).
- Keep the event `schema_version`, the spec
  [docs/specs/fault-event-contract.md](/docs/specs/fault-event-contract.md), and
  FlakeForge's independent implementation in lockstep; record any bump here. The
  conformance tripwire test enforces DocSentinel-vs-spec agreement locally.

## Notes & decisions

- 2026-10-26: Milestone opened from ADR 0002. The load-bearing decision is **no
  shared code**: the cross-tool contract is the written spec; each tool implements
  its own `FaultEvent`/`FaultEventSink` Protocol. The earlier shared-module design
  (a path-referenced `faultevents/` package) was dropped.
- 2026-10-26: Sinks are flexibly pluggable via the `FaultEventSink` Protocol;
  reference set is `JsonlSink`/`LoggingSink`/`SqliteSink`/`NullSink` plus a
  `python:<module>:<callable>` custom-sink loader reusing the FlakeForge
  `rule_modules` `importlib` precedent.
- 2026-10-27: ADR 0002 ratified `Accepted` by the user; implementation started with Story 01.0.
