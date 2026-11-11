# DocSentinel 0006 — Fault-telemetry specification

**Status:** specification only. No telemetry module, adapter, config options, or
CLI flags are implemented yet; this directory is the plan handed to
`python-expert` and `testing-expert`.

## What is in this directory

- [Milestone plan](/docs/roadmap/0006-fault-telemetry/plan.md) — opens with the
  `## Stories` table and the acceptance criteria.
- [Live completion status](/docs/roadmap/0006-fault-telemetry/status.md).
- Four story directories, each with a `README.md` (`## Tasks` table) and numbered
  task specs.

> **Directory-slug note:** the `01.0-shared-fault-event-module` and
> `04.0-tests-docs-and-extraction-readiness` slugs are kept for link stability.
> Per ADR 0002 there is **no shared/extracted module**: "shared" now means the
> shared *written contract*, and "extraction readiness" is now *conformance /
> drift-control readiness* against that contract. The story titles reflect the
> current design.

## Scope

A single, structured fault-telemetry event emitted whenever a rule evaluates a
document, shaped so DocSentinel and the sibling FlakeForge project emit the same
event vocabulary into a shared collector — coupled by a **written specification**
([docs/specs/fault-event-contract.md](/docs/specs/fault-event-contract.md)), not
shared code. stdlib-only, default-off, observational (never changes a scan
verdict), with flexibly pluggable sinks, emitted from one call site in
`engine.scan()`.

The decision and its trade-offs are recorded in
[ADR 0002](/docs/adr/0002-fault-telemetry-event-emission.md); the rule-code ->
fault-class table is [`docs/specs/fault-classes.md`](/docs/specs/fault-classes.md).

## Delivery order

Story 01.0 (spec + local event type/Protocol + conformance tripwire) first and
independently mergeable, then 02.0 (pluggable sinks + config/CLI surface, still
inert), then 03.0 (adapter + engine call site, where behaviour turns on), then
04.0 (tests, docs, conformance/mapping gates). Update the main
[docs/roadmap/README.md](/docs/roadmap/README.md) milestone table as a separate
documentation task when stories close.
