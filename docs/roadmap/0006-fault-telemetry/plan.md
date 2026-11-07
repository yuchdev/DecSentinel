# Milestone 0006 — Fault-Telemetry Event Emission

**Repository:** https://github.com/yuchdev/DocSentinel  
**Milestone path:** `docs/roadmap/0006-fault-telemetry/`  
**Status:** specification only; no telemetry module, adapter, config options or CLI flags exist yet  
**Decision record:** [ADR 0002](/docs/adr/0002-fault-telemetry-event-emission.md) (Accepted)  
**Cross-tool contract:** [docs/specs/fault-event-contract.md](/docs/specs/fault-event-contract.md)  
**Dependencies:** Milestones 0001–0005 complete (rule registry, `engine.scan()` single entry point, typed `Config` validation, `ScanResult`/`reporting` contracts).

## Goal

Emit one structured, cross-tool fault-telemetry event whenever a rule evaluates a
document, so fault-mode rates (fabricated-reference rate, cross-model
disagreement, HITL escalation rate) become measurable over time instead of
anecdotal. The event shape is defined by a **written specification** shared with
the sibling FlakeForge project — **no shared code, not even a path dependency** —
so a downstream collector can aggregate a mixed stream. The demo line: "once these
gates emit events, a model upgrade becomes measurable."

All work is **stdlib-only** (`dataclasses`, `json`, `datetime`, `pathlib`,
`logging`, `sqlite3`, `importlib`), **default-off**, and **observational** —
enabling it never changes a scan's verdict, exit code, or `ScanResult`. Emission
happens at exactly **one** call site in `engine.scan()`, reusing the
already-assembled findings.

## Design constraints (fixed by ADR 0002)

1. The cross-tool coupling is the written spec
   [docs/specs/fault-event-contract.md](/docs/specs/fault-event-contract.md), not
   an importable module. DocSentinel implements its own `FaultEvent` dataclass and
   `FaultEventSink` **Protocol** (PEP 544) in `telemetry/`; FlakeForge
   implements its own equivalent independently. No runtime import crosses repos.
2. The sink is **flexibly pluggable** via the `FaultEventSink` Protocol
   (`emit(event) -> None`, optional `close()`): reference sinks are `JsonlSink`
   (stdout/file, the default), `LoggingSink` (stdlib `logging`), `SqliteSink`
   (stdlib `sqlite3` DB reference), and `NullSink`. A project-local custom sink is
   selected by `python:<module>:<callable>`, reusing the FlakeForge `rule_modules`
   `importlib` loading precedent.
3. `model` is supplied by a CLI/config flag (`--generated-by-model` /
   `generated_by_model`), never sniffed from content or frontmatter.
4. No network sink in v1.
5. Opt-in via a `telemetry` extra and `telemetry_enabled` config (opt-in because
   emitting is a behaviour change, not for install weight).
6. `details` is bounded to JSON primitives and must never carry raw document text,
   file contents, or matched snippets (no-secrets/no-PII rule); load-bearing for
   the persisting `logging`/`sqlite` sinks.
7. A **conformance tripwire test** checks DocSentinel's own event shape, the
   `tier`/`outcome` vocabularies, and `schema_version` against literals copied
   from the spec, so a deliberate schema bump fails until spec and code agree.

Out of scope: a published shared package (explicitly not pursued), a network/OTLP
sink, HITL escalation emission (the `"escalated"` outcome is reserved in the
vocabulary only), and FlakeForge's own implementation (built separately against
the same spec).

## Stories

| Story | Deliverable | Depends on |
|---|---|---|
| [01.0](/docs/roadmap/0006-fault-telemetry/01.0-shared-fault-event-module/README.md) | Written contract spec + DocSentinel-local `FaultEvent`, `FaultEventSink` Protocol, `schema_version`, and the conformance tripwire | 0001–0005 |
| [02.0](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/README.md) | Pluggable sinks (`JsonlSink`/`LoggingSink`/`SqliteSink`/`NullSink`), `build_sink` factory with custom-callable loading, and the typed config/CLI surface | 01.0 |
| [03.0](/docs/roadmap/0006-fault-telemetry/03.0-adapter-and-engine-emission/README.md) | DocSentinel adapter (`events_for_result`), fault-class mapping wiring, single `engine.scan()` call site | 01.0, 02.0 |
| [04.0](/docs/roadmap/0006-fault-telemetry/04.0-tests-docs-and-extraction-readiness/README.md) | Full test matrix, mapping/conformance gates, docs, `doctor` surface, FlakeForge adoption note | 01.0–03.0 |

## Recommended delivery order / PR boundaries

1. **Story 01.0** first and mergeable alone: the spec doc plus the local event
   type, Protocol, and the conformance tripwire. Nothing depends on DocSentinel
   internals yet; the tripwire locks the shape to the spec.
2. **Story 02.0**: the reference sinks, the `build_sink` factory (including
   custom-callable loading), and the config/CLI surface — default-off, validated
   like the Milestone 0005 typed options. Still inert — no emission wired.
3. **Story 03.0**: the adapter and the one `engine.scan()` call site; this is
   where behaviour (optionally) turns on.
4. **Story 04.0** last: cross-surface/integration tests, the mapping-coverage and
   conformance gates, docs, `doctor`, and the FlakeForge adoption note. Do not
   close 0006 while any registered rule lacks a fault-class row.

## Profile and contract guarantees

- `ScanResult` shape, JSON report schema v1, exit codes, and `enabled_rules`
  semantics are **unchanged**. `ScanResult.schema_version` (int) is distinct from
  the event `schema_version` (string); neither changes the other.
- Fast profile stays stdlib-only at scan time; telemetry adds no third-party
  dependency (SQLite is stdlib; no DB client is added).
- Emission is skipped entirely when `telemetry_enabled` is false, and any sink
  error (including a failed custom-sink import) is swallowed so telemetry can never
  fail a scan.

## Acceptance criteria

- [ ] `docs/specs/fault-event-contract.md` is the canonical cross-tool contract;
      `telemetry/` implements DocSentinel's own `FaultEvent`/`FaultEventSink`
      with no shared/path-referenced module and no cross-repo import.
- [ ] `FaultEvent` is a frozen dataclass; `to_json_dict` renames `fault_class` ->
      `"class"` and every field round-trips through `json.loads`.
- [ ] The conformance tripwire test compares the event field set, `tier`/`outcome`
      vocabularies, and `schema_version` against the spec's literals and fails on
      drift.
- [ ] `FaultEventSink` is a PEP 544 `Protocol`; `JsonlSink`, `LoggingSink`,
      `SqliteSink`, and `NullSink` each satisfy it structurally; a custom no-op
      sink with only `emit` works.
- [ ] `build_sink` resolves `stdout` / `file:<path>` / `sqlite:<path>` /
      `logging` / `python:<module>:<callable>`; a malformed selector is a
      `ConfigError` at load, an import/open failure is swallowed at emit.
- [ ] `telemetry_enabled`/`telemetry_sink`/`generated_by_model` are typed,
      validated, loaded from standalone config, `[tool.doc_sentinel]`, and an
      injected `Config`; defaults keep telemetry off.
- [ ] `--telemetry`, `--telemetry-sink`, `--generated-by-model` apply as `Config`
      overrides through the existing `replace(settings, ...)` path.
- [ ] Emission is a single call site in `engine.scan()`, reuses the assembled
      findings (no second analyzer run), is skipped when disabled, and never alters
      exit code or `ScanResult`.
- [ ] Every registered rule code (DS101–DS118, DS201–DS204, DS301) maps to a fault
      class via [`src/docsentinel/fault_classes.md`](/src/docsentinel/fault_classes.md);
      an unmapped rule yields `"unmapped"` and fails the close gate.
- [ ] `details` never carries document text or matched snippets; a test asserts the
      bound (including through the persisting `sqlite`/`logging` sinks).
- [ ] `docsentinel doctor` reports telemetry enablement and the resolved sink
      destination.

## Reference documents

- [ADR 0002 — Fault-Telemetry Event Emission](/docs/adr/0002-fault-telemetry-event-emission.md)
- [Fault-event contract spec](/docs/specs/fault-event-contract.md)
- [Fault-class mapping table](/src/docsentinel/fault_classes.md)
- Existing patterns: [docs/roadmap/0005-deepening-test-case-stage-2/plan.md](/docs/roadmap/0005-deepening-test-case-stage-2/plan.md), [CLAUDE.md](/CLAUDE.md), [docs/architecture/README.md](/docs/architecture/README.md).
