# Task 01 — Adapter, fault-class mapping, and outcome rules

**Parent story:** [Story 03.0](/docs/roadmap/0006-fault-telemetry/03.0-adapter-and-engine-emission/README.md)  
**Proposed source:** `src/docsentinel/telemetry/`

## Required contract

The adapter lives in `telemetry/` alongside the event type and sinks; it is the
only code importing both the event machinery and DocSentinel types (`ScanResult`,
`Finding`, `RULES`). There is no shared/path-referenced module to keep clean — the
cross-tool coupling is the written spec only.

- A module-level `FAULT_CLASSES: dict[str, str]` transcribing the rows of
  [`docs/specs/fault-classes.md`](/docs/specs/fault-classes.md). The
  markdown table is the human source of truth; this dict is its machine mirror and
  the two must agree (Story 04.0 enforces it). A rule code absent from the dict maps
  to `"unmapped"`.
- `events_for_result(result, *, model, suppressed) -> Iterator[FaultEvent]` where
  `result` is the assembled `ScanResult`, `model` is `config.generated_by_model or
  None`, and `suppressed` is the tuple of findings removed by the baseline filter
  (passed in by the engine, which already has both the pre- and post-filter sets).

## Mapping rules (per ADR 0002 / spec §2)

- `domain = "docs"` (constant).
- `tier`: look up `RULES[finding.rule].profile`; `fast`/`standard` ->
  `"deterministic"`, `deep` -> `"heuristic"`.
- `fault_class`: `FAULT_CLASSES.get(finding.rule, "unmapped")`.
- `outcome` per finding:
  - heuristic (deep) finding -> `"advisory"`;
  - baseline-suppressed finding -> `"suppressed"`;
  - `severity == "error"` -> `"rejected"`;
  - `severity == "warning"` -> `"advisory"`.
  - For each rule in `result.enabled_rules` that was evaluated and produced **no**
    finding, emit one `"pass"` event (no `path`, `details={}`). Do **not** emit a
    `"pass"` for an opt-in rule whose policy is off (it was not evaluated — mirror
    the engine's `opt_in_satisfied` logic).
- `ts = utc_now_iso()`.
- `details`: only JSON primitives and already-public values — e.g.
  `{"severity": finding.severity, "line": finding.line}`. **Never** the finding
  message body if it could embed document text; prefer the rule code and the public
  `path`/`line`. This bound is the no-secrets/no-PII guard (spec §4) and is an
  explicit review item — load-bearing because the `sqlite`/`logging` sinks persist.

## Constraints

- No re-running of analyzers; read only what `ScanResult` and the passed-in
  `suppressed` tuple already hold.
- `events_for_result` is a pure generator: it builds events, it does not open sinks
  or touch config files.

## Tests (for `testing-expert`)

- Unit: an `error` finding -> `"rejected"`; a `warning` -> `"advisory"`; a deep
  finding -> `"advisory"`; a suppressed finding -> `"suppressed"`; an evaluated
  clean rule -> one `"pass"`; an off opt-in rule -> no event.
- Unit: `tier` follows the rule's profile; `fault_class` follows the table; an
  unknown rule -> `"unmapped"`.
- Unit: `model=None` when `generated_by_model` empty; the flag value otherwise.
- Unit: `details` carries no document text (assert against a finding whose message
  includes a snippet).
