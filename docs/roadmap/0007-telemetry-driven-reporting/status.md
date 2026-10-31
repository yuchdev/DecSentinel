# Milestone 0007 — completion status

**Planning state:** 🔶 In execution (1 of 5 stories complete). ADR 0003 is
`Proposed`; decisions D1–D6 in [plan.md](/docs/roadmap/0007-telemetry-driven-reporting/plan.md) await owner sign-off.

## Current status

| Story | Name | State | Tests executed |
|---|---|---|---|
| 01.0 | Telemetry package and report model | ✅ Complete (2/2 tasks) | Full suite 2679 passed, 9 skipped; self-scan exit 0; `uv build` ok; feature-reviewer LGTM; task-verifier PARTIAL (no blocking gaps, see notes) |
| 02.0 | Template engine | ⬜ Not started | — |
| 03.0 | Standard templates and cutover | ⬜ Not started | — |
| 04.0 | Extensions | ⬜ Not started | — |
| 05.0 | Tests, docs, acceptance | ⬜ Not started | — |

## Tracking rules

- Mark a story complete only when code, tests, docs and CI are merged.
- Golden report snapshots for the current `text`/`github`/`json` output are taken
  at the start of Story 01.0 and kept as the regression baseline for the
  restructure; they are retired only by Story 03.0's intentional output change.
- Do not close 0007 while `reporting.py` contains a format literal.
- Stories 02.0–04.0 of Milestone 0006 must not start before Story 01.0 here lands
  (path references to `telemetry.py` change).

## Notes & decisions

- 2026-10-30: Milestone opened from the CanonixEngine report review. Added
  requirement: no standard hardcoded rules — every format is a telemetry template.
- 2026-10-30: Observation to verify in Story 03.0: the CanonixEngine GitHub report
  repeats `::error file=README.md,line=12::dangling link -> /docs/adr/README.md`
  on consecutive lines. Confirm whether two links on one line is the cause or DS101
  emits duplicates; the report layer must not hide a detector bug by deduplicating.
- 2026-10-31: Execution started on branch `milestone/0007-telemetry-driven-reporting`. Phase R found no as-built artifacts (no `telemetry/` package, `reporting.py` unchanged) and no decomposition gaps. Decisions D1-D6 are taken as ratified at their recommended defaults because the owner started the run; ADR 0003 stays `Proposed` until the owner flips it. Revisit D1 (breaking JSON default) before Story 03.0 lands.
- 2026-10-31: Open decision **D7 (domain value)**: `telemetry/classify.py` defaults the domain to `"documentation"` (this milestone's spec), but the accepted cross-tool contract ([docs/specs/fault-event-contract.md](/docs/specs/fault-event-contract.md) lines 26/42/355) names DocSentinel's domain `"docs"`. Unconsumed so far; must be settled before Story 04.0 (`builtin:domain` default) and before the 0006 adapter imports `classify`.
- 2026-10-31: Story 01.0 waivers/follow-ups from verification: (a) wheel-contents check is manual only (templates do not exist yet; Story 03.0 adds the real package-data assertion); (b) `reporting.py` still imports `ADVISORY_BANNER` from `telemetry.model` (layering inversion, harmless; disappears at the Story 03.0 cutover); (c) `Finding` new fields use `compare=False`, so findings differing only in `type`/`value`/`column` compare equal; (d) add a §6 sentence that `documents[].bytes` may be null for findings outside the inventory; (e) test gaps for Story 05.0: DS101 column with several code spans/links on one line, and `\r`-only line endings; (f) Story 02.0 loader must bound the charset/length of invoker-supplied `model`.

### Story 01.0 - Telemetry package and report model (✅ 2026-10-31)

**Delivered**
- `telemetry.py` -> `telemetry/` package (`events.py`, `classify.py`, `model.py`); public import path unchanged; 12 golden report snapshots committed before the move.
- `Finding.column/value/type`; DS101-DS103 populate them; `ScanResult.rules_evaluated/opt_in_off`, notice derived from them (byte-identical).
- `ReportModel.build` + `CONTEXT_SCHEMA`; `classify()` pinned to `fault_classes.md`; schema-1 JSON still byte-identical via `_schema_v1_dict`.

**Tests / gate:** 2643 -> 2679 passed (9 skipped); goldens unchanged across the restructure; self-scan 0; `uv build` ok; docs link check 0 problems.

**Reconciliation:** both task specs consumed as written; extra shared module `classify.py` and extra `build()` keyword arguments (`strict`, `model`, `report_include_run_meta`, `report_schema_version`) are supersets, not departures.
