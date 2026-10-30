# Milestone 0007 — completion status

**Planning state:** 🔶 In execution (0 of 5 stories complete; Story 01.0 Task 01 done). ADR 0003 is
`Proposed`; decisions D1–D6 in [plan.md](/docs/roadmap/0007-telemetry-driven-reporting/plan.md) await owner sign-off.

## Current status

| Story | Name | State | Tests executed |
|---|---|---|---|
| 01.0 | Telemetry package and report model | 🔶 In progress (1/2 tasks) | Task 01: 13 golden + 4 unit tests; full suite 2643 passed, 9 skipped |
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
