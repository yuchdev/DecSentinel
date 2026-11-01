# Milestone 0007 — completion status

**Planning state:** 🔶 In execution (1 of 5 stories complete). ADR 0003 is
`Proposed`; decisions D1–D6 in [plan.md](/docs/roadmap/0007-telemetry-driven-reporting/plan.md) await owner sign-off.

## Current status

| Story | Name | State | Tests executed |
|---|---|---|---|
| 01.0 | Telemetry package and report model | ✅ Complete (2/2 tasks) | Full suite 2679 passed, 9 skipped; self-scan exit 0; `uv build` ok; feature-reviewer LGTM; task-verifier PARTIAL (no blocking gaps, see notes) |
| 02.0 | Template engine | ✅ Complete (2/2 tasks) | Full suite 3055 passed, 9 skipped, 1 load-induced timing flake (`test_root_times_n_workload_fails`, passes alone); self-scan 0; `uv build` ok; task-verifier PASS, feature-reviewer LGTM, security-auditor PASS_WITH_FOLLOWUP |
| 03.0 | Standard templates and cutover | 🔶 In progress (1/2 tasks) | Task 01: five packaged templates + goldens; targeted 466 passed; full suite 3112 passed before the last fix (2 golden failures were mid-edit, resolved); task-verifier PASS-with-notes, security-auditor PASS |
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
- 2026-10-31: Story 02.0 Task 01 (loader) done: `fb5e11a`, `5b9704d`, `fcb9c42`, threat model `docs/security/threat-model-0007-template-engine-2026-10-31.md`. Review found the github-sink injection (variable-first line; then legacy `##[` fallback); fixed with the rule that untrusted variables appear only in well-formed `::error|warning|notice|debug|group` command lines (spec section 8). Follow-ups: (a) Story 04.0 must tag `ext.*` and `telemetry_domains` values untrusted; (b) Task 02 must test `gha_data` escaping of `%`/CR/LF, the render-purity patch test (M13/M14) and a severity-routing github template (conditions with literal command names); (c) `terminal` sink is an accepted risk (T2-R2): user docs recommend `--format github` in Actions (added to `docs/user/tutorial/report.md`); (d) `tests/mock/test_standard_loader.py::test_ensure_standard_loaded_is_idempotent_on_success` fails when run alone at the Story 01.0 base too (order-dependent, pre-existing) and two wall-clock tests in `tests/unit/test_timing_helpers.py` failed once each under load; (e) `_emitted_text` in `loader.py` is long, extract the `well_formed` computation when touched again; (f) the loader reads `neutralize_text` from `reporting.py`, repoint to `filters.neutralize` in Task 02.
- 2026-10-31: **D7 ruled by the owner: the DocSentinel domain is `"docs"`** (matches the accepted fault-event contract and FlakeForge). `classify.DEFAULT_DOMAIN`, plan, Story 04.0 specs, template-format spec, ADR 0003 and CLAUDE.md updated; the per-path example now maps `docs/**` and `adr/**` to `docs`, `.claude/agents/**` to `agent`.

### Story 02.0 - Template engine (✅ 2026-10-31)

**Delivered**
- `telemetry/loader.py`: strict template loader/validator (file gate with `O_NOFOLLOW|O_NONBLOCK`, 256 KiB, duplicate-key/NaN rejection, closed schema, trust rule, github-sink well-formed-command rule); `ReportModel.build` bounds invoker-supplied `model`.
- `telemetry/engine.py` + `telemetry/filters.py`: logic-less text/JSON renderer, nine filters, `neutralize`/`gha_property`/`gha_data` byte-identical to the pre-move tables (checked on every code point), single-pass substitution, step/work/output budgets, streaming JSON encoder (`ensure_ascii` forced).
- `docs/security/threat-model-0007-template-engine-2026-10-31.md` with findings T1-T11, R1-R9 and verdicts; spec section 8 (sink/trust rules) updated.
- D7 ruled by the owner: domain `docs`.

**Tests / gate:** 2679 -> 3055 passed (9 skipped); self-scan 0; `uv build` ok. Security review took five rounds: github-sink injection (variable-first line, then legacy `##[` fallback), DAG/cycle context, late output cap, quadratic append, work that emits nothing (`MAX_STEPS` = 2,000,000), indented-JSON amplification (streaming encoder).

**Reconciliation:** both task specs consumed; supersets: `filters.py` (TemplateError lives here to avoid a cycle, re-exported from the loader), the step/work budgets and the streaming encoder, the closed github command-name list. `reporting.py` keeps the original escape functions (verbatim copies, parity-tested) until Story 03.0 deletes them.

**Follow-ups for later stories:** (a) Story 03.0: delete the duplicated originals in `reporting.py`; R4 invisible characters outside the neutralize table (soft hyphen, U+2060-2064, tag characters, Hangul fillers) change legacy output and parity tests together; the shipped `github.json` must obey the well-formed-command rule (literal command per severity branch, `gha_property` before the second `::`, `gha_data` after); the step cap (not `MAX_ITERATIONS`) is now the effective size limit, re-measure on the 358-document corpus (about 120k steps for 5000 findings); (b) R8 (LOW): encode very long context strings in slices; (c) Story 04.0: tag `ext.*` and `telemetry_domains` values untrusted; (d) Story 05.0: severity-routing and cap tests exist, add the CanonixEngine-scale performance run.
- 2026-11-01: Story 03.0 Task 01 done (`524a97c`, `30bf6e4`, `14c58d1`): five templates under `telemetry/templates/`; `json-v1` byte-equals the Story 01.0 snapshots; DS101 duplicate-annotation observation resolved (two links to one target on one line, DS101 reports both at distinct columns, pinned by a test). Deviations: `text.json` prints the scan's own `{notice}` (templates cannot add numbers; same bytes as legacy), `github.json` always emits `title=` and `col=` only with `line`, `domain` is the literal `"docs"` until Story 04.0 (switch to `$var` + `$default`), new `inventory` model variable, `RULE_TITLES` table in `classify.py` makes `type` independent of detector load state (pinned to the registry by a test), document counts are inventory-only. Open INFO items: `RULE_TITLES` could be a `MappingProxyType`; lone surrogates in JSON come out as `\udXXX` escapes as in schema 1. Step use at 358 docs/5000 findings: github ~106k, json ~62k, text ~38k, json-v1 ~36k of 2,000,000.
