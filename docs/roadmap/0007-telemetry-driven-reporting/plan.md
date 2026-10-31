# Milestone 0007 — Template-Driven Reporting on the Telemetry Package

**Repository:** https://github.com/yuchdev/DocSentinel  
**Milestone path:** `docs/roadmap/0007-telemetry-driven-reporting/`  
**Status:** specification only; nothing below is implemented  
**Decision record:** [ADR 0003](/docs/adr/0003-template-driven-reporting-on-telemetry.md) (Proposed)  
**Design spec:** [docs/specs/report-template-format.md](/docs/specs/report-template-format.md)  
**Dependencies:** Milestones 0001–0005 complete. Coordinates with [Milestone 0006](/docs/roadmap/0006-fault-telemetry/plan.md) (see "Coordination with 0006").

## Goal

Replace the three hardcoded renderers in `reporting.py` with **one template
renderer hosted in a new `src/docsentinel/telemetry/` package**. `text`, `github`
and `json` become three packaged templates (`text.json`, `github.json`,
`json.json`); no output format is written in Python. Make the reports usable:

- **Text:** each document's findings print directly under its first appearance;
  documents with no findings are not listed.
- **JSON:** document-centric (a record per document holding its `problems`, each
  with rule, type, value, severity, line, column, fault class, tier, outcome) so
  it can serve as the primary collection channel for hallucination data.
- **Extensible:** Python extensions add custom calculations and attributes such
  as `domain` (`docs` vs `agent`, derived from the file path) without
  touching the renderer.

Motivating evidence: the CanonixEngine runs in
`~/Projects/CanonixEngine/docs/reviews/docsentinel-docs-2026-10-26/` (9 reports,
3 depths × 3 formats; 358 documents; the inventory buries the findings).

## Design constraints (fixed by ADR 0003)

1. **No hardcoded format.** The renderer contains no format name, no report
   literal, no escaping rule. Everything is in the template or a declared filter.
   A tripwire test enforces this.
2. **Logic-less templates.** Closed sets of nodes, operators, conditions and
   filters; no `eval`, no third-party engine, no object traversal.
3. **Output safety is not optional.** Untrusted variables (`path`, `message`,
   `value`, `pending`) must pass a sink filter in text templates, enforced at
   template load. Control/bidi/zero-width neutralization behaves exactly as today.
4. **Deterministic by default.** Same input → same bytes. Timestamps and run ids
   are opt-in.
5. **stdlib-only** at scan time; templates are JSON.
6. **`import docsentinel` stays cheap**; the template engine loads on first render.
7. **Existing contracts hold:** exit codes, `enabled_rules`, baseline
   fingerprints, `ScanResult` equality semantics. JSON schema 1 stays reproducible
   from `json-v1.json`.

## Decisions requiring the owner's sign-off

These were not specified in the request; each has a recommended default so the
milestone can proceed, and a wrong guess costs one template line to change.

| # | Decision | Recommendation |
|---|---|---|
| D1 | `--format json` default becomes schema 2 (breaking for consumers of the two-array v1 shape). | Yes, flip the default; keep `--format json-v1` as a supported template; call it out in the release notes and bump the minor version. |
| D2 | Text report lists only documents *with* problems. | Yes; `--show-clean-documents` (config `report_show_clean_documents`) lists the rest. JSON always includes every document, since the denominator is what makes a rate. |
| D3 | The JSON field for the short category: the request's example uses both `"type"` and `"message"`. | `type` = short category (`dangling link`), `message` = full text, `value` = offending token. |
| D4 | Top-level JSON shape: your example shows a bare list of documents, but a report also needs profile/model/summary. | `json.json` is an envelope (`documents` list inside); the bare list ships as `json-documents.json`. |
| D5 | `python:` extensions execute code from a module path. | Refuse unless `--allow-python-extensions` / `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1`; `builtin:*` always allowed. |
| D6 | `outcome` in your example is `null`. | Compute it with the Milestone 0006 mapping (`rejected` / `advisory` / ...), `null` only when nothing maps. |

## Coordination with 0006

Milestone 0006 Story 01.0 Task 01 already landed `FaultEvent` in
`src/docsentinel/telemetry.py` and its docs name `telemetry.py` as the home of
sinks and the adapter. Story 01.0 here converts that module to a package
**before** 0006 Story 02.0 starts, preserving the import path
(`from docsentinel.telemetry import FaultEvent` keeps working) and rewriting 0006's
path references. 0006 Stories 02.0–04.0 then land into `telemetry/sinks.py` and
`telemetry/adapter.py`. The adapter and the report model share one source for
`fault_class`, `tier`, `outcome` and `domain`.

## Stories

| Story | Deliverable | Depends on |
|---|---|---|
| [01.0](/docs/roadmap/0007-telemetry-driven-reporting/01.0-telemetry-package-and-report-model/README.md) | `telemetry/` package (no behaviour change, import path preserved); optional `column`/`value`/`type` on `Finding`; `ReportModel` core provider; structured rule diagnostics on `ScanResult` | 0006 Story 01.0 |
| [02.0](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/README.md) | Template schema, loader/validator (variable lint, trust rule), renderer, filter table | 01.0 |
| [03.0](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/README.md) | `text.json`, `github.json`, `json.json`, `json-v1.json`, `json-documents.json`; `reporting.render()` delegates; CLI `--format`/`--template`; hardcode-ban tripwire | 02.0 |
| [04.0](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/README.md) | Extension API + loader + trust gate; `builtin:domain` and `builtin:document_stats` examples; config surface | 02.0 (03.0 for end-to-end) |
| [05.0](/docs/roadmap/0007-telemetry-driven-reporting/05.0-tests-docs-and-acceptance/README.md) | Test matrix, golden reports, security review, docs, CanonixEngine acceptance run | 01.0–04.0 |

## Recommended delivery order / PR boundaries

1. **01.0** alone: pure restructure + additive data; the diff must show zero change
   in any report output (golden snapshots taken *before* the move prove it).
2. **02.0** alone: the engine, unused by the CLI, fully unit-tested.
3. **03.0**: the cutover. Output changes here, and only here. Land templates and
   the `render()` delegation in one PR so no hardcoded path survives alongside.
4. **04.0**: extensions, which need 02.0's context schema but not the cutover.
5. **05.0** last, including the security-auditor gate on template loading and
   `python:` extensions.

## Profile and contract guarantees

- Exit codes `0/1/2` unchanged; a `TemplateError`/`ExtensionError` is exit `2`.
- `ScanResult` gains only defaulted fields; JSON schema 1 output is byte-identical
  via `json-v1.json`.
- Baseline fingerprints unchanged (new `Finding` fields excluded from the hash).
- `import docsentinel` and fast/standard scans import neither spaCy nor the
  template engine until a report is rendered.

## Acceptance criteria

- [ ] `src/docsentinel/telemetry/` exists; `docsentinel.telemetry.FaultEvent`,
      `to_json_dict`, `SCHEMA_VERSION`, `utc_now_iso` import unchanged;
      `src/docsentinel/telemetry.py` is gone.
- [ ] `reporting.py` has no format literal; the tripwire test passes and fails when
      a literal is added.
- [ ] `docsentinel scan --format text|github|json` output is produced solely by
      `telemetry/templates/{text,github,json}.json`.
- [ ] In the text report, every finding follows its document's line and documents
      without findings are absent (unless `--show-clean-documents`).
- [ ] The JSON report is one record per document with `problems`; each problem
      carries `rule`, `type`, `message`, `value`, `severity`, `line`, `column`,
      `fault_class`, `tier`, `outcome`.
- [ ] A text template referencing an untrusted variable without a sink filter is
      rejected at load; a control/bidi/zero-width injection fixture renders
      identically to today.
- [ ] `--format json-v1` reproduces the schema-1 report byte-for-byte on the
      existing fixtures.
- [ ] `--template PATH` renders a user template; an invalid one exits 2 with a
      neutralized message.
- [ ] `builtin:domain` labels a `.claude/agents/x.md` document `agent` and a
      `docs/x.md` document `docs`, in the report and in `FaultEvent.domain`.
- [ ] A `python:` extension is refused without the explicit opt-in; allowed with it.
- [ ] Two consecutive runs produce byte-identical default reports.
- [ ] CanonixEngine acceptance: re-running the 9 reports yields the specified
      shapes (recorded in the 05.0 task).

## Reference documents

- [ADR 0003](/docs/adr/0003-template-driven-reporting-on-telemetry.md) · [Template format spec](/docs/specs/report-template-format.md)
- [Milestone 0006](/docs/roadmap/0006-fault-telemetry/plan.md) · [ADR 0002](/docs/adr/0002-fault-telemetry-event-emission.md)
- Current renderer: [`src/docsentinel/reporting.py`](/src/docsentinel/reporting.py)
- Pattern precedent: [docs/roadmap/0005-deepening-test-case-stage-2/plan.md](/docs/roadmap/0005-deepening-test-case-stage-2/plan.md), [CLAUDE.md](/CLAUDE.md)
