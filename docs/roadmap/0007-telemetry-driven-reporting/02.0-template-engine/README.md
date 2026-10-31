# Story 02.0 — Template engine

**Category:** core engine · **Proposed sources:** `src/docsentinel/telemetry/{loader,engine,filters}.py`  
**Depends on:** [Story 01.0](/docs/roadmap/0007-telemetry-driven-reporting/01.0-telemetry-package-and-report-model/README.md).

## Goal

Implement the logic-less template language in
[docs/specs/report-template-format.md](/docs/specs/report-template-format.md):
load and validate a template, then render it against a `ReportModel` context. Not
wired into the CLI yet, so it can merge alone.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/01-template-schema-and-loader.md) | Template dataclasses/validation, variable parser, `variables_used` lint, condition grammar, trust rule, `TemplateError` -- ✅ Done 2026-10-31: `telemetry/loader.py` (`load_template`, `validate_template`, `TemplateError`, `FILTERS` signature table) with threat-model mitigations M1-M12, M13 depth, M14 load-time, M16, M17; M15 `model` bound in `ReportModel.build` |
| [02](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/02-renderer-filters-and-trust.md) | `text` and `json` renderers, `block`/`one-line`/`append` placement, filter table (`neutralize`, `gha_*`, `json`, …) |

## Definition of done

- Every node, operator, placement and filter in the spec has a unit test; every
  `TemplateError` condition in spec §10 has a negative test.
- `neutralize`/`gha_property`/`gha_data` are the **moved** functions from
  `reporting.py` (same tables, same outputs), so Story 03.0 can delete the originals.
- The engine imports only stdlib and `docsentinel.telemetry` siblings.
