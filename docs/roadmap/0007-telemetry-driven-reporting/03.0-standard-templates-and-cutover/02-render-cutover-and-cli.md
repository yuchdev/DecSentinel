# Task 02 — `render()` cutover, CLI, and the hardcode-ban tripwire

**Parent story:** [Story 03.0](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/README.md)  
**Proposed sources:** `src/docsentinel/reporting.py`, `src/docsentinel/cli.py`, `src/docsentinel/config.py`, `tests/unit/test_reporting_has_no_format_literals.py`

## Required contract

1. `reporting.render(result, format="text", *, config=None, template=None)`:
   resolve the template (`template` path, else `format` as a template name), build
   the `ReportModel`, call the engine. **No** `if format ==` branch, no literal
   line, no `json.dumps`. An unknown name raises `ValueError` (kept for API
   compatibility) wrapping the `TemplateError`.
2. Delete `_render_github`, `_gha_level`, `_escape_*`, `ADVISORY_BANNER` and the
   inline text/JSON paths from `reporting.py`; keep `neutralize_text` (re-export).
3. CLI (`cli.py`): `--format` becomes free-form with `choices` computed from the
   discovered template names (`text`, `github`, `json`, `json-v1`, `json-documents`,
   plus any in `report_templates_dir`); add `--template PATH` (wins over `--format`)
   and `--show-clean-documents`. Template and extension errors print
   `Scan failed:` through `neutralize_text` and exit `2`.
4. Config options (typed and validated like the 0005 options): `report_templates_dir`
   (root-contained dir, default none), `report_show_clean_documents` (bool, false),
   `report_include_run_meta` (bool, false).
5. Default `--format json` now resolves to schema 2 (decision D1). Document in the
   release notes and bump the minor version.
6. `docsentinel doctor` lists the discovered templates.

## Hardcode-ban tripwire

A unit test parses `reporting.py` and `telemetry/engine.py` with `ast` and fails
when either contains: a string constant equal to `"text"`, `"json"`, `"github"`; a
string containing `"::"`, `"Schema version"`, `"Profile:"`, `"bytes)"`; a call to
`json.dumps` in `reporting.py`; or a comparison against a format name. A second case
injects such a literal into a temp copy and asserts the tripwire fails (so it cannot
rot into a no-op).

## Tests (for `testing-expert`)

- Unit: `render` with an unknown name; with `template=` pointing at a bad file → exit-2 path in CLI test.
- Integration: `scan --format X` for every shipped template on each profile fixture;
  `--template` with a user template; `--show-clean-documents`.
- Mock: stub the engine to prove `render()` performs no formatting of its own.
- The existing `tests/**/test_reporting*` suite passes with only intentional
  golden updates, each justified in the PR description.
