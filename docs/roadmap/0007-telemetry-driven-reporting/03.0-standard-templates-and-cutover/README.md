# Story 03.0 — Standard templates and cutover

**Category:** user-facing change · **Proposed sources:** `src/docsentinel/telemetry/templates/*.json`, `src/docsentinel/reporting.py`, `src/docsentinel/cli.py`, `src/docsentinel/config.py`  
**Depends on:** [Story 02.0](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/README.md).

## Goal

Author the standard templates and make them the **only** way output is produced.
This is the one story where report bytes change.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/01-standard-templates.md) | `text.json`, `github.json`, `json.json`, `json-v1.json`, `json-documents.json` and their golden tests. ✅ Done. Deviations: (1) `text.json` prints the scan's own `{notice}` instead of rebuilding it from `rules_evaluated` and an `append` loop over `opt_in_off`. Templates cannot add numbers, and the deep notice counts opt-in rules and adds "(heuristic, advisory-only)", so a rebuilt line would disagree with the scan. The line is byte-identical to the legacy one. (2) `github.json` always adds `,title=<rule>`, adds `,col=<n>` only when `line` is set, and groups lines in document order; all shared fields are escaped byte-identically to the legacy output. (3) `domain` is the literal `"docs"` (D7): the loader rejects `doc.ext.domain.name` until Story 04.0 adds `ext.*`, which then switches to `$var` with `$default`. (4) New context variable `inventory` (spec §6), because `$for` cannot drop the out-of-inventory documents that `json-v1` must omit. (5) Goldens are named `expected.template-<name>`, because `expected.json`/`expected.github` already hold the pre-move snapshots; `json-v1` is checked against `expected.json`. Render steps for 358 documents and 5000 findings: github 106k, json 62k, text 38k, json-v1 36k (`MAX_STEPS` is 2,000,000). |
| [02](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/02-render-cutover-and-cli.md) | `reporting.render()` delegates to the engine; `--format` resolves template names; `--template`, `--show-clean-documents`; hardcode-ban tripwire. Implemented, pending review. Deviations: (1) `render()` adds keyword-only `root` (resolves `report_templates_dir`) and `strict` (feeds `outcome` under `--strict`) to the specified signature, and `template=` also accepts a loaded `Template`. (2) `--format` is validated after the configuration loads, not by argparse `choices`, because the choices include `report_templates_dir`; an unknown name prints `Scan failed: unknown --format ...; choose from: ...` and exits `2`. (3) `--show-clean-documents` is a new trusted context variable `show_clean_documents` (spec §6) that `text.json` reads; `documents_with_problems` keeps its meaning. (4) The tripwire also bans `"text"`/`"json"` in `telemetry/engine.py`, so the engine's template-type dispatch and `json`-filter sizing now use the constants `loader.TYPE_TEXT`/`TYPE_JSON` and `filters.JSON_FILTER` (no behaviour change). (5) Release notes and the minor version bump of contract item 5 are deferred to Story 05.0; the package version is unchanged here. |

## Definition of done

- `reporting.py` is a thin shim: `render()` and the re-exported `neutralize_text`.
- Text: findings directly under their document; clean documents hidden by default.
- JSON schema 2: a record per document with `problems`; all documents present.
- `--format json-v1` equals the pre-milestone golden snapshots byte-for-byte.
- The tripwire (Task 02) is green and demonstrably fails on a re-added literal.
- The duplicate-annotation observation in [status.md](/docs/roadmap/0007-telemetry-driven-reporting/status.md) is resolved or filed as a DS101 issue.
