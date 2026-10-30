# Story 03.0 — Standard templates and cutover

**Category:** user-facing change · **Proposed sources:** `src/docsentinel/telemetry/templates/*.json`, `src/docsentinel/reporting.py`, `src/docsentinel/cli.py`, `src/docsentinel/config.py`  
**Depends on:** [Story 02.0](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/README.md).

## Goal

Author the standard templates and make them the **only** way output is produced.
This is the one story where report bytes change.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/01-standard-templates.md) | `text.json`, `github.json`, `json.json`, `json-v1.json`, `json-documents.json` and their golden tests |
| [02](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/02-render-cutover-and-cli.md) | `reporting.render()` delegates to the engine; `--format` resolves template names; `--template`, `--show-clean-documents`; hardcode-ban tripwire |

## Definition of done

- `reporting.py` is a thin shim: `render()` and the re-exported `neutralize_text`.
- Text: findings directly under their document; clean documents hidden by default.
- JSON schema 2: a record per document with `problems`; all documents present.
- `--format json-v1` equals the pre-milestone golden snapshots byte-for-byte.
- The tripwire (Task 02) is green and demonstrably fails on a re-added literal.
- The duplicate-annotation observation in [status.md](/docs/roadmap/0007-telemetry-driven-reporting/status.md) is resolved or filed as a DS101 issue.
