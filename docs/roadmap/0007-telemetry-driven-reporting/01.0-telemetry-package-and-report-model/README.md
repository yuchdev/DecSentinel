# Story 01.0 — Telemetry package and report model

**Category:** restructure + data model · **Proposed sources:** `src/docsentinel/telemetry/`, `src/docsentinel/models.py`, `src/docsentinel/engine.py`  
**Depends on:** [Milestone 0006 Story 01.0](/docs/roadmap/0006-fault-telemetry/01.0-shared-fault-event-module/README.md) (its Task 01 already landed `FaultEvent` in `telemetry.py`).

## Goal

Create the home for everything else without changing a single byte of output:
turn `telemetry.py` into a package, give findings the extra attributes the new
reports need, and build the `ReportModel` -- the JSON-shaped context every template
renders from.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0007-telemetry-driven-reporting/01.0-telemetry-package-and-report-model/01-package-restructure.md) | `telemetry.py` → `telemetry/` package; import path preserved; 0006 docs re-pathed; golden snapshots of current reports |
| [02](/docs/roadmap/0007-telemetry-driven-reporting/01.0-telemetry-package-and-report-model/02-report-model-and-finding-enrichment.md) | Optional `Finding.column/value/type`, DS101–DS103 populate them, structured rule diagnostics on `ScanResult`, `ReportModel` core provider |

## Definition of done

- `from docsentinel.telemetry import FaultEvent, to_json_dict, SCHEMA_VERSION, utc_now_iso` works; `telemetry.py` no longer exists.
- Golden snapshots of today's `text`/`github`/`json` output (fast, standard, deep fixtures) are committed first and still pass after the move.
- `Finding` equality, `asdict`, and baseline fingerprints are unchanged for findings that do not set the new fields.
- `ReportModel.build(result, config)` returns a pure JSON-shaped dict matching the context schema in the [spec](/docs/specs/report-template-format.md) §6.
