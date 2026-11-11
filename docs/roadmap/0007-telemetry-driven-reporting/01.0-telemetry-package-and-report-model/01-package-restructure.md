# Task 01 — Restructure `telemetry.py` into a package

**Parent story:** [Story 01.0](/docs/roadmap/0007-telemetry-driven-reporting/01.0-telemetry-package-and-report-model/README.md)  
**Proposed sources:** `src/docsentinel/telemetry/__init__.py`, `events.py`, `tests/integration/test_report_golden_*.py`

## Required contract

1. **Snapshot first.** Before moving any code, add golden-output tests that
   capture today's `render(result, fmt)` for the existing fast, standard and deep
   fixtures in all three formats (assets under `tests/assets/report/<case>/`).
   Commit them in their own commit; they are the proof the restructure is inert.
2. `git mv src/docsentinel/telemetry.py src/docsentinel/telemetry/events.py`
   (history preserved). Create `telemetry/__init__.py` re-exporting every public
   name: `FaultEvent`, `to_json_dict`, `utc_now_iso`, `SCHEMA_VERSION`,
   `TIER_VOCABULARY`, `OUTCOME_VOCABULARY`, with `__all__`.
3. Reserve the layout (empty modules are **not** created; later stories add them):
   `events.py`, `model.py`, `filters.py`, `templates/` (package data), `engine.py`
   (renderer), `loader.py`, `extensions.py`, `builtin/`.
4. Declare `telemetry/templates/*.json` as package data in `pyproject.toml`
   (hatchling `include`), and verify with `uv build` that the wheel contains them.
5. Update every path reference to `telemetry.py` in Milestone 0006 docs, ADR 0002,
   `docs/README.md`, `fault-classes.md` headers and `CLAUDE.md` to `telemetry/`
   (use the `/doc-xref` skill, then `/link-check`).

## Constraints

- No logic change; `git diff -M` should show a rename plus a new `__init__`.
- `tests/unit/test_telemetry.py` passes unmodified (it imports the public path).

## Tests (for `testing-expert`)

- Golden: the nine snapshots pass before and after the move.
- Unit: every previously public name is importable from `docsentinel.telemetry`
  and from no other path being required; `docsentinel.telemetry.__all__` is exact.
- Build: wheel listing contains `docsentinel/telemetry/__init__.py`.
