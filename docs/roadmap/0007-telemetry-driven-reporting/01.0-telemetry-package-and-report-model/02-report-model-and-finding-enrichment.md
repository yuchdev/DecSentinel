# Task 02 — Finding enrichment, rule diagnostics and `ReportModel`

**Parent story:** [Story 01.0](/docs/roadmap/0007-telemetry-driven-reporting/01.0-telemetry-package-and-report-model/README.md)  
**Proposed sources:** `src/docsentinel/models.py`, `src/docsentinel/engine.py`, `src/docsentinel/detectors/fast/{links,comments,paths}.py`, `src/docsentinel/telemetry/model.py`

## Required contract

### Finding enrichment

Add to `Finding` (all `Optional`, default `None`, appended after `line`):
`column: int | None`, `value: str | None`, `type: str | None`.

- `baseline.py` fingerprints keep hashing exactly `rule`, `path`, `message`,
  `severity`, `line` (whatever it hashes today). A test asserts a finding with and
  without the new fields has the same fingerprint.
- `value` must follow the same no-secrets rule as `FaultEvent.details`: only the
  offending token the detector already echoes in `message` (a link target, a
  name), never a surrounding snippet.
- Populate in this task: `DS101` (`type="dangling link"`/`"dangling anchor"`,
  `value`=target, `column` of the link target), `DS102` (`type="stray html comment"`),
  `DS103` (`type="unresolvable path"`, `value`=path). Other rules leave `None`;
  `ReportModel` derives `type` for them from the rule title (`rules.py`), so no
  report field is ever missing for lack of detector work. Later rules adopt the
  fields opportunistically.

### Structured diagnostics on `ScanResult`

`ScanResult.notice` is a pre-baked string, so a template cannot loop over the
opt-in rules. Add defaulted fields `rules_evaluated: int = 0` and
`opt_in_off: tuple[tuple[str, str], ...] = ()` (`(code, option)`), computed in
`engine.scan()` where the notice is built today, and make the `notice` string a
function of them (single source). The legacy `notice` text stays byte-identical.

### `ReportModel`

`telemetry/model.py`: `ReportModel.build(result, config, *, extensions=()) -> dict`
returning the context in [spec §6](/docs/specs/report-template-format.md):

- run-level scalars, counts, `severity_counts`, `rule_counts`, `opt_in_off`,
  `advisory` (the deep banner moves here as data; `ADVISORY_BANNER` is no longer a
  `reporting.py` constant);
- `documents` (every document, `problems` attached by path, source order stable) and
  `documents_with_problems`; flat `findings`;
- per problem: `rule`, `rule_title`, `type`, `message`, `value`, `severity`, `line`,
  `column`, `fault_class`, `tier`, `outcome`. `fault_class`/`tier`/`outcome` come
  from the **same function** Milestone 0006's adapter uses (build it here as
  `classify(finding, config)` and have the adapter import it, or consume 0006's if
  already landed) so the report and the event stream cannot diverge;
- `run.generated_at` / `run.id` only when `report_include_run_meta` is on.

The result must be JSON-shaped (assert with a recursive type check in tests).

## Tests (for `testing-expert`)

- Unit: fingerprint invariance; `asdict(Finding)` gains only `None` keys; legacy
  `notice` equals the string built from `rules_evaluated`/`opt_in_off`.
- Unit: `ReportModel.build` on a tiny `ScanResult` -- groups problems under the right
  document, documents without findings have `problems == []`, counts add up.
- Integration (`_ds101_ds102_ds103`): enriched columns/values for each rule's assets.
- Property: building the model twice yields equal dicts (determinism).
