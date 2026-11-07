# Task 02 — Documentation and CanonixEngine acceptance

**Parent story:** [Story 05.0](/docs/roadmap/0007-telemetry-driven-reporting/05.0-tests-docs-and-acceptance/README.md)

## Documentation (for `docs-writer` / `docs-updater`)

- `CLAUDE.md`: replace the `reporting.py` architecture bullet and add the
  `telemetry/` package, template/extension surface, the new `report_*` and
  `telemetry_extensions`/`telemetry_domains` options, and the "no hardcoded format"
  convention.
- `README.md` and `docs/user/`: new report samples, `--format`/`--template`,
  `json` schema 2 vs `json-v1`, the "Custom reports" guide (Story 04.0).
- `docs/architecture/README.md`: the pipeline diagram from the spec.
- `docs/adr/README.md`: ADR 0003 → `Accepted` when the owner signs off D1–D6.
- Release notes: JSON default change (D1), minor version bump, migration line
  (`--format json-v1`).
- `docs/roadmap/README.md` row for 0007 set to the final state.

## Acceptance run

Against `~/Projects/CanonixEngine/docs` regenerate the nine reports (fast /
standard / deep × text / github / json), saving them under
`docs/reviews/` here as `canonix-acceptance-<date>/`. Verify and record in
`status.md`:

1. Text: the first line after the header block is a document with findings, and
   its findings follow immediately; no zero-finding document is listed.
2. JSON: the `adr/0003-pipeline-introspection-and-unified-debug-mode.md` record has
   `bytes: 15033` and three DS101 problems with line/column/value; clean documents
   appear with `problems: []`; `summary.by_rule` totals equal the text report's
   finding count.
3. GitHub: annotations carry `col`/`title`; the repeated `README.md:12` lines are
   explained (two links on one line, or a DS101 duplicate bug filed).
4. Same corpus, `domain` extension on: `.claude/agents` documents report `agent`.
5. Report-size note for the 358-document run (JSON vs v1) for the record.

Reviews directory is read through `/link-check` and must not be scanned as input
by the self-scan CI step.
