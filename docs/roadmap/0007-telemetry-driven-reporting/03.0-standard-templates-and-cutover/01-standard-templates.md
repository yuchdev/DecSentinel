# Task 01 — The standard templates

**Parent story:** [Story 03.0](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/README.md)  
**Proposed sources:** `src/docsentinel/telemetry/templates/{text,github,json,json-v1,json-documents}.json`

## Required contract

All five are valid under the Task 01 loader of Story 02.0 and use no extension.

| Template | Shape |
|---|---|
| `text.json` | Header lines (schema version, profile, documents with-problems count, enabled rules, rules-evaluated line with the `append` loop of opt-in rules, advisory banner when set), then for each document with problems: `path (N bytes)` followed by indented `severity: path: message` lines; then `Pending:` lines. Spec §4 has the authoritative excerpt. |
| `github.json` | One `::error|warning file=<path>,line=<n>,col=<c>,title=<rule>::<message>` per problem, grouped by document order; `col`/`line` omitted when null via `$if` on the property list; level from `severity` through a template `when`, not Python. `gha_property` on file/title, `gha_data` on message. |
| `json.json` | Schema 2 envelope, spec §5: `schema_version`, `profile`, `run`, `summary`, `rules`, `documents[{path, bytes, domain?, problems[...]}]`, `pending`. `domain` uses `$default` so the template works without the domain extension. |
| `json-v1.json` | Reproduces the schema-1 report: `asdict(ScanResult)` key order and nesting (`schema_version`, `profile`, `documents`, `findings`, `enabled_rules`, `pending`, `notice`) plus the `advisory` key only for a non-empty deep result. Uses `$var` over the exact legacy values; indent 2. |
| `json-documents.json` | The bare list of per-document records from the original request. |

Notes:

- The `severity → level` mapping (`error`→error, anything else→warning) is data in
  the template (`$if`), replacing `_gha_level`.
- Standard templates never reference `run.generated_at`/`run.id`; they remain
  deterministic.
- Authoring aid: a `docsentinel report-template lint PATH` helper is **not** in
  scope here (Story 05.0 documents `--template` validation through exit code 2).

## Tests (for `testing-expert`)

- Integration, per template and per profile fixture: golden outputs under
  `tests/assets/report/<case>/expected.<template>`; files named with the rule-ID
  suffix convention.
- `json-v1` golden equals the Story 01.0 pre-move snapshots exactly.
- Text golden: assert, on a multi-document fixture, that every `error:`/`warning:`
  line is preceded (without an intervening document line) by its document's line,
  and no document with zero findings appears.
- GitHub golden: injection fixtures (CR/LF, `::`, ESC, U+202E in a path and in a
  message) match the pre-milestone escaped output for the same fields.
- JSON: `json.loads` round-trip; every problem has the ten keys; a clean document
  has `"problems": []`.
