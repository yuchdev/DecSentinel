# Task 02 — Shipped examples: `domain` and `document_stats`

**Parent story:** [Story 04.0](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/README.md)  
**Proposed sources:** `src/docsentinel/telemetry/builtin/domain.py`, `src/docsentinel/telemetry/builtin/document_stats.py`, `examples/docsentinel.toml`, `docs/user/` guide

## `builtin:domain`

Assigns a free-string `domain` to each document from its path (the same free-string
vocabulary as the 0006 contract: `documentation`, `agent`, ... never a closed enum).

- Config: `telemetry_domains` -- an **ordered** table of glob → domain, first match
  wins, default fallback `"*"` (default value `"documentation"` if absent). Globs
  use the restricted literal/`?`/`*`/`**` subset already used by
  `documentation_naming_prefix_patterns` (no regex), matched against the
  scan-root-relative POSIX path; the options table validates globs at load.
- `provide_document` returns `{"name": "<domain>", "matched": "<glob>"}`; also
  exposed as the shorthand `doc.domain` when this extension is enabled so the
  standard `json.json` (which reads `doc.domain` with `$default`) gains the field
  with no template edit. Findings inherit it through `p.ext.domain.name`.
- The 0006 adapter calls the same `domain_for(path, config)` function, so
  `FaultEvent.domain` and the report cannot disagree.
- Example config shipped in `examples/docsentinel.toml`:
  `".claude/agents/**" = "agent"`, `".claude/skills/**" = "agent"`,
  `"docs/**" = "documentation"`, `"adr/**" = "documentation"`.

## `builtin:document_stats` (custom calculation)

Shows a calculation, not a lookup: per document, `problem_count_per_kb`
(`problems / (bytes / 1024)`, rounded to 3 places, `0.0` for empty documents), and
at run level `worst_documents` (top 5 by that density, ties broken by path so the
output stays deterministic). Used in the docs as the "write your own" walkthrough.

## Documentation

`docs/user/` gets a "Custom reports" guide: template anatomy, a worked
`--template` example, writing a `python:` extension end to end, and the trust
model. Cross-link the spec and the examples; run `/link-check`.

## Tests (for `testing-expert`)

- Unit: first-match-wins, fallback, `**` depth, a path matching two globs picks the
  earlier; invalid glob → `ConfigError` at load.
- Integration (`_ds101`): `.claude/agents/x.md` → `agent`, `docs/x.md` →
  `documentation` in `json.json`; the same two paths in emitted `FaultEvent`s
  (once 0006 Story 03.0 is merged -- gate this case with a clear skip reason).
- Unit: `document_stats` arithmetic, zero-byte document, tie-break determinism.
- Docs: the guide's example template and extension are executed by a test so the
  documentation cannot rot.
