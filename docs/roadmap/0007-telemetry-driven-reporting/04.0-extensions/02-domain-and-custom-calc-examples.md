# Task 02 — Shipped examples: `domain` and `document_stats`

**Parent story:** [Story 04.0](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/README.md)  
**Proposed sources:** `src/docsentinel/telemetry/builtin/domain.py`, `src/docsentinel/telemetry/builtin/document_stats.py`, `examples/docsentinel.toml`, `docs/user/` guide  
**Threat model (normative):** [threat-model-0007-extensions-2026-11-03.md](/docs/security/threat-model-0007-extensions-2026-11-03.md)

## `builtin:domain`

Assigns a `domain` label to each document from its path. The vocabulary is open
(`docs`, `agent`, ...; never a closed enum) but every value must match
`^[a-z][a-z0-9_-]{0,63}$` (owner decision D-D, the 0006 vocabulary). The label is
asserted by the repository, not authenticated (residual R5).

### Config: `telemetry_domains` (owner decision D-E)

An **array of tables**, so a key-sorting TOML formatter cannot reorder it. Order is
the array order; first match wins; when nothing matches the result is
`classify.DEFAULT_DOMAIN` (`"docs"`). The catch-all is spelled `"**"` (`"*"` matches
top-level files only).

```toml
[[tool.doc_sentinel.telemetry_domains]]   # [[telemetry_domains]] in docsentinel.toml
glob = ".claude/agents/**"
domain = "agent"

[[tool.doc_sentinel.telemetry_domains]]
glob = "docs/**"
domain = "docs"
```

- `Config.telemetry_domains: tuple[tuple[str, str], ...] = ()` stores
  `(glob, domain)` pairs in array order (M23). Each entry is a table with exactly the
  keys `glob` and `domain`, both strings; anything else is a `ConfigError`.
- **Glob grammar (M20).** The glob is split on `/`. `**` is allowed only as a whole
  segment and matches zero or more whole segments; `*` matches zero or more
  characters other than `/`; `?` matches exactly one character other than `/`; every
  other character is a literal. Refused: `[`, `]`, `{`, `}`, `\`, `!` at segment
  start, empty segments, `.`/`..` segments, a leading `/`, and any
  `neutralize`-table code point. Matching is case-sensitive over the
  scan-root-relative POSIX path exactly as discovered (no NFC, no `realpath`, no
  filesystem access).
- **Matcher (M21).** This is **new code**, not a reuse of
  `documentation_naming_prefix_patterns` (which has no `**` and matches one
  component). A non-regex, segment-wise dynamic-programming matcher, worst case
  O(pattern segments x path segments x segment cost); the per-segment step may reuse
  the DS118 two-pointer walk (`_glob_matches`). No `re` compiled from user text and
  no `fnmatch`.
- **Bounds (M22).** <= 256 entries; glob <= 256 characters and <= 32 segments; all globs together
  <= 4096 characters (added by the closure threat model, follow-up (a));
  domain matches the D-D pattern. Checked in `load_config` **and** again in
  `domain_for` for an injected `Config` (fail closed with `ConfigError`).

### Contract

```python
def domain_for(path: str, config: Config) -> str: ...
```

- Returns `DEFAULT_DOMAIN` unless `"builtin:domain"` is in the effective
  `config.telemetry_extensions` (argv `builtin:` specs are merged there, Task 01);
  otherwise the first matching entry's domain, or `DEFAULT_DOMAIN` when none matches.
  Memoized per path (M18).
- **`doc.domain` is a core key (M24).** `DOCUMENT_SCHEMA` gains `domain` (`str`,
  `UNTRUSTED`), always present. The core provider sets it to
  `domain_for(path, config)`; it is never copied from any hook return.
  `json.json` switches from the literal `"domain": "docs"` to
  `{"$var": "doc.domain", "$default": "docs"}`, byte-identical (`"docs"`) for
  default runs.
- `provide_document` returns `{"name": "<domain>", "matched": "<glob>" | null}`
  (`null` when the fallback applied) under `doc.ext.domain`; findings reach it as
  `p.ext.domain.name`. Both are `any`/`UNTRUSTED` (spec §6).
- The 0006 adapter calls the same `domain_for(path, config)` with the same effective
  `Config`, so `FaultEvent.domain` and `doc.domain` cannot disagree.
- Example config shipped in `examples/docsentinel.toml`: `.claude/agents/**` and
  `.claude/skills/**` -> `agent`, `docs/**` and `adr/**` -> `docs`, then a `**` ->
  `docs` catch-all, in that order.

## `builtin:document_stats` (custom calculation)

Shows a calculation, not a lookup. Per document, `problem_count_per_kb` =
`round(problems / (bytes / 1024), 3)` (M34):

- `bytes is None` (a finding path outside the inventory, such as a DS204 Python
  source) gives `null`, and the document is excluded from `worst_documents`;
- `bytes == 0` gives `0.0`;
- the value cannot be NaN or infinite by construction.

At run level, `worst_documents` holds at most 5 entries, ordered by
`(-density, path)`. It is computed once, in `provide_run`, with a heap of size 5, so
the extension is O(D + F) per render (M18). Used in the docs as the "write your own"
walkthrough.

## Documentation

`docs/user/` gets a "Custom reports" guide: template anatomy, a worked
`--template` example, writing a `python:` extension end to end, and the trust
model. The trust model section states (threat model checklist item 13):

- `python:` extensions are argv-only (`--extension python:...`) and need
  `--allow-python-extensions` or `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1`; a
  `python:` entry in config is an error;
- never set the gate env on jobs that run untrusted PR heads;
- run the console script (not `python -m`) or `python -P`, and do not put the
  checkout on `PYTHONPATH`; modules and `sys.path` entries inside the scan root, its
  project root or cwd are refused (the running interpreter's own `site-packages`
  is exempt, amended 2026-11-03);
- residuals R1-R5: an admitted extension is full in-process code; a hook that never
  returns is bounded only by the CI job timeout; pytest and pre-commit already run
  repository code; `domain` is a repository-asserted label.

Cross-link the spec and the examples; run `/link-check`.

## Security requirements

This task must satisfy, and its close review checks (threat model checklist items
10-13): **M18, M20, M21, M22, M23, M24, M34**. It also relies on Task 01's M11
(`ext.*` is `any`/UNTRUSTED) and M25 (builtin names reserved) for the `domain`
subtree.

## Tests (for `testing-expert`)

- Unit (M20-M23): first match wins; `**` at depth 0 / 1 / 5; `*` does not cross
  `/`; `"*"` matches only top-level files and `"**"` matches all; no match gives
  `"docs"`; each refused grammar element gives `ConfigError`; 257 entries, a
  257-character glob, a 33-segment glob and an `Agent!` domain are refused; an entry
  with an extra key or a non-string value is refused; an injected `Config` with 10k
  entries raises `ConfigError` in `domain_for`; the adversarial pattern
  `**/a*a*a*a*b/**/x` against a 4096-character `a/a/...` path finishes within an
  op-count/time bound; array order is preserved in both the standalone and the
  pyproject form.
- Unit (M24): `doc.domain` is `"docs"` when `builtin:domain` is not loaded, even with
  `telemetry_domains` set; a hook cannot change it; default `json.json` output is
  byte-identical before and after this task.
- Integration (`_ds101`): `.claude/agents/x.md` -> `agent`, `docs/x.md` -> `docs` in
  `json.json`; the same two paths in emitted `FaultEvent`s equal `doc.domain` (once
  0006 Story 03.0 is merged -- gate this case with a clear skip reason).
- Unit (M34): an out-of-inventory finding (`bytes: null`), a zero-byte document,
  equal densities (tie-break by path), at most 5 `worst_documents`, identical output
  bytes on two runs.
- Unit (M18): both builtins on 50k synthetic documents stay within an op-count/time
  bound.
- Docs: the guide's example template and extension are executed by a test so the
  documentation cannot rot.
