# Architecture and milestone boundaries

## Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [Rule codes and selection](#rule-codes-and-selection)
- [Policy options (Milestone 0005)](#policy-options-milestone-0005)
- [Report options (Milestone 0007)](#report-options-milestone-0007)
- [Fast profile rules](#fast-profile-rules)
- [Opt-in policy rules](#opt-in-policy-rules)
- [Standard profile](#standard-profile)
- [Deep profile](#deep-profile)
- [Schema versioning](#schema-versioning)

## Overview

Every consumer (CLI, Python library, pytest plugin) goes through the same engine.

| Module           | Responsibility                                                                                    |
|------------------|---------------------------------------------------------------------------------------------------|
| `config`         | Validates local TOML input and builds the effective `Config`.                                     |
| `discovery`      | Inventories Markdown files in a stable order.                                                     |
| `engine.scan`    | Orchestrates the registered analyzers and applies baseline filters.                               |
| `reporting`      | `render()`: resolves a report template and renders the shared `ScanResult` through it.            |
| `telemetry`      | Fault events, finding classification (`classify`) and the report context (`ReportModel`).         |
| pytest plugin    | Opt-in; calls the same engine.                                                                    |

`engine.scan` forwards the effective `Config` to any analyzer that declares a third `config`
parameter. The two-argument `detect(root, documents)` form remains supported.

### Report pipeline (Milestone 0007)

A report is never formatted by the engine or a detector. The scan result is turned into a plain
JSON-shaped context and handed to a logic-less template renderer
([contract](/docs/specs/report-template-format.md#1-pipeline)):

```text
ScanResult --> ReportModel (core provider) --> + extension providers --> context
                                                                           |
template.json --> loader/validator --> renderer(template, context) --> sink (str)
```

- `ReportModel.build` classifies each finding (`classify`, the single source of fault class, tier,
  outcome and `domain`) and never exposes `ScanResult` or `Finding` objects to a template.
- Extensions (`builtin:domain`, `builtin:document_stats`, and `python:` ones allowed only from the
  command line) add data under their own `ext.<name>` namespace. See
  [Custom reports](/docs/user/tutorial/custom-reports.md).
- The Milestone 0006 fault-event adapter is not implemented. When it lands it is specified to take
  `domain` from the same `domain_for` function, so reports and events cannot disagree.

## Configuration

Configuration is discovered in this order; the first match wins:

1. An explicit configuration path, which bypasses discovery.
2. A standalone `docsentinel.toml` (alias `doc_sentinel.toml`; both present is a `ConfigError`) at the scan root. Its keys are top-level.
3. The `[tool.doc_sentinel]` table of a root-level `pyproject.toml`.
4. Built-in defaults.

A `Config` injected by a library caller still wins over any discovered file. Such a `Config`
bypasses load-time validation, so the caller is responsible for passing valid values.

## Rule codes and selection

| Prefix  | Profile    |
|---------|------------|
| `DS1xx` | `fast`     |
| `DS2xx` | `standard` |
| `DS3xx` | `deep`     |

- Profiles are **exact, not cumulative**: a `deep` run contains only `deep` findings.
- `select` accepts exact codes or prefixes such as `DS1`. An empty list selects every rule in the
  active profile.
- `ignore` uses the same matching and takes precedence over `select`.

## Policy options (Milestone 0005)

Milestone 0005 adds a block of typed, validated policy options to `Config`. They load from both the
standalone `docsentinel.toml` and the `[tool.doc_sentinel]` table, and:

- reject unknown keys (strict);
- validate enums, positive and non-negative integers, and non-empty string lists;
- reject path options that escape the scan root.

Every option below is consumed by a registered rule. With `DS118` registered, the whole block is
consumed. Options are grouped by the rule that reads them.

### Anchors - `DS104`

| Option                    | Default    | Meaning                                                                 |
|---------------------------|------------|-------------------------------------------------------------------------|
| `anchor_collision_policy` | `explicit` | `off` or `explicit`: whether conflicting explicit anchors are reported. |
| `anchor_renderer`         | `github`   | Renderer whose heading slugging `DS104` emulates (only `github` today). |

### Headings - `DS105`

| Option                   | Default    | Meaning                                                             |
|--------------------------|------------|---------------------------------------------------------------------|
| `heading_level_policy`   | `no-skips` | `off` or `no-skips`: whether skipped heading levels are reported.   |
| `first_heading_level`    | `1`        | Expected level (1 to 6) of a document's first heading.              |
| `multiple_h1_policy`     | `allow`    | `allow` or `warn`: policy for repeated H1 headings.                 |
| `setext_heading_support` | `true`     | Whether setext (underlined) headings take part in the check.        |

### Empty sections - `DS106`

| Option                         | Default  | Meaning                                                                                                                   |
|--------------------------------|----------|---------------------------------------------------------------------------------------------------------------------------|
| `empty_section_policy`         | `leaf`   | `off`, `leaf` or `all`: which sections are checked for visible content.                                                   |
| `placeholder_content_policy`   | `ignore` | `ignore` or `count`: whether HTML comments count as section content.                                                      |
| `image_content_counts`         | `true`   | Whether an image counts as section content.                                                                               |
| `empty_section_min_text_chars` | `0`      | A section is flagged when its visible non-whitespace characters are `<=` this value; `0` means any visible text suffices. |

### Reference definitions - `DS108`

| Option                            | Default      | Meaning                                                           |
|-----------------------------------|--------------|-------------------------------------------------------------------|
| `unused_reference_definitions`    | `false`      | Whether unused reference definitions are reported.                |
| `duplicate_reference_definitions` | `warn`       | `off`, `warn` or `error`: severity for each repeated definition.  |
| `reference_label_normalization`   | `commonmark` | Label normalization dialect (only `commonmark` today).            |

### Fenced code - `DS109`, `DS110`

| Option                          | Default      | Meaning                                                                              |
|---------------------------------|--------------|--------------------------------------------------------------------------------------|
| `fence_dialect`                 | `gfm-subset` | Fence dialect recognized by `DS109`; also gates whether `DS110` emits at all.        |
| `report_stray_closing_fence`    | `false`      | Whether a closing fence with no opener is reported.                                  |
| `require_fence_languages`       | `false`      | Switches `DS110` on: meaningful fences must carry a language label.                  |
| `allow_unlabelled_empty_fences` | `true`       | Whether an empty fence may omit its language label.                                  |
| `allowed_fence_languages`       | `[]`         | Allowlist of fence languages; empty allows any.                                      |

### Navigation - `DS112`

| Option                      | Default | Meaning                                                                          |
|-----------------------------|---------|----------------------------------------------------------------------------------|
| `navigation_indexes`        | `[]`    | Index documents whose list-item links form the navigation. Switches `DS112` on.  |
| `navigation_required`       | `[]`    | Documents that must be linked from some navigation index.                        |
| `navigation_unique_targets` | `true`  | Whether a target may be linked only once across navigation.                      |
| `navigation_check_missing`  | `true`  | Whether a navigation link to a non-existent local file is reported.              |

### Local assets - `DS113`

| Option                  | Default                               | Meaning                                                                                                       |
|-------------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `asset_extensions`      | `png, jpg, jpeg, svg, webp, gif, pdf` | Extensions (case-insensitive) that make a link-shaped reference count as an asset. Images are always checked. |
| `check_html_asset_tags` | `true`                                | Whether HTML `<img>`, `<source>` and `<a href>` references are inspected.                                     |
| `check_markdown_images` | `true`                                | Whether Markdown image references are inspected.                                                              |
| `check_srcset`          | `true`                                | Whether `srcset` candidates are inspected.                                                                    |
| `missing_asset_policy`  | `error`                               | `off`, `warn` or `error`: severity of a missing or non-regular asset. `off` skips filesystem access.          |

### Path boundaries - `DS116`

| Option                 | Default    | Meaning                                                                       |
|------------------------|------------|-------------------------------------------------------------------------------|
| `root_escape_policy`   | `error`    | `off`, `warn` or `error`: severity of a reference that escapes the scan root. |
| `decode_percent_paths` | `true`     | Whether percent-encoded paths are decoded once before checking.               |
| `windows_path_policy`  | `portable` | `off` or `portable`: whether Windows-specific path forms are reported.        |

### Tables - `DS117`

| Option               | Default      | Meaning                                                                         |
|----------------------|--------------|---------------------------------------------------------------------------------|
| `table_enable`       | `true`       | Whether the table check runs at all.                                            |
| `table_dialect`      | `gfm-subset` | Pipe-table dialect (only `gfm-subset` today); an unknown dialect emits nothing. |
| `table_strict_cells` | `true`       | Whether every row must have the header's cell count.                            |

### Document identity - `DS114`

| Option                       | Default  | Meaning                                                                    |
|------------------------------|----------|----------------------------------------------------------------------------|
| `document_id_field`          | `id`     | Frontmatter key that carries a document's stable identity.                 |
| `document_id_scope`          | `corpus` | `corpus` or `directory`: scope within which identities must be unique.     |
| `document_id_case_sensitive` | `true`   | Whether identities are compared case-sensitively.                          |
| `document_id_required`       | `false`  | Whether every document must declare an identity.                           |

### Deprecated references - `DS115`

| Option                       | Default | Meaning                                                                              |
|------------------------------|---------|--------------------------------------------------------------------------------------|
| `deprecated_references_file` | `""`    | Root-contained TOML mapping of `[[replacement]]` entries. Switches `DS115` on.       |
| `deprecated_check_prose`     | `true`  | Whether prose and inline-code identifiers are scanned for deprecated names.          |
| `deprecated_check_links`     | `true`  | Whether local link and reference-definition targets are scanned.                     |
| `deprecated_case_sensitive`  | `true`  | Whether deprecated names match case-sensitively.                                     |

### Naming - `DS118`

| Option                                 | Default                 | Meaning                                                                                     |
|----------------------------------------|-------------------------|---------------------------------------------------------------------------------------------|
| `documentation_naming`                 | `off`                   | `off`, `kebab` or `snake`: the naming style to enforce. Switches `DS118` on.                |
| `documentation_naming_allow`           | `README.md`, `index.md` | File names (or whole relative paths) exempt from the policy.                                |
| `documentation_naming_directories`     | `true`                  | Whether directory components are checked as well as file names.                             |
| `documentation_naming_prefix_patterns` | `[]`                    | Glob exceptions for prefixes such as numeric ADR numbers (`?` and `*` only, never a regex). |

## Report options (Milestone 0007)

Every report is rendered from a template (see the
[report template format](/docs/specs/report-template-format.md)). These typed options load from
both config file forms and are validated like the policy options above:

| Option                        | Default | Meaning                                                                                      |
|-------------------------------|---------|----------------------------------------------------------------------------------------------|
| `report_templates_dir`        | none    | Directory, relative to the scan root, of extra templates selectable by name with `--format`. |
| `report_show_clean_documents` | `false` | Whether the text report also lists documents without problems (`--show-clean-documents`).    |
| `report_include_run_meta`     | `false` | Whether the report context carries the per-run `run.generated_at` and `run.id` values.       |

- `report_templates_dir` is checked lexically when the configuration loads. The template loader
  applies the full containment gate (no symlink out of the root) before it lists or opens anything
  in the directory. A packaged template name can never be shadowed by a directory template.
- `docsentinel scan --format NAME` accepts any packaged name (`text`, `github`, `json`, `json-v1`,
  `json-documents`) or a template name from `report_templates_dir`. `--template PATH` renders an
  invoker-supplied file and wins over `--format`. Any template error prints `Scan failed:` and exits
  `2`. `docsentinel doctor` lists the discovered templates.
- `--format json` is schema 2 (one record per document). The schema-1 bytes are `--format json-v1`.

## Fast profile rules

The registered [Story 02.0](../roadmap/0001-generic-implementation/02.0-fast-profile-structural-detectors/README.md)
`fast` rules run locally with the standard library only. No external service, network or model is
used. Rules `DS104` to `DS118` build on the shared `markdown_blocks.py` scanner, except `DS114` and
`DS118` (noted below).

The [rules table](../user/reference/rules.md) lists every rule with its severity, activation, fault
class and config keys; it is drift-tested against the registry.

### `DS104` - anchor conflicts

Reports an explicit HTML anchor that repeats another, or that shadows a generated heading anchor.

### `DS105` - heading levels

Reports skipped heading levels and a first heading that violates `first_heading_level`. Optionally
reports multiple H1 headings.

### `DS106` - empty sections

Reports a heading whose body has no visible, publishable content.

### `DS108` - reference definitions

Checks reference *identifiers* and *definitions*, never whether the target exists (that is `DS101`).
It works over the same scanner's fence, inline-code and comment masks.

- Flags undefined full `[text][label]` and collapsed `[label][]` references.
- Flags each duplicate definition after the first (`duplicate_reference_definitions`).
- Flags unused definitions only when `unused_reference_definitions` is enabled.
- Normalizes labels under the `commonmark` dialect.
- Never reports shortcut `[label]` uses, escaped brackets, footnotes, inline links or masked regions.

### `DS109` - fence boundaries

Reports unclosed or malformed fenced code blocks, via the shared scanner.

### `DS110` - fence languages (opt-in)

Reports meaningful fenced code blocks that omit the language label required by policy.

- Emits nothing unless `require_fence_languages` is enabled.
- Reuses `DS109`'s fence tokens.
- Also consumes `allow_unlabelled_empty_fences` and `allowed_fence_languages`.
- `fence_dialect` gates whether it emits at all.

### `DS112` - navigation integrity (opt-in)

Emits nothing unless `navigation_indexes` names one or more index documents. For each index it
scopes navigation to links on list items, derived over the scanner's masked text (R1).

- Reports a target linked more than once (`navigation_unique_targets`).
- Reports a link whose local destination does not exist (`navigation_check_missing`, `os.stat` only).
- Reports a target that escapes the scan root, lexically and with zero filesystem access. This
  intentionally overlaps `DS116`.
- Across indexes, reports a `navigation_required` document that no navigation link points at.
- The README's "appear exactly once" contract is the union of the presence check
  (`navigation_required`) and the uniqueness check (`navigation_unique_targets`, default on), not
  one coupled rule.
- A missing, unreadable, non-regular, out-of-root or non-discovered configured index is a
  fail-closed `ConfigError` (readiness error, CLI exit 2), never a finding and never a silent clean
  result.
- Echoes only a bounded, repr-escaped copy of the author's raw target or configured path, never a
  resolved path. See the [DS112 threat model](../security/threat-model-ds112-navigation-integrity-2026-10-23.md).

### `DS113` - missing assets

Reports local media and document assets that do not exist as a regular file inside the scan root.

- Checks Markdown images, HTML `<img>` and `<source>` `src`/`srcset`, HTML `<a href>`, and used
  reference-definition targets.
- Images are checked regardless of extension. `asset_extensions` gates only link-shaped references,
  so ordinary `.md` links stay `DS101`'s concern.
- Reuses `is_ds116_owned` and `escapes_via_symlink` to defer every `DS116`-owned or in-root
  symlink-out target to `DS116`. It never stats an escape.
- Decides existence and type with `os.stat` plus `S_ISREG` only and never opens content, so a
  committed FIFO, device, socket or directory is a non-regular-file finding without being read.
- Echoes only a bounded, repr-escaped copy of the author's raw target. See the
  [DS113 threat model](../security/threat-model-ds113-missing-assets-2026-10-23.md).

### `DS114` - document identity

Unlike the other Milestone 0005 fast rules, it carries its own minimal, bounded, standard-library-only
frontmatter reader instead of the shared scanner. (Milestone 0004's `DS111` metadata rule is not in
this tree.)

- Reads only the configured `document_id_field` from each document's opening YAML frontmatter.
- Normalizes values to Unicode NFC with whitespace collapsed; case-folds when
  `document_id_case_sensitive` is false.
- Enforces uniqueness within `document_id_scope`, and flags a document lacking an identity when
  `document_id_required` is set.
- Stays silent for `DS111`-owned malformed metadata (an unterminated or over-long opening block, or
  a duplicate id key).
- When the field is present once in a well-formed block with an unsupported value shape (flow
  collection, anchor/alias/tag, block scalar, nested mapping or sequence, unterminated quoted
  scalar), emits one explicit finding at the field's line and excludes that document from collision
  detection. This is a finding, never a `ConfigError`, so one odd document never aborts the scan
  with exit 2.
- Reads only the bounded head of each in-root document, never follows a reference, and echoes only a
  bounded, repr-escaped identity, path or field name.

### `DS115` - deprecated references (opt-in)

Emits nothing unless `deprecated_references_file` names a root-contained TOML mapping of
`[[replacement]]` entries: `old`, `new`, `kind` (`prose`, `link` or `identifier`), and optional
`scope` globs, including `!`-prefixed excludes for the historical-archive exemption.

- Matches each mapped `old` token literally with whole-token boundaries. It is never compiled as a
  user regex, so `APIv1` never matches inside `APIv10`.
- The `kind` selects what is searched:
  - `prose` runs over the masked physical lines.
  - `identifier` runs over inline-code span text.
  - `link` runs over local link and reference-definition targets, matched lexically with zero
    filesystem probing (existence is `DS101`'s concern, root escape is `DS116`'s).
- `deprecated_check_prose` gates prose and identifier, `deprecated_check_links` gates links, and
  `deprecated_case_sensitive` governs the single case policy: NFC normalization on both sides, no
  NFKC or confusable folding.
- Reports literal occurrences and never chases a replacement chain, so cycles are inert.
- A missing, unreadable, non-regular, out-of-root, oversized, unparseable or schema-invalid mapping,
  including a cross-entry duplicate or conflicting `old`, is a fail-closed `ConfigError` (readiness
  error, CLI exit 2). The path is re-validated defensively (`DS116` containment, `S_ISREG` and a
  size cap) before any open, because an injected `Config` bypasses `load_config`.
- Reuses the shared resolver only for string identity, and echoes only a bounded, repr-escaped copy
  of the configured path, matched token and suggested replacement. See the
  [DS115 threat model](../security/threat-model-ds115-deprecated-references-2026-10-23.md).

### `DS116` - path boundaries

Reports documentation references whose target escapes the configured scan root, via the shared
resolver in `markdown_blocks.py`. Consumes `root_escape_policy`, `decode_percent_paths` and
`windows_path_policy`.

Its scope differs by reference kind (Story 11.0 code-span ruling):

- **Links, image sources, reference definitions and HTML `href`/`src`/`srcset`** are checked at full
  strictness. `DS101` delegates all unsafe link targets to `DS116` via `is_ds116_owned` instead of
  resolving or stat-ing them.
- **Inline code spans** are documentation, so only genuine traversal is reported: a lexical root
  escape, its percent-encoded and residual-encoding forms, or an in-root symlink pointing outside.
  Drive, UNC, backslash, control and regex or escape snippets are left to `DS103`, which keeps its
  exact pre-Story-11 behavior for them and skips only the root-escape and symlink-out code spans
  `DS116` owns.

The shared `ResolvedReference.reason` field carries the typed sub-category (`drive`, `unc`,
`backslash`, `control`, `template`, `glob`) that lets `DS116` separate unsafe targets from safe ones.
The detector never reads a path outside the root and echoes only a bounded, repr-escaped copy of the
author's raw target. See the
[DS116 threat model](../security/threat-model-ds116-path-boundaries-2026-10-22.md), including its
"Rulings during implementation" section.

### `DS117` - pipe tables

Reports inconsistent cell counts and malformed alignment markers in GFM pipe tables, via the
scanner's fence mask. Emits nothing when `table_enable` is false or `table_dialect` names an
unsupported dialect.

### `DS118` - naming policy (opt-in)

A **pure path-string policy**, unlike every other fast rule: it reads neither the shared scanner nor
the filesystem (no `open`, `stat` or `realpath`), never reads document content, and decides entirely
from each discovered document's relative POSIX path.

- Emits nothing unless `documentation_naming` selects a style: `kebab` (lowercase ASCII words joined
  by single hyphens) or `snake` (single underscores).
- `documentation_naming_allow` exempts exact file names or whole paths (default `README.md` and
  `index.md`).
- `documentation_naming_prefix_patterns` takes a restricted, bounded literal/`?`/`*` glob subset,
  never a user regex, for numeric ADR prefixes and similar.
- `documentation_naming_directories` controls whether directory components are checked.
- Reports each offending component once (directories outermost-first, then the file) with a
  deterministic, ASCII, policy-conformant suggested rename.
- Never renames a file, so `DS101` stays responsible for any link a later user rename breaks.
- Echoes the offending name bounded and `unicode_escape`-ed. An injected `Config` with an
  unrecognized style or out-of-bounds prefix patterns fails closed with a `ConfigError`.

## Opt-in policy rules

Four rules (`DS110`, `DS112`, `DS115`, `DS118`) implement an *opt-in policy* that is inert until a
project configures it. `rules.Rule` carries an optional `opt_in_option` field naming the `Config`
option that switches the policy on (empty for ordinary always-active rules).
`rules.opt_in_satisfied(rule, config)` returns whether that option is set to an enabling value:
truthy and not the string `"off"`, covering boolean, tuple and string option shapes.

Opt-in status is reported, never hidden:

- **`ScanResult.notice`** counts only genuinely evaluated rules and names any active opt-in rule
  whose policy is off, for example:
  `12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming).`
  The notice is built from two structured `ScanResult` fields, `rules_evaluated` (int) and
  `opt_in_off` (`(code, option)` pairs), so templates can loop over the off rules. JSON schema v1,
  exit codes and `enabled_rules` semantics are unchanged: selection stays orthogonal to whether an
  opt-in policy fires.
- **`docsentinel rules`** marks such a rule, for example:
  - `DS110: Missing language labels on code fences [opt-in: set require_fence_languages]`
  - `DS112: Declared documentation navigation integrity [opt-in: set navigation_indexes]`
  - `DS115: Deprecated names and migrated references [opt-in: set deprecated_references_file]`
  - `DS118: Documentation file and directory naming policy [opt-in: set documentation_naming]`
- **`docsentinel doctor`** counts them separately, for example:
  `fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)`.

## Standard profile

The registered `standard` rules come from
[Milestone 0002 Story 02.0](../roadmap/0002-standard-profile-detectors/02.0-text-complexity-detector/README.md),
[Story 03.0](../roadmap/0002-standard-profile-detectors/03.0-corpus-statistics-duplicate-and-low-information/README.md)
and [Story 04.0](../roadmap/0002-standard-profile-detectors/04.0-doc-vs-code-signature-mismatch/README.md).

| Rule    | Reports                                                | Severity | Library                    |
|---------|--------------------------------------------------------|----------|----------------------------|
| `DS201` | High text complexity above the grade-level threshold   | warning  | `textstat`                 |
| `DS202` | Duplicated text or facts across paragraph chunks       | warning  | `scikit-learn`             |
| `DS203` | Paragraphs that are lexically thin and non-distinctive | warning  | `scikit-learn`, `textstat` |
| `DS204` | Docstring and function signature mismatches            | error    | `docsig`                   |

- `DS201` supports a single global `max_grade_level` threshold (per-category thresholds are future
  work) and skips documents with fewer prose words than `min_document_words`.
- `DS202` uses cosine similarity on a shared TF-IDF corpus model.
- `DS204` is the only `standard` detector that reads Python source, via `code_discovery.discover_python`
  and `Config.docsig_paths`, rather than Markdown.

### Size limits

| Option                | Default | Meaning                                                                             |
|-----------------------|---------|-------------------------------------------------------------------------------------|
| `min_document_words`  | `50`    | Integer `>= 1`. `DS201` skips documents with fewer prose words.                     |
| `min_paragraph_words` | `5`     | Integer `>= 1`. Paragraphs with fewer words stay out of the `DS202`/`DS203` corpus. |
| `min_paragraph_chars` | `30`    | Integer `>= 0`. Paragraphs with fewer visible characters stay out of that corpus.   |

A paragraph must clear both paragraph floors. The two floors are part of the `build_corpus_model`
memoization key, so distinct settings never reuse a stale corpus within a process. The TF-IDF
vectorizer settings, the `DS203` normalization references and the `DS201` Flesch-Kincaid metric are
fixed calibration internals and are not configurable. All defaults reproduce historical behavior
byte-for-byte.

### Optional dependencies and lazy loading

The detectors live behind the optional `docsentinel[standard]` extra (`scikit-learn`, `textstat`,
`docsig`). To keep the fast scan lightweight, they sit behind a lazy-loading boundary,
`ensure_standard_loaded()`.

- **Lazy loading:** the standard package is imported only when `profile="standard"` is requested or
  when inspecting rules via `rules` and `doctor`. `scan --profile fast` never imports or touches
  standard dependencies.
- **Graceful CLI degradation:** a `standard` scan without the extra fails cleanly with an actionable
  installation message and exit code `2`, with no traceback. `rules` prints installation guidance for
  standard rules and exits `0`; `doctor` reports whether the profile is available or uninstalled.
- **Milestone scope:** with Milestone 0002 complete, `DS201` to `DS204` are registered. With
  Milestone 0003 complete, `DS301` is registered as the deep candidate detector.

### CI and pre-commit policy

The `fast` profile runs on every commit through the default `docsentinel-fast` pre-commit hook.
`standard` is CI-and-on-demand, not an every-commit blocker:

- **Local opt-in hook:** `docsentinel-standard` in `.pre-commit-hooks.yaml`, with `stages: [manual]`
  and `additional_dependencies: ["docsentinel[standard]"]`. It runs only on explicit invocation
  (`pre-commit run docsentinel-standard --hook-stage manual`), so contributors are not blocked by
  heavy dependencies or longer runtimes.
- **Dedicated CI lane:** CI runs
  `docsentinel scan . --profile standard --baseline .docsentinel-standard-baseline.json` with the
  `standard` extra installed.
- **Separate baseline files:** standard findings are baselined in `.docsentinel-standard-baseline.json`,
  distinct from `.docsentinel-baseline.json`, so the two profiles keep disjoint fingerprints and can
  be adopted independently.
- **Non-blocking advisory warnings:** CI does not fail on advisory warnings (`DS201` to `DS203`). It
  fails only on errors (`DS204`) or when `--strict` is explicitly configured.

## Deep profile

The registered [Milestone 0003 Story 02.0](../roadmap/0003-deep-profile-and-periodic-review/02.0-fact-contradiction-candidate-detector/README.md)
`deep` rule is `DS301`: it reports fact-contradiction candidates across Markdown documents where
differing numeric or named-entity claims are made about the same subject (`warning`, evaluated with
`spacy` and `textacy`).

Semantic SVO extraction is heuristic and expected to report false positives, so the profile runs
under strict safety and advisory boundaries:

- **Explicit opt-in gate.** Deep checks require one of: `deep_confirm = true` in configuration,
  `--i-understand-deep-is-heuristic` on the CLI, or `DOCSENTINEL_DEEP_CONFIRM=1` in the environment.
  An unconfirmed scan runs zero deep analyzers and reports an explanatory pending notice.
- **Optional dependencies, loaded lazily.** `spacy`, `textacy` and the `en_core_web_sm` model live in
  the `docsentinel[deep]` extra and load only when a confirmed deep scan runs.
- **Advisory-only exit codes.** Deep findings are candidates for review. A deep scan always exits
  `0`, even under `--strict` or with findings present, and prints an advisory banner. Promoting deep
  findings to build failures (for example `--fail-on-deep`) is deferred.
- **Periodic review loop.** Review runs asynchronously, weekly or on demand, through the
  `/loop deep-review` loop driving the `docs-reviewer` agent. It triages candidates and audits
  doc-vs-code behavioral drift without blocking commits or CI.

## Schema versioning

`ScanResult` exposes a `schema_version` integer field (`1` in M0) as its first field, identifying the
contract shape for JSON and text consumers.

`schema_version` increments by exactly 1 whenever a field is removed, renamed, or has its *meaning*
changed (not merely added) in `ScanResult`'s JSON representation. Adding a new optional field with a
sensible default does **not** require a bump; only breaking changes do. This mirrors
semantic versioning for data, not for code.

Milestone 0007 adds defaulted fields that the schema-1 JSON report deliberately omits, so its output
stays byte-identical:

- `Finding.column`, `Finding.value` and `Finding.type` are optional report attributes. They are
  excluded from equality, hashing and baseline fingerprints. `value` holds only the token the
  message already echoes, such as a link target, never a surrounding snippet. `DS101`, `DS102` and
  `DS103` set them; other rules leave them `None`.
- `ScanResult.rules_evaluated` and `ScanResult.opt_in_off` hold the structured form of `notice`.

`telemetry.model.ReportModel.build(result, config)` turns a `ScanResult` into the JSON-shaped
context that report templates render from. `telemetry.model.CONTEXT_SCHEMA` declares each variable
with its type and trust tag. Problems carry `fault_class`, `tier` and `outcome` from
`telemetry.classify.classify`, the function the Milestone 0006 adapter is specified to use. See the
[report template format](/docs/specs/report-template-format.md).
