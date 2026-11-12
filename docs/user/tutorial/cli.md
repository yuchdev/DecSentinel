# Using DocSentinel as an Executable (CLI)

The `docsentinel` command-line tool provides fast, deterministic documentation linting and static analysis for local development and CI/CD pipelines.

---

## Command Overview

DocSentinel provides the following CLI subcommands:

| Command                | Purpose                                                                 |
|------------------------|-------------------------------------------------------------------------|
| `docsentinel scan`     | Analyze Markdown documents and report findings                          |
| `docsentinel baseline` | Capture current findings into a baseline file to suppress legacy issues |
| `docsentinel init`     | Create a starter `docsentinel.toml` configuration file                  |
| `docsentinel rules`    | List all available and active rules per profile                         |
| `docsentinel doctor`   | Diagnose environment readiness and optional dependency installations    |

---

## Scanning Documents (`docsentinel scan`)

The `scan` command is the primary entry point for documentation validation.

### Basic Invocations

```bash
# Scan the current repository with default settings
docsentinel scan

# Scan a specific directory
docsentinel scan docs/

# Scan a single Markdown file
docsentinel scan docs/README.md
```

### Analysis Profiles

DocSentinel supports three distinct profiles via `--profile`:

#### 1. Fast Profile (`--profile fast`) - Default

Runs structural and reference rules. All rules use only the Python standard
library. Sixteen rules are registered; twelve are evaluated by default (four are
opt-in policies that are silent until their option is set):

Every rule, with its severity, activation and options, is listed in the
[rules table](../reference/rules.md).

```bash
docsentinel scan --profile fast
```

**Opt-in rules.** `DS110`, `DS112`, `DS115`, and `DS118` are inert until you set
their enabling option. The scan notice reports exactly which ones are off:

```
12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming).
```

To enable an opt-in rule, set its option in `docsentinel.toml` (see
[Configuration Reference](../reference/configuration.md)):

```toml
# Enable DS110: require a language label on every non-empty code fence.
require_fence_languages = true

# Enable DS118: enforce kebab-case file and directory names.
documentation_naming = "kebab"
```

#### 2. Standard Profile (`--profile standard`)
Runs statistical corpus detectors and docstring synchronization:
- `DS201`: Text readability complexity exceeds threshold
- `DS202`: Duplicate text across documents (cosine similarity check)
- `DS203`: Low information content (short/boilerplate files)
- `DS204`: Docstring parameter/return mismatch against Python code signatures

```bash
docsentinel scan --profile standard
```

#### 3. Deep Profile (`--profile deep`)
Runs deep heuristic NLP analysis (`DS301` fact-contradiction candidate detector). Deep checks are heuristic, compute-intensive, and require explicit confirmation:

```bash
docsentinel scan --profile deep --i-understand-deep-is-heuristic
# or via environment variable
DOCSENTINEL_DEEP_CONFIRM=1 docsentinel scan --profile deep
```

---

## Filtering Rules: `--select` and `--ignore`

You can restrict or exclude specific rules using comma-separated rule codes or prefixes:

```bash
# Only run rule DS101 and DS103
docsentinel scan --select DS101,DS103

# Run all DS2xx standard rules
docsentinel scan --profile standard --select DS2

# Exclude comment checks (DS102)
docsentinel scan --ignore DS102
```

---

## Output Formats: `--format`

Every report is rendered from a template. `--format NAME` selects one by name. Five templates ship
with DocSentinel. The [Report Formats](report.md) guide shows each one in full and explains how to
migrate scripts written for the old output.

### 1. Human-Readable Text (`--format text`) - Default

Prints the scan summary, then each document that has problems with its findings indented directly
under it:

```bash
docsentinel scan --format text
```

```text
Documents: 2 (1 with problems)
...
README.md (74 bytes)
  error: README.md:3:15: dangling link -> docs/nope.md
```

Clean documents are hidden. Add `--show-clean-documents` (or set
`report_show_clean_documents = true`) to list them too.

### 2. Structured JSON (`--format json`)

Outputs a JSON object that follows **schema 2**: a summary, the rule status, and one record per
document with its problems inside it. Clean documents are included with an empty `problems` list:

```bash
docsentinel scan --format json
```

Abridged JSON payload:
```json
{
  "schema_version": 2,
  "profile": "fast",
  "run": { "model": null, "notice": "12 fast rule(s) evaluated; ...", "advisory": null },
  "summary": { "documents": 2, "documents_with_problems": 1, "findings": 1,
               "by_severity": { "error": 1 }, "by_rule": { "DS101": 1 } },
  "rules": { "enabled": ["DS101", "DS102", "..."], "evaluated": 12, "opt_in_off": [ { "code": "DS110", "option": "require_fence_languages" } ] },
  "documents": [
    {
      "path": "README.md",
      "bytes": 74,
      "domain": "docs",
      "problems": [
        { "rule": "DS101", "type": "dangling link", "message": "dangling link -> docs/nope.md",
          "value": "docs/nope.md", "severity": "error", "line": 3, "column": 15,
          "fault_class": "dangling_reference", "tier": "deterministic", "outcome": "rejected" }
      ]
    },
    { "path": "docs/setup.md", "bytes": 15, "domain": "docs", "problems": [] }
  ],
  "pending": []
}
```

`rules.enabled` lists every rule selected in the active profile (selection is orthogonal to whether
an opt-in policy fires). `rules.opt_in_off` separately names the opt-in rules that are selected but
currently silent.

### 3. Legacy JSON (`--format json-v1`)

Outputs the schema 1 JSON that `--format json` printed before this release, unchanged: a flat
`findings` list in which each finding carries its own `path`. Use it for consumers that have not
moved to schema 2:

```bash
docsentinel scan --format json-v1
```

### 4. Document records only (`--format json-documents`)

Outputs only the `documents` array of schema 2, as a bare JSON list.

### 5. GitHub Actions Annotations (`--format github`)

Formats findings as GitHub Actions workflow commands (`::error` and `::warning`). Each one carries
`title=` with the rule code, and `col=` when the column is known:

```bash
docsentinel scan --format github
```

```text
::error file=README.md,line=3,col=15,title=DS101::dangling link -> docs/nope.md
```

### Custom templates: `--template` and `report_templates_dir`

- `--template PATH` renders with a template file you supply. It wins over `--format`.
- `report_templates_dir` in the configuration names a directory under the scan root. Each
  `NAME.json` in it can be selected with `--format NAME`. Packaged names always win.

An unknown format name or an invalid template prints `Scan failed: ...` on stderr and exits `2`.
`docsentinel doctor` lists the templates you can select. See
[Report Formats](report.md#custom-templates) and the
[report template format](../../specs/report-template-format.md).

### Site-root links: `--link-root`

A link starting with `/` resolves against the link root, by default the
nearest directory holding `.git` (see `link_root` in the configuration
reference). `--link-root PATH` overrides it for one run, for example when the
docs are not in a git repository. PATH is absolute or relative to the current
directory and must be the scan root or one of its ancestors (never the
filesystem root). The flag is trusted invoker input and wins over the
configuration; a bad value exits with code `2`. A `link_root` in a
configuration file is bounded instead (the nearest `.git`, or an ancestor
holding a project marker).

Because the flag is trusted, never put `--link-root` in pre-commit `args:` or in
a `pull_request_target` workflow, where a contributor could choose it.

```bash
docsentinel scan docs --link-root .
```

---

## Strict Mode and Exit Codes

### Exit Code Rules

| Exit Code | Meaning                                                                                |
|-----------|----------------------------------------------------------------------------------------|
| `0`       | Clean run (no error-level findings, or deep advisory findings)                         |
| `1`       | One or more error-level findings detected (or any warnings when `--strict` is enabled) |
| `2`       | Configuration error, invalid CLI flags, or filesystem scan failure                     |

### Strict Mode (`--strict`)

By default, warning-level findings do not fail the build (exit code `0`). Use `--strict` to elevate all findings to build-failing conditions (exit code `1`):

```bash
docsentinel scan --strict
```

*Note: Deep profile findings (`DS301`) are heuristic candidates and advisory-only; they always return exit code `0` to avoid blocking CI pipelines.*

---

## Baselines: Suppressing Existing Debt (`docsentinel baseline`)

When introducing DocSentinel to an existing project with legacy issues:

### 1. Generate the Baseline

```bash
# Capture fast profile findings
docsentinel baseline --output .docsentinel-baseline.json

# Capture standard profile findings
docsentinel baseline --profile standard --output .docsentinel-standard-baseline.json
```

### 2. Run Scans with Baseline Filtering

```bash
docsentinel scan --baseline .docsentinel-baseline.json
```

All existing issues recorded in `.docsentinel-baseline.json` are suppressed. The scan will only report and fail on new issues introduced in subsequent commits.

---

## Environment Diagnostics (`docsentinel doctor`)

Verify which profiles, dependencies, and language models are ready on your machine:

```bash
docsentinel doctor
```

Example output:
```text
Inventory: available
standard profile: available
deep profile: not ready
  ✓ deep libraries installed (spacy, textacy)
  ✗ deep model missing (en_core_web_sm): python -m spacy download en_core_web_sm
fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)
standard rules: 4 registered
deep rules: 1 registered
```

The deep profile requires an additional model download even after
`pip install "docsentinel[deep]"`:

```bash
python -m spacy download en_core_web_sm
```

---

## Listing Rules (`docsentinel rules`)

Inspect all registered detection rules across profiles:

```bash
docsentinel rules
```

---

## Project Configuration (`docsentinel init`)

Generate a starter `docsentinel.toml` configuration:

```bash
docsentinel init
```

Created `docsentinel.toml`:
```toml
profile = "fast"
include = ["*.md", "**/*.md"]
exclude = [".git", ".venv", "node_modules"]
select = []
ignore = []

# Standard profile thresholds (profile = "standard"); defaults shown.
# max_grade_level = 14.0          # DS201: flag prose above this readability grade
# duplicate_similarity = 0.85     # DS202: flag paragraph pairs at/above this cosine similarity
# min_information_score = 0.15    # DS203: flag paragraphs scoring below this information score
# docsig_paths = ["src"]          # DS204: Python source roots checked against docstrings
#
# Statistical size limits (standard profile); defaults shown.
# min_document_words = 50         # DS201: skip documents with fewer prose words
# min_paragraph_words = 5         # DS202/DS203: skip paragraphs with fewer words
# min_paragraph_chars = 30        # DS202/DS203: skip paragraphs shorter than this
```

`docsentinel init` refuses to run in a directory that already contains the
equivalent alias `doc_sentinel.toml`, because keeping both files is ambiguous.

For a comprehensive example of fast-profile policy options (DS104–DS118) with
all defaults documented, see [examples/docsentinel.toml](/examples/docsentinel.toml).
