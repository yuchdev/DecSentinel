# DocSentinel

DocSentinel is a deterministic-first documentation quality assurance and static analysis framework for Markdown repositories and Python docstrings. It validates document integrity, cross-references, text quality, and docstring synchronization without sending sensitive document content across networks.

All three initial milestones are complete, providing a fully working command-line tool and Python library:

* **`fast` default profile:** Sub-second structural and reference checks; all 16 rules use only the Python standard library at scan time. Note: `pyproject.toml` lists `spacy` as a core runtime dependency (so every installation includes spaCy), but `import docsentinel` no longer imports spaCy at a module load and fast and standard profile scans never call any spaCy API. Whether to remove spaCy from the core dependencies is an open product decision; it does not affect scan correctness or the fast-profile runtime guarantee.
  * `DS101` dangling links/anchors
  * `DS102` stray HTML comments
  * `DS103` unresolvable path-like code spans 
  * `DS104` conflicting heading and explicit anchors
  * `DS105` heading hierarchy and section levels
  * `DS106` empty or contentless sections
  * `DS108` reference-style link definition integrity (undefined or duplicated reference labels)
  * `DS109` malformed or unclosed fenced code blocks
  * `DS110` missing language labels on code fences (opt-in; off unless `require_fence_languages` is enabled)
  * `DS112` declared documentation navigation integrity: within the Markdown indexes named by `navigation_indexes`, a navigation target linked more than once (`navigation_unique_targets`), a navigation link whose local destination does not exist (`navigation_check_missing`), a target that escapes the scan root, and a `navigation_required` document that no navigation link points at (warning severity; opt-in, off unless `navigation_indexes` is set). A missing or unreadable configured index is a fail-closed readiness error (exit 2)
  * `DS113` missing local media and document assets: Markdown images, HTML `<img>`/`<source>` `src`/`srcset`, HTML `<a href>`, and used reference-definition targets whose local file does not exist as a regular file inside the scan root (error severity). Images are checked regardless of extension; `asset_extensions` gates link-shaped references, the `check_*` toggles enable each reference kind, and `missing_asset_policy` (off/warn/error) downgrades or silences it. External URLs, `data:` URIs, templates, and root escapes (DS116's concern) are skipped
  * `DS114` duplicate stable document identifiers: two documents that declare the same stable frontmatter identity within `document_id_scope` (`corpus`/`directory`), reading only the configured `document_id_field` (default `id`); values are normalized to Unicode NFC with whitespace collapsed, and case-folded when `document_id_case_sensitive` is false, while `document_id_required` additionally flags each document lacking an identity (error severity). Malformed metadata (an unterminated block or duplicate id key) is left to metadata validation and stays silent, but an unsupported value shape of the configured field yields one explicit finding
  * `DS115` deprecated names and migrated references: in-scope textual occurrences of names explicitly mapped as deprecated in the TOML mapping named by `deprecated_references_file`, with the suggested replacement and the mapping provenance (warning severity; opt-in, off unless `deprecated_references_file` is set). `prose` and `identifier` matches (over prose and inline code) are gated by `deprecated_check_prose`, `link` matches (over local link targets, lexical only — existence stays DS101's concern) by `deprecated_check_links`, and `deprecated_case_sensitive` governs the case; fenced code and an explicit `scope` exemption keep historical examples clean. A missing, out-of-root, or schema-invalid mapping (including a conflicting duplicate entry) is a fail-closed readiness error (exit 2)
  * `DS116` references that escape the documentation root, such as parent-directory traversal, percent-encoded escapes, and Windows drive, UNC, or backslash paths (error severity). Links, images, reference definitions, and HTML `href`/`src`/`srcset` are checked at full strictness; inline code spans are documentation, so there DS116 reports only genuine traversal (a root escape or an in-root symlink pointing outside), leaving drive, UNC, backslash, and regex or escape snippets to DS103
  * `DS117` malformed GFM pipe-table structure
  * `DS118` documentation file and directory naming policy: discovered document paths whose components do not match the portable-ASCII style named by `documentation_naming` (`kebab`/`snake`), with a deterministic suggested rename (warning severity; opt-in, off unless `documentation_naming` selects a style). `documentation_naming_allow` (default `README.md`/`index.md`) and `documentation_naming_prefix_patterns` (numeric ADR prefixes and similar) exempt conventional names, and `documentation_naming_directories` scopes whether directory components are checked. It is a pure path-string policy: it reads no document content, touches no filesystem, and never renames a file
* **`standard` profile:** Corpus-level statistics and docstring synchronization via `docsentinel[standard]` 
  * `DS201` prose readability complexity
  * `DS202` paragraph duplication
  * `DS203` low-information content
  * `DS204` Python docstring-to-code signature mismatch
* **`deep` profile:** Semantic NLP contradiction candidate analysis via `docsentinel[deep]`. Gated by explicit opt-in confirmation with advisory-only exit codes.
  * `DS301` fact-contradiction candidates across documents 

## Requirements and Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/) (or standard `pip`).

```sh
# Everything: fast, standard and deep profiles
pip install docsentinel

# or with uv
uv add docsentinel

# The deep profile also needs its spaCy model (one-time download)
python -m spacy download en_core_web_sm
```

The profile extras `docsentinel[fast]`, `docsentinel[standard]` and `docsentinel[deep]` select a
profile by name (for example `pip install "docsentinel[fast]"`). They are aliases: pip extras can
only add dependencies, so they do **not** make the installation lighter - every profile's dependencies
are already part of a plain `pip install docsentinel`.

pip cannot run code after an installation, so the starter configuration is a separate, explicit step:

```sh
docsentinel init                  # create docsentinel.toml in the current directory
docsentinel init path/to/dir      # ... or in a specific directory
docsentinel init --project-root   # ... or next to the nearest uv.lock / pyproject.toml
```

In a terminal, `init` asks for confirmation first; pass `--yes` to skip the prompt. It never
overwrites an existing file.

## Command-Line Usage

```sh
# Initialize starter docsentinel.toml configuration
uv run docsentinel init

# Run deterministic fast-profile scan on the current repository
uv run docsentinel scan

# Scan specific directories or files
uv run docsentinel scan docs/
uv run docsentinel scan docs/README.md

# Scan with standard or deep profile
uv run docsentinel scan --profile standard
uv run docsentinel scan --profile deep --i-understand-deep-is-heuristic

# Output formats: text (default), json (schema 2), json-v1 (old schema 1), json-documents, github annotations
uv run docsentinel scan --format json
uv run docsentinel scan --format json-v1   # the schema-1 bytes that --format json produced before 1.2.0
uv run docsentinel scan --format github    # use this one in GitHub Actions
uv run docsentinel scan --template my-report.json   # your own template, wins over --format
# Writing a template or an extension: docs/user/tutorial/custom-reports.md

# Strict mode: fail on warnings as well as errors
uv run docsentinel scan --strict

# Baseline legacy findings to prevent build regressions
uv run docsentinel baseline . --output .docsentinel-baseline.json
uv run docsentinel scan --baseline .docsentinel-baseline.json

# Inspect active detection rules and diagnostic environment readiness
uv run docsentinel rules
uv run docsentinel doctor
```

### Exit Codes Contract

- `0` — Scan completed with no blocking findings (or advisory-only deep candidates).
- `1` — Scan found blocking errors (or warnings when `--strict` is enabled).
- `2` — Configuration error, invalid arguments, or filesystem scan failure.

## Configuration

DocSentinel loads configuration from `docsentinel.toml` (or the equivalent alias `doc_sentinel.toml`) at the scan root, or from the `[tool.doc_sentinel]` table in `pyproject.toml`:

```toml
# docsentinel.toml: keys at the top level, no table header.
# In pyproject.toml put the same keys under a [tool.doc_sentinel] table instead.
profile = "fast"
include = ["*.md", "**/*.md"]
exclude = [".git", ".venv", "node_modules", "dist"]
select = []
ignore = []
baseline = ".docsentinel-baseline.json"

# Standard profile thresholds (optional)
max_grade_level = 14.0          # DS201: flag prose above this readability grade
duplicate_similarity = 0.85     # DS202: flag paragraph pairs at/above this cosine similarity
min_information_score = 0.15    # DS203: flag paragraphs scoring below this information score
docsig_paths = ["src"]          # DS204: Python source roots checked against docstrings

# Standard profile statistical size limits (optional)
min_document_words = 50         # DS201: skip documents with fewer prose words
min_paragraph_words = 5         # DS202/DS203: skip paragraphs with fewer words
min_paragraph_chars = 30        # DS202/DS203: skip paragraphs shorter than this

# Deep profile opt-in confirmation (optional)
deep_confirm = false
```

Patterns match relative paths; exclude patterns also match directory names. Symlinked files are skipped for safety. Output order and document inventory are stable and deterministic.

## Python Library

The CLI and Python API share the same engine and frozen data models:

```python
from pathlib import Path
from docsentinel import Config, load_config, scan

# Quick scan with default settings
result = scan(".")

print(f"Profile: {result.profile}")
print(f"Documents scanned: {len(result.documents)}")
print(f"Findings: {len(result.findings)}")

for finding in result.findings:
    print(f"[{finding.severity.upper()}] {finding.rule} in {finding.path}:{finding.line} - {finding.message}")

# Programmatic scan with explicit configuration
config = Config(
    profile="standard",
    select=("DS201", "DS204"),
    docsig_paths=("src",),
)
result = scan(".", config=config)
```

## Pytest Integration

DocSentinel includes an opt-in pytest plugin exposing the `docsentinel_scan` fixture:

```sh
uv run pytest -p docsentinel.pytest_plugin
```

```python
def test_documentation_integrity(docsentinel_scan):
    result = docsentinel_scan(".")
    assert not [f for f in result.findings if f.severity == "error"]
```

## Pre-commit Integration

DocSentinel provides pre-commit hooks in `.pre-commit-hooks.yaml`:

- `docsentinel-fast`: Runs fast structural checks on every commit (fast rules use stdlib only at run time; `pyproject.toml` lists `spacy` as a core dependency but spaCy is not imported during fast or standard scans — see the [dependency note](docs/user/tutorial/README.md#dependency-note) in the tutorial).
- `docsentinel-standard`: Manual on-demand hook for standard corpus and signature analysis.

## Documentation and Resources

- [User Tutorial](docs/user/tutorial/README.md) — Comprehensive guide for CLI and Python library consumers.
- [Statistical Checks Reference](docs/user/reference/statistical-checks.md) — Full reference for the six standard-profile threshold keys (DS201–DS203).
- [Configuration Reference](docs/user/reference/configuration.md) — All fast-profile policy options for DS104–DS118, with defaults and valid values.
- [Architecture](docs/architecture/README.md) — Architectural design, profile boundaries, and data contracts.
- [Markdown Scanner Guide](docs/dev/markdown_scanner.md) — Developer guide for adding rules, resolver ownership, and the security checklist.
- [Roadmap](docs/roadmap/README.md) — Detailed milestone, story, and task specifications.
- [Contributing](CONTRIBUTING.md) — Development guidelines and validation commands.
