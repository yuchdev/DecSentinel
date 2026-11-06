# DocSentinel User Tutorial

DocSentinel is a deterministic documentation quality assurance and static analysis engine for Markdown codebases. It verifies document integrity, cross-references, text quality, and docstring synchronization without sending sensitive document content across networks.

This tutorial guides you through using DocSentinel both as a **command-line executable (CLI)** and as an embedded **Python library**.

---

## Table of Contents

1. [Installation](#installation)
2. [Core Concepts](#core-concepts)
3. [Using DocSentinel as an Executable (CLI)](#using-docsentinel-as-an-executable-cli)
4. [Using DocSentinel as a Python Library](#using-docsentinel-as-a-python-library)
5. [Configuration](#configuration)
6. [Managing Baselines for Legacy Debt](#managing-baselines-for-legacy-debt)
7. [CI/CD and Pre-commit Integration](#cicd-and-pre-commit-integration)
8. [Further Reading](#further-reading)

---

## Installation

DocSentinel provides three installation tiers depending on the analysis profile you need:

### 1. Fast Profile (Core)

Installs the core engine, CLI, and deterministic structural checks
(`DS101`–`DS118`, sixteen rules total). No optional extras are required at
scan time; all fast rules use only the Python standard library at run time.
See the [dependency note](#dependency-note) below for a known inconsistency.

```bash
pip install docsentinel
# or with uv
uv add docsentinel
```

### 2. Standard Profile (Corpus statistics & Signature checks)

Installs standard detectors including readability complexity (`DS201`), duplicate text (`DS202`), low-information detection (`DS203`), and docstring-to-code signature validation (`DS204`):

```bash
pip install "docsentinel[standard]"
# or with uv
uv add --extra standard docsentinel
```

### 3. Deep Profile (Semantic NLP & Heuristic Review)

Installs deep heuristic checks (`DS301`) for paragraph claim contradictions:

```bash
pip install "docsentinel[deep]"
# Download required spaCy model
python -m spacy download en_core_web_sm
```

You can verify your environment anytime with:

```bash
docsentinel doctor
```

---

## Core Concepts

### Profiles

| Profile | Focus | Execution Speed | Optional extras |
|---------|-------|-----------------|-----------------|
| **`fast`** (default) | Structural and reference integrity: 16 rules (DS101–DS118) | Sub-second | None (fast rules use stdlib only at scan time) |
| **`standard`** | Corpus analysis (text complexity, duplication, low-information text, docstring sync) | Fast (seconds) | `docsentinel[standard]`: `scikit-learn`, `textstat`, `docsig` |
| **`deep`** | Semantic contradictions and subject-verb-object claims | Heuristic / Compute-intensive | `docsentinel[deep]`: `spacy`, `textacy`, `en_core_web_sm` model |

### Dependency note

`pyproject.toml` lists `spacy>=3.8.16` as a **core** runtime dependency, so every
`pip install docsentinel` also installs spaCy. However, as of Story 15.0,
`import docsentinel` no longer imports spaCy at module load: DS301's `contradictions`
module imports its spaCy-dependent `_triples` module lazily on the first deep scan
via `importlib.import_module`. Fast and standard scans never import or call any spaCy
API. Whether to remove spaCy from the core dependencies in `pyproject.toml` is an
open product decision; it does not affect fast or standard scan correctness or the
"stdlib only at run time" guarantee for the fast profile.

### Exit Codes Contract

DocSentinel strictly follows predictable CLI exit codes for scriptability and CI pipelines:

- **`0`**: Scan succeeded with no blocking findings (or advisory-only deep profile candidates).
- **`1`**: Scan completed and found blocking errors (or warnings under `--strict`).
- **`2`**: Configuration error, invalid arguments, or filesystem scan failure.

---

## Using DocSentinel as an Executable (CLI)

For complete CLI options and workflows, see the [CLI Tutorial](cli.md).

### 1. Initialize Configuration

Generate a starter configuration file (`docsentinel.toml`):

```bash
docsentinel init
```

### 2. Run a Basic Scan

Scan the current working directory using the default `fast` profile:

```bash
docsentinel scan
```

Scan a specific subdirectory or document:

```bash
docsentinel scan docs/
docsentinel scan docs/README.md
```

### 3. Scan with Different Profiles

```bash
# Standard profile
docsentinel scan --profile standard

# Deep profile (requires explicit opt-in acknowledgment)
docsentinel scan --profile deep --i-understand-deep-is-heuristic
```

### 4. Filter and Select Specific Rules

```bash
# Evaluate only DS101 and DS103
docsentinel scan --select DS101,DS103

# Exclude comment checks (DS102)
docsentinel scan --ignore DS102
```

### 5. Output Formats

```bash
# Standard human-readable table (default)
docsentinel scan --format text

# Machine-readable JSON output (Schema v1)
docsentinel scan --format json

# GitHub Actions workflow annotations (::error, ::warning)
docsentinel scan --format github
```

---

## Using DocSentinel as a Python Library

For advanced programmatic recipes and test framework integrations, see the [Python Library Tutorial](library.md).

### Basic Programmatic Scan

```python
from pathlib import Path
from docsentinel import scan, Config

# Scan directory with default fast profile
result = scan(Path("."))

print(f"Scanned {len(result.documents)} documents.")
print(f"Found {len(result.findings)} issues.")

for finding in result.findings:
    print(f"[{finding.rule}] {finding.path}:{finding.line or 1} - {finding.message}")
```

### Custom Configuration in Code

```python
from docsentinel import scan, Config

config = Config(
    profile="standard",
    include=("*.md", "docs/**/*.md"),
    exclude=(".venv", "node_modules", "dist"),
    select=("DS201", "DS204"),
    max_grade_level=14.0,
    docsig_paths=("src",),
)

result = scan(".", config=config)

if result.findings:
    print(f"Scan failed with {len(result.findings)} finding(s).")
else:
    print("All documentation quality gates passed!")
```

### Working with `ScanResult` and `Finding`

Both `ScanResult` and `Finding` are frozen, immutable dataclasses:

```python
result = scan(".")

# Access scanned documents
for doc in result.documents:
    print(f"Document: {doc.path} ({doc.bytes} bytes)")

# Access findings
for finding in result.findings:
    print(f"Rule: {finding.rule}")
    print(f"Severity: {finding.severity}")
    print(f"Location: {finding.path}:{finding.line}")
    print(f"Message: {finding.message}")

# Scan metadata
print(f"Active rules: {result.enabled_rules}")
print(f"Pending/Notices: {result.pending or result.notice}")
```

---

## Configuration

DocSentinel loads configuration from either `docsentinel.toml` (the alias `doc_sentinel.toml` is also accepted; do not keep both in one directory) or `pyproject.toml` (under `[tool.doc_sentinel]`).

### Example `docsentinel.toml`

```toml
profile = "fast"
include = ["*.md", "docs/**/*.md"]
exclude = [".git", ".venv", "node_modules", "build", "dist"]
select = []
ignore = []
baseline = ".docsentinel-baseline.json"

# Standard profile settings
max_grade_level = 16.0
duplicate_similarity = 0.85
min_information_score = 0.15
docsig_paths = ["src"]

# Deep profile opt-in
deep_confirm = false
```

For the full reference for the standard-profile statistical keys (valid ranges,
defaults, comparison rules, and worked examples), see the
[Statistical Checks reference](../reference/statistical-checks.md).

### Example `pyproject.toml`

```toml
[tool.doc_sentinel]
profile = "standard"
include = ["docs/**/*.md", "README.md"]
exclude = [".venv", "dist"]
baseline = ".docsentinel-standard-baseline.json"
```

---

## Managing Baselines for Legacy Debt

Baselines allow teams to adopt DocSentinel on established repositories without failing builds on existing legacy issues.

### 1. Capture Current State into Baseline

```bash
docsentinel baseline --output .docsentinel-baseline.json
```

### 2. Subsequent Scans Filter Known Findings

Configure `baseline = ".docsentinel-baseline.json"` in `docsentinel.toml` or pass `--baseline`:

```bash
docsentinel scan --baseline .docsentinel-baseline.json
```

Existing findings stored in the baseline are ignored; only newly introduced issues will be reported!

---

## CI/CD and Pre-commit Integration

### Pre-commit Configuration (`.pre-commit-config.yaml`)

```yaml
repos:
  - repo: https://github.com/DocSentinel/DocSentinel
    rev: v0.1.0
    hooks:
      # Fast profile hook (structural checks)
      - id: docsentinel-fast
      
      # Optional standard profile hook (requires optional dependencies)
      # - id: docsentinel-standard
```

### GitHub Actions Workflow (`.github/workflows/docs.yml`)

```yaml
name: Documentation Quality

on:
  push:
    branches: [main]
  pull_request:

jobs:
  docsentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      
      - name: Install DocSentinel
        run: pip install docsentinel
      
      - name: Run DocSentinel Scan
        run: docsentinel scan --format github --strict
```

---

## Further Reading

- [CLI Tutorial & Reference Guide](cli.md) — Comprehensive command-line documentation.
- [Custom Reports](custom-reports.md) — Write your own report template and extensions.
- [Python Library Guide](library.md) — In-depth Python integration, Pytest plugin, and custom extensions.
- [Statistical Checks Reference](../reference/statistical-checks.md) — DS201–DS203 threshold keys.
- [Configuration Reference](../reference/configuration.md) — All Milestone 0005 fast-profile policy options (DS104–DS118).
- [DocSentinel Architecture Overview](/docs/architecture/README.md) — Internal engine and pipeline design.
- [Markdown Scanner Developer Guide](/docs/dev/markdown_scanner.md) — How to add a rule, resolver ownership, security checklist.
- [Python Coding Standard](/docs/dev/python_coding_standard.md) — Contributor development standards.
