# Statistical Checks (Standard Profile)

This page is the reference for DocSentinel's three statistical quality detectors:
DS201 (text complexity), DS202 (duplicate text), and DS203 (low-information
content). It covers every configurable key, what each one controls, how to
choose a value, what a finding looks like, and how to validate that your
configuration is working.

## Overview

DS201, DS202, and DS203 run only under `--profile standard` (install extra:
`pip install "docsentinel[standard]"`). They are deterministic — no machine
learning models are trained per-run, no network calls are made, and the same
inputs always produce the same findings. They produce `warning`-severity
findings and are advisory quality signals: a finding means the text warrants
human review, not that the document is necessarily wrong.

The six keys described on this page only change findings when the active profile
is `standard`. The fast profile (`--profile fast`) never reads their values to
decide anything, so setting them while running a fast scan has no effect on its
findings. They are still validated every time the config file is loaded, whatever
the profile: an invalid value (see [Validation Errors](#validation-errors)) makes
even a fast scan fail with exit code 2.

## Where to Set the Keys

You can set these keys in three places. The engine applies the following
precedence (first match wins):

1. A `Config` object passed directly in the Python API
2. A **docsentinel.toml** file at the scan root (standalone)
3. A `[tool.doc_sentinel]` table in **pyproject.toml** at the scan root

When both **docsentinel.toml** and **pyproject.toml** exist at the scan root,
the standalone file wins and **pyproject.toml** is not read. This behaviour is
confirmed in the `load_config` function in the `docsentinel` package.

### docsentinel.toml

Create or edit **docsentinel.toml** at the root of your repository. All keys
are at the top level:

```toml
profile = "standard"

# DS201 — text complexity
max_grade_level = 12.0       # flag prose above this Flesch-Kincaid grade
min_document_words = 50      # skip documents with fewer prose words than this

# DS202 — duplicate text
duplicate_similarity = 0.85  # flag paragraph pairs at or above this cosine similarity

# DS203 — low-information content
min_information_score = 0.15 # flag paragraphs with an information score below this

# DS202 and DS203 — paragraph size floors
min_paragraph_words = 5      # exclude paragraphs with fewer words than this
min_paragraph_chars = 30     # exclude paragraphs with fewer characters than this

# DS204 — docstring/signature check (non-statistical)
docsig_paths = ["src"]
```

### pyproject.toml

The same keys go under `[tool.doc_sentinel]`:

```toml
[tool.doc_sentinel]
profile = "standard"
max_grade_level = 12.0
min_document_words = 50
duplicate_similarity = 0.85
min_information_score = 0.15
min_paragraph_words = 5
min_paragraph_chars = 30
docsig_paths = ["src"]
```

### Python Library

Pass a `Config` object to `scan`. A `Config` injected this way takes precedence
over any file on disk:

```python
from pathlib import Path
from docsentinel import scan, Config

config = Config(
    profile="standard",
    max_grade_level=12.0,
    min_document_words=50,
    duplicate_similarity=0.85,
    min_information_score=0.15,
    min_paragraph_words=5,
    min_paragraph_chars=30,
)

result = scan(Path("."), config=config)
for finding in result.findings:
    print(f"[{finding.rule}] {finding.path}:{finding.line} {finding.message}")
```

Note: `Config(...)` constructed directly bypasses the file-load validation in
`load_config`. You are responsible for passing values within the documented
ranges.

### CLI

Profile and scan path are set on the command line; the threshold keys are read
from the config file discovered at the scan root:

```bash
uv run docsentinel scan docs/ --profile standard --format text
```

There are no CLI flags for the six threshold keys. To change a threshold for a
one-off run, write a temporary **docsentinel.toml** at the target directory or
pass a `Config` via the Python API.

### Scaffolded Defaults

`docsentinel init` writes a **docsentinel.toml** with all six keys commented
out at their defaults so you can see and uncomment exactly what to change:

```toml
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

## Key Reference

The table below lists every configurable key for the statistical checks. All
six keys are optional; omitting them gives the default shown.

`docsig_paths` (DS204, `list of strings`, default `["src"]`) is the one
non-statistical standard key: it names the Python source roots that DS204
inspects for docstring/signature mismatches. It is not covered further on this
page.

| Key | Rule(s) | Type | Valid range | Default | Comparison used by the rule |
|-----|---------|------|-------------|---------|------------------------------|
| `max_grade_level` | DS201 | float | > 0 | 14.0 | Flag when grade **>** threshold (strict) |
| `duplicate_similarity` | DS202 | float | 0.0 to 1.0 | 0.85 | Flag when cosine **>=** threshold (inclusive) |
| `min_information_score` | DS203 | float | 0.0 to 1.0 | 0.15 | Flag when score **<** threshold (strict) |
| `min_document_words` | DS201 | integer | >= 1 | 50 | Skip document when prose words **<** this (strict) |
| `min_paragraph_words` | DS202, DS203 | integer | >= 1 | 5 | Exclude paragraph when words **<** this (strict) |
| `min_paragraph_chars` | DS202, DS203 | integer | >= 0 | 30 | Exclude paragraph when chars **<** this (strict) |

A paragraph enters the DS202/DS203 corpus only when it clears **both**
`min_paragraph_words` and `min_paragraph_chars`. Either floor alone is
sufficient to exclude a paragraph.

## DS201: Text Complexity

### What It Measures

DS201 scores each document's prose readability using the Flesch-Kincaid grade
level metric (via the `textstat` library). A grade level of 8.0 corresponds
roughly to eighth-grade reading ease; 14.0 corresponds to a demanding
undergraduate text.

Before scoring, the detector strips the following from the raw Markdown so that
non-prose constructs do not distort the score:

- Fenced code blocks (backtick and tilde, including their contents)
- Inline code spans
- HTML tags
- Images (`![alt](url)`)
- Link URLs (the link text is kept)
- ATX heading markers (`#` through `######`)
- Blockquote prefixes (`>`)
- List item markers (`-`, `*`, `+`, `1.`)

The remaining text is passed to `textstat.flesch_kincaid_grade`. The metric
assumes English-language prose; results are unreliable for non-English text.

A document is skipped entirely — and no finding is emitted — when its stripped
prose word count is strictly below `min_document_words`. This avoids penalising
short notes, stubs, or index files for readability.

### How to Choose a Value

Lower `max_grade_level` to enforce simpler prose; raise it to allow more
complex writing.

- **8–10** — suitable for user-facing documentation aimed at general audiences,
  marketing copy, and getting-started guides.
- **10–12** — typical for developer tutorials and how-to guides.
- **12–14** — appropriate for technical references and API documentation.
- **14–16** — the upper boundary most engineering documentation sits under; the
  default 14.0 matches this range.
- **>16** — rarely appropriate to enforce; mainly useful as a loose guard
  against accidental academic-style prose.

Lowering the threshold increases findings; raising it suppresses them. Start at
the default 14.0 and tune based on actual scan results.

Set `min_document_words` higher to skip more short documents. At the default
of 50, a single paragraph of typical prose is enough to trigger scoring. Lower
it if you want even stub documents scored; the minimum allowed value is 1.

### What a Finding Looks Like

```text
  warning: docs/guide.md: Readability grade level 18.3 exceeds threshold 14.0
```

The format is:

```text
  warning: <path>: Readability grade level <actual> exceeds threshold <configured>
```

Both values are rounded to one decimal place.

### Examples

The following examples use a document with 29 prose words (after stripping).
At the default `min_document_words = 50` the document is skipped. Lowering
the floor to 25 causes it to be scored and flagged.

**Default — document skipped:**

```bash
$ uv run docsentinel scan /path/to/dir --profile standard --format text
```

```text
Schema version: 1
Profile: standard
Documents: 1 (0 with problems)
Enabled rules: ["DS201", "DS202", "DS203", "DS204"]
4 standard rule(s) evaluated.
```

No findings. The document has fewer than 50 prose words.

**After setting `min_document_words = 25` and `max_grade_level = 10.0`:**

```toml
profile = "standard"
min_document_words = 25
max_grade_level = 10.0
```

```text
Schema version: 1
Profile: standard
Documents: 1 (1 with problems)
Enabled rules: ["DS201", "DS202", "DS203", "DS204"]
4 standard rule(s) evaluated.
short_doc.md (322 bytes)
  warning: short_doc.md: Readability grade level 30.8 exceeds threshold 10.0
```

The same document is now scored and flagged.

**Complex prose flagged at default threshold (14.0):**

```text
Schema version: 1
Profile: standard
Documents: 1 (1 with problems)
Enabled rules: ["DS201", "DS202", "DS203", "DS204"]
4 standard rule(s) evaluated.
complex.md (765 bytes)
  warning: complex.md: Readability grade level 27.3 exceeds threshold 14.0
```

**Same document cleared by raising `max_grade_level = 20.0`:**

```text
Schema version: 1
Profile: standard
Documents: 1 (1 with problems)
Enabled rules: ["DS201", "DS202", "DS203", "DS204"]
4 standard rule(s) evaluated.
complex.md (765 bytes)
  warning: complex.md: Readability grade level 27.3 exceeds threshold 20.0
```

The finding still appears because the grade (27.3) still exceeds 20.0. Setting
`max_grade_level = 30.0` would suppress it.

## DS202: Duplicate Text

### What It Measures

DS202 detects paragraphs that are near-duplicates of other paragraphs anywhere
in the scanned corpus (across all documents).

The detection method:

1. Extract paragraphs from all scanned Markdown documents. Fenced code blocks,
   HTML comments, inline code, HTML tags, images, link URLs, heading markers,
   blockquote prefixes, and list markers are stripped. A paragraph is excluded
   from the corpus when its visible character count is strictly below
   `min_paragraph_chars` or its word count is strictly below
   `min_paragraph_words`.
2. Fit a single TF-IDF vectoriser across all paragraphs in the corpus.
   (Settings: English stop words, sublinear term frequency, word token pattern
   `\b\w+\b`.)
3. Compute the full pairwise cosine similarity matrix.
4. Report every pair (i, j) where `i < j` and cosine similarity
   `>= duplicate_similarity`. Each pair is reported once, attributed to the
   later paragraph (j), referencing the earlier one (i).

The algorithm compares every paragraph against every other paragraph. Cost
grows quadratically with the number of paragraphs that pass the size floors:
for a corpus of N paragraphs, N×(N-1)/2 pairs are evaluated. This is
manageable for documentation corpora of typical size (hundreds of paragraphs)
but worth noting for very large corpora.

### How to Choose a Value

`duplicate_similarity` must be a float between 0.0 and 1.0 inclusive.

- **1.0** — only exact (byte-identical after stripping) duplicates are reported.
- **0.95** — near-identical text with minor wording variation.
- **0.85** (default) — paragraphs that share the same core content with light
  paraphrasing. A good starting point for catching copy-paste.
- **0.70** — paragraphs that cover the same topic with different wording.
  Useful for broad "do we duplicate this concept?" checks but generates more
  false positives.

Raise toward 1.0 when your documentation intentionally repeats shared boilerplate
(for example, installation prerequisites repeated across several guides). Use
`ignore = ["DS202"]` or a baseline file to suppress known-good duplicates
rather than raising the threshold so high that real duplicates are missed.

### What a Finding Looks Like

```text
  warning: docs/guide.md: near-duplicate of docs/install.md#chunk0 (cosine 1.00): 'Install the application by running the setup script and foll'
```

The format is:

```text
  warning: <later_path>: near-duplicate of <earlier_path>#chunk<index> (cosine <similarity>): '<preview>'
```

`<preview>` is the first 60 characters of the later paragraph (after stripping).

### Examples

Two documents containing the same paragraph at the default threshold (0.85):

```text
Schema version: 1
Profile: standard
Documents: 2 (1 with problems)
Enabled rules: ["DS201", "DS202", "DS203", "DS204"]
4 standard rule(s) evaluated.
doc_b.md (357 bytes)
  warning: doc_b.md: near-duplicate of doc_a.md#chunk0 (cosine 1.00): 'Install the application by running the setup script and foll'
  warning: doc_b.md: near-duplicate of doc_a.md#chunk1 (cosine 1.00): 'You need Python 3.10 or later and at least 4 GB of RAM for t'
```

**Short paragraph ignored at defaults, then captured after lowering the floors:**

At defaults (`min_paragraph_words = 5`, `min_paragraph_chars = 30`), a
5-word paragraph such as "This is a short note." (21 characters) is excluded
from the corpus because it is below `min_paragraph_chars = 30`.

After setting:

```toml
profile = "standard"
min_paragraph_words = 3
min_paragraph_chars = 0
```

```text
  warning: doc_b.md: near-duplicate of doc_a.md#chunk0 (cosine 1.00): 'This is a short note.'
  warning: doc_b.md: near-duplicate of doc_a.md#chunk1 (cosine 1.00): 'Configure the application by editing the settings file locat'
```

The short paragraph is now in the corpus and the duplicate is reported.

## DS203: Low-Information Content

### What It Measures

DS203 flags paragraphs that are both lexically thin and non-distinctive. It
combines two signals into a single **information score** in [0, 1]:

- **Type-token ratio (TTR):** the fraction of distinct words in the paragraph
  (unique words / total words). A paragraph where every word is different has
  TTR = 1.0; a paragraph of repeated words approaches 0.0.
- **Maximum TF-IDF weight:** the largest TF-IDF value assigned to any single
  word in the paragraph by the shared corpus vectoriser. High-weight words are
  distinctive (they appear in few other paragraphs). A paragraph whose every
  word also appears in many other paragraphs has a low maximum weight.

The information score formula is:

```
score = sqrt(min(TTR / 0.5, 1.0) * min(max_tfidf / 0.3, 1.0))
```

In plain terms: a paragraph scores near 1.0 when it contains a diverse
vocabulary (TTR at or above 0.5) **and** at least one word that is rare in the
corpus (max TF-IDF at or above 0.3). A paragraph scores 0.0 when either signal
is zero (for example, purely repeated words or all stop-words).

DS203 uses the same corpus built by DS202: the same paragraph extraction,
stripping, and TF-IDF vectoriser. Only paragraphs that pass both
`min_paragraph_words` and `min_paragraph_chars` are scored.

A paragraph is flagged when `score < min_information_score` (strictly less
than).

### How to Choose a Value

`min_information_score` must be a float between 0.0 and 1.0 inclusive.

- **0.0** — disable DS203 without removing it from the active rule set.
- **0.10–0.15** — default range: flag only the most obviously thin content
  (pure repetition, all stop-words, extremely short distinct-word count).
- **0.20–0.30** — tighter: catches more formulaic content. Expect more false
  positives on bullet lists and short reference entries.
- **>0.30** — aggressive: most real documentation will generate findings.
  Mainly useful as a temporary diagnostic.

Lower the value to reduce false positives; raise it to catch more borderline
content. When a legitimate short-form section (a list of names, a changelog
entry) is flagged, prefer `ignore = ["DS203"]` or a baseline over raising the
threshold globally.

### What a Finding Looks Like

```text
  warning: docs/notes.md: low-information paragraph (score 0.00 < 0.15): 'The the the the the the the the the the the the the the the '
```

The format is:

```text
  warning: <path>: low-information paragraph (score <actual> < <threshold>): '<preview>'
```

Both score values are rounded to two decimal places. `<preview>` is the first
60 characters of the paragraph (after stripping).

### Examples

**Two findings at the default threshold (0.15):**

A document containing repetitive paragraphs alongside a document with
substantive content:

```text
Schema version: 1
Profile: standard
Documents: 2 (1 with problems)
Enabled rules: ["DS201", "DS202", "DS203", "DS204"]
4 standard rule(s) evaluated.
trivial.md (182 bytes)
  warning: trivial.md: low-information paragraph (score 0.00 < 0.15): 'The the the the the the the the the the the the the the the '
  warning: trivial.md: low-information paragraph (score 0.00 < 0.15): 'Is is is is is is is is is is is is is is is is is is is is '
```

**Same documents with `min_information_score = 0.0` — all findings suppressed:**

```toml
profile = "standard"
min_information_score = 0.0
```

```text
Schema version: 1
Profile: standard
Documents: 2 (0 with problems)
Enabled rules: ["DS201", "DS202", "DS203", "DS204"]
4 standard rule(s) evaluated.
```

No findings. Setting `min_information_score = 0.0` means no score is strictly
below the threshold.

## Fixed Internals (Not Configurable)

The following are calibration internals; they are not exposed as configuration
options. Adjusting `min_information_score` is the supported way to tune DS203
sensitivity.

| Internal | Value | Used by |
|----------|-------|---------|
| TTR normalisation reference | 0.5 | DS203 score formula |
| TF-IDF normalisation reference | 0.3 | DS203 score formula |
| TF-IDF stop words | English | DS202, DS203 corpus |
| TF-IDF token pattern | `\b\w+\b` | DS202, DS203 corpus |
| TF-IDF term frequency | sublinear (`log(1 + tf)`) | DS202, DS203 corpus |
| Readability metric | Flesch-Kincaid grade level | DS201 |
| Language assumption | English | DS201 |

The TTR normalisation reference of 0.5 means a paragraph with 50% distinct
words saturates the TTR component. The TF-IDF normalisation reference of 0.3
means a paragraph with at least one word whose TF-IDF weight is 0.3 or above
saturates the distinctiveness component. Both caps are part of the formula (the
`min(..., 1.0)` clamps) and prevent any single signal from dominating.

## Recipes

### Enforce Stricter Readability for Tutorials

Lower `max_grade_level` for guides aimed at general audiences:

```toml
profile = "standard"
max_grade_level = 10.0
```

### Suppress Noisy Boilerplate Duplicates

If your docs deliberately repeat shared content (installation prerequisites,
license notices), raise `duplicate_similarity` rather than ignoring DS202
entirely:

```toml
duplicate_similarity = 0.95
```

Alternatively, capture known duplicates in a baseline file and commit it:

```bash
uv run docsentinel baseline --output .docsentinel-standard-baseline.json
```

Then reference it in your config:

```toml
baseline = ".docsentinel-standard-baseline.json"
```

### Skip Short Reference Pages

If your corpus includes many short stub pages or auto-generated index files,
raise `min_document_words` to prevent DS201 from scoring them:

```toml
min_document_words = 100
```

### Include Short Bullet-Like Paragraphs in the Corpus

Lower the paragraph floors to include short list-style entries in DS202 and
DS203 analysis:

```toml
min_paragraph_words = 3
min_paragraph_chars = 0
```

Be aware this will include nearly every paragraph, which increases the corpus
size and may increase false-positive findings.

### Use `select` / `ignore` Instead of Retuning

You can activate only the statistical rules you care about:

```toml
select = ["DS201", "DS202"]
```

Or suppress a rule you do not need without uninstalling the profile:

```toml
ignore = ["DS203"]
```

### Large Corpora

DS202 evaluates every pair of paragraphs in the corpus. For a corpus of N
paragraphs (all those passing the size floors), the number of pairs evaluated
is N×(N-1)/2. For 1 000 paragraphs that is ~500 000 comparisons; for 10 000
paragraphs that is ~50 million. Memory is also proportional to N² for the
similarity matrix. If scan time is a concern with a very large documentation
set, raise `min_paragraph_words` and `min_paragraph_chars` to reduce N, or
use a baseline to suppress known findings and limit the active check to changed
documents using `select = ["DS202"]` with a scoped path argument.

## Validation and Troubleshooting

### Validation Errors

If DocSentinel reads an invalid value for any of the six keys, it exits with
code 2 and a `ConfigError`. The table below lists the exact error messages.

| Key | Invalid input | Error message |
|-----|--------------|---------------|
| `max_grade_level` | `false`, `0`, `-1`, `"high"` | `max_grade_level must be a positive number` |
| `duplicate_similarity` | `false`, `-0.1`, `1.1`, `"high"` | `duplicate_similarity must be a number between 0 and 1` |
| `min_information_score` | `false`, `-0.1`, `1.1`, `"low"` | `min_information_score must be a number between 0 and 1` |
| `min_document_words` | `false`, `0`, `-1`, `5.0`, `"fifty"` | `min_document_words must be an integer >= 1` |
| `min_paragraph_words` | `false`, `0`, `-1`, `5.0` | `min_paragraph_words must be an integer >= 1` |
| `min_paragraph_chars` | `false`, `-1`, `5.0` | `min_paragraph_chars must be a non-negative integer` |
| Any misspelled key | `max_grade_levl = 14.0` | `Unknown config options: max_grade_levl` |

Note: `max_grade_level`, `duplicate_similarity`, and `min_information_score`
accept both integer and float TOML values (for example `14` is valid for
`max_grade_level`). The three integer keys (`min_document_words`,
`min_paragraph_words`, `min_paragraph_chars`) reject float TOML values
(for example `50.0`) even when the value is integral.

### My Setting Seems Ignored

Check the following in order:

1. **Profile is set to `standard`.** The six keys only change findings when the
   active profile is `standard`. Running `--profile fast` (the default) does not
   use them to produce findings, although their values are still validated and an
   invalid one fails the scan with exit code 2.
2. **The `docsentinel[standard]` extra is installed.** Run
   `uv run docsentinel doctor` to confirm. Without the extra, the profile
   request fails with exit code 2.
3. **Key name is spelled exactly.** Compare your config key character-for-character
   against the names in the [Key Reference](#key-reference) table. A misspelled
   key triggers the `Unknown config options` error at startup.
4. **Standalone file is not shadowing pyproject.** If both **docsentinel.toml**
   and **pyproject.toml** exist at the scan root, the standalone file wins.
   Settings in **pyproject.toml** are silently ignored when the standalone file
   is present.
5. **A baseline is suppressing known findings.** If you have `baseline =
   ".docsentinel-standard-baseline.json"` configured and the finding was
   captured in a previous baseline run, it will be suppressed on subsequent
   scans. Delete or regenerate the baseline to see all current findings.

### Exit Codes

The three statistical detectors all emit `warning` severity findings. Under
the default scan mode, warnings do not cause a non-zero exit code. With
`--strict`, all warnings are treated as errors and produce exit code 1.

DS204 (docstring/signature mismatch) emits `error` severity findings, which
always produce exit code 1 regardless of `--strict`.

| Condition | Exit code |
|-----------|-----------|
| No findings, or only suppressed findings | 0 |
| DS201/DS202/DS203 warnings only (no `--strict`) | 0 |
| DS201/DS202/DS203 warnings with `--strict` | 1 |
| DS204 errors | 1 |
| Config or scan failure | 2 |
