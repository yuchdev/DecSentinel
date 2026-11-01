# Report Formats

`docsentinel scan` renders every report from a **template**. `--format NAME` picks a template by
name, and five templates ship with DocSentinel:

| Format           | Flag                      | Audience                                | Carries rule code | Carries line and column |
|------------------|---------------------------|-----------------------------------------|-------------------|-------------------------|
| `text`           | `--format text`           | A person reading a terminal             | No                | No                      |
| `json`           | `--format json`           | Scripts, dashboards, other tools        | Yes               | Yes (may be `null`)     |
| `github`         | `--format github`         | GitHub Actions annotations              | Yes (`title=`)    | Yes (when known)        |
| `json-v1`        | `--format json-v1`        | Existing consumers of the schema 1 JSON | Yes               | Line only               |
| `json-documents` | `--format json-documents` | Tools that want only the document list  | Yes               | Yes (may be `null`)     |

`text` is the default. Every format is rendered from one `ScanResult`, so they never disagree about
*what* was found. They differ only in how much of it they show. If you need the rule code (for
example to add it to `ignore`), use `json` or `github`.

You can also add your own templates (see [Custom templates](#custom-templates)).

The format never changes the [exit code](README.md#exit-codes-contract). That is decided from the
findings alone.

## Table of Contents

1. [Changed in this release: migration](#changed-in-this-release-migration)
2. [The example used on this page](#the-example-used-on-this-page)
3. [Text format](#text-format)
4. [JSON format](#json-format)
5. [Legacy and document-only JSON](#legacy-and-document-only-json)
6. [GitHub format](#github-format)
7. [Custom templates](#custom-templates)
8. [Report options](#report-options)
9. [Exit codes and the report](#exit-codes-and-the-report)
10. [Deep profile differences](#deep-profile-differences)
11. [Hostile characters in paths and messages](#hostile-characters-in-paths-and-messages)
12. [Choosing a format](#choosing-a-format)

---

## Changed in this release: migration

This release changes the default report formats. Scripts that parse the old output need one of
the changes below.

| Before                                                    | Now                                                                                         | What to do                                                                 |
|-----------------------------------------------------------|---------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| `--format json` printed schema 1 (a flat `findings` list) | `--format json` prints schema 2: one record per document, with its problems inside it       | Switch to `--format json-v1` to keep the schema 1 shape, or read schema 2  |
| `text` listed every document, then every finding unindented (`error: PATH: MESSAGE`) | `text` lists each document that has problems, with its findings indented two spaces under it. Clean documents are hidden | Match `  SEVERITY: PATH: MESSAGE` (two leading spaces). Pass `--show-clean-documents` to list every document |
| `Documents: N`                                            | `Documents: N (M with problems)`                                                            | Read only the first number if you need the old value                       |
| `github` printed `::error file=PATH,line=N::MESSAGE`       | `github` adds `col=` when the column is known and always adds `title=RULE`                   | Annotation consumers need no change. Update parsers that split the property list |

The `json-v1` bytes are the same as the old `--format json` bytes. The exit codes are unchanged.

---

## The example used on this page

Every sample below comes from scanning this tiny tree with the default `fast` profile:

```text
README.md          (74 bytes)
docs/setup.md      (15 bytes)
```

where `README.md` is:

```markdown
# Guide

See [missing](docs/nope.md) and [bad](#nowhere).

<!-- stray -->
```

It produces three findings: a dangling link and a missing anchor (both `DS101`, severity `error`,
line 3) and a stray HTML comment (`DS102`, severity `warning`, line 5). `docs/setup.md` is clean.

---

## Text format

```bash
docsentinel scan --format text
```

```text
Schema version: 1
Profile: fast
Documents: 2 (1 with problems)
Enabled rules: ["DS101", "DS102", "DS103", "DS104", "DS105", "DS106", "DS108", "DS109", "DS110", "DS112", "DS113", "DS114", "DS115", "DS116", "DS117", "DS118"]
12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming).
README.md (74 bytes)
  error: README.md: dangling link -> docs/nope.md
  error: README.md: missing anchor '#nowhere' in this file
  warning: README.md: stray HTML comment: '<!-- stray -->'
```

The output is a plain list of lines, always in this order:

| # | Line                                          | Meaning                                                                                                              |
|---|-----------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| 1 | `Schema version: N`                           | Version of the scan result contract (currently `1`). This is not the JSON report schema.                            |
| 2 | `Profile: NAME`                               | The profile that ran: `fast`, `standard` or `deep`.                                                                  |
| 3 | `Documents: N (M with problems)`              | `N` Markdown documents were found and scanned. `M` of them have at least one finding.                               |
| 4 | `Enabled rules: [...]`                        | JSON array of rule codes selected for this run, after `select` / `ignore`. Written as JSON on one line.             |
| 5 | notice                                        | One sentence describing what was actually evaluated (see below).                                                     |
| 6 | *(deep only)* advisory banner                 | Present only for the `deep` profile when it has findings. See [Deep profile differences](#deep-profile-differences). |
| 7 | `PATH (N bytes)` for each document            | Not indented. Only documents with problems, in stable sorted order, unless `--show-clean-documents` is set.         |
| 8 | `  SEVERITY: PATH: MESSAGE` under its document | Indented two spaces. One line per finding, directly under the document it belongs to.                              |
| 9 | `Pending: REASON` for each pending reason     | Work that was requested but could not run, such as missing optional dependencies.                                   |

### Reading a finding line

```text
  error: README.md: dangling link -> docs/nope.md
  └─┬─┘  └───┬───┘  └─────────────┬──────────────┘
severity    path               message
```

- **`severity`** is `error` or `warning`. Errors fail the scan. Warnings fail it only with `--strict`.
- **`path`** is relative to the scan root and uses `/` separators.
- **`message`** is the detector's explanation. It often echoes a short excerpt of the source (here
  `'<!-- stray -->'`).

The text format **omits the rule code and the line number**. Both exist on every finding. `json`
shows the rule code, line and column, and `github` shows them in its `title=`, `line=` and `col=`
properties. To find which rule produced a line, run `docsentinel scan --format json`, or search the
[Configuration Reference](../reference/configuration.md) for the message wording.

### The notice line

The notice states how many rules *actually ran* and names opt-in rules that are registered but
switched off:

```text
12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming).
```

`Enabled rules` lists **16** codes but the notice says **12** were evaluated. The four extra codes
(`DS110`, `DS112`, `DS115`, `DS118`) are opt-in policy rules. They are selected, yet emit nothing
until you set the option shown in parentheses. This is not an error. A clean scan with opt-in rules
off means those four policies were not checked.

### Reading a clean scan

With no findings, the report ends after the notice line, because clean documents are hidden:

```text
Schema version: 1
Profile: fast
Documents: 1 (0 with problems)
Enabled rules: ["DS101", "DS102", ...]
12 fast rule(s) evaluated; opt-in rule(s) not enabled: ...
```

There is no "no problems found" line. Check the exit code (`0`) to confirm success.

### Listing every document

Pass `--show-clean-documents` (or set `report_show_clean_documents = true`) to list clean
documents too. Each one is a `PATH (N bytes)` line with nothing under it:

```bash
docsentinel scan --show-clean-documents
```

```text
...
README.md (74 bytes)
  error: README.md: dangling link -> docs/nope.md
  error: README.md: missing anchor '#nowhere' in this file
  warning: README.md: stray HTML comment: '<!-- stray -->'
docs/setup.md (15 bytes)
```

### Pending lines

```text
Pending: deep profile confirmed, but its dependencies are unavailable - install the deep extra (pip install docsentinel[deep]) and the model (python -m spacy download en_core_web_sm)
```

A `Pending:` line means a part of the scan did not run. Treat it as "unchecked", not "clean".

---

## JSON format

```bash
docsentinel scan --format json
```

JSON is the complete machine contract. `--format json` prints **schema 2**: a summary, the rule
status, and one record per scanned document with its problems inside it. Clean documents are
included with `"problems": []`, so you can compute a fault rate. Output uses two-space indentation:

```json
{
  "schema_version": 2,
  "profile": "fast",
  "run": {
    "model": null,
    "notice": "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), ...",
    "advisory": null
  },
  "summary": {
    "documents": 2,
    "documents_with_problems": 1,
    "findings": 3,
    "by_severity": { "error": 2, "warning": 1 },
    "by_rule": { "DS101": 2, "DS102": 1 }
  },
  "rules": {
    "enabled": ["DS101", "DS102", "DS103", "DS104", "DS105", "DS106", "DS108", "DS109", "DS110", "DS112", "DS113", "DS114", "DS115", "DS116", "DS117", "DS118"],
    "evaluated": 12,
    "opt_in_off": [
      { "code": "DS110", "option": "require_fence_languages" },
      { "code": "DS112", "option": "navigation_indexes" },
      { "code": "DS115", "option": "deprecated_references_file" },
      { "code": "DS118", "option": "documentation_naming" }
    ]
  },
  "documents": [
    {
      "path": "README.md",
      "bytes": 74,
      "domain": "docs",
      "problems": [
        {
          "rule": "DS101",
          "type": "dangling link",
          "message": "dangling link -> docs/nope.md",
          "value": "docs/nope.md",
          "severity": "error",
          "line": 3,
          "column": 15,
          "fault_class": "dangling_reference",
          "tier": "deterministic",
          "outcome": "rejected"
        },
        {
          "rule": "DS101",
          "type": "dangling anchor",
          "message": "missing anchor '#nowhere' in this file",
          "value": "#nowhere",
          "severity": "error",
          "line": 3,
          "column": 39,
          "fault_class": "dangling_reference",
          "tier": "deterministic",
          "outcome": "rejected"
        },
        {
          "rule": "DS102",
          "type": "stray html comment",
          "message": "stray HTML comment: '<!-- stray -->'",
          "value": null,
          "severity": "warning",
          "line": 5,
          "column": 1,
          "fault_class": "residual_markup",
          "tier": "deterministic",
          "outcome": "advisory"
        }
      ]
    },
    { "path": "docs/setup.md", "bytes": 15, "domain": "docs", "problems": [] }
  ],
  "pending": []
}
```

The real output expands each array and object onto its own lines. Some are compacted above for
readability.

### Top-level fields

| Field            | Type             | Description                                                                                       |
|------------------|------------------|---------------------------------------------------------------------------------------------------|
| `schema_version` | integer          | Report schema. `2` for `--format json`. Check it before parsing if you depend on the shape.       |
| `profile`        | string           | `"fast"`, `"standard"` or `"deep"`.                                                               |
| `run`            | object           | `notice` (the text format's notice sentence), `advisory` (the deep banner or `null`) and `model`. |
| `summary`        | object           | `documents`, `documents_with_problems`, `findings`, plus `by_severity` and `by_rule` counts.      |
| `rules`          | object           | `enabled` (rule codes active for this run), `evaluated` (how many ran) and `opt_in_off`.          |
| `documents`      | array of objects | Every scanned document, sorted, each with its `problems`. Baselined findings are already removed. |
| `pending`        | array of strings | Reasons part of the scan did not run. Empty when everything requested ran.                        |

`rules.opt_in_off` lists the opt-in rules that are selected but whose policy is off, each as
`{"code": ..., "option": ...}`. Opt-in rules appear in `rules.enabled` even while their policy is off.

### `documents[]`

| Field      | Type             | Description                                                                         |
|------------|------------------|-------------------------------------------------------------------------------------|
| `path`     | string           | Path relative to the scan root, `/`-separated.                                      |
| `bytes`    | integer or null  | File size in bytes. `null` only for a finding path that is not a scanned document.  |
| `domain`   | string           | Always `"docs"` for the packaged template.                                          |
| `problems` | array of objects | The document's findings. Empty array for a clean document.                          |

### `documents[].problems[]`

| Field         | Type            | Description                                                                                          |
|---------------|-----------------|------------------------------------------------------------------------------------------------------|
| `rule`        | string          | Rule code such as `"DS101"`. Use this value in `select` / `ignore`.                                  |
| `type`        | string or null  | Short category such as `"dangling link"`. Falls back to the rule title when the detector gave none. |
| `message`     | string          | Human-readable explanation, possibly echoing a short source excerpt.                                 |
| `value`       | string or null  | The offending token the message already echoes (a link target or path), or `null`.                  |
| `severity`    | string          | `"error"` or `"warning"`.                                                                            |
| `line`        | integer or null | 1-based line number, or `null` when the rule cannot point at a single line (for example a corpus-level finding). |
| `column`      | integer or null | 1-based column, or `null` when unknown.                                                              |
| `fault_class` | string          | The fault category, such as `"dangling_reference"`.                                                  |
| `tier`        | string          | `"deterministic"`, or `"heuristic"` for the `deep` profile.                                          |
| `outcome`     | string          | `"rejected"` for errors (and warnings under `--strict`), `"advisory"` for warnings and deep findings. |

Always handle `line: null` and `column: null`. Documents and problems are emitted in a
deterministic order, so identical input gives identical output.

### Parsing example

```bash
# Count errors
docsentinel scan --format json | jq '[.documents[].problems[] | select(.severity == "error")] | length'

# One "rule path:line message" row per finding
docsentinel scan --format json | jq -r '.documents[] | .path as $p | .problems[] | "\(.rule) \($p):\(.line // 1) \(.message)"'

# Which rules fire most
docsentinel scan --format json | jq '.summary.by_rule'
```

Note that `docsentinel scan` exits `1` when it finds blocking problems, so in a script that uses
`set -e` or `pipefail`, capture the output first and examine the exit code separately.

### Encoding

JSON output is ASCII-only. Every control character and non-ASCII character in a path or message is
written as a `\uXXXX` escape, so hostile file names cannot inject anything into a log. Your JSON
parser restores the original characters. This applies to every JSON format.

---

## Legacy and document-only JSON

### `--format json-v1`

`json-v1` prints the schema 1 JSON that `--format json` printed before this release, byte for byte.
Use it to keep an existing consumer working:

```json
{
  "schema_version": 1,
  "profile": "fast",
  "documents": [
    { "path": "README.md", "bytes": 74 },
    { "path": "docs/setup.md", "bytes": 15 }
  ],
  "findings": [
    { "rule": "DS101", "path": "README.md", "message": "dangling link -> docs/nope.md", "severity": "error", "line": 3 },
    { "rule": "DS101", "path": "README.md", "message": "missing anchor '#nowhere' in this file", "severity": "error", "line": 3 },
    { "rule": "DS102", "path": "README.md", "message": "stray HTML comment: '<!-- stray -->'", "severity": "warning", "line": 5 }
  ],
  "enabled_rules": ["DS101", "DS102", "...", "DS118"],
  "pending": [],
  "notice": "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), ..."
}
```

`documents[]` holds only `path` and `bytes`. Each `findings[]` entry carries its own `path`. For the
`deep` profile with findings, a top-level `advisory` string is added. It is absent otherwise.

### `--format json-documents`

`json-documents` prints only the `documents` array of schema 2: a bare JSON list of
`{path, bytes, domain, problems}` records, with clean documents included.

---

## GitHub format

```bash
docsentinel scan --format github
```

```text
::error file=README.md,line=3,col=15,title=DS101::dangling link -> docs/nope.md
::error file=README.md,line=3,col=39,title=DS101::missing anchor '#nowhere' in this file
::warning file=README.md,line=5,col=1,title=DS102::stray HTML comment: '<!-- stray -->'
```

This format prints **only** workflow commands, one per finding, grouped by document, and nothing
else: no schema line, no document list, no notice, no `Pending:` lines. GitHub Actions turns each
line into an annotation on the pull request's *Files changed* tab and in the workflow run summary.
The rule code appears as the annotation title.

### Line anatomy

```text
::error file=README.md,line=3,col=15,title=DS101::dangling link -> docs/nope.md
└─┬──┘ └───────────────┬───────────────────────┘  └─────────────┬────────────┘
 level            properties                                 message
```

| Part       | Rule                                                                                          |
|------------|-----------------------------------------------------------------------------------------------|
| level      | `error` for findings of severity `error`. **Everything else becomes `warning`**.              |
| `file=`    | The finding's path, relative to the scan root.                                                |
| `line=`    | Included only when the finding has a line number.                                             |
| `col=`     | Included only when the finding has both a line and a column.                                  |
| `title=`   | Always included: the rule code, such as `DS101`.                                              |
| message    | The finding's message, after the escaping below.                                              |

A finding without a line is written as `::warning file=PATH,title=RULE::message`.

### Escaping

Workflow commands use `%`-escaping so that no message can end the command early or start a new
one. DocSentinel applies the runner's contract:

| Where                         | Character | Written as |
|-------------------------------|-----------|------------|
| property (`file=`, `title=`)  | `%`       | `%25`      |
| property                      | CR        | `%0D`      |
| property                      | LF        | `%0A`      |
| property                      | `:`       | `%3A`      |
| property                      | `,`       | `%2C`      |
| message (after `::`)          | `%`       | `%25`      |
| message                       | CR        | `%0D`      |
| message                       | LF        | `%0A`      |

So a file named `a,b:c.md` is reported as `file=a%2Cb%3Ac.md`, and GitHub decodes it back. Colons
and commas are left alone in the message because they are only special inside properties.

### Clean scans

When there are no findings the command prints an empty line (a lone newline) and exits `0`. No
annotations are created.

### Using it in a workflow

```yaml
- name: Run DocSentinel Scan
  run: docsentinel scan --format github --strict
```

The step fails when the exit code is non-zero, and annotations appear either way. Add `--strict` if
warnings should fail the job. Without it only errors do. See the [CLI Tutorial](cli.md) for more
options.

---

## Custom templates

A template is a JSON file that describes the report. The format is specified in the
[report template format](../../specs/report-template-format.md). There are two ways to use your
own template:

- **By name.** Set `report_templates_dir` to a directory under the scan root. Every `NAME.json` in
  it becomes selectable with `--format NAME`. A packaged name (`text`, `json`, `github`,
  `json-v1`, `json-documents`) always wins, so a directory template can never replace one.
- **By path.** `--template PATH` renders with that file and wins over `--format`:

  ```bash
  docsentinel scan --template ci/report.json
  ```

A template is validated before the scan runs. An unknown name, an unreadable file or an invalid
template prints `Scan failed: ...` on stderr and exits `2`. `docsentinel doctor` lists the
packaged templates and the ones it finds in `report_templates_dir`.

---

## Report options

These options go in `docsentinel.toml` (or the `[tool.doc_sentinel]` table of `pyproject.toml`):

| Option                        | Default | Meaning                                                                                         |
|-------------------------------|---------|-------------------------------------------------------------------------------------------------|
| `report_templates_dir`        | none    | Directory, relative to the scan root, of extra templates selectable by name with `--format`.    |
| `report_show_clean_documents` | `false` | Whether the text report also lists documents without problems. `--show-clean-documents` sets it. |
| `report_include_run_meta`     | `false` | Whether templates may use the per-run `run.generated_at` and `run.id` values.                   |

`report_templates_dir` must stay inside the scan root. A symlink that leads out of the root is
refused. A directory with more than 1024 templates or more than 4096 entries of any kind is refused
too, instead of being listed partly.

---

## Exit codes and the report

| Code | Meaning                                                                       | What you see on stdout                     |
|------|-------------------------------------------------------------------------------|--------------------------------------------|
| `0`  | No blocking findings (or the `deep` profile, which is advisory only).         | The report; may still list warnings.       |
| `1`  | At least one `error`, or any finding at all when `--strict` is set.           | The report.                                |
| `2`  | Configuration or scan failure (bad config, unreadable root, missing opt-in file). | Nothing on stdout; an error line on **stderr**. |

Practical consequences:

- **Warnings print but do not fail** unless you pass `--strict`. An exit code of `0` with `  warning:` lines in a text report is normal.
- **Exit `2` produces no report in any format.** This includes an unknown `--format` name or an invalid template. The message `Scan failed: ...` goes to stderr, so do not try to parse stdout as JSON without checking the exit code first.
- All formats share the same exit code for the same scan.

---

## Deep profile differences

The `deep` profile (`DS301`) is heuristic, so its findings are candidates for human review rather than verdicts.

- **Exit code is always `0`**, even with `--strict`.
- **Text:** when there are findings, the line `Deep findings are heuristic candidates for review - they do not fail the build.` is inserted after the notice line.
- **JSON:** in `json` (schema 2) the same sentence is `run.advisory`, which is `null` when there are no findings and for the other profiles. In `json-v1` it is a top-level `"advisory"` string that is absent in those cases.
- **GitHub:** unchanged. Findings still become annotations, with no banner.

If the deep extra is not installed, the scan does not fail. It reports no enabled rules (`"rules": {"enabled": []}` in `json`, `"enabled_rules": []` in `json-v1`) and explains in `pending`:

```text
Deep profile detection skipped because dependencies are unavailable.
Pending: deep profile confirmed, but its dependencies are unavailable - install the deep extra (pip install docsentinel[deep]) and the model (python -m spacy download en_core_web_sm)
```

---

## Hostile characters in paths and messages

File names and source excerpts come from the repository being scanned, so they are untrusted. Without protection, a file name containing an ANSI escape, a line feed, or a right-to-left override could rewrite terminal output, forge extra log lines, or reorder displayed text.

| Format   | Protection                                                                                                                     |
|----------|--------------------------------------------------------------------------------------------------------------------------------|
| `text`   | Control and invisible characters are replaced with visible, ASCII backslash escapes (`\x1b`, `‮`, `\U0001f600`-style). |
| `github` | The same neutralisation, with CR and LF then percent-encoded as `%0D` / `%0A` as described above.                              |
| `json`, `json-v1`, `json-documents` | `json.dumps` escapes everything non-ASCII as `\uXXXX`.                                                  |

Neutralised characters: C0 controls (including ESC, CR, LF, TAB), DEL, C1 controls, bidirectional formatting characters, zero-width characters, line and paragraph separators, and lone surrogates (from undecodable file names). Ordinary letters, digits, punctuation and accented or non-Latin text pass through unchanged.

The `text` format is not escaped for GitHub Actions. It leaves `::` and `##[` alone, so a hostile file name or message in text output can act as a workflow command when the scan runs in a workflow. In GitHub Actions, use `--format github`. If you need text output there, wrap it in `::stop-commands::<random token>` and `::<random token>::`. Pick a fresh random token for each run.

This is purely a display concern: [baseline](README.md#managing-baselines-for-legacy-debt) fingerprints are computed from the raw finding fields, never from the escaped output, so escaping never changes whether a finding matches the baseline.

---

## Choosing a format

| You want to...                                         | Use      |
|--------------------------------------------------------|----------|
| Read results in your terminal                          | `text`   |
| Know *which rule* produced a finding                   | `json` or `github` |
| Post-process, chart or store results                   | `json`   |
| Keep a script written for the old JSON working         | `json-v1` |
| Get only the per-document records                      | `json-documents` |
| Annotate pull requests in GitHub Actions               | `github` |
| Detect "part of the scan did not run"                  | `json` (`pending`) or `text` (`Pending:` lines) |
| Detect which opt-in policies were off                  | `json` (`rules.opt_in_off`) or `text` (notice line) |

Calling the library directly gives you the same data without formatting. See the [Python Library Guide](library.md) and use `docsentinel.reporting.render(result, "json")` when you want one of these renderings in-process.
