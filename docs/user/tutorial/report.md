# Report Formats

`docsentinel scan` can render the same scan result in three formats, selected with `--format`:

| Format   | Flag                | Audience                          | Carries rule code | Carries line number |
|----------|---------------------|-----------------------------------|-------------------|---------------------|
| `text`   | `--format text`     | A person reading a terminal       | No                | No                  |
| `json`   | `--format json`     | Scripts, dashboards, other tools  | Yes               | Yes (may be `null`) |
| `github` | `--format github`   | GitHub Actions annotations        | No                | Yes (when known)    |

`text` is the default. All three are produced from one `ScanResult` by `docsentinel.reporting.render`, so they never disagree about *what* was found; they differ only in how much of it they show. If you need the rule code (for example to add it to `ignore`), use `json`.

The format never changes the [exit code](README.md#exit-codes-contract). That is decided from the findings alone.

## Table of Contents

1. [The example used on this page](#the-example-used-on-this-page)
2. [Text format](#text-format)
3. [JSON format](#json-format)
4. [GitHub format](#github-format)
5. [Exit codes and the report](#exit-codes-and-the-report)
6. [Deep profile differences](#deep-profile-differences)
7. [Hostile characters in paths and messages](#hostile-characters-in-paths-and-messages)
8. [Choosing a format](#choosing-a-format)

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

It produces three findings: a dangling link and a missing anchor (both `DS101`, severity `error`, line 3) and a stray HTML comment (`DS102`, severity `warning`, line 5).

---

## Text format

```bash
docsentinel scan --format text
```

```text
Schema version: 1
Profile: fast
Documents: 2
Enabled rules: ["DS101", "DS102", "DS103", "DS104", "DS105", "DS106", "DS108", "DS109", "DS110", "DS112", "DS113", "DS114", "DS115", "DS116", "DS117", "DS118"]
12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming).
  README.md (74 bytes)
  docs/setup.md (15 bytes)
error: README.md: dangling link -> docs/nope.md
error: README.md: missing anchor '#nowhere' in this file
warning: README.md: stray HTML comment: '<!-- stray -->'
```

The output is a plain list of lines, always in this order:

| # | Line                                        | Meaning                                                                                              |
|---|---------------------------------------------|------------------------------------------------------------------------------------------------------|
| 1 | `Schema version: N`                         | Version of the result contract (currently `1`). Same value as `schema_version` in JSON.              |
| 2 | `Profile: NAME`                             | The profile that ran: `fast`, `standard` or `deep`.                                                  |
| 3 | `Documents: N`                              | How many Markdown documents discovery found and scanned.                                             |
| 4 | `Enabled rules: [...]`                      | JSON array of rule codes selected for this run, after `select` / `ignore`. Written as JSON on one line. |
| 5 | notice                                      | One sentence describing what was actually evaluated (see below).                                     |
| 6 | *(deep only)* advisory banner               | Present only for the `deep` profile when it has findings. See [Deep profile differences](#deep-profile-differences). |
| 7 | `  PATH (N bytes)` for each document        | Indented two spaces. One line per scanned document, in stable sorted order.                          |
| 8 | `Pending: REASON` for each pending reason   | Work that was requested but could not run, such as missing optional dependencies.                    |
| 9 | `SEVERITY: PATH: MESSAGE` for each finding  | One line per finding, with no indentation.                                                           |

### Reading a finding line

```text
error: README.md: dangling link -> docs/nope.md
└─┬─┘  └───┬───┘  └─────────────┬──────────────┘
severity  path             message
```

- **`severity`** is `error` or `warning`. Errors fail the scan; warnings fail it only with `--strict`.
- **`path`** is relative to the scan root and uses `/` separators.
- **`message`** is the detector's explanation. It often echoes a short excerpt of the source (here `'<!-- stray -->'`).

The text format **omits the rule code and the line number**. Both exist on every finding; they are only visible in `json` (rule code and line) and `github` (line). To find which rule produced a line, run `docsentinel scan --format json`, or search the [Configuration Reference](../reference/configuration.md) for the message wording.

### The notice line

The notice states how many rules *actually ran* and names opt-in rules that are registered but switched off:

```text
12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming).
```

`Enabled rules` lists **16** codes but the notice says **12** were evaluated. The four extra codes (`DS110`, `DS112`, `DS115`, `DS118`) are opt-in policy rules: they are selected, yet emit nothing until you set the option shown in parentheses. This is not an error. A clean scan with opt-in rules off means those four policies were not checked.

### Reading a clean scan

With no findings, the report simply ends after the document list:

```text
Schema version: 1
Profile: fast
Documents: 1
Enabled rules: ["DS101", "DS102", ...]
12 fast rule(s) evaluated; opt-in rule(s) not enabled: ...
  setup.md (15 bytes)
```

There is no "no problems found" line. Check the exit code (`0`) to confirm success.

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

JSON is the complete, stable machine contract. It serializes the whole `ScanResult` with two-space indentation:

```json
{
  "schema_version": 1,
  "profile": "fast",
  "documents": [
    { "path": "README.md", "bytes": 74 },
    { "path": "docs/setup.md", "bytes": 15 }
  ],
  "findings": [
    {
      "rule": "DS101",
      "path": "README.md",
      "message": "dangling link -> docs/nope.md",
      "severity": "error",
      "line": 3
    },
    {
      "rule": "DS101",
      "path": "README.md",
      "message": "missing anchor '#nowhere' in this file",
      "severity": "error",
      "line": 3
    },
    {
      "rule": "DS102",
      "path": "README.md",
      "message": "stray HTML comment: '<!-- stray -->'",
      "severity": "warning",
      "line": 5
    }
  ],
  "enabled_rules": ["DS101", "DS102", "DS103", "DS104", "DS105", "DS106", "DS108", "DS109", "DS110", "DS112", "DS113", "DS114", "DS115", "DS116", "DS117", "DS118"],
  "pending": [],
  "notice": "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), ..."
}
```

The real output expands each array element onto its own lines; it is compacted above for readability.

### Top-level fields

| Field            | Type             | Always present | Description                                                                                          |
|------------------|------------------|----------------|------------------------------------------------------------------------------------------------------|
| `schema_version` | integer          | Yes            | Contract version. Currently `1`. Check it before parsing if you depend on the shape.                 |
| `profile`        | string           | Yes            | `"fast"`, `"standard"` or `"deep"`.                                                                  |
| `documents`      | array of objects | Yes            | Every scanned document, sorted. Empty array when nothing was discovered.                             |
| `findings`       | array of objects | Yes            | Every reported finding. Empty array on a clean scan. Baselined findings are already removed.         |
| `enabled_rules`  | array of strings | Yes            | Rule codes active for this run. Opt-in rules appear here even while their policy is off.             |
| `pending`        | array of strings | Yes            | Reasons part of the scan did not run. Empty when everything requested ran.                           |
| `notice`         | string           | Yes            | The same sentence as the text format's notice line.                                                  |
| `advisory`       | string           | **Deep only**  | Present only when `profile` is `deep` **and** there is at least one finding. See below.              |

### `documents[]`

| Field   | Type    | Description                                              |
|---------|---------|----------------------------------------------------------|
| `path`  | string  | Path relative to the scan root, `/`-separated.           |
| `bytes` | integer | File size in bytes.                                      |

### `findings[]`

| Field      | Type            | Description                                                                                         |
|------------|-----------------|-----------------------------------------------------------------------------------------------------|
| `rule`     | string          | Rule code such as `"DS101"`. Use this value in `select` / `ignore`.                                 |
| `path`     | string          | Document the finding is in, relative to the scan root.                                              |
| `message`  | string          | Human-readable explanation, possibly echoing a short source excerpt.                                |
| `severity` | string          | `"error"` or `"warning"`. (A finding's default severity is `"warning"`.)                            |
| `line`     | integer or null | 1-based line number, or `null` when the rule cannot point at a single line (for example a corpus-level finding). |

Always handle `line: null`. Findings are emitted in the engine's deterministic order, so identical input gives identical output.

### Parsing example

```bash
# Count errors
docsentinel scan --format json | jq '[.findings[] | select(.severity == "error")] | length'

# One "rule path:line message" row per finding
docsentinel scan --format json | jq -r '.findings[] | "\(.rule) \(.path):\(.line // 1) \(.message)"'

# Which rules fire most
docsentinel scan --format json | jq -r '.findings[].rule' | sort | uniq -c | sort -rn
```

Note that `docsentinel scan` exits `1` when it finds blocking problems, so in a script that uses `set -e` or `pipefail`, capture the output first and examine the exit code separately.

### Encoding

JSON output is ASCII-only. Every control character and non-ASCII character in a path or message is written as a `\uXXXX` escape, so hostile file names cannot inject anything into a log. Your JSON parser restores the original characters.

---

## GitHub format

```bash
docsentinel scan --format github
```

```text
::error file=README.md,line=3::dangling link -> docs/nope.md
::error file=README.md,line=3::missing anchor '#nowhere' in this file
::warning file=README.md,line=5::stray HTML comment: '<!-- stray -->'
```

This format prints **only** workflow commands, one per finding, and nothing else: no schema line, no document list, no notice, no `Pending:` lines. GitHub Actions turns each line into an annotation on the pull request's *Files changed* tab and in the workflow run summary.

### Line anatomy

```text
::error file=README.md,line=3::dangling link -> docs/nope.md
└─┬──┘ └──────┬──────────────┘  └──────────────┬──────────┘
 level    properties                         message
```

| Part       | Rule                                                                                                          |
|------------|---------------------------------------------------------------------------------------------------------------|
| level      | `error` for findings of severity `error`; **everything else becomes `warning`**.                              |
| `file=`    | The finding's path, relative to the scan root.                                                                |
| `line=`    | Included only when the finding has a line number. Otherwise the line is `::warning file=PATH::message`.       |
| message    | The finding's message, after the escaping below.                                                              |

The rule code is **not** included. If you need it in annotations, use JSON and build your own commands.

### Escaping

Workflow commands use `%`-escaping so that no message can end the command early or start a new one. DocSentinel applies the runner's contract:

| Where                     | Character | Written as |
|---------------------------|-----------|------------|
| property (`file=`)        | `%`       | `%25`      |
| property                  | CR        | `%0D`      |
| property                  | LF        | `%0A`      |
| property                  | `:`       | `%3A`      |
| property                  | `,`       | `%2C`      |
| message (after `::`)      | `%`       | `%25`      |
| message                   | CR        | `%0D`      |
| message                   | LF        | `%0A`      |

So a file named `a,b:c.md` is reported as `file=a%2Cb%3Ac.md`, and GitHub decodes it back. Colons and commas are left alone in the message because they are only special inside properties.

### Clean scans

When there are no findings the command prints an empty line (a lone newline) and exits `0`. No annotations are created.

### Using it in a workflow

```yaml
- name: Run DocSentinel Scan
  run: docsentinel scan --format github --strict
```

The step fails when the exit code is non-zero, and annotations appear either way. Add `--strict` if warnings should fail the job; without it only errors do. See the [CLI Tutorial](cli.md) for more options.

---

## Exit codes and the report

| Code | Meaning                                                                       | What you see on stdout                     |
|------|-------------------------------------------------------------------------------|--------------------------------------------|
| `0`  | No blocking findings (or the `deep` profile, which is advisory only).         | The report; may still list warnings.       |
| `1`  | At least one `error`, or any finding at all when `--strict` is set.           | The report.                                |
| `2`  | Configuration or scan failure (bad config, unreadable root, missing opt-in file). | Nothing on stdout; an error line on **stderr**. |

Practical consequences:

- **Warnings print but do not fail** unless you pass `--strict`. An exit code of `0` with `warning:` lines in a text report is normal.
- **Exit `2` produces no report in any format.** The message `Scan failed: ...` goes to stderr, so do not try to parse stdout as JSON without checking the exit code first.
- All formats share the same exit code for the same scan.

---

## Deep profile differences

The `deep` profile (`DS301`) is heuristic, so its findings are candidates for human review rather than verdicts.

- **Exit code is always `0`**, even with `--strict`.
- **Text:** when there are findings, the line `Deep findings are heuristic candidates for review - they do not fail the build.` is inserted after the notice line.
- **JSON:** the same sentence appears as a top-level `"advisory"` string. The key is absent when there are no findings, and absent for the other profiles.
- **GitHub:** unchanged. Findings still become annotations, with no banner.

If the deep extra is not installed, the scan does not fail. It reports `"enabled_rules": []` and explains in `pending`:

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
| `json`   | `json.dumps` escapes everything non-ASCII as `\uXXXX`.                                                                        |

Neutralised characters: C0 controls (including ESC, CR, LF, TAB), DEL, C1 controls, bidirectional formatting characters, zero-width characters, line and paragraph separators, and lone surrogates (from undecodable file names). Ordinary letters, digits, punctuation and accented or non-Latin text pass through unchanged.

The `text` format is not escaped for GitHub Actions. It leaves `::` and `##[` alone, so a hostile file name or message in text output can act as a workflow command when the scan runs in a workflow. In GitHub Actions, use `--format github`. If you need text output there, wrap it in `::stop-commands::<random token>` and `::<random token>::`. Pick a fresh random token for each run.

This is purely a display concern: [baseline](README.md#managing-baselines-for-legacy-debt) fingerprints are computed from the raw finding fields, never from the escaped output, so escaping never changes whether a finding matches the baseline.

---

## Choosing a format

| You want to...                                         | Use      |
|--------------------------------------------------------|----------|
| Read results in your terminal                          | `text`   |
| Know *which rule* produced a finding                   | `json`   |
| Post-process, chart or store results                   | `json`   |
| Annotate pull requests in GitHub Actions               | `github` |
| Detect "part of the scan did not run"                  | `json` (`pending`) or `text` (`Pending:` lines) |
| Detect which opt-in policies were off                  | `json` (`notice`) or `text` |

Calling the library directly gives you the same data without formatting. See the [Python Library Guide](library.md) and use `docsentinel.reporting.render(result, "json")` when you want one of these renderings in-process.
