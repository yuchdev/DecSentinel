# Custom Reports

DocSentinel renders every report from a JSON **template** over a JSON-shaped **context**.
You can write your own template, and you can add your own data to the context with an
**extension**. This guide walks through both, end to end.

The examples on this page are executed by the test suite
(`tests/integration/test_custom_reports_guide_ds101.py`), so the output shown here is
what DocSentinel really prints.

## Table of Contents

1. [The example repository](#the-example-repository)
2. [Template anatomy](#template-anatomy)
3. [Domains: labelling documents by path](#domains-labelling-documents-by-path)
4. [A worked `--template` example](#a-worked---template-example)
5. [Writing a `python:` extension](#writing-a-python-extension)
6. [The `document_stats` builtin](#the-document_stats-builtin)
7. [Trust model](#trust-model)
8. [Further reading](#further-reading)

---

## The example repository

The examples scan a small repository with three Markdown files. Two of them have
dangling links (`DS101`):

| File                         | Content                                                          |
|------------------------------|------------------------------------------------------------------|
| `README.md`                  | A heading and a working link to `docs/setup.md`.                 |
| `docs/setup.md`              | A heading and a link to `configure.md`, which does not exist.    |
| `.claude/agents/reviewer.md` | A heading and links to `rules.md` and `style.md`; neither exists. |

---

## Template anatomy

A template is one JSON file. Every template has the same envelope:

| Key                   | Meaning                                                                              |
|-----------------------|--------------------------------------------------------------------------------------|
| `template_version`    | Always `1`.                                                                          |
| `name`                | Kebab-case name. `--format NAME` selects a template by this name.                    |
| `type`                | `"text"` (lines for a terminal or a CI log) or `"json"` (one JSON document).         |
| `description`         | Free text, shown nowhere but useful to readers.                                      |
| `requires_extensions` | Names of extensions the template reads. Listing a name never loads the extension.    |

A **`text`** template has `output` and `lines`. Each line node has a `text` with
`{variable}` references and a `variables_used` list naming exactly those variables. A
`loop` node repeats its `body` for each element of a list, such as
`documents_with_problems`, and a variable can pass through filters:
`{doc.path|neutralize}`.

A **`json`** template has `output`, `schema_version` and a `body`. In the body,
`{"$var": "doc.path"}` inserts a value by type, `{"$for": "documents", "as": "doc", "each": ...}`
maps a list, and every other value is copied as written.

The context holds run-level values (`findings_count`, `documents_count`, `profile`,
...), the `documents` list (each with `path`, `bytes`, `domain`, `problem_count` and
`problems`) and the flat `findings` list. Extension data lives only under `ext`:
`ext.<name>` for the run, `doc.ext.<name>` for a document and `p.ext.<name>` for a
problem.

Two rules keep templates safe:

- **Untrusted values need a sink filter in text templates.** Paths, messages, domains
  and every `ext.*` value come from the scanned repository. In a `text` template each of
  them must end its filter chain with `neutralize` (or `gha_property`/`gha_data` under
  the `github` sink); otherwise loading the template fails. `json` templates are
  exempt, because JSON serialization escapes everything.
- **Mistakes fail before the scan.** An unknown variable, a missing `variables_used`
  entry, an extension the template needs but nobody loaded: each one stops the run
  with `Scan failed: ...` and exit code `2`, and nothing is printed on stdout.

The complete contract is the
[report template format](/docs/specs/report-template-format.md) (context schema in
section 6, filters in section 7, trust rule in section 8, extensions in section 9).

---

## Domains: labelling documents by path

Every document in the context has a `domain`. It is `"docs"` unless you load the
`builtin:domain` extension and give it a table of path globs. Put this in
`docsentinel.toml` at the scan root:

```toml
telemetry_extensions = ["builtin:domain"]

[[telemetry_domains]]
glob = ".claude/agents/**"
domain = "agent"

[[telemetry_domains]]
glob = "**"
domain = "docs"
```

- The rules are tried in order and the **first match wins**. A path no rule matches gets
  `"docs"`.
- `**` is a whole path segment and matches any number of directories (zero included).
  `*` matches any characters inside one segment and `?` exactly one; neither crosses a
  `/`. So `"*"` matches top-level files only, and the catch-all is `"**"`.
- Character classes (`[...]`), braces, backslashes and a leading `!` are refused, as
  are empty, `.` and `..` segments. Matching is case-sensitive.
- A domain matches `^[a-z][a-z0-9_-]{0,63}$`. At most 256 rules; a glob has at most 256
  characters and 32 segments. A bad entry is a configuration error (exit `2`).
- It is an array of tables, so a TOML formatter that sorts keys cannot reorder it.
- In `pyproject.toml`, write `[[tool.doc_sentinel.telemetry_domains]]`.

[`examples/telemetry-domains.toml`](/examples/telemetry-domains.toml) is a fuller
example that maps `.claude/agents/**` and `.claude/skills/**` to `agent`.

With `builtin:domain` loaded, the packaged `json` report shows each document's domain,
and a template can also read `doc.ext.domain.name` (the same label) and
`doc.ext.domain.matched` (the glob that matched, or `null` when the default applied).
The same label goes to fault events (Milestone 0006), so a report and the event stream
never disagree. You can also enable the extension for one run with
`--extension builtin:domain` instead of `telemetry_extensions`.

---

## A worked `--template` example

Save this as `domain-summary.json`, anywhere you like:

```json
{
  "template_version": 1,
  "name": "domain-summary",
  "type": "text",
  "description": "One line per document with problems: its domain, problem count and path.",
  "requires_extensions": ["domain"],
  "output": { "join": "\n", "trailing_newline": false, "sink": "terminal" },
  "lines": [
    {
      "type": "line",
      "text": "{findings_count} finding(s) in {documents_with_problems_count} of {documents_count} document(s)",
      "variables_used": ["findings_count", "documents_with_problems_count", "documents_count"]
    },
    {
      "type": "loop",
      "over": "documents_with_problems",
      "as": "doc",
      "placement": "block",
      "body": [
        {
          "type": "line",
          "text": "[{doc.domain|neutralize}] {doc.path|neutralize}: {doc.problem_count} problem(s), matched by {doc.ext.domain.matched|default(\"(default)\")|neutralize}",
          "variables_used": ["doc.domain", "doc.path", "doc.problem_count", "doc.ext.domain.matched"]
        }
      ]
    }
  ]
}
```

Then run it from the repository root (with the `docsentinel.toml` above):

```bash
docsentinel scan --template domain-summary.json
```

It prints:

```text
3 finding(s) in 2 of 3 document(s)
[agent] .claude/agents/reviewer.md: 2 problem(s), matched by .claude/agents/**
[docs] docs/setup.md: 1 problem(s), matched by **
```

The exit code is `1`, as for every report with an `error` finding: a template never
changes the exit code. To make the template selectable as `--format domain-summary`,
put it in a directory under the scan root and set `report_templates_dir` (see
[Custom templates](report.md#custom-templates)).

Note how every repository value ends with `|neutralize`. Remove it from `doc.path` and
the template no longer loads.

---

## Writing a `python:` extension

An extension is a Python object with a `name` and up to three optional hooks:

| Hook                                      | Called                   | Its return lands under |
|-------------------------------------------|--------------------------|------------------------|
| `provide_run(model)`                      | once per report          | `ext.<name>`           |
| `provide_document(doc, model)`            | once per document        | `doc.ext.<name>`       |
| `provide_problem(problem, doc, model)`    | once per problem         | `p.ext.<name>`         |

Each hook returns a `dict` of plain JSON data (`dict`, `list`, `str`, `int`, finite
`float`, `bool`, `None`) or `None`. Its arguments are read-only copies of the context:
mappings cannot be changed and lists are tuples. An extension can never change a core
value such as `doc.path` or `doc.domain`; it only writes its own `ext.<name>` subtree.
The `name` matches `^[a-z][a-z0-9_]{0,63}$` and may not be a builtin name (`domain`,
`document_stats`).

This extension computes how many problems each document has per KiB, and lists the
three densest documents. Save it as `density_report.py`:

```python
"""Example report extension: problems per KiB of each document."""

import heapq


class DensityExtension:
    """Adds ``doc.ext.density.per_kb`` and the run-level ``ext.density.worst``."""

    name = "density"

    def provide_document(self, doc, model):
        """Return the problem density of one document."""
        return {"per_kb": per_kb(doc)}

    def provide_run(self, model):
        """Return the three densest documents, densest first, ties by path."""
        ranked = [
            (-per_kb(doc), doc["path"])
            for doc in model["documents"]
            if doc["problem_count"] and per_kb(doc) is not None
        ]
        return {"worst": [path for _, path in heapq.nsmallest(3, ranked)]}


def per_kb(doc):
    """Return problems per KiB, ``None`` without a size, ``0.0`` for an empty file."""
    size = doc["bytes"]
    if size is None:
        return None
    if size == 0:
        return 0.0
    return round(doc["problem_count"] / (size / 1024), 3)


def make():
    """Build the extension; DocSentinel calls this with no arguments."""
    return DensityExtension()
```

`bytes` is `None` for a finding on a file outside the scanned Markdown inventory (for
example a `DS204` Python source), so the calculation must handle it.

Next, a template that reads the new values. Save it as `density-report.json`:

```json
{
  "template_version": 1,
  "name": "density-report",
  "type": "json",
  "description": "Problem density per document and the densest documents.",
  "requires_extensions": ["density"],
  "schema_version": 2,
  "output": { "indent": 2, "ensure_ascii": true, "sort_keys": false },
  "body": {
    "worst": { "$var": "ext.density.worst" },
    "documents": {
      "$for": "documents",
      "as": "doc",
      "each": {
        "path": { "$var": "doc.path" },
        "domain": { "$var": "doc.domain" },
        "problems": { "$var": "doc.problem_count" },
        "per_kb": { "$var": "doc.ext.density.per_kb" }
      }
    }
  }
}
```

The module must be importable from **outside** the repository you scan: install it as a
package into the environment that runs DocSentinel, or put its directory on
`PYTHONPATH` when that directory is not inside the checkout. Then name it on the
command line and open the trust gate (see [Trust model](#trust-model)):

```bash
docsentinel scan path/to/repo --template density-report.json \
  --extension python:density_report:make --allow-python-extensions
```

It prints:

```json
{
  "worst": [
    ".claude/agents/reviewer.md",
    "docs/setup.md"
  ],
  "documents": [
    {
      "path": ".claude/agents/reviewer.md",
      "domain": "agent",
      "problems": 2,
      "per_kb": 25.6
    },
    {
      "path": "README.md",
      "domain": "docs",
      "problems": 0,
      "per_kb": 0.0
    },
    {
      "path": "docs/setup.md",
      "domain": "docs",
      "problems": 1,
      "per_kb": 15.059
    }
  ]
}
```

If a hook raises or returns something that is not plain JSON data, the report fails
with `Scan failed: extension density: ...` and exit code `2`, and nothing is printed
on stdout. Extensions may also register filters named `ext.<name>.<filter>`; a filter
is never a sink, so its output still needs `neutralize` in a text template. See
section 9 of the [report template format](/docs/specs/report-template-format.md).

---

## The `document_stats` builtin

DocSentinel ships the same calculation as `builtin:document_stats`, which needs no
trust gate:

- `doc.ext.document_stats.problem_count_per_kb`: problems per KiB, rounded to three
  places; `0.0` for an empty file and `null` when the size is unknown.
- `ext.document_stats.worst_documents`: up to five documents with problems, each
  `{path, bytes, problem_count, problem_count_per_kb}`, densest first and ties ordered by
  path. Documents without a known size are left out.

Enable it with `--extension builtin:document_stats` or
`telemetry_extensions = ["builtin:document_stats"]`, and list `document_stats` in your
template's `requires_extensions`.

---

## Trust model

A `python:` extension is ordinary Python code running inside DocSentinel, so
DocSentinel only runs one that **you**, the person invoking it, chose:

- `python:` extensions come **only from the command line**
  (`--extension python:<module>:<callable>`), and only with
  `--allow-python-extensions` or `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1` (exactly `1`).
  A `python:` entry in `telemetry_extensions` is a configuration error, whatever the
  gate says, so a scanned repository's own configuration can never pick code to run.
  `builtin:` extensions need no gate.
- **Never set the gate variable on CI jobs that run untrusted pull-request heads**, for
  example in a workflow-wide `env:` block next to a `pull_request_target` job.
- **Run the `docsentinel` console script** (not `python -m docsentinel`), or run Python
  with `-P`, and **do not put the checkout on `PYTHONPATH`**. DocSentinel refuses a
  `python:` extension when any import path entry, or the module itself, lies inside the
  scan root, its project root(s) or the current directory. The running interpreter's
  own `site-packages` is exempt, so an extension installed into the environment works.
- Report data from the repository (paths, messages, domains, extension output) is
  untrusted. Templates must neutralize it in text output, as shown above.

Risks DocSentinel accepts and does not remove:

- **R1.** An admitted `python:` extension is full in-process code. The checks above
  protect against hostile *data* and bugs, not against a malicious extension you chose
  to run.
- **R2.** A hook that never returns is not stopped by DocSentinel; your CI job timeout
  is the backstop.
- **R3.** The origin check is a point-in-time check: a checkout modified while the scan
  runs, `.pth` files, `sitecustomize` and a `PYTHONPATH` you set yourself are outside
  DocSentinel's control.
- **R4.** pytest (`conftest.py`) and pre-commit (`language: system`) already run
  repository code, so the gate adds no protection there.
- **R5.** `domain` is a label the repository asserts in its own configuration, not a
  verified attribute. A repository can label its agent files as `docs`.

The full analysis is the
[extensions threat model](/docs/security/threat-model-0007-extensions-2026-11-03.md).

---

## Further reading

- [Report Formats](report.md): the packaged templates and their output.
- [Report template format](/docs/specs/report-template-format.md): the full template contract.
- [`examples/telemetry-domains.toml`](/examples/telemetry-domains.toml): a domain table to copy.
- [CLI Tutorial](cli.md): every `scan` option.
