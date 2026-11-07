# Report template format (v1)

**Status:** Proposed (Milestone 0007) · **Decision record:** [ADR 0003](/docs/adr/0003-template-driven-reporting-on-telemetry.md)  
**Owner module:** `src/docsentinel/telemetry/` · **Standard templates:** `src/docsentinel/telemetry/templates/{text,github,json}.json`

Every report DocSentinel prints -- `text`, `github`, `json`, or a user's own -- is
the output of **one** renderer applied to **one** template over **one** context.
No output format is hardcoded: the renderer contains no format names, no literal
report lines, and no escaping rules. This document is the contract for all three.

## 1. Pipeline

```
ScanResult --> ReportModel (core provider) --> + extension providers --> context
                                                                           |
template.json --> loader/validator --> renderer(template, context) --> str
```

- The **context** is a plain, JSON-shaped tree (`dict`/`list`/`str`/`int`/`float`/`bool`/`None`).
  The renderer never sees `ScanResult`, `Finding`, or any object, so a template
  cannot reach attributes, methods, or `__class__`-style introspection.
- The renderer is **logic-less**: substitution, iteration, a closed set of
  conditions, and a closed set of filters. No `eval`, no expression language, no
  Jinja, no `str.format` on template text.
- Output is **deterministic** for a given `(ScanResult, config, template)`. Values
  that vary per run (`run.generated_at`, `run.id`) come from an opt-in provider
  and are absent by default.

## 2. Common envelope

```json
{
  "template_version": 1,
  "name": "text",
  "type": "text",
  "description": "Human-readable report, findings grouped under their document.",
  "requires_extensions": []
}
```

| Key | Rules |
|---|---|
| `template_version` | Integer; this spec is `1`. Unknown version -> `TemplateError`. |
| `name` | Kebab-case; must equal the file stem for packaged templates. |
| `type` | `"text"` or `"json"`. Unknown type -> `TemplateError`. |
| `requires_extensions` | Extension names (`^[a-z][a-z0-9_]{0,63}$`) that must be loaded (Section 9); missing -> `TemplateError`. A template that references `ext.<n>...` or a filter `ext.<n>.<f>` must list `<n>` here, otherwise it is a load-time `TemplateError`. Listing a name never loads anything. |
| unknown keys | Rejected (fail closed), so a typo never silently drops content. |

## 3. Variable syntax

- `{name}` -- context lookup; `{doc.path}` -- dotted path over dicts; `{items.0}` -- list index.
- `{value|filter|filter(arg)}` -- filter chain, applied left to right.
- `{{` and `}}` -- literal braces.
- A reference to an unknown variable is a **load-time** `TemplateError` (the loader
  knows the context schema), never an empty string at render time.
- `variables_used` on a node is mandatory in `text` templates and must equal the
  set of variables the node's `text` references. The loader checks both directions,
  so the declaration is lint-enforced documentation, not a second source of truth.

## 4. `text` templates

```json
{
  "type": "text",
  "output": { "join": "\n", "trailing_newline": false, "sink": "terminal" },
  "lines": [ <node>, ... ]
}
```

In `output`, `join` may only be `"\n"`, and `sink` is `"terminal"` (default) or `"github"`;
`sink` selects which filters count as sinks (Section 8); a line starting with `::` requires
`"github"`. No template string or key may contain a code point that `neutralize`
escapes (controls, CR/LF, bidi, zero-width, separators, lone surrogates).

### Node types

| `type` | Purpose | Keys |
|---|---|---|
| `line` | One output line. | `text`, `variables_used`, optional `when` |
| `loop` | Iterate a list in context. | `over`, `as`, `placement`, `when`; then `text` + `separator` (inline placements) or `body` (block) |
| `group` | A conditional run of nodes with no loop. | `when`, `body` |

`loop.placement`:

| Value | Behaviour |
|---|---|
| `"block"` (default) | Render `body` once per item; each emitted line goes on its own output line. This is how findings appear **directly under their document**: an outer loop over `documents_with_problems` emits the document line, then an inner loop over `doc.problems` emits the indented finding lines. |
| `"one-line"` | Render `text` per item and join with `separator` into **one** output line. |
| `"append"` | Like `one-line`, but the result is appended to the previously emitted line (no line break). Used for a trailing list after a `line`, e.g. `... not enabled: ` + `DS110 (set x), DS112 (set y)`. Nothing is appended for an empty list. |

`text` may carry `prefix`/`suffix` on inline loops, emitted only when the list is non-empty.

### Conditions (`when`)

A closed grammar; anything else is a `TemplateError`:

```json
{ "var": "profile", "eq": "deep" }
{ "var": "doc.problem_count", "gt": 0 }
{ "var": "advisory", "truthy": true }
{ "all": [ <cond>, <cond> ] }   { "any": [ ... ] }   { "not": <cond> }
```

Operators: `eq`, `ne`, `in`, `gt`, `lt`, `truthy`, `falsy`.

### Example (excerpt of `text.json`)

```json
{
  "template_version": 1, "name": "text", "type": "text",
  "lines": [
    { "type": "line", "text": "Schema version: {schema_version}", "variables_used": ["schema_version"] },
    { "type": "line", "text": "Profile: {profile}", "variables_used": ["profile"] },
    { "type": "line", "text": "Documents: {documents_count} ({documents_with_problems_count} with problems)",
      "variables_used": ["documents_count", "documents_with_problems_count"] },
    { "type": "line", "text": "Enabled rules: {enabled_rules|json}", "variables_used": ["enabled_rules"] },
    { "type": "line", "when": { "var": "opt_in_off", "falsy": true },
      "text": "{rules_evaluated} {rules_type} rule(s) evaluated.",
      "variables_used": ["rules_evaluated", "rules_type"] },
    { "type": "line", "when": { "var": "opt_in_off", "truthy": true },
      "text": "{rules_evaluated} {rules_type} rule(s) evaluated; opt-in rule(s) not enabled: ",
      "variables_used": ["rules_evaluated", "rules_type"] },
    { "type": "loop", "over": "opt_in_off", "as": "rule", "placement": "append", "separator": ", ",
      "when": { "var": "opt_in_off", "truthy": true },
      "text": "{rule.code} (set {rule.option})", "variables_used": ["rule.code", "rule.option"] },
    { "type": "line", "when": { "var": "advisory", "truthy": true },
      "text": "{advisory}", "variables_used": ["advisory"] },
    { "type": "loop", "over": "documents_with_problems", "as": "doc", "placement": "block", "body": [
      { "type": "line", "text": "{doc.path|neutralize} ({doc.bytes} bytes)", "variables_used": ["doc.path", "doc.bytes"] },
      { "type": "loop", "over": "doc.problems", "as": "p", "placement": "block", "body": [
        { "type": "line", "text": "  {p.severity}: {doc.path|neutralize}: {p.message|neutralize}",
          "variables_used": ["p.severity", "doc.path", "p.message"] } ] } ] },
    { "type": "loop", "over": "pending", "as": "reason", "placement": "block", "body": [
      { "type": "line", "text": "Pending: {reason|neutralize}", "variables_used": ["reason"] } ] }
  ]
}
```

The `Documents:` header counts inventory documents only (`documents_count`,
`documents_with_problems_count`; see Section 6), matching the legacy `Documents: N`
line. A finding on a path outside the inventory (for example a `DS204` Python
source) is still listed under its own document line, without a byte size, but is
not counted in the header.

## 5. `json` templates

```json
{
  "type": "json",
  "schema_version": 2,
  "output": { "indent": 2, "ensure_ascii": true, "sort_keys": false },
  "body": <value>
}
```

`body` is any JSON value. A JSON object whose keys start with `$` is an
**operator**; every other value is emitted literally.

| Operator | Meaning |
|---|---|
| `{"$var": "doc.path"}` | The context value at that path, **by type** (a list stays a list, `None` stays `null`). `{"$var": "run"}` embeds a whole sub-tree -- this is the "widest reporting" escape hatch. |
| `{"$var": "x", "$default": 0}` | Fallback when the value is `None`. |
| `{"$for": "documents", "as": "doc", "each": <value>}` | Map a list through `each`. |
| `{"$if": <cond>, "then": <value>, "else": <value>}` | Conditional value; omit `else` to yield `null`. |
| `{"$str": "{doc.path}:{p.line}"}` | Interpolated string (same variable syntax, filters allowed). |
| `{"$omit_if": <cond>, "value": <value>}` | Inside an object, drop the key when the condition holds. |

In `output`, `indent` is `null` or an integer 0..8, and `ensure_ascii` must be `true` in v1.
`ensure_ascii=true` is the safety property of the JSON sink: every control and
non-ASCII code point is escaped by serialization, so no `neutralize` filter is
needed (and none is applied, preserving JSON v1 behaviour).

### Standard `json.json` (schema 2) body shape

```json
{
  "schema_version": 2,
  "profile": "fast",
  "run": { "model": null, "notice": "...", "advisory": null },
  "summary": { "documents": 358, "documents_with_problems": 41, "findings": 187,
               "by_severity": { "error": 150, "warning": 37 }, "by_rule": { "DS101": 150 } },
  "rules": { "enabled": ["DS101"], "evaluated": 12, "opt_in_off": [ { "code": "DS110", "option": "require_fence_languages" } ] },
  "documents": [
    {
      "path": "adr/0003-pipeline-introspection-and-unified-debug-mode.md",
      "bytes": 15033,
      "domain": "docs",
      "problems": [
        { "rule": "DS101", "type": "dangling link", "message": "dangling link -> /docs/x.md",
          "value": "/docs/x.md", "severity": "error", "line": 3, "column": 15,
          "fault_class": "dangling_reference", "tier": "deterministic", "outcome": "rejected" }
      ]
    }
  ],
  "pending": []
}
```

Clean documents are **included** with `"problems": []`: the denominator is what
turns a fault count into a fault *rate*. `summary.documents` and
`summary.documents_with_problems` count inventory documents only; a document entry
appended for an out-of-inventory finding path (`bytes: null`) is listed in
`documents` but not counted. The bare list-of-documents shape from the
original request ships as the example template `json-documents.json`.

## 6. Context schema

The loader validates every reference against this schema. Each variable carries a
**trust** tag; see Section 8.

### Run level (core provider)

| Variable | Type | Trust |
|---|---|---|
| `schema_version` | int (legacy `ScanResult.schema_version`) | trusted |
| `report_schema_version` | int (template's declared schema) | trusted |
| `profile` | str | trusted |
| `enabled_rules` | list[str] | trusted |
| `documents_count`, `documents_with_problems_count` | int: inventory documents only (`len(inventory)` and the inventory documents with at least one problem); a path outside the inventory that `documents` appends is never counted, so the counts are the fault-rate denominator and match the legacy `Documents: N` | trusted |
| `findings_count` | int (every finding, including those on out-of-inventory paths) | trusted |
| `rules_evaluated` | int | trusted |
| `rules_type` | str (the profile name) | trusted |
| `opt_in_off` | list[{`code`, `option`}] | trusted |
| `notice` | str (legacy pre-built string, kept for json v1) | trusted |
| `advisory` | str or null (deep-profile banner when it applies) | trusted |
| `pending` | list[str] | **untrusted** |
| `severity_counts`, `rule_counts` | dict[str,int] | trusted |
| `model` | str or null (`generated_by_model`) | trusted |
| `show_clean_documents` | bool: `--show-clean-documents` / `report_show_clean_documents`; the `text` template lists every document when set, only those with problems otherwise | trusted |
| `documents`, `documents_with_problems` | list[document] | -- |
| `findings` | flat list[problem] (each carrying its `document_path`) | -- |
| `inventory` | list[{`path`, `bytes`}]: the scanned documents exactly as in schema 1, without the entries `documents` appends for finding paths outside the inventory (used by `json-v1`) | `path` **untrusted**, `bytes` trusted |
| `run.generated_at`, `run.id` | str | trusted, **opt-in only** |

### Document

`path` (**untrusted**), `bytes`, `domain` (str, **untrusted**; always present, set by
the core provider from `domain_for(path, config)`, `"docs"` unless `builtin:domain` is
loaded; never filled from an extension hook), `problem_count`, `severity_counts`,
`problems` (list), plus extension keys under `ext.<name>.*` (e.g.
`doc.ext.domain.name`).

### Extension data (`ext`)

`ext` exists at run, document (`doc.ext`) and problem (`p.ext`) level. It resolves as
an `object` whose members are only the names in the template's `requires_extensions`.
Every deeper segment (`ext.<name>.*`) has the value kind **`any`**, which is always
**untrusted**; trust is inherited by every descendant and list element. No extension
and no template can mark an `ext.*` value trusted. An `any` value is accepted where a
scalar is expected only with a render-time check (a container is a `TemplateError`),
and `$for`/`over` on a non-list `any` is a `TemplateError`.

### Problem

| Variable | Notes | Trust |
|---|---|---|
| `rule`, `rule_title`, `severity`, `line`, `column`, `fault_class`, `tier`, `outcome` | `column`/`line` may be null | trusted |
| `type` | short category (`dangling link`); when the detector gave none, the rule title with a lower-cased first letter, taken from a static table so it never depends on which profiles were loaded; null for an unknown rule | trusted |
| `message` | full detector message | **untrusted** |
| `value` | offending token (target path, name); null if not extracted | **untrusted** |
| `document_path` | repeated for flat `findings` | **untrusted** |

## 7. Filters

| Filter | Effect | Sink |
|---|---|---|
| `neutralize` | Backslash-escape C0/C1/DEL, bidi, zero-width, line separators, lone surrogates (the existing `_neutralize_controls` table, CR/LF included). | text |
| `gha_property` | `neutralize` (CR/LF kept) then percent-encode `% \r \n : ,`. | github |
| `gha_data` | `neutralize` (CR/LF kept) then percent-encode `% \r \n`. | github |
| `json` | `json.dumps` (ASCII-safe). | any |
| `join(sep)`, `len`, `lower`, `upper`, `default(x)` | Plain transforms; never a sink. | -- |
| `ext.<ext>.<name>` | Filter registered by an extension; returns a JSON scalar. | **never** |

Filters are pure functions `str -> str` (or the stated type) registered in a
closed table; a template cannot define one. An extension may add filters named
exactly `ext.<own name>.<filter>` (`<filter>` matching `[a-z][a-z0-9_]{0,63}`), with
a declared arity (0 or 1 quoted literal) and declared input kinds. They live in a
per-render registry, never in the core table. An extension filter is **never a
sink** and cannot declare itself one, and the output of any chain that contains an
extension filter is **untrusted**, whatever the trust of its input (Section 8).

## 8. Trust rule (fail closed)

A `text`-type template that references an **untrusted** variable must route it
through a core *sink* filter (`neutralize`, `gha_property`, `gha_data`, `json`;
extension filters are never sinks) **before it is emitted**. Otherwise the
loader raises `TemplateError` -- an author cannot forget escaping, and a custom
template cannot reintroduce the log-forging / Trojan-Source holes the current
renderer closes. `json` templates are exempt: serialization is the sink.

The rule is checked strictly (threat model T1/T2):

- A list element (a loop alias) inherits the list's trust. A container with no tag of its
  own is untrusted when any member is untrusted.
- Dicts, and lists not reduced by `join`/`len`/`json`, cannot be emitted in text.
- The chain must **end** with the sink, so `{p.message|neutralize|upper}` is rejected.
- A chain that contains an `ext.*` filter is treated as **untrusted** whatever its input,
  so it too must end with a core sink and, under `"sink": "github"`, obey every rule for
  untrusted variables below. So `{p.message|ext.x.f}` is rejected in text, and
  `{profile|ext.x.f}` is rejected on a plain github line but accepted as
  `::error ...::{profile|ext.x.f|gha_data}`.
- Every `ext.*` variable is untrusted (Section 6), at every depth.
- With `"sink": "github"` in `output`, only `gha_property`/`gha_data` count as sinks. Any
  variable (trusted or not) before the second `::` of a command line needs
  `gha_property`, and so does every variable of an `append` loop. An untrusted variable
  after the second `::` needs `gha_data`.
- With `"sink": "github"`, every emitted line that holds a variable (including inline
  loops, whose `prefix` counts) must start with literal text that is neither empty nor a
  lone `:` once leading whitespace is trimmed. So `{p.message|gha_data}` cannot start a line.
- With `"sink": "github"`, an **untrusted** variable may appear only on a well-formed
  workflow command line. The line must start (after optional spaces) with a literal `::`
  and a literal command name from the closed list `error`, `warning`, `notice`, `debug`,
  `group`, followed by a literal space or `::`. It must also contain a literal second `::`.
  Any other line falls back to the runner's legacy parser, which finds `##[` anywhere in
  the line, and the `gha_*` filters do not escape `#`, `[` or `]`. Plain lines may carry
  only trusted variables. So may `append` loops, because the loader cannot prove which
  line they continue. So `Finding: {p.message|gha_data}`, `::warning {p.message|gha_property}`
  and `::{p.message|gha_property}::...` are rejected.
- With `"sink": "github"`, a variable may not directly follow a literal ending in `#`
  (the loop `prefix`, and the item text plus `separator` of an inline loop, count). So no
  value can complete a `##[` marker.
- In an inline loop, each item's segment is judged from the `prefix` plus the item's own
  literals. So a `one-line` loop whose `text` is the whole
  `::error file={p.document_path|gha_property},line={p.line|gha_property}::{p.message|gha_data}`
  command is accepted, and so is one whose `prefix` opens the command.
- The `terminal` sink does not target GitHub Actions: `neutralize` leaves `::` and `##[`
  alone. In a workflow, use `--format github` or a `github`-sink template, or wrap text
  output in `::stop-commands::<random token>`.

## 9. Extensions (variables, calculations, filters)

Extensions are Python callables that add data to the context. They never touch
the renderer.

The normative security contract is
[threat-model-0007-extensions-2026-11-03.md](/docs/security/threat-model-0007-extensions-2026-11-03.md)
(M1-M34); the task specs of
[Story 04.0](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/README.md)
carry the details.

- Extension names match `^[a-z][a-z0-9_]{0,63}$`. Builtin names (`domain`,
  `document_stats`, ...) are reserved: a `python:` extension using one, two
  extensions with one name, or one spec given twice is an `ExtensionError`.
- Variables are namespaced: an extension named `domain` can only write under
  `ext.domain.*`, `doc.ext.domain.*`, `p.ext.domain.*`. It cannot add, replace or
  remove a core variable at any level, and all of its data is untrusted (Section 6).
- Three hooks, all optional: `provide_run(model) -> Mapping`,
  `provide_document(doc, model) -> Mapping`, `provide_problem(problem, doc, model) -> Mapping`.
  Hooks receive deep-frozen copies. Returned trees must be JSON-shaped and within the
  depth/size bounds, and are copied into fresh builtin objects; anything else is an
  `ExtensionError`.
- Selection. `--extension SPEC` (repeatable) takes a spec, `builtin:<name>` or
  `python:<module>:<callable>`. `telemetry_extensions = ["builtin:domain"]` in config
  may hold **only** `builtin:` specs; a `python:` (or any other) entry in config is a
  `ConfigError` (exit 2) whatever the gate says. `builtin:*` names resolve through a
  static table inside the package and never need the gate.
- Trust gate. A `python:` spec runs arbitrary code. It is accepted **only from argv**
  and only when the invoker also passes `--allow-python-extensions` or sets
  `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS` to exactly `"1"` (any other value is refused).
  Only the CLI reads that variable; the library API takes an explicit
  `allow_python_extensions=False` keyword and never reads the environment. The gate
  is enforced inside the single `importlib` helper shared with the Milestone 0006
  `python:` sink, before any import, and a module whose origin lies inside the scan
  root or the cwd is refused. So a scanned repository's own `docsentinel.toml`, or a
  module it adds, can never choose code to execute.
- A failing extension during a **report** is a fail-closed `ExtensionError`
  (CLI exit 2, neutralized message, nothing written to stdout). During
  fault-**event emission** (Milestone 0006) a hook failure is swallowed with one
  bounded stderr warning per extension, because telemetry must never fail a scan.
  A refused `python:` spec or a config error is **never** swallowed: it is exit 2 on
  both paths.
- `requires_extensions` is checked against the loaded, validated names after the
  gate and before the scan; it never loads an extension, and its error message
  never suggests the gate or a module path.

The shipped example, `builtin:domain`, assigns `domain` from the document path
using an ordered array of glob rules (first match wins; `"docs"` when nothing
matches):

```toml
[[tool.doc_sentinel.telemetry_domains]]
glob = ".claude/agents/**"
domain = "agent"

[[tool.doc_sentinel.telemetry_domains]]
glob = ".claude/skills/**"
domain = "agent"

[[tool.doc_sentinel.telemetry_domains]]
glob = "docs/**"
domain = "docs"

[[tool.doc_sentinel.telemetry_domains]]
glob = "**"
domain = "docs"
```

Globs are split on `/`: `**` (a whole segment) matches zero or more segments, `*`
and `?` never cross `/`, everything else is literal; the catch-all is `"**"`.
Domain values match `^[a-z][a-z0-9_-]{0,63}$`. Bounds: at most 256 rules, 256 characters and
32 segments per glob, and 4096 characters of glob text in total. Matching uses a non-regex matcher.

The same `domain_for(path, config)` fills the core `doc.domain`; the Milestone 0006 adapter
(not implemented yet) is specified to call it for `FaultEvent.domain` too, so the report and
the event stream cannot disagree. `json.json` emits `{"$var": "doc.domain", "$default": "docs"}`.

## 10. Errors

| Error | When | CLI |
|---|---|---|
| `TemplateError` | unreadable/oversized/unparseable/invalid template, unknown variable/filter/operator, `variables_used` mismatch, untrusted variable without a sink filter, missing required extension | exit 2 |
| `ExtensionError` | extension import/hook failure, non-JSON-shaped or oversized return, namespace or reserved-name violation, `python:` extension refused by the gate or the origin check (exit 2 on the event path too) | exit 2 |
| `ConfigError` | a non-`builtin:` entry in `telemetry_extensions`; an invalid or out-of-bounds `telemetry_domains` entry | exit 2 |

Messages echo bounded, `neutralize`d text. Templates named in config must be
root-contained regular files of bounded size (same containment gate as DS115's
mapping file); a template given on the command line is trusted like any argv path.
