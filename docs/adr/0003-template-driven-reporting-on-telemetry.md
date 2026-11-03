# 0003 - Template-Driven Reporting Built on a Telemetry Package

> **Status:** Proposed
>
> **Date:** 2026-10-30
>
> **Supersedes:** _(none)_
>
> **Superseded by:** _(none)_

## Context

`reporting.py` renders three formats with three unrelated code paths:
`_render_github` (hand-built `::level` lines), an inline `lines = [...]` list for
text, and `dataclasses.asdict` for JSON. A review of the CanonixEngine docs (358
documents, `docs/reviews/docsentinel-docs-2026-10-26/`) showed the cost:

1. **Text** prints all 358 `path (N bytes)` lines first and the findings after
   them; the reader scrolls past the inventory to find results. Findings are not
   attached to their document.
2. **JSON** is two parallel arrays (`documents`, `findings`) joined only by a path
   string, with no column, offending value, category, fault class, or outcome. It
   is the primary channel for collecting hallucination data, and it is the
   narrowest of the three.
3. **GitHub** carries no column, title, or document context.
4. Adding any field means editing three renderers, and there is no way for a team
   to add its own (for example a `domain` of `docs` vs `agent`).

Milestone 0006 puts a `FaultEvent` in `src/docsentinel/telemetry.py`. The same
facts (rule, fault class, tier, outcome, model, domain) are what the report
should carry, so the report and the event stream should be one model.

## Decision

1. **Every output format is a template.** `text`, `github`, and `json` are three
   packaged files, `telemetry/templates/{text,github,json}.json`, interpreted by
   one renderer. The renderer holds no format names, no report literals and no
   escaping logic; `reporting.render()` becomes a thin call into it. A tripwire
   test fails if a format literal reappears in Python.
2. **`telemetry.py` becomes the package `src/docsentinel/telemetry/`.** It owns
   the event types (moved, import path `docsentinel.telemetry` preserved), the
   report model, the template loader/validator/renderer, the filters, and the
   extension API. Reports and fault events are built from the same
   `ReportModel`.
3. **Templates are logic-less data** (spec:
   [docs/specs/report-template-format.md](/docs/specs/report-template-format.md)):
   `text` templates with `line`/`loop`/`group` nodes and `variables_used` lint;
   `json` templates with `$var`/`$for`/`$if`/`$str` operators. No `eval`, no
   third-party template engine, no object access from a template.
4. **Escaping is a template-declared filter, enforced at load.** Untrusted
   variables (`path`, `message`, `value`) must pass through a sink filter in a text
   template or the template is rejected. This preserves the existing
   control/bidi/zero-width neutralization guarantee for custom templates.
5. **Extensions add data, not rendering.** Python extensions contribute
   namespaced variables and filters; `builtin:domain` is the shipped example
   (domain from path: `docs`, `.claude/agents`, ...). `python:` extensions need an
   explicit invoker opt-in because a scanned repo's config must not run code: they
   are accepted only from argv with `--allow-python-extensions` (or the env var set
   to exactly `1`), never from config, and the gate lives in the one `importlib`
   helper shared with the Milestone 0006 `python:` sink (plan D5, as amended by
   [the extensions threat model](/docs/security/threat-model-0007-extensions-2026-11-03.md)).
   Extension data is always untrusted and extension filters are never sinks.
6. **JSON moves to report schema 2** (document-centric, one record per document
   with its problems, clean documents included). The v1 shape remains available
   as the packaged template `json-v1.json`, golden-tested byte-for-byte.
7. **`Finding` gains optional `column`, `value`, `type`** (default `None`).
   Baseline fingerprints keep hashing exactly the current fields, so existing
   baselines stay valid.

## Alternatives considered

- **Jinja2 (or similar).** Rejected: a new runtime dependency in a stdlib-only
  fast profile, and a general expression language over scanned (untrusted) data.
- **`str.format` templates.** Rejected: attribute/index traversal
  (`{x.__class__}`) makes the template an introspection surface.
- **Keep three renderers, add fields to each.** Rejected: it is the status quo
  that produced the three divergent reports, and it leaves no extension point.
- **Extensions as renderer subclasses.** Rejected: extension authors would own
  escaping and could break the output-safety guarantee; data-only extensions
  cannot.

## Consequences

- Positive: one place to change a report; users and CI can ship their own
  template; the JSON stream can grow without touching Python; report and event
  data cannot disagree.
- Negative: the JSON default changes (schema 2) and the text/GitHub bytes change;
  the template loader/validator is real new surface to maintain and test.
- Risks: a template-DSL that keeps growing. Mitigation: the operator and filter
  sets are closed and versioned (`template_version`); anything more goes in an
  extension.

## Related

- [ADR 0002 - Fault-Telemetry Event Emission](/docs/adr/0002-fault-telemetry-event-emission.md)
- [Milestone 0007](/docs/roadmap/0007-telemetry-driven-reporting/plan.md)
- [Report template format](/docs/specs/report-template-format.md)
