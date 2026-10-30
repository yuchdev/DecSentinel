# Task 01 — Template schema and loader

**Parent story:** [Story 02.0](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/README.md)  
**Proposed source:** `src/docsentinel/telemetry/loader.py`

## Required contract

`load_template(source) -> Template`, where `source` is a packaged name, a path, or
an already-parsed dict (for tests). Resolution order for a **name**: packaged
`telemetry/templates/<name>.json`, then `report_templates_dir` from config.

Validation (all failures raise `TemplateError` with a bounded, neutralized message
naming the JSON path of the offending node, e.g. `lines[7].loop.over`):

1. File gate for config/CLI-named files: regular file, size ≤ 256 KiB, UTF-8, valid
   JSON, no duplicate object keys (use `object_pairs_hook`). Config-named paths are
   root-contained via the shared resolver/containment gate used by DS115 -- do not
   add a second resolver.
2. Envelope: `template_version == 1`, `name`, `type ∈ {text, json}`, no unknown keys
   at any level.
3. Variable references parsed from every `text`/`$str`/`$var`/`over`/`when`; each
   resolved against the context **schema** (spec §6, exported by `model.py` as
   `CONTEXT_SCHEMA`, including trust tags and loop-scoped names introduced by `as`).
   Unknown variable or filter → error.
4. `variables_used` present on every text `line`/inline-`loop`, equal to the
   referenced set.
5. Condition grammar closed to `eq/ne/in/gt/lt/truthy/falsy/all/any/not`.
6. **Trust rule (spec §8):** in a `text` template an untrusted variable must have a
   sink filter in its chain; otherwise error.
7. `requires_extensions` checked later by the renderer entry (Story 04.0), but the
   field is parsed and validated here.

Return an immutable parsed form (frozen dataclasses) so rendering cannot mutate a
cached template; cache by `(name, mtime, size)` for packaged templates.

## Tests (for `testing-expert`)

- One unit test per validation rule, each with a tiny inline template.
- Duplicate-key and oversize-file fixtures; unknown-key typo (`"varibles_used"`).
- Trust rule: `{p.message}` rejected, `{p.message|neutralize}` accepted, `{p.line}`
  accepted un-filtered; a `json` template needs no filter.
- Mock: `report_templates_dir` outside the root is refused without opening it.
