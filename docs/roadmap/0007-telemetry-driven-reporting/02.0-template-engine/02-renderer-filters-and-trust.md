# Task 02 — Renderer and filter table

**Parent story:** [Story 02.0](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/README.md)  
**Proposed sources:** `src/docsentinel/telemetry/engine.py`, `src/docsentinel/telemetry/filters.py`

## Required contract

`render_template(template, context, *, extensions=()) -> str`.

- **text:** walk `lines`; `line` emits one line; `loop` with `block` renders `body`
  per item, `one-line` joins items with `separator` (honouring `prefix`/`suffix`
  only when non-empty), `append` extends the previously emitted line and is a no-op
  for an empty list; `group` is a conditional run. Join with `output.join`; honour
  `trailing_newline`.
- **json:** evaluate `body` with `$var` (typed, `$default`), `$for`, `$if`, `$str`,
  `$omit_if`; serialize with `json.dumps(indent, ensure_ascii, sort_keys)`.
  `ensure_ascii` is forced `true` for the standard templates (a test pins it).
- Loop variables are lexically scoped by `as`; shadowing a core name is a
  load-time error (Task 01).
- `filters.py`: the closed table from spec §7. Move `_build_control_table`,
  `_neutralize_controls`, `_escape_property`, `_escape_data` here verbatim, exposing
  `neutralize`, `gha_property`, `gha_data`. `reporting.neutralize_text` is re-pointed
  to `filters.neutralize` and stays public.
- Filters are pure and total: a filter given the wrong type raises `TemplateError`,
  never a bare `TypeError`.
- Rendering is side-effect free and never reads files, env vars, or the clock.

## Tests (for `testing-expert`)

- Unit per placement mode, including an empty list under `append` and `one-line`.
- Unit: `neutralize` of ESC / CR-LF / U+202E / U+200B / lone surrogate equals the
  pre-move `_neutralize_controls` output (parametrize from the existing
  `reporting` tests, which must keep passing).
- Property: for any context string, a text template using `|neutralize` emits no
  C0/C1/bidi/zero-width code point (hypothesis-free: sweep the code-point ranges).
- Unit: JSON `$var` of a list returns a list; `None` → `null`; `$default` applies.
- Determinism: rendering twice yields identical bytes.
