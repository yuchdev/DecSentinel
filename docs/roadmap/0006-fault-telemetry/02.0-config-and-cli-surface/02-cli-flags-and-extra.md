# Task 02 — Config options, CLI flags, telemetry extra, and doctor surface

**Parent story:** [Story 02.0](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/README.md)  
**Proposed sources:** `src/docsentinel/config.py`, `src/docsentinel/cli.py`, `pyproject.toml`

## Config options (`config.py`)

| Option | Type | Default | Validation |
|--------|------|---------|-----------|
| `telemetry_enabled` | bool | `False` | append to `_BOOL_OPTIONS` (reuses `_require_bool`) |
| `telemetry_sink` | str | `"stdout"` | a string; parsed by `build_sink` (`stdout` / `file:<path>` / `sqlite:<path>` / `logging` / `python:<module>:<callable>`). **Not** root-constrained — the path/target is an output artifact a CI step owns, unlike input-path options such as `navigation_indexes`/`deprecated_references_file`. A malformed selector is a `ConfigError` at load time |
| `generated_by_model` | str | `""` | a string; empty serialises to `model: null` in the event |

> **Pending reconciliation (Milestone 0007 requirement).** The `telemetry_sink` row
> above conflicts with the requirement recorded in
> [Task 01](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/01-typed-config-options.md):
> `python:` is argv-only (a config `python:` selector is a `ConfigError`), and
> config-sourced `file:`/`sqlite:` paths must be root-contained.

- Add the three names to `_CONFIG_OPTIONS` and the three fields (with defaults and
  `:ivar:` docstrings) to the frozen `Config`.
- `telemetry_enabled` joins `_BOOL_OPTIONS`, validated by the existing loop.
- `telemetry_sink` and `generated_by_model` are validated as strings in
  `_load_extra_options` (reject non-string with `ConfigError`; empty `telemetry_sink`
  normalises to `"stdout"`, empty `generated_by_model` is the valid "unset" value).
  Validate the `telemetry_sink` selector grammar at load so a typo fails fast.
  Explicitly note why `telemetry_sink` is **not** passed through `_is_within_root`.

## CLI flags (on the `scan` subparser, `cli.py`)

- `--telemetry` — `action="store_true"`, `dest="telemetry_enabled"`.
- `--telemetry-sink SELECTOR` — `dest="telemetry_sink"`, default `None`.
- `--generated-by-model ID` — `dest="generated_by_model"`, default `None`.

Apply them through the **existing** override mechanism in `main()` (add to the
`changes` dict and `replace(settings, **changes)`, exactly as `--profile` /
`--select` / `--baseline` do). A `None` from argparse means "not passed" and must
leave the config value untouched; `--telemetry` sets `telemetry_enabled=True` only
when present. Do not add a second `scan()` call site and do not change the existing
`(ConfigError, ValueError, OSError) -> exit 2` handling.

## Optional extra (`pyproject.toml`)

Add `telemetry = []` to `[project.optional-dependencies]`, next to the existing
`fast`/`standard`/`deep` aliases, with a comment noting it is a behaviour-gate
alias (opt-in because emitting events is a behaviour change) carrying no
third-party dependency (SQLite is stdlib).

## Doctor surface (`doctor` subcommand)

Add one line reporting telemetry readiness, e.g.
`telemetry: disabled (enable with --telemetry or telemetry_enabled)` or, when
enabled, `telemetry: enabled -> <resolved sink>` (`stdout`, the file path, the
sqlite path, `logging`, or the `python:` target). Keep it one line, consistent with
existing `doctor` output.

## Tests (for `testing-expert`)

- Unit: defaults are off/`"stdout"`/empty; a standalone config and a
  `[tool.doc_sentinel]` table both load the three options; an injected `Config` is
  used verbatim.
- Unit: a non-bool `telemetry_enabled`, a non-string `telemetry_sink`/malformed
  selector, and a non-string `generated_by_model` each raise `ConfigError`.
- Unit: a `telemetry_sink = "file:../out.jsonl"` that escapes the root is
  **accepted** (contrast with a root-constrained option that would reject it).
- Integration: `docsentinel scan --telemetry` flips `telemetry_enabled`;
  `--telemetry-sink` and `--generated-by-model` reach the effective config; omitting
  each flag leaves the config/file value intact.
- Integration: `docsentinel doctor` prints the telemetry line in both states.
- E2E: a scan without any telemetry flag is byte-for-byte unchanged in stdout and
  exit code versus before this milestone.
