# Story 02.0 — Pluggable sinks and the config/CLI surface

**Category:** extension surface + configuration · **Proposed sources:** `src/docsentinel/telemetry/`, `src/docsentinel/config.py`, `src/docsentinel/cli.py`, `pyproject.toml`  
**Depends on:** [Story 01.0](/docs/roadmap/0006-fault-telemetry/01.0-shared-fault-event-module/README.md).

> **Slug note:** this directory keeps the `config-and-cli-surface` slug; it now
> also carries the pluggable-sink reference implementations and the `build_sink`
> factory, because sink selection is what the config/CLI surface drives.

## Goal

Deliver the flexibly pluggable sinks and the typed config/CLI surface that selects
them, so a CI step can opt into telemetry and route events to stdout/JSONL, the
stdlib `logging` stack, a SQLite DB, or a project-local custom sink. This story
leaves telemetry **inert** — no emission is wired until Story 03.0 — so it can
merge safely on its own.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/01-typed-config-options.md) | Reference sinks (`JsonlSink`, `LoggingSink`, `SqliteSink`, `NullSink`) and the `build_sink` factory with `python:<module>:<callable>` custom-sink loading |
| [02](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/02-cli-flags-and-extra.md) | `telemetry_enabled` / `telemetry_sink` / `generated_by_model` config options, the `--telemetry` / `--telemetry-sink` / `--generated-by-model` flags, the `telemetry` extra, and the `doctor` surface |

## Definition of done

- The four reference sinks each satisfy the `FaultEventSink` Protocol
  structurally; all are stdlib-only (SQLite via `sqlite3`, no DB client dep).
- `build_sink(config)` resolves `stdout` / `file:<path>` / `sqlite:<path>` /
  `logging` / `python:<module>:<callable>`; the `python:` form reuses the
  FlakeForge `rule_modules` `importlib` precedent and its trust boundary. A
  malformed selector raises `ConfigError`; an import/open failure is left to be
  swallowed by the engine (Story 03.0).
- Three options added to `_CONFIG_OPTIONS`, with defaults on the frozen `Config`
  and strict validation; loaded from standalone config, `[tool.doc_sentinel]`, and
  an injected `Config`. Defaults keep telemetry off (`telemetry_enabled = False`,
  `telemetry_sink = "stdout"`, `generated_by_model = ""`).
- CLI flags apply as `Config` overrides via the existing `replace(settings, ...)`
  path; `telemetry = []` added to optional-dependencies; `doctor` reports state and
  the resolved sink destination.
- No behaviour change to any scan: options and sinks exist but nothing emits yet.
