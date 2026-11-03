# Task 01 — Reference sinks and the `build_sink` factory

**Parent story:** [Story 02.0](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/README.md)  
**Proposed source:** `src/docsentinel/telemetry/`

Full runnable reference implementations are in
[the contract spec](/docs/specs/fault-event-contract.md) §6–§7; this task lands
them in DocSentinel and wires the selector factory.

## Reference sinks (all stdlib-only, each satisfies `FaultEventSink`)

- **`JsonlSink(stream, *, owns_stream=False)`** — one compact JSON line per `emit`
  (`json.dumps(to_json_dict(event), separators=(",", ":"))` + `"\n"`, then flush);
  `close()` closes the stream only when `owns_stream`. A helper opens a file in
  **append** text mode (UTF-8, newline `"\n"`) with `owns_stream=True`.
- **`LoggingSink(logger=None, *, level=logging.INFO)`** — logs each event as a JSON
  string through the stdlib `logging` module (default logger
  `"docsentinel.telemetry"`). No `close` (logging owns handler lifecycle).
- **`SqliteSink(path)`** — the stdlib `sqlite3` database reference: `CREATE TABLE
  IF NOT EXISTS fault_events (...)`, one parameterised `INSERT` per `emit`,
  `details` stored as a JSON string in a `TEXT` column; `close()` closes the
  connection. **No DB client dependency** — it is the shape a user adapts to
  Postgres/other DBs themselves (spec §6.5 documents that contract).

## `build_sink` factory

`build_sink(config) -> FaultEventSink` parses `config.telemetry_sink`:

| Selector | Result |
|---|---|
| `"stdout"` | `JsonlSink(sys.stdout, owns_stream=False)` |
| `"file:<path>"` | append-mode `JsonlSink(..., owns_stream=True)` |
| `"sqlite:<path>"` | `SqliteSink(<path>)` |
| `"logging"` | `LoggingSink()` |
| `"python:<module>:<callable>"` | `importlib.import_module(<module>)`, then call `<callable>()` with no args; assert the result satisfies `FaultEventSink` |

- The `python:` form **reuses the FlakeForge `rule_modules` loading precedent**
  (`importlib`-resolved dotted target) and inherits its **trust boundary**: a
  project-local target is code DocSentinel imports and runs, so honour it only from
  a trusted/loaded config, never from an untrusted checkout without opt-in. Mirror
  FlakeForge's error reporting shape (name the module/callable plus the underlying
  exception).
- **Requirement from Milestone 0007 (cross-reference, not a redesign).** The
  [0007 extensions threat model](/docs/security/threat-model-0007-extensions-2026-11-03.md)
  (T1, M1-M4; plan D5 / decision D-A) binds this task:
  - The `python:` gate is the one inside the **shared `importlib` helper**
    ([0007 Story 04.0 Task 01](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/01-extension-api-and-loader.md)).
    `build_sink` must call that helper with the gate decision and must not call
    `importlib` itself.
  - A `python:` sink is **argv-only** (`--telemetry-sink python:...` with
    `--allow-python-extensions` or `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1` exactly).
    `telemetry_sink = "python:..."` in config is a `ConfigError`. A refused spec is
    exit 2, never swallowed by the emission path.
  - `file:<path>` / `sqlite:<path>` paths read from repository config must be
    **root-contained** (threat model "Out of scope, flagged for 0006", CWE-73). This
    supersedes the "Not root-constrained" wording and the `file:../out.jsonl`
    acceptance test in [Task 02](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/02-cli-flags-and-extra.md),
    which the 0006 owner must reconcile before coding.
- When telemetry is disabled the engine never calls `build_sink` (it uses
  `NullSink`); `build_sink` itself is only invoked for an enabled scan.
- A malformed/unknown selector raises `ValueError`/`ConfigError`; an
  import/connect/open failure raises for the engine to swallow (Story 03.0).

## Constraints

- **No network sink.** The Protocol boundary exists so a future HTTP/OTLP sink is a
  new class, not a change to `build_sink` callers.
- `JsonlSink` file mode is append (not truncate) so repeated scans accumulate one
  JSONL stream.
- stdlib-only; SQLite via `sqlite3`; no third-party DB driver.

## Tests (for `testing-expert`)

- Unit: `JsonlSink` over an `io.StringIO` writes exactly one JSON object line per
  event; `close()` respects `owns_stream` (stdout never closed, file closed).
- Unit: `LoggingSink` emits one log record per event at the configured level
  (assert via `caplog`); the record payload is valid JSON with the agreed keys.
- Unit: `SqliteSink` inserts one row per event into `fault_events`; a round-trip
  `SELECT` returns the agreed columns and the `details` JSON; a second scan appends.
- Unit: `build_sink` resolves each selector; `python:<module>:<callable>` imports a
  test module and returns its sink; an unknown kind raises; a bad `python:` target
  raises a clear error naming module/callable.
