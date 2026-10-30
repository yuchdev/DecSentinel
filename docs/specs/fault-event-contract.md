# Fault-Event Contract (cross-tool specification)

**Status:** v1 (`schema_version = "1.0"`) · **Canonical home:** this file, in the
DocSentinel repository · **Decision record:**
[ADR 0002](/docs/adr/0002-fault-telemetry-event-emission.md)

This document is the **single source of truth** for the fault-telemetry event
shared by DocSentinel and its sibling FlakeForge. It is a *written contract*, not
an importable module: each tool implements its own `FaultEvent` dataclass and
`FaultEventSink` Protocol and is verified **separately** against the literals
here. The two tools share no runtime code - **no shared package, not even a path
dependency.** FlakeForge references this file by a relative note in its own ADR.

A collector reading a mixed JSONL/row stream from both tools can aggregate on the
fields and vocabularies below because both tools emit the same wire shape at the
same `schema_version`.

## 1. Event wire shape

One structured event is emitted whenever a rule evaluates a unit of content. The
wire form (JSON object / one DB row) is:

```json
{
  "ts": "2026-08-30T00:00:00Z",
  "domain": "docs",
  "class": "dangling_reference",
  "tier": "deterministic",
  "rule": "DS101",
  "outcome": "rejected",
  "model": "anthropic/claude-x",
  "schema_version": "1.0",
  "details": {"severity": "error", "line": 42}
}
```

### 1.1 Fields

| Wire key | Python attr | Type | Semantics |
|---|---|---|---|
| `ts` | `ts` | `str` | RFC-3339 UTC timestamp with a trailing `Z` (e.g. `datetime.now(timezone.utc)` rendered with `Z`). Event creation time, not scan start. |
| `domain` | `domain` | `str` | Free string naming the producing tool's content domain: `"docs"` (DocSentinel), `"code"` (FlakeForge), future values. **Not** a closed enum. |
| `class` | `fault_class` | `str` | The fault class the rule belongs to (e.g. `dangling_reference`). Free string shared across tools; stable once published because collectors aggregate on it. The Python attribute is `fault_class` because `class` is a keyword; serialization renames it. |
| `tier` | `tier` | `str` | `"deterministic"` or `"heuristic"`. See §2. |
| `rule` | `rule` | `str` | The producing rule code (`"DS101"`, `"X013"`). |
| `outcome` | `outcome` | `str` | One of the §2 outcome vocabulary. |
| `model` | `model` | `str \| None` | Generator model id supplied by the invoking CI step, or `null` when unknown. Never sniffed from content. |
| `schema_version` | `schema_version` | `str` | Contract version string (§3). Distinct from any tool's internal report version. |
| `details` | `details` | `object` | Shallow map of JSON primitives only (`str`/`int`/`float`/`bool`/`null`). Optional per-event context. **Never** raw document text, file contents, or matched snippets (§4). |

### 1.2 Keyword-collision rename

`class` is a Python keyword, so the in-memory attribute is `fault_class`. Each
tool's serializer (`to_json_dict`) is the **only** place the rename to the wire
key `"class"` happens; every other field keeps its name verbatim.

## 2. Vocabularies

Both are open, shared string vocabularies - documented here, **not** enforced as
closed enums in code, so a tool can add a value with a minor `schema_version` bump
without breaking a reader.

### 2.1 `tier`

| Value | Meaning |
|---|---|
| `deterministic` | A strictly deterministic rule (DocSentinel `fast`/`standard`; FlakeForge AST rules). |
| `heuristic` | A heuristic/semantic rule (DocSentinel `deep`; advisory only). |

A producer derives `tier` from the rule's own profile/kind; it is not stored in
the fault-class table.

### 2.2 `outcome`

| Value | Meaning | Produced by DocSentinel v1? |
|---|---|---|
| `pass` | The rule was evaluated and produced no finding. | Yes - one per evaluated clean rule. |
| `rejected` | A blocking finding (`error`, or `warning` under `--strict`). | Yes. |
| `advisory` | A non-blocking finding (`warning`, or any `heuristic`/deep finding). | Yes. |
| `suppressed` | A finding removed by the baseline filter. | Yes. |
| `escalated` | Reserved for a future human-in-the-loop hop. | No - reserved in the vocabulary; FlakeForge/collectors may use it. |

## 3. `schema_version` and bump policy

- `schema_version` is a **string** (`"1.0"`), independent of any tool's internal
  report-format version (e.g. DocSentinel's `ScanResult.schema_version`, an int).
  It versions the *cross-tool event contract* so a collector reading a mixed
  stream can route and migrate by version.
- **Minor bump** (`"1.0"` -> `"1.1"`): additive, backward-compatible change - a new
  `details` key, a new `outcome`/`tier`/`domain` value, a new optional field. A
  reader of `"1.0"` still parses `"1.1"`.
- **Major bump** (`"1.0"` -> `"2.0"`): breaking change - renaming or removing a
  top-level field, or changing a field's type/meaning.
- Any bump is a **coordinated change in all producers plus the collector**. In
  DocSentinel, the bump touches both `SCHEMA_VERSION` in `telemetry/events.py` and the
  literal tables in this spec in the *same* commit; the conformance tripwire test
  (§6) fails until they agree. FlakeForge mirrors the spec change independently.

## 4. No secrets / no PII

`details` is an open escape hatch bounded to JSON primitives. It must carry only
codes, counts, and already-public values the tool's normal report would print
anyway (e.g. `severity`, `line`, `path`). It must **never** carry raw document
text, file contents, matched snippets, or any secret/PII-bearing value. The
`logging` and `sqlite` sinks *persist* events, so this bound is load-bearing. Each
producer's adapter - not the event type or the sink - is responsible for honouring
it, and it is an explicit review-checklist item.

## 5. The `FaultEventSink` Protocol

The sink is where a producer sends events. The contract is PEP 544 structural
typing - **no inheritance required**. The only required method is `emit`:

```python
from typing import Protocol, runtime_checkable


@runtime_checkable
class FaultEventSink(Protocol):
    """Anything that can receive fault-telemetry events.

    Structural (PEP 544): an object satisfies this by having a compatible
    ``emit`` method; it need not inherit from this Protocol. A sink MAY also
    expose ``close(self) -> None`` for resource lifecycle, which the producer
    calls (duck-typed) only when present.
    """

    def emit(self, event: FaultEvent) -> None:
        """Deliver one event. Must not raise into the producer's caller."""
        ...
```

A producer treats `emit` as fire-and-forget: a sink that raises must never change
the scan's verdict or exit code (the engine swallows sink errors). Sinks holding
an OS resource (a file handle, a DB connection) should additionally implement
`close(self) -> None`; the producer calls it in a `finally` after the last event
when the attribute is present.

## 6. Reference implementations

All reference sinks below are **stdlib-only** and runnable as written (given the
tool's own `FaultEvent`/`to_json_dict`). They are the examples a user copies or
adapts. DocSentinel ships these in `src/docsentinel/telemetry/`.

Assumed helpers from the owning module (each tool defines its own copy):

```python
SCHEMA_VERSION = "1.0"


def to_json_dict(event: FaultEvent) -> dict[str, object]:
    """Serialise *event*, renaming ``fault_class`` to the wire key ``class``."""
    data = dataclasses.asdict(event)
    data["class"] = data.pop("fault_class")
    return data
```

### 6.1 `JsonlSink` - JSON Lines to a stream or file (the default)

```python
import json
import sys
from typing import TextIO


class JsonlSink:
    """Write one compact JSON line per event to a text stream.

    :param stream: An open text stream (e.g. ``sys.stdout`` or a file).
    :param owns_stream: When ``True``, :meth:`close` closes *stream*; when
        ``False`` (the default, used for ``sys.stdout``) it leaves it open.
    """

    def __init__(self, stream: TextIO, *, owns_stream: bool = False) -> None:
        self._stream = stream
        self._owns_stream = owns_stream

    def emit(self, event: FaultEvent) -> None:
        line = json.dumps(to_json_dict(event), separators=(",", ":"), sort_keys=True)
        self._stream.write(line + "\n")
        self._stream.flush()

    def close(self) -> None:
        if self._owns_stream:
            self._stream.close()


def open_jsonl_file(path: str) -> JsonlSink:
    """Open *path* in append text mode (UTF-8, ``\\n`` newlines) as a sink."""
    stream = open(path, "a", encoding="utf-8", newline="\n")
    return JsonlSink(stream, owns_stream=True)
```

Append (not truncate) mode lets repeated scans accumulate one JSONL stream. The
default stdout sink does **not** own the stream, so `close()` never closes stdout.

### 6.2 `LoggingSink` - route through the stdlib `logging` module

```python
import json
import logging


class LoggingSink:
    """Emit each event as a log record through the stdlib ``logging`` module.

    Events flow into the project's existing logging configuration (handlers,
    formatters, levels), so a team already shipping logs to a collector gets
    telemetry for free.

    :param logger: The logger to use; defaults to ``logging.getLogger("docsentinel.telemetry")``.
    :param level: The level each event is logged at (default ``logging.INFO``).
    """

    def __init__(self, logger: logging.Logger | None = None, *, level: int = logging.INFO) -> None:
        self._logger = logger or logging.getLogger("docsentinel.telemetry")
        self._level = level

    def emit(self, event: FaultEvent) -> None:
        self._logger.log(self._level, json.dumps(to_json_dict(event), sort_keys=True))

    # No ``close``: the logging module owns handler lifecycle, not this sink.
```

### 6.3 `SqliteSink` - the concrete stdlib database reference

```python
import json
import sqlite3


class SqliteSink:
    """Persist each event as one row in a SQLite ``fault_events`` table.

    This is the stdlib reference for a database sink. It adds **no** third-party
    DB client dependency; a user targeting Postgres/MySQL/etc. writes an
    equivalent class with the same ``emit`` shape, swapping the driver and the
    connect/insert calls (see §6.5).

    :param path: Filesystem path to the SQLite database (created if absent).
    """

    _DDL = (
        "CREATE TABLE IF NOT EXISTS fault_events ("
        "  ts TEXT NOT NULL,"
        "  domain TEXT NOT NULL,"
        "  class TEXT NOT NULL,"
        "  tier TEXT NOT NULL,"
        "  rule TEXT NOT NULL,"
        "  outcome TEXT NOT NULL,"
        "  model TEXT,"
        "  schema_version TEXT NOT NULL,"
        "  details TEXT NOT NULL"  # JSON-encoded primitives map
        ")"
    )
    _INSERT = (
        "INSERT INTO fault_events"
        " (ts, domain, class, tier, rule, outcome, model, schema_version, details)"
        " VALUES (:ts, :domain, :class, :tier, :rule, :outcome, :model, :schema_version, :details)"
    )

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute(self._DDL)
        self._conn.commit()

    def emit(self, event: FaultEvent) -> None:
        row = to_json_dict(event)
        row["details"] = json.dumps(row["details"], sort_keys=True)
        self._conn.execute(self._INSERT, row)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
```

The `details` map is stored as a JSON string in a `TEXT` column so the row stays
schema-stable as `details` keys evolve. Parameterised inserts (`:name`
placeholders) avoid any SQL-injection surface from event values.

### 6.4 Writing your own sink

Any object with a compatible `emit` satisfies the Protocol - no base class, no
registration. A no-op custom sink and a trivial in-memory one:

```python
class NullSink:
    """Discard every event. The default when telemetry is disabled."""

    def emit(self, event: FaultEvent) -> None:
        pass


class ListSink:
    """Collect events in memory - handy in tests or a custom aggregator."""

    def __init__(self) -> None:
        self.events: list[FaultEvent] = []

    def emit(self, event: FaultEvent) -> None:
        self.events.append(event)


# Both satisfy the Protocol structurally:
assert isinstance(NullSink(), FaultEventSink)   # runtime_checkable confirms `emit`
assert isinstance(ListSink(), FaultEventSink)
```

A project-local sink is selected by the `python:<module>:<callable>` selector
(§7): the callable is imported and invoked with no arguments to return a sink
instance.

### 6.5 Contract for a custom DB (or any resource) sink

A user adapting `SqliteSink` to another database (or writing any resource-holding
sink) must honour:

- `emit(self, event: FaultEvent) -> None` - the only required method; accepts one
  event, returns nothing, and should not raise into the caller.
- Serialise through the tool's `to_json_dict(event)` so the persisted/forwarded
  shape matches §1 (including the `fault_class` -> `class` rename).
- Store `details` as JSON primitives only; never expand it into secret/PII-bearing
  columns (§4).
- Implement `close(self) -> None` to release the connection/handle; the producer
  calls it once after the last event.
- Use parameterised queries / safe encoding for event values - treat `model`,
  `rule`, and `details` as untrusted strings.

## 7. Sink selection (DocSentinel surface)

DocSentinel's `build_sink(config)` factory maps the `telemetry_sink` config/CLI
value to a sink. FlakeForge may use different option names; the selector grammar
is a DocSentinel convenience, not part of the cross-tool wire contract.

| `telemetry_sink` value | Resolves to |
|---|---|
| `"stdout"` (default when enabled) | `JsonlSink(sys.stdout)` (does not own the stream) |
| `"file:<path>"` | `open_jsonl_file(<path>)` (append, owns the stream) |
| `"sqlite:<path>"` | `SqliteSink(<path>)` |
| `"logging"` | `LoggingSink()` |
| `"python:<module>:<callable>"` | `importlib.import_module(<module>)`, then call `<callable>()` to get a sink |

The `python:` form reuses the FlakeForge `rule_modules` loading precedent
(`importlib`-resolved dotted target) and its **trust boundary**: a project-local
target is code DocSentinel imports and runs, so it is only honoured from a
trusted/loaded config, never from an untrusted checkout without explicit opt-in. A
malformed selector is a `ConfigError` at config-load time; an import/connect/open
failure at emission time is swallowed (telemetry is observational and never fails a
scan).

## 8. Per-tool differences (lockstep summary)

| Concern | DocSentinel | FlakeForge |
|---|---|---|
| `domain` | `"docs"` | `"code"` |
| Rule codes | `DS1xx`/`DS2xx`/`DS3xx` | `X0xx` |
| `tier` source | profile (`fast`/`standard` -> deterministic, `deep` -> heuristic) | rule kind |
| `"escalated"` | reserved, not emitted v1 | may emit for its HITL hop |
| Event type / Protocol / sinks | its own copy in `telemetry/` | its own copy in its repo |
| Shared | **this spec only** | **this spec only** |

Any change to §1-§4 is a coordinated `schema_version` bump across both tools and
the collector; this spec and the two ADRs are the migration anchor.
