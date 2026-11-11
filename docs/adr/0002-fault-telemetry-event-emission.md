# 0002 - Fault-Telemetry Event Emission via a Written Contract and Pluggable Sinks

> **Status:** Accepted
>
> **Date:** 2026-10-26
>
> **Supersedes:** _(none)_
>
> **Superseded by:** _(none)_

> **Revision note:** an earlier draft of this decision shared the event code as a
> path-referenced `faultevents/` module copied into both DocSentinel and the
> sibling FlakeForge repo. That approach is **dropped**. This record replaces it
> with a *written contract* plus independent per-tool implementations and a
> flexibly pluggable sink interface - **no shared code at all, not even a path
> dependency.**

## Context

DocSentinel and its sibling FlakeForge (an AST lint engine, `dependencies = []`,
at a separate repository) are both deterministic/heuristic quality gates over
machine-generated content - DocSentinel over docs, FlakeForge over code. Today
each one answers a single yes/no question per run and throws away everything it
learned. Fault-mode rates that a team actually wants to track over time -
fabricated-reference rate, cross-model disagreement, human-in-the-loop (HITL)
escalation rate - stay anecdotal because nothing durable is recorded when a rule
evaluates something. The demo framing is: "once these gates emit events, a model
upgrade becomes measurable."

The requirement is a single, structured telemetry event emitted whenever a rule
evaluates content, shaped so the two tools produce the *same* event vocabulary and
a downstream collector can aggregate across both. The starting schema is agreed:

```json
{
  "ts": "2026-08-30T00:00:00Z",
  "domain": "docs",
  "class": "dangling_reference",
  "tier": "deterministic",
  "rule": "DS101",
  "outcome": "rejected",
  "model": "<generator-model-id or null>",
  "schema_version": "1.0",
  "details": {}
}
```

### Forces that shaped the decision

- **No shared runtime artifact.** A path-referenced shared module is still a
  shared build/runtime artifact: a change in one repo silently alters the other's
  behaviour, and the "extract into a published package later" promise created an
  implicit shared-ownership contract with no real boundary enforcement. The
  cross-tool coupling should be a *specification*, not an import.
- **Structural typing over inheritance.** PEP 544 `Protocol` lets each tool define
  its own event type and sink interface that are interchangeable *by shape*, with
  zero import coupling. The contract that must stay aligned is small and
  human-readable.
- **Flexible sinks.** The sink must be pluggable - a plain log line, a JSONL
  file/stdout, a database, or a user-supplied custom destination - not just "file
  or stdout."

Constraints fixed before this ADR (not re-litigated here):

- **`model` comes from a flag**, supplied by the invoking CI step
  (`--generated-by-model` / a `generated_by_model` config option). No frontmatter
  sniffing or content-based provenance detection.
- **stdlib-only.** DocSentinel's fast profile is stdlib-only at scan time and
  FlakeForge has zero runtime dependencies; the telemetry code uses only
  `dataclasses`, `json`, `datetime`, `pathlib`, `logging`, `sqlite3`, `importlib`.
  No DB client dependency is added - SQLite is the stdlib reference a user adapts.
- **No network sink in v1.** Built-in sinks are stdout/JSONL file, `logging`, and
  SQLite; anything else is a user-provided custom sink.
- Emission is **opt-in** - not because of install weight (there is none) but
  because emitting events is a behaviour change.

DocSentinel's existing contracts shape where this lands: every consumer (CLI,
library, pytest plugin) funnels through `engine.scan()`, which assembles one
`ScanResult` (`models.py`); `reporting.render` serialises it via
`dataclasses.asdict`; `config.py` validates every typed option before building a
frozen `Config`; and `ScanResult.schema_version` (an `int`, currently `1`)
versions the **JSON report**, a different thing from a telemetry event.
DocSentinel has no module-loading extension of its own today; the sibling
FlakeForge `rule_modules` convention (an importable dotted target resolved with
`importlib`, with an explicit trust boundary and a `--no-config` escape) is the
precedent the custom-sink loader reuses rather than inventing a new mechanism.

## Decision

Introduce fault-telemetry as **a written contract plus a DocSentinel-owned
implementation**, emitted from exactly one call site in `engine.scan()`. Nothing
is shared as code between the two tools.

### 1. The cross-tool contract is a written spec, not a module

The canonical contract lives at
[`docs/specs/fault-event-contract.md`](/docs/specs/fault-event-contract.md) in
**this** repo (DocSentinel is the spec's canonical home). It defines, in prose and
literal tables:

- the event's field names, types, and semantics;
- the `tier` vocabulary (`"deterministic"` | `"heuristic"`) and the `outcome`
  vocabulary (`"pass"` | `"rejected"` | `"escalated"` | `"suppressed"` |
  `"advisory"`);
- the `schema_version` string (`"1.0"`) and its bump policy;
- the `FaultEventSink` **Protocol** signature (PEP 544 structural typing:
  `emit(event: FaultEvent) -> None`, no inheritance required).

FlakeForge references this spec by a relative note in its own ADR; it does **not**
import anything from DocSentinel. The two codebases share a document, never a
symbol.

### 2. DocSentinel implements its OWN event type and Protocol

In `src/docsentinel/telemetry/` (co-located with the adapter and the
fault-class mapping it already owns), DocSentinel defines, independently:

- **`FaultEvent` - a frozen dataclass** (not a `TypedDict`). The whole codebase
  models contracts as frozen dataclasses (`Document`, `Finding`, `ScanResult`,
  `Config`, `Rule`); a frozen dataclass gives a construction-time contract and
  immutability a `TypedDict` cannot, and serialises through the same
  `dataclasses.asdict`/`json` path `reporting.render` already uses. Proposed shape
  (described, not implemented):

  ```
  @dataclass(frozen=True, kw_only=True)
  class FaultEvent:
      ts: str                       # RFC-3339 UTC, 'Z' suffix (datetime.now(UTC).isoformat())
      domain: str                   # free string: "docs", "code", future values - NOT an enum
      fault_class: str              # serialised under JSON key "class" (reserved word)
      tier: str                     # "deterministic" | "heuristic"
      rule: str                     # "DS101", "X013"
      outcome: str                  # see vocabulary in the spec
      model: str | None             # generator model id, or None
      schema_version: str = SCHEMA_VERSION
      details: Mapping[str, str | int | float | bool | None] = field(default_factory=dict)
  ```

  A module-level `to_json_dict(event)` renames `fault_class` -> `"class"` on the
  way out so the wire schema matches the agreed shape. `details` is a shallow,
  JSON-primitive mapping - the open escape hatch for rule-specific fields, bounded
  to primitives so no sink is ever handed an unserialisable or secret-bearing
  object graph.

- **`FaultEventSink` - a `Protocol`** (DocSentinel's own copy of the contract's
  shape; structurally compatible with any object - including a future FlakeForge
  sink - without a shared base class):

  ```
  @runtime_checkable
  class FaultEventSink(Protocol):
      def emit(self, event: FaultEvent) -> None: ...
  ```

  `emit` is the only method the contract requires. A sink MAY also expose
  `close(self) -> None` for resource lifecycle; the engine calls `close()` only
  when the sink provides it (duck-typed), so a minimal custom sink needs just
  `emit`.

FlakeForge will independently define its own equivalent `FaultEvent` and
`FaultEventSink` in its own repo. The two share no runtime import - only the
written spec they are each separately verified against.

### 3. Drift control: a conformance tripwire test

A test in DocSentinel's suite checks DocSentinel's own `FaultEvent` field set, the
`tier`/`outcome` vocabularies, and the `schema_version` string against **literal
values copied from the spec doc**. A deliberate schema bump fails this test until
both the implementation and the spec are updated in the same change. This is a
*local tripwire*, not cross-repo enforcement: it cannot see FlakeForge, but it
guarantees DocSentinel never silently drifts from its own published spec.

### 4. Pluggable sinks - a small reference set plus custom loading

`emit` is the whole interface, so a sink can route events anywhere. DocSentinel
ships stdlib-only reference sinks (full runnable examples live in the spec):

- **`JsonlSink(stream, *, owns_stream=False)`** - the original default: one compact
  JSON line per `emit` to stdout or an appended UTF-8 file; `close()` closes the
  stream only when it owns it.
- **`LoggingSink(logger=None, *, level=logging.INFO)`** - routes each event through
  the stdlib `logging` module at a configurable level, so events flow into a
  project's existing logging config. Serialises with `to_json_dict` + `json.dumps`.
- **`SqliteSink(path)`** - the concrete stdlib database reference (`sqlite3`):
  creates a `fault_events` table if absent and inserts one row per event. It is the
  shape a user adapts to Postgres/other DBs **themselves**; no DB client dependency
  is added. The spec documents the contract a user's own DB sink must satisfy.
- **`NullSink`** - no-op; the default when telemetry is off.

A user who needs something else (HTTP, OTLP, a queue) writes a class with an
`emit(event) -> None` method - no inheritance, no registration decorator. The spec
carries a short "writing your own sink" example (a no-op/custom sink) proving the
Protocol is satisfied structurally.

Sink selection (config/CLI, see layer 6) accepts either a built-in **kind string**
or a **project-local Python target**:

| `telemetry_sink` value | Resolves to |
|---|---|
| `"stdout"` (default when enabled) | `JsonlSink(sys.stdout)` |
| `"file:<path>"` | `JsonlSink(open(<path>, "a"), owns_stream=True)` |
| `"sqlite:<path>"` | `SqliteSink(<path>)` |
| `"logging"` | `LoggingSink()` |
| `"python:<module>:<callable>"` | the callable, imported via `importlib`, called with no args to return a sink |

The `python:` form **reuses the FlakeForge `rule_modules` loading precedent**
(dotted import target resolved with `importlib`, same trust boundary) rather than
inventing a new extension mechanism; it inherits that convention's security note: a
project-local telemetry target is code DocSentinel imports and runs, so it is only
honoured from a trusted/loaded config and never resolved from an untrusted checkout
without opt-in. A `build_sink(config)` factory in `telemetry/` parses the
selector and returns the sink; an unparseable/unknown kind raises `ValueError`
(surfacing at the engine as a swallowed emission error - never a scan failure).

### 5. DocSentinel adapter and emission call site

`telemetry/` also holds the adapter - the only module importing both the event
machinery and DocSentinel types. `events_for_result(result, *, model, suppressed)
-> Iterator[FaultEvent]` reads the **already-assembled** `ScanResult`; it does not
re-run analyzers or duplicate finding iteration. Mapping rules:

- `domain` is the constant `"docs"`.
- `tier` from the rule's profile: `fast`/`standard` -> `"deterministic"`,
  `deep` -> `"heuristic"`.
- `fault_class` from the rule-code -> fault-class table
  ([`docs/specs/fault-classes.md`](/docs/specs/fault-classes.md)).
- `outcome` per finding: `error` -> `"rejected"`; `warning` -> `"advisory"`
  (`"rejected"` under `--strict`, matching the exit-code contract); deep/heuristic
  -> `"advisory"`; baseline-removed -> `"suppressed"`. An evaluated rule with no
  finding emits one `"pass"` event. `"escalated"` is reserved for a future HITL hop
  (part of the shared vocabulary, not produced by DocSentinel v1).

Emission happens at exactly one call site, immediately **after** the `ScanResult`
is assembled and **before** it is returned: `scan()` builds the sink from config
via `build_sink`, feeds it `events_for_result(...)`, and `close()`s it (when the
sink offers `close`) in a `finally`. Emission never changes `scan()`'s return
value, never raises into the caller (a sink error is swallowed and the scan still
succeeds - telemetry is observational, not a gate), and is skipped entirely when
`telemetry_enabled` is false.

### 6. Config and CLI surface

New typed `Config` options, validated in `config.py` exactly like the existing
Milestone 0005 options (added to `_CONFIG_OPTIONS`, defaults on the frozen
`Config`, strict validation):

| Option | Type | Default | Validation |
|--------|------|---------|-----------|
| `telemetry_enabled` | bool | `False` | `_require_bool` (joins `_BOOL_OPTIONS`) |
| `telemetry_sink` | str | `"stdout"` | string; parsed by `build_sink` (`stdout` / `file:<path>` / `sqlite:<path>` / `logging` / `python:<module>:<callable>`). The path/target is an **output artifact** a CI step owns, so it is **not** root-constrained (unlike input paths such as `navigation_indexes`). A malformed value is a validation `ConfigError` at load time; an import/open failure at emission time is swallowed |
| `generated_by_model` | str | `""` | string; `""` serialises to `model: null` |

New CLI flags on the `scan` subparser, applied as `Config` overrides via the
existing `replace(settings, ...)` path in `cli.py` (same mechanism as
`--profile`/`--select`):

- `--telemetry` (store_true) -> `telemetry_enabled=True`
- `--telemetry-sink SELECTOR` -> `telemetry_sink`
- `--generated-by-model ID` -> `generated_by_model`

`docsentinel doctor` reports whether telemetry is enabled and the resolved sink
destination.

### 7. Optional extra

Add `telemetry = []` to `[project.optional-dependencies]` - an empty
behaviour-gate alias exactly like the existing `fast`/`standard`/`deep` aliases
(the code has no third-party deps). It documents the opt-in without pulling
anything in.

## Alternatives Considered

| Alternative | Pros | Cons | Reason rejected |
|-------------|------|------|-----------------|
| Shared path-referenced `faultevents/` module copied into both repos (the previous draft) | One event definition; "verbatim" reuse; near-zero-diff extraction later | Still a shared runtime artifact with implicit cross-repo ownership and no real boundary; a change in one repo silently alters the other; the extraction promise is unenforceable | **Rejected** - replaced by a written spec + independent per-tool implementations |
| `TypedDict` instead of a frozen dataclass for the event | Zero construction cost; already a plain dict for JSON | No immutability, no construction-time contract, diverges from every other model in the codebase | Rejected - frozen dataclass matches house style and serialises through the same `asdict`/`json` path |
| A single fixed sink (file/stdout only) | Simplest surface | Cannot route to logging/DB/custom destinations; every new destination is a core change | Rejected - the requirement is flexible pluggability via a Protocol |
| An abstract base class (`abc.ABC`) for sinks | Explicit `isinstance` checks; shared `close()` default | Forces inheritance and an import coupling; a FlakeForge sink could not satisfy it without importing DocSentinel | Rejected - PEP 544 `Protocol` gives structural compatibility with zero coupling |
| A new bespoke plugin/registry mechanism for custom sinks | Tailored to telemetry | Reinvents what FlakeForge `rule_modules` already does; two extension idioms to learn | Rejected - reuse the `rule_modules` `importlib` precedent (`python:<module>:<callable>`) |
| Reuse `ScanResult.schema_version` (int) for the event | One version number | Conflates the report format with the cross-tool event contract; the two evolve independently and live in different repos | Rejected - event `schema_version` is a separate string contract |
| Written spec + DocSentinel-owned `FaultEvent`/`FaultEventSink` Protocol, pluggable sinks, one engine call site, conformance tripwire (chosen) | Zero import coupling; stdlib-only; flexible routing; one call site; drift-tripwired against the spec | Each tool maintains its own copy of the shape; cross-repo alignment is human discipline, not a compiler check | **Accepted** |

## Consequences

### Positive

- **Zero code coupling.** DocSentinel and FlakeForge share only a Markdown spec;
  neither imports the other, so there is no shared build artifact, no vendoring,
  and no "whose repo owns this module" ambiguity.
- **Flexible routing.** A user sends events to stdout/JSONL, the stdlib `logging`
  stack, a SQLite DB, or any custom destination satisfying `emit`, chosen from
  config or CLI with no core change.
- **Structural typing.** A sink needs one method and no base class; a future
  HTTP/OTLP sink is a new class, not a change to `build_sink` callers.
- **One call site** in `engine.scan()` means CLI, library API, and pytest plugin
  all emit identically, with no second iteration of findings.
- **Default-off and swallow-on-error:** enabling telemetry cannot change a scan's
  verdict, exit code, or `ScanResult`.

### Negative

- **The contract is a human discipline, not a shared type.** Because each tool owns
  its own `FaultEvent`, nothing *mechanically* stops the two from drifting across
  repos. Mitigations: the written spec is the single source of truth, and
  DocSentinel's conformance tripwire test fails on any local drift from it. A schema
  change is still a coordinated `schema_version` bump in both repos plus any
  collector - this ADR, the spec, and the FlakeForge mirror ADR are the migration
  anchor. **Affected components:** the spec
  (`docs/specs/fault-event-contract.md`), `telemetry/` (event, Protocol, sinks,
  adapter, factory), `engine.scan()` (call site), `config.py`/`cli.py` (surface),
  and FlakeForge's independent implementation. **Migration path:** bump
  `SCHEMA_VERSION` and the spec's literal tables in one change (the tripwire forces
  this), then mirror the spec change in FlakeForge and the collector.
- **Custom-sink loading runs user code.** The `python:<module>:<callable>` target is
  imported and executed, carrying the same trust boundary as FlakeForge
  `rule_modules`: only honour it from a trusted/loaded config, never from an
  untrusted checkout without explicit opt-in. A load/open failure is swallowed at
  emission (telemetry never fails a scan), so a broken target degrades to no
  telemetry rather than a crash.
- The fault-class mapping is hand-maintained; a new rule shipped without a table
  entry falls back to `"unmapped"` and must be flagged in review, or events
  mis-aggregate silently.
- `details` is a deliberate open escape hatch. To honour the no-secrets/no-PII rule
  it is **bounded to JSON primitives and must never carry raw document text, file
  contents, or matched snippets** - only codes, counts, and already-public path
  strings the `ScanResult` would print anyway. The adapter, not the event type, is
  responsible for this; it is a review checklist item. The `logging` and `sqlite`
  sinks persist events, so this bound is load-bearing for those sinks.

## Validation / Rollout

- Rollout is behind `telemetry_enabled` (default false), so landing the code is
  inert until a CI step opts in - zero behaviour change for existing users.
- Acceptance: with telemetry enabled, a scan that produces findings emits one event
  per finding plus one `"pass"` event per evaluated clean rule; each event
  round-trips through `json.loads` (for the JSONL/logging sinks) or inserts one row
  (SQLite); `class`/`tier`/`outcome` match the mapping table; `model` is the flag
  value or `null`; a disabled scan emits nothing; a sink error does not change the
  exit code; the conformance tripwire passes against the spec's literals.
- Implementation: `python-expert` (event type + Protocol, reference sinks + custom
  loader, adapter, engine wiring, config/CLI surface - see
  [Milestone 0006](/docs/roadmap/0006-fault-telemetry/plan.md)). Tests:
  `testing-expert` (unit: event construction + `to_json_dict` key rename, each sink
  including SQLite round-trip and logging capture, the custom-callable loader, the
  outcome mapping, the conformance tripwire; mock: sink error swallowed;
  integration: a CLI scan with `--telemetry --telemetry-sink ... --generated-by-model`).
- The FlakeForge mirror ADR implements its own event type and sink Protocol
  independently against the same spec; only its adapter (`domain="code"`, `X`-rule
  mapping, possible `"escalated"` HITL emission) and its config surface names
  differ. Nothing is imported across repos.

## Links

- **Cross-tool contract spec:** [docs/specs/fault-event-contract.md](/docs/specs/fault-event-contract.md)
- **Roadmap milestone:** [docs/roadmap/0006-fault-telemetry/plan.md](/docs/roadmap/0006-fault-telemetry/plan.md)
- **Fault-class mapping:** [docs/specs/fault-classes.md](/docs/specs/fault-classes.md)
- **Custom-loader precedent:** FlakeForge `rule_modules` convention (sibling repo `docs/custom-rules.md`).
- **Supporting specs:** [docs/architecture/README.md](/docs/architecture/README.md), [CLAUDE.md](/CLAUDE.md)
