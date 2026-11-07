# Task 02 — `FaultEventSink` Protocol and the null sink

**Parent story:** [Story 01.0](/docs/roadmap/0006-fault-telemetry/01.0-shared-fault-event-module/README.md)  
**Proposed source:** `src/docsentinel/telemetry/`

## Required contract

Define the sink boundary as a PEP 544 `Protocol` (structural typing — **no
inheritance required**), mirroring [the contract spec](/docs/specs/fault-event-contract.md) §5:

```
@runtime_checkable
class FaultEventSink(Protocol):
    def emit(self, event: FaultEvent) -> None: ...
```

- `emit` is the only method the contract requires. A sink MAY also expose
  `close(self) -> None`; the engine (Story 03.0) calls `close()` only when the sink
  provides it (duck-typed), so a minimal custom sink needs just `emit`.
- Provide `NullSink` — `emit` is a no-op; this is the default when telemetry is
  off. (The routing sinks `JsonlSink`/`LoggingSink`/`SqliteSink` and the
  `build_sink` factory land in [Story 02.0](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/README.md).)

## Constraints

- `@runtime_checkable` so tests and `build_sink` can assert a resolved object is a
  sink without forcing inheritance.
- The Protocol must stay minimal (`emit` required, `close` optional) so a future
  HTTP/OTLP sink or a FlakeForge sink is compatible by shape alone.
- stdlib-only; no cross-repo import.

## Tests (for `testing-expert`)

- Unit: `NullSink().emit(event)` writes/returns nothing and does not raise.
- Unit: `isinstance(NullSink(), FaultEventSink)` is `True`; a bare object without
  `emit` is `False`.
- Unit: an object with only `emit` (no `close`) satisfies the Protocol.
