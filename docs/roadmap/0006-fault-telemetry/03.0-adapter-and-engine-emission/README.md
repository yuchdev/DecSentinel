# Story 03.0 — DocSentinel adapter and single-call-site emission

**Category:** integration · **Proposed sources:** `src/docsentinel/telemetry/`, `src/docsentinel/engine.py`  
**Depends on:** [Story 01.0](/docs/roadmap/0006-fault-telemetry/01.0-shared-fault-event-module/README.md), [Story 02.0](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/README.md).

## Goal

Map DocSentinel findings onto `FaultEvent`s and emit them from exactly one call
site in `engine.scan()`, reusing the already-assembled findings. This is the only
story that turns behaviour on (and only when `telemetry_enabled`).

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0006-fault-telemetry/03.0-adapter-and-engine-emission/01-adapter-and-fault-class-mapping.md) | `events_for_result` adapter, `FAULT_CLASSES` mapping lookup, outcome/tier rules |
| [02](/docs/roadmap/0006-fault-telemetry/03.0-adapter-and-engine-emission/02-engine-single-call-site.md) | One emission call site in `engine.scan()`, default-off, error-swallowing, `build_sink` + `close()` lifecycle |

## Definition of done

- The adapter in `telemetry/` is the only code importing both the event
  machinery and DocSentinel types (`ScanResult`, `Finding`, `RULES`).
- `events_for_result` reads the finished `ScanResult` (and the pre-baseline finding
  set for `"suppressed"`) without re-running analyzers or duplicating finding
  iteration.
- Every registered rule maps to a fault class via
  [`src/docsentinel/fault_classes.md`](/src/docsentinel/fault_classes.md); an
  unmapped rule yields `"unmapped"`.
- Emission is one call site, builds the sink via `build_sink`, `close()`s it when
  the sink offers `close`, is skipped when disabled, and never alters the exit code
  or `ScanResult`; a sink error (including a failed custom-sink import) is
  swallowed.
