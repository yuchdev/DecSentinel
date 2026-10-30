# Story 04.0 — Extensions

**Category:** extension surface · **Proposed sources:** `src/docsentinel/telemetry/extensions.py`, `src/docsentinel/telemetry/builtin/`, `src/docsentinel/config.py`  
**Depends on:** [Story 02.0](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/README.md) (context schema); end-to-end demo needs [Story 03.0](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/README.md).

## Goal

Let a team add custom calculations and attributes (`domain`, per-document stats,
anything JSON-shaped) to every report and to fault events, without touching the
renderer, and prove it with two shipped examples.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/01-extension-api-and-loader.md) | `Extension` Protocol, namespacing, loader for `builtin:` and `python:`, trust gate, error model |
| [02](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/02-domain-and-custom-calc-examples.md) | `builtin:domain` (path → domain), `builtin:document_stats` (custom calculation), config and docs for writing your own |

## Definition of done

- A document under `.claude/agents/` reports `domain: "agent"`, one under `docs/`
  reports `"documentation"`, via `doc.ext.domain.name` and as `FaultEvent.domain`.
- `python:` extensions are refused without the explicit invoker opt-in.
- A broken extension fails a report with exit 2 and never fails event emission.
