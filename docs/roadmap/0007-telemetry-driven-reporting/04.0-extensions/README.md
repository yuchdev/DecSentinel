# Story 04.0 — Extensions

**Category:** extension surface · **Proposed sources:** `src/docsentinel/telemetry/extensions.py`, `src/docsentinel/telemetry/builtin/`, `src/docsentinel/config.py`  
**Depends on:** [Story 02.0](/docs/roadmap/0007-telemetry-driven-reporting/02.0-template-engine/README.md) (context schema); end-to-end demo needs [Story 03.0](/docs/roadmap/0007-telemetry-driven-reporting/03.0-standard-templates-and-cutover/README.md).  
**Threat model (normative):** [threat-model-0007-extensions-2026-11-03.md](/docs/security/threat-model-0007-extensions-2026-11-03.md) -- mitigations M1-M34 are acceptance criteria; owner decisions D-A..D-E are applied as recorded in the tasks.

## Goal

Let a team add custom calculations and attributes (`domain`, per-document stats,
anything JSON-shaped) to every report and to fault events, without touching the
renderer, and prove it with two shipped examples.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/01-extension-api-and-loader.md) ✅ | `Extension` Protocol, namespacing, loader for `builtin:` and `python:`, argv-only trust gate in the shared importlib helper, error model (M1-M17, M25-M33) |
| [02](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/02-domain-and-custom-calc-examples.md) | `builtin:domain` (path -> domain, core `doc.domain`), `builtin:document_stats` (custom calculation), config and docs for writing your own (M18, M20-M24, M34) |

## Definition of done

- A document under `.claude/agents/` reports `domain: "agent"`, one under `docs/`
  reports `"docs"`, as the core `doc.domain`, via `doc.ext.domain.name` and as
  `FaultEvent.domain`, all from one `domain_for`.
- `python:` extensions are accepted only from argv (`--extension`) with the explicit
  invoker gate; a `python:` entry in config is a `ConfigError`.
- A broken extension fails a report with exit 2 and never fails event emission; a
  refused `python:` spec is exit 2 on both paths.
- Out of scope: `--allow-repo-python-extensions` (D-B) and a wall-clock extension
  budget (D-C, accepted risk).
