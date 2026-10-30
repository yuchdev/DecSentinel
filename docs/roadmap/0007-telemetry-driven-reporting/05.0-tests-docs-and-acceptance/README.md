# Story 05.0 — Tests, docs and acceptance

**Category:** hardening · **Proposed sources:** `tests/`, `docs/`, `CLAUDE.md`, `README.md`  
**Depends on:** Stories 01.0–04.0.

## Goal

Close the milestone: full test matrix, security review of the two code-loading
surfaces, documentation, and a real-world acceptance run on the CanonixEngine
corpus that motivated it.

## Tasks

| Task | Deliverable |
|---|---|
| [01](/docs/roadmap/0007-telemetry-driven-reporting/05.0-tests-docs-and-acceptance/01-test-matrix-and-security-review.md) | Cross-surface test matrix, tripwires, `security-auditor` review of template loading and `python:` extensions |
| [02](/docs/roadmap/0007-telemetry-driven-reporting/05.0-tests-docs-and-acceptance/02-docs-and-canonixengine-acceptance.md) | `CLAUDE.md`/README/architecture/user docs, release notes, CanonixEngine acceptance run |

## Definition of done

- Every acceptance criterion in [plan.md](/docs/roadmap/0007-telemetry-driven-reporting/plan.md) is checked with evidence in [status.md](/docs/roadmap/0007-telemetry-driven-reporting/status.md).
- Full suite and CI (`uv sync --locked`, pytest with the plugin, self-scans, `uv build`) pass.
- `/link-check`, `/verify-task` for each story, and `/pr-review` are clean.
