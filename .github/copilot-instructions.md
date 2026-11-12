# Copilot instructions for DocSentinel

Project architecture, commands, conventions and test layout live in [`CLAUDE.md`](../CLAUDE.md), which Copilot also reads. This file only describes the agent tooling.

## Layout

| Path | Purpose |
|---|---|
| `.github/agents/<name>.agent.md` | Custom agents (roster below). Delegate with the `task` tool using the agent name. |
| `.github/skills/<name>/SKILL.md` | Skills, invoked as `/<name>`. Includes the former commands `implement-milestone`, `implement-story`, `update-docs` and `deep-review`. |
| `.github/hooks/docsentinel.json` | Hook configuration (`SessionStart`, `PreToolUse`, `PostToolUse`, `Stop`). |
| `.github/hooks/scripts/` | Python hook implementations, shared helpers in `_common.py`. |
| `.copilot/state/`, `.copilot/logs/` | Git-ignored runtime state (loop cursors) and hook logs. |
| `.claude/` | Thin pointers for Claude Code only: `settings.json` hooks and symlinks to `agents/` and `skills/`. |

## Agent roster

| Agent | Use for |
|---|---|
| `agent-orchestrator` | Coordinating multi-step work across the specialists below. |
| `app-architect` | Design decisions, ADRs, interface contracts. No implementation code. |
| `python-expert` | Any change to `src/` or `tests/`. |
| `testing-expert`, `test-documenter` | Test authoring and test docstrings. |
| `feature-reviewer`, `security-auditor`, `background-reviewer` | Review, threat modelling, asynchronous deep review. |
| `task-verifier` | Spec-compliance check against `docs/roadmap/**`. |
| `docs-writer`, `docs-updater`, `docs-reviewer` | New docs, doc sync, DS301 triage. |

Run `docs-updater` once per docs-impacting change set, after the tests are green and before the push. The triggers and the document map are in [documentation_sync.md](/docs/dev/documentation_sync.md); `python-expert` ends every report with a `Docs impact` line.
| `incident-analyst` | Lifecycle and escalation-safety review. |

## Skills

`adr-write`, `dep-audit`, `doc-xref`, `document-tests`, `link-check`, `pr-review`, `secret-scan`, `test-gap`, `verify-task`, `implement-story`, `implement-milestone`, `update-docs`, `deep-review`.

The loop skills run one iteration per invocation and keep a cursor in `.copilot/state/`; re-run the same command to continue (or use `/autopilot`).

## Hooks

- `secret_scan.py` blocks edits that contain likely secrets.
- After edits: formatting, style fixes, dependency audit, doc link check.
- On stop: `run_tests.py` (ruff and pytest) blocks the stop on failure. Set `DOC_SENTINEL_SKIP_TESTS=1` for known WIP.
- `guard_bash.py` is provided but deliberately not registered.
- Hook configs are loaded at session start; restart the CLI after changing them.
