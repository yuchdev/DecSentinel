# Documentation sync policy

This file decides **when** the `docs-updater` agent runs and **which documents** it must check.
Agents and skills refer to it rather than restating it. Change it here first.

## 1. When to run docs-updater

Run `docs-updater` **once per change set**, when the change set hits a trigger in §2:

1. **After the code is final.** Tests are green, and when there is a review, `feature-reviewer`
   has returned LGTM. Never run it per edit or mid-change: the docs would chase a moving target.
2. **Before the push.** The docs update lands in the same commit, or in a `docs:` commit pushed
   together with the code. Code describing new behaviour never reaches `master` alone.
3. **Whoever spawned the implementer starts it.** Subagents cannot start agents. `python-expert`
   reports a `Docs impact` line (§4) and the caller runs `docs-updater`. The caller can be the
   main session, `implement-story` or a plan from `agent-orchestrator`. A change the main session
   makes directly, or a commit the owner pushes, counts too.

If no trigger fires, skip it and say `Docs impact: none` with the reason.

## 2. Triggers

| ID | Trigger | Typical files |
|---|---|---|
| R | A rule is added, removed or renamed, or what it reports changes: severity, scope, skips, path resolution, message or type label | `/src/docsentinel/detectors/`, `/src/docsentinel/rules.py`, `/src/docsentinel/markdown_blocks.py`, `/src/docsentinel/link_root.py`, `/src/docsentinel/discovery.py` |
| C | A CLI command, flag, default, exit code or output changes | `/src/docsentinel/cli.py` |
| K | A config key is added or removed, or its default or validation changes | `/src/docsentinel/config.py`, `/src/docsentinel/link_root.py` |
| O | A report format, packaged template, context variable or `Finding` field changes | `/src/docsentinel/telemetry/`, `/src/docsentinel/models.py`, `/src/docsentinel/reporting.py` |
| P | The public Python API or the pytest fixture changes | `/src/docsentinel/__init__.py`, `/src/docsentinel/engine.py` `scan()`, `/src/docsentinel/pytest_plugin.py` |
| A | **Architecture**: a new or removed module or package, a responsibility moved between modules, an engine pipeline step, a new or removed dependency, extra or profile | any `/src/` layout change, `/pyproject.toml` |
| D | A developer workflow that `/CLAUDE.md` describes changes: CI, hooks, agents, skills | `/.github/`, `/.claude/` |

These are **not** triggers: a refactor with no behaviour change, a performance change, test-only
or lint-only changes, or a bug fix that restores documented behaviour. A bug fix is a trigger if the
docs described the bug.

## 3. Documents to check, by trigger

| ID | Documents |
|---|---|
| R | `/docs/user/reference/rules.md` (source of truth for rule metadata, drift-tested; `python-expert` updates it with the code); `/README.md` rule bullet; `/CLAUDE.md` Architecture (`/src/docsentinel/config.py`, `/src/docsentinel/rules.py`, `/src/docsentinel/detectors/`); `/docs/user/reference/configuration.md` for the rule's options; `/docs/dev/markdown_scanner.md` for resolver ownership; `/docs/specs/finding-types.md` for type labels; `/docs/specs/fault-classes.md` for a new rule code |
| C | `/README.md` Command-Line Usage and Exit Codes; `/docs/user/tutorial/cli.md`; `/CLAUDE.md` Commands and the `/src/docsentinel/cli.py` entry |
| K | `/README.md` Configuration example (common keys only); `/docs/user/reference/configuration.md` (every key, plus the key-to-rule table); `/CLAUDE.md` `/src/docsentinel/config.py` entry |
| O | `/docs/specs/report-template-format.md`; `/docs/user/tutorial/report.md` and `/docs/user/tutorial/custom-reports.md`; `/CLAUDE.md` `/src/docsentinel/reporting.py` and `/src/docsentinel/telemetry/` entries |
| P | `/README.md` Python Library and Pytest Integration; `/docs/user/tutorial/library.md`; `/CLAUDE.md` |
| A | `/docs/architecture/README.md`; diagrams under `/docs/diagrams/`. `app-architect` reports a `Diagram impact` line and the caller hands it to `diagram-creator`; `docs-updater` never edits a diagram source; the governing ADR status; `/CLAUDE.md` Architecture; the `/README.md` profile introduction for dependency changes |
| D | `/CLAUDE.md` Commands; `/.github/copilot-instructions.md`; `/docs/agent/` |

Every trigger also covers these:

- the `/docs/README.md` index, for any added, moved or removed document;
- a proposed `/RELEASE_NOTES.json` line for an R, C, K, O or P change. Propose it only; the owner
  decides releases.

## 4. The `Docs impact` line

The implementing agent ends its report with one line:

```text
Docs impact: R, K -> DS101 now resolves / targets against link_root; new key link_root
```

or `Docs impact: none (internal refactor, no behaviour change)`. The caller passes this line and
the change set (commit range or file list) to `docs-updater` as its brief.

## 5. Why

- The `link_root` change (commits 1ed0808 and 56de38a) changed how DS101, DS103, DS112, DS113
  and DS116 resolve `/` links.
- It updated `/docs/user/reference/configuration.md`, `/docs/user/tutorial/cli.md` and `/CLAUDE.md`, but left the `/README.md` rule list and
  CLI usage stale.
- `docs-updater` was never started: nothing told anyone when to run it, and its brief did not map
  source files to the documents that describe them.
