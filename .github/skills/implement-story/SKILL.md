---
name: implement-story
description: Drives one story to completion, implementing exactly one task per iteration. Resolves the story from a milestone's plan.md, gates on status.md, then walks the story README's task queue - implementing, verifying, and running quality gates per task. Updates the story README after each task and status.md when the story lands. Self-terminates when the story reaches ✅ Complete.
---

# implement-story - per-task implementation skill for one story

Invoke as `/implement-story <story>`. This skill takes **one story** (e.g. "Hello World Endpoint", story `1.0`) and drives it to
completion. Each invocation performs **exactly one iteration**: it implements one pending task, verifies it against
its spec, runs the relevant quality-gate skills, records progress, persists the cursor file, and then either terminates (story ✅ Complete) or tells the user to continue by re-running `/implement-story <story>` (same argument), which resumes from the cursor file. In `/autopilot` mode the agent can simply continue with the next iteration in the same session instead of stopping.

The navigation chain it follows every iteration:

```
docs/roadmap/{NNNN}-{milestone-slug}/plan.md          → find the story in ## Stories
        └─ status.md                                   → gate on ## Current status
              └─ {TT.t}-{story-slug}/README.md          → read ## Tasks queue
                    └─ {NN}-{task-slug}.md               → the spec for THIS iteration
```

---

## Argument

`<story>` identifies which story to drive. Accepted forms (most specific wins):

- `0001/1.0` or `0001 1.0` - explicit milestone + story number.
- `1.0` - story number only; resolve the milestone by scanning every
  `docs/roadmap/{NNNN}-*/plan.md` `## Stories` table for that number.
- `"Hello World Endpoint"` - story name; matched (case-insensitive, substring) against the
  `Name` column of the same tables.

If the argument matches zero or more than one story, **stop** and ask the user to
disambiguate - do not guess.

**Number → folder mapping:** a story number `T.t` maps to the folder prefix `{TT.t}`
zero-padded to two digits before the dot: `3.2 → 03.2`, `6.1 → 06.1`, `8 → 08.0`. The
matching story folder is `docs/roadmap/{NNNN}-{milestone-slug}/{TT.t}-{story-slug}/`.

---

## Per-run state cursor (token-economy core)

This skill re-enters the **same growing conversation** (or a fresh one on re-invocation), so anything the main agent reads
directly stays in context for *every* subsequent iteration. The milestone path, story folder,
and task queue do **not** change within a run - reparsing the ~500-line `plan.md` and
~150-line `status.md` each iteration would add ~10k tokens of pure rediscovery per iteration.
Instead, resolve once and persist a small cursor:

```
.copilot/state/implement-story-{story-slug}.json
```
```json
{
  "milestone_path": "docs/roadmap/0001-working-implementation",
  "story_number": "1.0",
  "story_name": "Hello World Endpoint",
  "story_folder": "docs/roadmap/0001-working-implementation/01.0-hello-world-endpoint",
  "task_heading": "## Tasks",
  "task_queue": [
    {"nn": "01", "slug": "config-model", "status": "complete"},
    {"nn": "02", "slug": "...", "status": "not_started"}
  ],
  "next_index": 1,
  "docs_impact": ["R, K -> DS101 resolves / targets against link_root"]
}
```

The cursor is a **derived cache**, not the source of truth: the story `README.md` and
`status.md` remain authoritative. Refresh the cursor only when a task closes (Step 7).
`{story-slug}` is a filesystem-safe slug of the `<story>` argument.

## Iteration algorithm

### Step 1 - load or build the run cursor

Check for the cursor file.

- **Warm path - cursor exists:** read it (~300 tokens) and go straight to Step 3. Do **not**
  re-read `plan.md`, `status.md`, or the README - they are already distilled into the cursor.
- **Cold path - no cursor (first iteration, or it was deleted):** do the discovery **inside a
  cheap subagent**, not in the main agent, so the large file bodies never enter the persistent
  conversation context. Delegate with the `task` tool using the `explore` agent type with this instruction:

  > Resolve story `<story>` for the implement-story skill. (1) In each
  > `docs/roadmap/{NNNN}-*/plan.md` `## Stories` table, find the row matching the story number or
  > name; record milestone path, story number `{TT.t}`, and name. Number→folder: pad to two
  > digits before the dot (`3.2 → 03.2`); resolve `…/{TT.t}-{story-slug}/`. (2) In that
  > milestone's `status.md` `## Current status` table, read the story row's Status cell. (3) In
  > the story `README.md`, find the task table (heading `## Tasks`, or legacy
  > `## Task overview`) and list each task's `{NN}`, slug, and status.
  > **Return ONLY** a JSON object: `{milestone_path, story_number, story_name, story_folder,
  > task_heading, status_gate, task_queue:[{nn,slug,status}]}`. No prose, no file bodies.

  Branch on the returned `status_gate`:
  - `⬜ Not started` / `🔶 In progress` → write the cursor (`next_index` = first pending
    task) and continue to Step 3.
  - `✅ Complete` → do **not** re-implement. Delegate to the `task-verifier` custom agent (`task` tool) against the story folder,
    report its verdict, and **stop** (do NOT ask to re-run). A completed story is verified, not rebuilt.
  - Argument matched zero or >1 story → **stop** and ask the user to disambiguate.
  - No decomposed folder / no README → **stop**: this skill drives a decomposed story.
  - Missing `status.md` (milestones 0002-0004) → the agent returns `status_gate: "absent"`;
    treat as `⬜ Not started` and proceed (the table is created in Step 7).

If the main agent ever needs a single field it doesn't have, prefer a narrow `grep` of one row
(e.g. `grep -n "^| 3.2 " <status.md>`) over a full read of the file.

### Step 2 - pick the next pending task

From the cursor's `task_queue`, choose the **first** task whose status is `🔶`/Partial,
else the first `⬜`/Not started. Partial is prioritised: unfinished work carries higher
regression risk than new work. Record its `{NN}`, slug, and spec path
`{story_folder}/{NN}-{task-slug}.md`.

If every task is `✅ Complete` (or deferred per the Step 7 completion rule), jump straight
to Step 7 to close the story.

Read **only the chosen task spec** in full - it is the authoritative brief for this
iteration (Files, symbols/fields, validators, tests, success criteria, constraints). This is
a *different* file each iteration, so it is necessary cost, not repeated cost.

### Step 3 - implement via the dev-fleet agents

Delegate the task spec with the `task` tool, using the custom agent type named below (each is defined in `.github/agents/<name>.agent.md`). Independent units within one
task may run concurrently; units with stated ordering dependencies run sequentially:

| Spec role keyword  | Fleet agent                             | Agentic action               |
|---------------------|------------------------------------------|-------------------------------|
| `Architect`        | `app-architect`                         | evaluate design               |
| `Python Expert`    | `python-expert`                         | task implementation           |
| `Testing Expert`   | `testing-expert` then `python-expert`   | QA then fix regressions       |
| `Security Auditor` | `security-auditor` then `python-expert` | advisory then implementation  |
| `Docs Writer`      | `docs-writer` or `docs-updater`         | write or update docs          |

Brief each coder/QA agent with **paths and section references, not pasted file bodies** -
pasting a spec bills it twice (once in your context, once in theirs):

- The task spec **path** (`{story_folder}/{NN}-{task-slug}.md`) - the agent reads it itself. Add a one-line scope note, not the spec text.
- The cross-cutting rules in `@docs/dev/python_coding_standard.md` - full annotations, ruff,
  RAII, this project's log-redaction mechanism (if it has one), no bare `except:`, unit +
  mocked-integration tests.
  Also point the agent to `CLAUDE.md` (and `.github/copilot-instructions.md`) § "Project status" and § "Conventions":
  - Never describe an empty findings list as a validated audit.
  - Detectors must be explicit and deterministic, with result tests before registration in `ANALYZERS`.
  - `standard`/`deep` must not imply checks that do not exist.
  - No network or model calls.

  Point them as well to `CONTRIBUTING.md`, which restates these rules. There is no logging or redaction utility; the package does no logging. If the milestone's `plan.md` carries its own cross-cutting
  guidelines section, name it for the agent to read.

**Return discipline (keeps the parent context lean):** instruct every delegated agent to return
a **compact structured summary** - files changed, symbols added, pass/fail, coverage delta -
and to **never echo diffs, file contents, or full test logs**. A subagent's internal reads and
reasoning are discarded with its context; only its final message persists in the session, so that
message is the only thing you pay to carry forward.

**Security-sensitive tasks** (auth middleware, anything parsing untrusted or
attacker-influenced input, external-service credentials or tokens): delegate to the `security-auditor` custom agent (`task` tool)
**before** coding begins. It reads the spec and writes a threat model to
`docs/security/<date>-<topic>.md`; the coder picks that up as an additional input. A CRITICAL
finding blocks merge - stop and require human sign-off.

### Step 4 - stop-and-ask when implementation needs a decision

During implementation the skill **may pause to ask the user** whenever the spec is ambiguous,
a design choice materially shapes the final implementation, or a deviation from the spec
looks warranted. Ask the user with concrete options, apply the answer, and
continue the same iteration. Prefer asking to guessing for anything that is expensive to
reverse. (Routine, unambiguous implementation does **not** pause - only genuine forks.)

### Step 5 - verification gate

Run **only this task's** verification, not the whole suite: scope `pytest` to
the task's own test file(s) and use `-q` (capture the summary line, not per-test `-v` output),
plus `python .github/hooks/scripts/style_fixes.py --check <path>`. Do **not** pipe full pytest output into context -
a green run is one summary line; on failure, tail only the failing assertions. The full suite
runs once at story completion (Step 7), and the Stop hook gates the session end regardless.

On failure:

- Diagnose, delegate the fix to the `python-expert` custom agent (`task` tool), re-run. Repeat until green or until the
  failure is clearly a spec ambiguity needing human input - in that case stop and
  surface the blocker.

### Step 6 - spec-compliance gate (`/verify-task`)

With verification green, run `/verify-task {task-path}` where `{task-path}` is the
spec path from Step 2 (relative to `docs/roadmap/`, without the `.md` extension). It delegates to
the `task-verifier` custom agent (`task` tool) for a compliance matrix + verdict:

- **PASS** → record a **single line** (`✓ verify-task PASS`), not the full matrix - the
  matrix only earns its tokens when there is something to act on. Continue to Step 7.
- **PARTIAL** → log the deviation list (this is worth carrying); continue, and feed those
  deviations into the `/pr-review` context so the reviewer sees them.
- **FAIL** → delegate the blocking gaps back to the `python-expert` custom agent (max 1 retry), re-run
  Step 5 then this step. If still FAIL after one retry, surface the gaps and stop.

Then run the applicable quality-gate skills. **Skip any gate whose trigger condition is false -
do not delegate to an agent that can only find nothing.** Each gate is module-scoped, never tree-wide:

| Condition                                                | Skill                                                                                                                                |
|----------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| Always                                                   | `/test-gap src/doc_sentinel/<task-module>/` - report coverage delta; if < 85 % delegate missing tests to the `testing-expert` custom agent (`task` tool). |
| `pyproject.toml` or any `requirements*.txt` changed      | `/dep-audit`                                                                                                                         |
| Any file under an API route, auth, or middleware path changed, or anywhere handling credentials/tokens | `/secret-scan src/doc_sentinel/<changed-module>/` |
| Task touches docs / public API                           | `/link-check docs/` - inbound references still resolve.                                                                              |
| `python-expert` reported `Docs impact` other than `none` | Do not run `docs-updater` yet. Append the line to the cursor's `docs_impact` list, which runs at story completion (Step 7). |

### Step 7 - record the task, then check the story

**After each task completes:**

1. Edit the story README `{story_folder}/README.md` - set **only this task's** row Status
   cell to `✅ Complete` (or `🔶`/deferred with a one-line note if only partially done). A
   targeted row edit, not a rewrite.
2. **Refresh the cursor** (`.copilot/state/implement-story-{story-slug}.json`): update
   this task's `status` and advance `next_index`. This keeps the next iteration on the warm
   path - it never has to re-read the README.

**Then test the story-completion condition** over the cursor's `task_queue`:

> The story is **✅ Complete** when the feature is overall created and working - even if 1-2
> **minor** tasks are explicitly deferred. Do not block completion on optional or
> enhancement tasks (e.g. a caching optimization) once the core feature is delivered and
> green. A *major* task still `⬜`/`🔶` means the story is **🔶 In progress**, not complete.

- **Story not yet complete** → go to Step 8 (continue with the next task).
- **Story complete** → this is the **one** place the whole suite runs: execute
  `uv run pytest tests/unit/ -q --cov=doc_sentinel` once (summary line only), then run
  `/pr-review` (must reach LGTM or have REQUEST_CHANGES resolved). If the cursor's
  `docs_impact` list is not empty, delegate **once** to the `docs-updater` custom agent (`task` tool):
  - pass it the collected lines and the story's commit range, per [documentation_sync.md](/docs/dev/documentation_sync.md);
  - wait for it to finish before the story commit is pushed;
  - an architecture (`A`) trigger also asks `docs-updater` to check `docs/architecture/README.md` and the diagrams.

  Then update
  `{milestone_path}/status.md` `## Current status` with a **targeted row edit**:
  - Set the story row's Status cell to `✅ Complete` (note any deferred tasks inline,
    e.g. "✅ Complete (task 11 deferred)").
  - Update the Tests cell with the test files introduced.
  - Append/extend the `## Story N - <Name>` summary paragraph: what was delivered, key
    implementation decisions, coverage numbers, and any deferred items.
  - Run `/link-check docs/roadmap/` to confirm the edits keep every link/anchor resolving.
  - **Delete the cursor** `.copilot/state/implement-story-{story-slug}.json` (the run
    is over; a stale cursor would mislead a future invocation).
  - **Stop** (do NOT ask to re-run) - the story is done.

### Step 8 - continue

Copilot CLI has no wakeup/scheduler. With the cursor saved (Step 7), end the invocation by
telling the user to re-run the literal `/implement-story <story>` (the **same** `<story>`
argument); it resumes from the cursor file on the warm path. Include a one-line status:
"advancing to next pending task of story {TT.t} <Name> after completing task {NN}".
In `/autopilot` mode, skip the hand-off and continue directly with the next iteration
(Step 1, warm path) in the same session.

---

## Story-specific notes

Most stories need nothing here - Steps 3-6 already cover the general case. Add a
`### Story {TT.t} - <Name>` subsection only when a specific story carries a real gotcha future
iterations must not rediscover from scratch: a non-obvious ordering dependency between its
tasks, a security-sensitive subsystem that always needs the `security-auditor` agent before coding
starts, an artifact category (generated code, vendored fixtures, build output) that should
skip the usual lint/typing gate, or a dependency that must land before a task can pass.
Keep each note to what the next iteration needs to act correctly on - not a running
commentary on the story.

---

## Token-economy invariants

Because the skill continues in one growing conversation, the cost that compounds is whatever
**permanently lands in the main context**. Hold these every iteration:

1. **Resolve once, cache forever (per run).** Steps 1-2 read the cursor (~300 tokens), never
   re-parse `plan.md`/`status.md`/README. Cold-start discovery happens *inside a subagent* so
   the file bodies never enter the persistent context.
2. **Read narrow.** Grep single rows / `offset`+`limit` to a table; never full-read a large
   doc from the main agent. Full reads of the *current task spec* are the only exception
   (necessary, and a different file each time).
3. **Delegate, then demand terse returns.** Push reads, analysis, and reasoning into subagents
   (discarded with their context); require compact structured summaries back - no diffs, file
   bodies, or full test logs. `verify-task` PASS = one line.
4. **Run the minimum gate.** Task-scoped tests with `-q`; full suite once at story close;
   skip any quality gate whose trigger is false; module-scope the ones that fire.
5. **Keep narration terse and lean on `/compact`.** A status line, not a recap - the main
   agent's "thinking out loud" persists; a subagent's does not. On a long story, `/compact`
   between iterations resets the accumulated tail.

## Termination

The skill terminates when the target story's row in the milestone `status.md` shows ✅ Complete. Otherwise each invocation ends after one iteration with the cursor saved and a request to re-run `/implement-story <story>`.

| Condition                                           | Action                                       |
|-------------------------------------------------------|--------------------------------------------------|
| Target story reaches `✅ Complete` (Step 7)         | Update status.md, print summary, do NOT ask to re-run |
| Story already `✅ Complete` at Step 1               | Run `task-verifier`, report, do NOT ask to re-run  |
| Argument matches zero or >1 story                   | Stop, ask the user to disambiguate           |
| Verification fails after the fix retries (Step 5)   | Surface the blocker, stop                    |
| `task-verifier` FAIL after one retry (Step 6)       | Surface blocking gaps, stop                  |
| `security-auditor` issues a CRITICAL finding        | Stop, require human sign-off                 |
| `/pr-review` returns REQUEST_CHANGES after 2 rounds | Stop, surface the diff                       |

---

## Skill ↔ skill relationship

This skill is the **sentence**; the other skills are its **vocabulary**. It calls `/verify-task`
(spec compliance), `/test-gap` (coverage), `/dep-audit`, `/secret-scan`, `/link-check`, and
`/pr-review` at the right checkpoints, and delegates implementation (via the `task` tool) to the dev-fleet custom agents
listed in `.github/agents/agent-orchestrator.agent.md`'s roster. One level up,
the `implement-milestone` skill (`.github/skills/implement-milestone/SKILL.md`) drives a whole milestone by executing this
skill's Steps 2-6 per iteration with milestone-scoped overrides (see its composition
contract); this file remains the authority on all per-task mechanics.
