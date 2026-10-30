# DocSentinel Roadmap

Planning and progress tracking for DocSentinel, organized as a three-tier
hierarchy: **Milestone → Story → Task**.

## Hierarchy & vocabulary

| Tier          | Meaning                                                                                                       | Lives in                                                |
|---------------|---------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|
| **Milestone** | A large, strategic initiative / development direction (e.g. the generic implementation effort).               | A folder `docs/roadmap/{NNNN}-{milestone-slug}/`.       |
| **Story**     | One deliverable unit of a milestone (e.g. "AWS Bedrock Backend"). Listed in the milestone's `## Stories` table. | A subfolder `…/{TT.t}-{story-slug}/` with a `README.md`. |
| **Task**      | An atomic, implementable spec (one file, one set of classes/tests). Listed in the story's `## Tasks` table. | A file `…/{TT.t}-{story-slug}/{NN}-{task-slug}.md`.   |

A *task* is part of a *story*; a *story* is part of a *milestone*.

## File & folder convention

```
docs/roadmap/
  README.md                              ← this index + convention
  {NNNN}-{milestone-slug}/               ← MILESTONE
    plan.md                              ← milestone spec; opens with a `## Stories` table
    status.md                            ← progress tracker (optional); `## Current status` table
    {TT.t}-{story-slug}/                 ← STORY
      README.md                          ← story spec; opens with a `## Tasks` table
      {NN}-{task-slug}.md                ← TASK spec
```

- `{NNNN}` - zero-padded milestone number (`0001`, `0002`, …).
- `{TT.t}` - story number, carried from the milestone's `## Stories` table (e.g. `03.2`, `06.1`, `08.0`).
- `{NN}` - zero-padded task order (`01`, `02`, …).
- Slugs are kebab-case.

### Heading vocabulary

- A milestone's `plan.md` lists its stories under a `## Stories` heading (table column: `Story`).
- A story's `README.md` lists its tasks under a `## Tasks` heading.

### Linking convention

When a document references another **specific** document, use an
absolute-from-repo-root Markdown link:

```
[docs/roadmap/0001-generic-implementation/plan.md](/docs/roadmap/0001-generic-implementation/plan.md)
```

- Always a leading `/` (repo root), never relative `../../` chains.
- **Template** paths (containing `{` / `}`, e.g. `` `{NN}-{task-slug}.md` ``) stay as
  backtick code spans, not links.
- Run `python scripts/check_doc_links.py docs/` (or the `/link-check` skill) to verify every
  link target and `#heading-anchor` resolves. The `doc_link_check` hook runs it on edits.

## Milestones

| #    | Milestone                                                             | Spec                                             | Status                                               |
|------|-----------------------------------------------------------------------|--------------------------------------------------|------------------------------------------------------|
| 0001 | Generic implementation: rule registry, config conventions, and the first `fast`-profile detectors | [plan.md](./0001-generic-implementation/plan.md) | ✅ [status.md](./0001-generic-implementation/status.md) |
| 0002 | Standard-profile detectors: corpus duplication, low-information content, text complexity, doc-vs-code signature mismatch | [plan.md](./0002-standard-profile-detectors/plan.md) | ✅ [status.md](./0002-standard-profile-detectors/status.md) |
| 0003 | Deep-profile detector, opt-in gating, and the periodic `docs-reviewer` agent/loop | [plan.md](./0003-deep-profile-and-periodic-review/plan.md) | ✅ [status.md](./0003-deep-profile-and-periodic-review/status.md) |
| 0004 | Deepening test cases: specification only (DS107 orphan docs, DS111 metadata, DS119 migration markers, DS120 terminology, DS121 near-duplicate sections, DS122 near-duplicate docs, DS123 stale symbol refs) — not implemented in the current checkout; superseded in scope by Milestone 0005 | [plan.md](./0004-deepening-test-cases/plan.md) | ⏸ Spec only — [status.md](./0004-deepening-test-cases/status.md) |
| 0005 | Deepening test cases stage 2: thirteen new fast rules DS104–DS118 (anchors, headings, sections, reference integrity, fences, pipe tables, navigation, missing assets, path boundaries, document identity, deprecated references, naming policy) with 191 fixture scenarios (185 specified + 6 DS116 close-gate cases, see status.md) and a full shared Markdown scanner | [plan.md](./0005-deepening-test-case-stage-2/plan.md) | 🔄 In progress — [status.md](./0005-deepening-test-case-stage-2/status.md) |
| 0006 | Fault-telemetry event emission: one structured event per rule evaluation, coupled to the sibling FlakeForge by a written contract ([spec](/docs/specs/fault-event-contract.md)) rather than shared code. DocSentinel-local `FaultEvent`/`FaultEventSink` PEP 544 Protocol, flexibly pluggable sinks (JSONL/stdout, stdlib `logging`, SQLite, and custom `python:<module>:<callable>`), a typed config/CLI surface (`telemetry_enabled`, `telemetry_sink`, `generated_by_model`), a conformance tripwire, and a single `engine.scan()` call site — stdlib-only, default-off, observational | [plan.md](./0006-fault-telemetry/plan.md) | 📝 Spec only — [status.md](./0006-fault-telemetry/status.md) |
| 0007 | Template-driven reporting on a `telemetry/` package: `text`, `github` and `json` become packaged templates (no hardcoded format), findings print under their document, JSON becomes document-centric schema 2 with rule/type/value/line/column/fault class/tier/outcome, plus a Python extension API (`builtin:domain`: `documentation` vs `agent` by path) | [plan.md](./0007-telemetry-driven-reporting/plan.md) | 📝 Spec only — [status.md](./0007-telemetry-driven-reporting/status.md) |
