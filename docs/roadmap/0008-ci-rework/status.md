# Milestone 0008 — completion status

**Planning state:** 📝 Specification only (0 of 7 stories implemented). Story specs
(story README and task files) are authored when the milestone is started.

## Current status

| Story | Name | State | Tests executed |
|---|---|---|---|
| 01.0 | CI output contract | ⬜ Not started | — |
| 02.0 | Job topology | ⬜ Not started | — |
| 03.0 | Bounded pytest output | ⬜ Not started | — |
| 04.0 | Self-scan reporting | ⬜ Not started | — |
| 05.0 | Self-scan signal and baseline hygiene | ⬜ Not started | — |
| 06.0 | Local/CI parity | ⬜ Not started | — |
| 07.0 | Regression guards | ⬜ Not started | — |

## Tracking rules

- Mark a story complete only when its workflow changes have run green on GitHub,
  not from a local run alone.
- Never print a full report or an unbounded test log to CI output, even
  temporarily while debugging; write it to an artifact.

## Notes & decisions

- 2026-11-11: Milestone opened after CI run 42863733518 produced a 51,896-line log.
  Interim mitigation, before this milestone:
  - the `.claude/skills/mermaid` vendored docs are excluded from the self-scan;
  - self-scan reports are written with `-o` and uploaded as an artifact;
  - `.github/scripts/print_report.py` prints a report only up to 15 findings, and
    otherwise the finding count, line count, path and the text `Blocking findings`
    recap;
  - `text.json` ends with that recap.

  Story 04.0 replaces the interim reporter; it doesn't extend it.
