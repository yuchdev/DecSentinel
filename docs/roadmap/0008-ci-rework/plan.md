# Milestone 0008 — CI Rework: Concise, Structured Failure Reporting

**Repository:** https://github.com/yuchdev/DocSentinel  
**Milestone path:** `docs/roadmap/0008-ci-rework/`  
**Status:** specification only  
**Dependencies:** Milestone 0007 (template-driven reports, `--output`, the text
`Blocking findings` recap and the `blocking_count` context variable).

## Goal

Rebuild CI from scratch so that a failed run tells a maintainer **what failed, where,
and why** within a short read, and never floods the log. A failing check should be
identifiable from the job name alone, and the first screen of its log (and the run's
job summary) should state the reason. Full data stays available as artifacts, never
as log output.

The trigger was run `42863733518`: the log was 51,896 lines. About 46,000 were one
JSON report printed to stdout, and about 4,000 more were non-blocking warnings, which
buried the 72 errors that actually failed the step. The interim fix
(`print_report.py`, the text recap) stops that one case. This milestone replaces
the ad-hoc workflow with a designed one and covers the other ways CI can fail
unreadably.

## Problem inventory (observed, 2026-11-11)

| # | Problem | Effect |
|---|---|---|
| P1 | Full reports printed to the log (JSON self-scan, about 46,000 lines) | The failure reason can't be found without downloading the log |
| P2 | 3,906 non-baselined DS103 warnings in every self-scan, against a 711-entry baseline | Non-blocking noise hides blocking lines; the baseline has silently drifted |
| P3 | One monolithic job: sync, pytest (about 6 min), three self-scans and the build run in sequence | The failing check is only found by reading steps; a late failure costs a full rerun |
| P4 | Default `fail-fast` cancels the other matrix leg (3.13 was cancelled when 3.12 failed) | It's impossible to tell whether a failure depends on the Python version |
| P5 | ruff, flakeforge X and docsig run locally (Stop hook, delivery gate) but not as CI steps; CI omits the `deep` extra | A local pass doesn't predict CI, and CI doesn't check what the hooks check |
| P6 | pytest failure output is unbounded: assertions embed whole CLI reports (for example `assert status == 0, out + err`) | One failing test can print thousands of lines |
| P7 | Vendored third-party content (skills) is excluded per tool, by hand (ruff and docsentinel each have their own list; mermaid was missing) | Upstream docs break the self-scan without warning |
| P8 | No job summary, no annotations budget, no artifacts naming convention | No structured, at-a-glance view of a run |

## Design principles

1. **Budget, not best effort.** Every check has a written log budget (for example at
   most 200 lines logged for a failing check, 20 for a passing one). Anything larger
   goes to an artifact. The budget is enforced by a test, not by convention.
2. **Reason last, summary first.** Each check logs a short header, then the bounded
   detail, and ends with the reason it failed. Each check also adds one row to the
   run's job summary (`$GITHUB_STEP_SUMMARY`): name, verdict, counts, and the first
   few blocking items.
3. **One check per job.** The job name says what failed (lint, unit, integration,
   self-scan, build). Jobs run in parallel where possible, and the matrix uses
   `fail-fast: false`.
4. **Local/CI parity.** CI steps and the local hooks call the same entry points with
   the same arguments, so a local pass predicts a CI pass.
5. **Signal, not noise.** The self-scan carries zero un-triaged findings. Each
   warning is fixed, baselined deliberately or excluded by policy, and baseline
   drift is itself a reported check.
6. **No new runtime dependencies.** CI helpers are stdlib Python; pytest output
   shaping uses pytest's own options and hooks.

## Stories

| Story | Deliverable | Depends on |
|---|---|---|
| 01.0 | **CI output contract:** a spec for the per-check log budget, the header/detail/reason layout, the job-summary row, artifact names and retention, and what "the reason" means for each check type (test, lint, scan, build) | — |
| 02.0 | **Job topology:** split the workflow into lint, unit+mock, integration, self-scan and build jobs, with `fail-fast: false`, a uv cache, extras parity (a `deep` leg or an explicit, documented skip) and `concurrency` cancellation of superseded runs | 01.0 |
| 03.0 | **Bounded pytest output:** quiet reporting with a failure-only summary and short tracebacks; a conftest hook that caps assertion messages and captured output to the budget; a JUnit XML artifact; a job-summary table of failed tests; replace assertions that embed whole reports with a tail-capped helper | 01.0 |
| 04.0 | **Self-scan reporting:** generalise the interim `print_report.py` into one CI reporter for all scan steps, covering the budget, the job-summary row, a cap on GitHub annotations through `--format github`, and the artifacts. Every `docsentinel scan` in a workflow writes with `-o` | 01.0 |
| 05.0 | **Self-scan signal and baseline hygiene:** triage the 3,906 DS103 warnings. They are long-standing, not a regression: the count is the same at 56de38a^. They include dotted identifiers in code spans and repo-root-relative paths that exist (for example the roadmap index, flagged 16 times). Fix the detector or baseline them deliberately; one shared vendored-content exclude list consumed by ruff and docsentinel; a baseline-drift check that reports new and stale fingerprints | 04.0 |
| 06.0 | **Local/CI parity:** one entry-point script per check (for example a `scripts/ci.py` with lint, unit, integration, self-scan and build subcommands) called by both the workflow and the local hooks (Stop hook, flakeforge delivery gate) | 02.0, 03.0, 04.0 |
| 07.0 | **Regression guards:** tests that (a) run each CI reporter against a synthetic huge report and assert the output stays within budget, and (b) lint the workflow files, so a scan step without `-o`, or a step that prints a report file to the log, fails | 03.0, 04.0, 06.0 |

## Exit gates

- A deliberately broken branch (one per check type: a failing unit test, a ruff
  error, a blocking self-scan finding, a build error) fails CI with **every** failing
  job's log within the 01.0 budget, and the reason visible in the job summary
  without opening a log.
- The self-scan reports zero un-triaged findings; the baseline-drift check passes.
- The local hooks and CI call the same entry points (06.0); a local pass of
  `scripts/ci.py all` predicts a CI pass on the same tree.
- The 07.0 guards are part of the regular suite.

## Out of scope

- Changing DocSentinel's own report formats beyond what 04.0 needs (they are
  template-driven since Milestone 0007).
- Release automation (the release workflow), except to apply the same output contract
  if it prints reports.
- External CI dashboards or services.
