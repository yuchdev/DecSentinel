# Threat Model - Milestone 0007 closure (Story 05.0) - 2026-11-04

Addendum to [threat-model-0007-template-engine-2026-10-31.md](/docs/security/threat-model-0007-template-engine-2026-10-31.md)
(T1-T11, R1-R7, M1-M17) and [threat-model-0007-extensions-2026-11-03.md](/docs/security/threat-model-0007-extensions-2026-11-03.md)
(T1-T14, M1-M34, R1-R5). Those findings are not repeated. This note covers only what
the Story 05.0 work itself adds: the test matrix (Task 01), the docs, release notes,
version bump and the CanonixEngine acceptance run (Task 02). No product code was changed.

## Assets & trust boundaries

- **A-ext corpus**: `~/Projects/CanonixEngine/docs` is a second repository. Treat it as
  untrusted input (file names, link targets, its own `docsentinel.toml` /
  `pyproject.toml`, including `report_templates_dir` and `telemetry_domains`).
- **A-commit**: reports written to `docs/reviews/canonix-acceptance-<date>/` cross from
  "tool output" to "committed repo content". They are then read by the self-scan,
  `/link-check`, CI logs, and shipped in the sdist (checked: `uv build --sdist`
  already ships `docs/reviews/*` and `docs/security/*`, because there is no
  `[tool.hatch.build.targets.sdist]` include list).
- **A-docs**: release notes, README, CLAUDE.md and the user guides are copied into CI
  workflows by readers, so any unsafe example they contain gets reused.

## Findings

### [MEDIUM] C1 Acceptance reports leak scanned content into the repository and the sdist
- Vector / evidence: Task 02 commits nine reports from an external corpus under
  `docs/reviews/`. The sdist has no include list (`pyproject.toml:68-69` configures
  only the wheel), so `docsentinel-1.1.0.tar.gz` already carries `docs/reviews/README.md`.
  The reports echo document paths, messages and `value` (link targets).
- Impact: CanonixEngine paths, link targets (which may hold URLs with tokens) and the
  file layout get published in git history and on PyPI (CWE-200, CWE-538).
- Mitigation: (1) the owner confirms CanonixEngine content may be published, or the
  reports stay out of git and only the derived numbers go into `status.md`. (2) Before
  committing, check the reports for absolute paths (`/Users/`, `$HOME`), the user name,
  and secret-shaped strings (tokens, `?key=`, `Authorization`). (3) Add an sdist
  include/exclude list so `docs/reviews/` and `docs/security/` do not ship, or record
  that shipping them is intended. (4) Leave `report_include_run_meta` off, so no
  `run.id` or `generated_at` gets committed.

### [MEDIUM] C2 Committed reports get scanned or replayed as live commands
- Vector / evidence: the CI self-scan runs `docsentinel scan .` (`.github/workflows/ci.yml:21-23`).
  `docsentinel.toml:2` excludes `tests/assets/*` but not `docs/reviews/`. The
  `github.json` output is made of well-formed `::error`/`::warning` commands.
- Impact: (a) a report saved as `.md` becomes self-scan input, which produces spurious
  findings or a baseline drift. (b) Any later `cat` of the github report in a CI step
  turns every line into a live annotation. Each line is individually safe (M-gha),
  but the step would forge annotations on files that do not exist in this repo
  (CWE-117, CWE-74). (c) A text report opened in a terminal is only as safe as the
  `neutralize` table (R4 invisible characters stay visible).
- Mitigation: save the reports as `.txt`/`.json`/`.gha.txt`, never `.md`. Add
  `docs/reviews/canonix-acceptance-*` to the self-scan `exclude` anyway. Add an index
  `README.md` that is the only Markdown file there, for `/link-check`. Never print the
  github report in a workflow.

### [MEDIUM] C3 The acceptance run must not widen the `python:` gate
- Vector: acceptance item 4 ("domain extension on") can be done with
  `builtin:domain` + `[[telemetry_domains]]`. Running it with
  `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1` exported in the shell, or from inside the
  CanonixEngine checkout (where its config, `$PWD` and markers apply), puts the
  operator's machine at A-ext's mercy if any `python:` spec is ever added.
- Mitigation: run from the DocSentinel checkout with `--config` pointing to a
  DocSentinel-owned config (`examples/telemetry-domains.toml` or a copy). No
  `--extension python:*`, no `--allow-python-extensions`, and the env var unset (state
  this in `status.md`). The run must use the locked env (`uv run --locked`) so that it
  exercises the released code paths.

### [LOW] C4 Docs and release notes that normalise the `python:` opt-in
- Vector: `docs/user/tutorial/custom-reports.md:281,347` already shows
  `--allow-python-extensions` and the env var. Release notes and README samples get
  copied into CI.
- Impact: readers set the env var at workflow or job level (every step, including
  `pull_request_target` jobs that check out PR heads), or in a repo-controlled
  `.envrc`/direnv file, which hands the gate to the scanned repository (extensions T1/R4).
- Mitigation: see the Task 02 constraints below.

### [LOW] C5 Version bump and packaged templates
- Templates ship as package data (`tests/integration/test_template_package_data.py`).
  A version bump must not reintroduce `force-include` or an artifact path that would
  pull a working-tree template over the packaged one (the packaged-first resolution,
  M-name, relies on the wheel contents). Re-run that test against the built wheel after
  the bump. The default JSON schema change (D1) is a consumer-integrity issue: release
  notes must give the `--format json-v1` migration line.

## Task 01 security checklist (beyond what exists)

| # | Check | Existing coverage | Gap? |
|---|---|---|---|
| 1 | Hostile `path` through all five packaged templates (CLI) | `tests/integration/test_reporter_hostile_filename.py` | no |
| 2 | Hostile `message`/`value`/`pending` through text/github/json and a **custom `--template`** in one integration fixture | unit: `tests/unit/test_reporting_control_characters.py`, `test_telemetry_extension_templates.py`; no CLI fixture with hostile `value` + custom template | **yes** |
| 3 | Two CLI scans give byte-identical output for every template x fast/standard/deep | unit only: `test_telemetry_engine.py:1626`, `test_telemetry_model.py:235`, `test_telemetry_document_stats.py:157` | **yes** (integration) |
| 4 | Untrusted variable without sink rejected; neutralize tables pinned | `tests/unit/test_telemetry_loader.py`, `test_telemetry_filters.py` | no |
| 5 | `TemplateError`/`ExtensionError` exit 2; findings exit 1; deep advisory exit 0 | `tests/mock/test_extension_trust_gate.py`, `tests/integration/test_report_cli_templates_ds101.py` | verify `ExtensionError` -> 2 through the CLI; deep is skipped without the spaCy model (03.0 f) |
| 6 | `import docsentinel` + text render imports no spaCy and no **user** extension module | `tests/integration/test_import_isolation.py` (spaCy only), `tests/unit/test_importlib_tripwire.py` | **yes**: assert no `python:` module is imported when none was requested |
| 7 | M32 pytest-plugin half: plugin config in a scanned repo cannot reach `python:` | `tests/mock/test_extension_trust_gate.py:362` covers doctor/rules/init/baseline only | **yes** (follow-up c) |
| 8 | `doctor` with an escaping or symlinked `report_templates_dir`; `--format` with `--baseline`/`--strict` | none (03.0 follow-up d) | **yes** |
| 9 | Whole `telemetry_domains` table budget (many max-length star globs) bounded in time/steps | per-glob bounds only (`config.py:108-109`); `tests/unit/test_telemetry_domains.py` has no worst-case test | **yes** (follow-up a) |
| 10 | `value`/`details` never carry snippets | `tests/integration/test_finding_enrichment_ds101_ds102_ds103.py` | no; extend it to DS104+ if they populate `value` |
| 11 | Self-scan ignores `docs/reviews/canonix-acceptance-*` and the sdist excludes it | none | **yes** (C1/C2) |
| 12 | Performance: 358-document report within 2x the pre-milestone time | `scripts/bench_corpus.py` pattern, no test | **yes** (also re-measures R5/R7 step use) |

### Ranking of open follow-ups

- **(c) M32 plugin half, no dedicated test: MUST close before the milestone ends.** It
  is the missing proof for Task 01 item 4 on a code-loading surface. Same for the NUL
  `origin_roots` entry: it must raise `ExtensionError`, not `ValueError` (error
  contract, small fix plus a test).
- **(a) Domain matcher worst case: SHOULD fix before close.** It is reachable from a
  scanned repo's config on every default JSON scan (`domain_for` always runs). It only
  affects availability (CWE-1333-like, CWE-400), but the fix is a cheap total-character
  budget in `validate_telemetry_domains`. If deferred, record it as an accepted residual
  next to D-C.
- **(b) Stale `domain_table` cache: MAY stay recorded.** It needs an in-process library
  caller that mutates a validated `Config`. LOW integrity impact (wrong `domain`
  label), so fix it when the code is touched.
- **(c) F3 string-keyed `check_path` cache, F5 tripwire spellings, 40-hop off-by-one:
  MAY stay recorded.** F3 falls under the accepted R3 (point-in-time check), F5 is a
  test-hygiene gap, and the hop bound fails closed.
- **(g) 0006 spec amendments: MUST be recorded as blocking on Milestone 0006 Task 02/03
  before 0007 closes.** No 0007 code change is needed, but the 0006 specs must state
  that `telemetry_sink` is root-contained and that the adapter calls `domain_for`. The
  0007 docs must not imply either is already done.

## Constraints for Task 02 docs

1. **0006 honesty**: do not claim FaultEvent emission, `telemetry_sink`, or an adapter
   that consumes `classify`/`domain_for`. State that `EventHookGuard` has no
   production caller and that the FaultEvent half of the domain acceptance test is
   skipped until 0006 Story 03.0.
2. **`python:` wording**, used the same way everywhere (CLAUDE.md, README, release
   notes, guide):
   - argv-only (`--extension python:...` plus `--allow-python-extensions` or
     `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1`, exactly `1`);
   - a `python:` entry in config is a `ConfigError`;
   - an admitted extension runs with **full trust** (R1, not a sandbox);
   - the origin check is point-in-time (R3);
   - an editable or project-local install is refused.
   Never describe the gate as "safe for untrusted repos".
3. Never show the env var set at workflow or job level, in a `pull_request_target`
   example, in `.envrc`, or in a pre-commit hook `args:`. If an example is needed,
   scope it to a single step that runs on trusted refs.
4. Recommend `--format github` (not `text`) in Actions (T2-R2). Do not suggest
   printing saved reports in CI (C2).
5. Domain labels are asserted by the scanned repo (R5). Do not present `doc.domain` as
   a verified ownership signal.
6. Do not write absolute local paths (`~/Projects/CanonixEngine`, `/Users/...`) into
   shipped docs or release notes. In `status.md`, refer to the corpus by name only.
7. Release notes: put the JSON default change (D1) and the `--format json-v1`
   migration line first. Note that `report_templates_dir` fails closed for every
   format (03.0 b).

## Verdict: PASS_WITH_FOLLOWUP

No CRITICAL or HIGH findings. Task 01 may start. Milestone close is gated on: checklist
gaps 2, 3, 6, 7, 8, 11 closed, follow-up (c) M32/NUL closed, (a) fixed or explicitly
accepted, (g) recorded on 0006, and C1 resolved (owner consent plus a pre-commit
leak check, or reports kept out of git).
