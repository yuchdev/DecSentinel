---
name: deep-review
description: Periodic (weekly / on-demand) deep-profile review: runs the confirmed deep scan, captures DS301 candidates, drives the docs-reviewer custom agent to triage them and review doc-vs-code behavioral drift, files a dated report to docs/reviews/. Explicitly not a per-commit hook.
---

# deep-review

Periodic and on-demand review workflow for DocSentinel's `deep` profile and doc-vs-code behavioral drift. Invoke as `/deep-review [--weekly]`.

## Cadence and execution policy

- **On-demand by default**: `/deep-review` executes a single review cycle and terminates immediately after writing the review report.
- **Weekly periodic mode**: Copilot CLI has no built-in scheduler. `--weekly` marks the run as one cycle of a weekly cadence; the cadence itself is achieved by running the skill from cron or a scheduled GitHub Actions workflow (e.g. `copilot -p "/deep-review --weekly"`), or manually once a week. Each run performs exactly one cycle and never reschedules itself.
- **Never per-commit**: Deep scans and semantic reviews are computationally expensive, heuristic, and advisory. This skill must **never** be attached to commit hooks or blocking CI gates.

## Initial rotating review slices

The skill rotates across the doc-source pairs over successive weekly cycles:

1. `docs/architecture/README.md` ↔ `src/docsentinel/engine.py`, `src/docsentinel/config.py`
2. `README.md` ↔ `src/docsentinel/cli.py`
3. `docs/dev/python_coding_standard.md` ↔ `ruff.toml`, `pyproject.toml`
4. `CONTRIBUTING.md` ↔ `tests/` test fixtures and scan entry points

## Step algorithm

### 1. Readiness gate
Check whether deep profile dependencies and models are installed:
```bash
python -c "from docsentinel.deep_support import deep_ready; import sys; sys.exit(0 if deep_ready() else 1)"
```
If exit code is non-zero (dependencies or model missing), print setup guidance and **stop immediately without writing a report**.

### 2. Capture candidates
Run the confirmed deep scan and save JSON output to `.copilot/state/deep-review-candidates.json`.
Use `--format json-v1`: it keeps the schema 1 shape (one flat `findings` list, each entry with its
own `path`) that the `docs-reviewer` triage reads. The default `--format json` is schema 2, which
groups problems per document.
```bash
mkdir -p .copilot/state
docsentinel scan --profile deep --i-understand-deep-is-heuristic --format json-v1 > .copilot/state/deep-review-candidates.json
```

### 3. Select review slice
Read the `slice_index` from `.copilot/state/deep-review-state.json` (defaulting to `0` when absent), and use it modulo the four slices above to select the current doc/source pair. The candidates report remains scan output only and is never used as state.

### 4. Drive `docs-reviewer`
Delegate with the `task` tool using the custom agent type `docs-reviewer` (defined in `.github/agents/docs-reviewer.agent.md`), passing the file paths for the captured candidates JSON and the selected doc/source review slice. Instruct the agent to generate `docs/reviews/YYYY-MM-DD-deep-review.md`.

### 5. Record & finish
- After the report is successfully written, atomically update `.copilot/state/deep-review-state.json` with `{"slice_index": <selected index + 1>}`. Do not advance the cursor if candidate capture or report generation fails.
- **On-demand mode**: Print summary of findings and report location, then terminate.
- **Periodic mode (`--weekly`)**: Print the same summary and terminate. The next weekly cycle is started externally (cron / scheduled GitHub Actions workflow running `copilot -p "/deep-review --weekly"`, or manually); it resumes from the `slice_index` cursor.

## Termination

On-demand mode terminates after one report is written; each periodic (`--weekly`) run is also a single cycle that stops after its report, or earlier if deep dependencies are unavailable.

| Mode | Condition | Action |
|---|---|---|
| Any | Deep dependencies/model not installed | Print install guidance and stop |
| On-demand | Report written to `docs/reviews/` | Print summary and stop |
| Periodic (`--weekly`) | Report written to `docs/reviews/` | Print summary and stop; next cycle is triggered externally (cron / scheduled workflow) |
