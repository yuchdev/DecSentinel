# Task 01 — Cross-surface tests, mapping gate, conformance tripwire, no-PII

**Parent story:** [Story 04.0](/docs/roadmap/0006-fault-telemetry/04.0-tests-docs-and-extraction-readiness/README.md)  
**Proposed sources:** `tests/unit/`, `tests/mock/`, `tests/integration/`

## Required tests (for `testing-expert`)

- **Single-call-site parity:** the CLI (`docsentinel scan --telemetry`), the
  library API (`from docsentinel import scan`), and the pytest plugin's
  `docsentinel_scan` fixture all produce the same event stream for the same corpus
  — proving the one `engine.scan()` call site serves every consumer.
- **Mapping-coverage gate (unit):** iterate `RULES` and assert every registered
  code appears in the adapter's `FAULT_CLASSES` dict; separately assert the dict and
  [`fault-classes.md`](/docs/specs/fault-classes.md) agree (parse the table). A
  new rule shipped without a row fails this test, not production.
- **Conformance tripwire (unit):** assert DocSentinel's `FaultEvent` field set, the
  `tier`/`outcome` vocabularies, and `SCHEMA_VERSION` equal literals transcribed
  from [the spec](/docs/specs/fault-event-contract.md) §1–§3. A schema change that
  updates one but not the other fails.
- **Per-sink tests:** `JsonlSink` (stdout + append file, one JSON line per event),
  `LoggingSink` (captured via `caplog`, valid JSON payload), `SqliteSink` (row
  round-trip via `SELECT`, append across scans), `NullSink` (no output), and the
  `python:<module>:<callable>` loader (imports a test sink; a bad target errors
  clearly).
- **No-PII bound (unit):** build a `Finding` whose `message` embeds a document
  snippet; assert the emitted event's `details` and top-level fields contain no
  substring of that snippet — including after it passes through the persisting
  `SqliteSink` (read the row back) and `LoggingSink`.
- **Schema round-trip (unit):** every emitted JSONL/logging line parses with
  `json.loads` and carries exactly the agreed keys (`ts`, `domain`, `class`,
  `tier`, `rule`, `outcome`, `model`, `schema_version`, `details`).
- **Default-off (e2e):** a scan with no telemetry flag is byte-for-byte identical in
  stdout and exit code to the pre-milestone behaviour.

## Constraints

- Follow the repo test layout: `tests/unit/` tiny inline strings, `tests/mock/` for
  the sink-error and bad-`python:`-target cases, `tests/integration/` over
  `tests/assets/` corpora.
- Do not weaken existing DS1xx/DS2xx/DS301 suites; telemetry tests are additive.
