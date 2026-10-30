# Task 01 — Test matrix and security review

**Parent story:** [Story 05.0](/docs/roadmap/0007-telemetry-driven-reporting/05.0-tests-docs-and-acceptance/README.md)

## Test matrix

Follow the repo layout (`tests/unit`, `tests/mock`, `tests/integration` with
`tests/assets/<case>/`), and run each of these across fast, standard and deep
fixtures where a profile matters:

| Concern | Layer | Check |
|---|---|---|
| Restructure inert | integration | pre-move goldens (Story 01.0) |
| Determinism | integration | two scans → identical bytes, all templates |
| No hardcoded format | unit | AST tripwire (Story 03.0 Task 02) |
| Output safety | integration | injection fixtures in `path`, `message`, `value`, `pending` through text/github/json and a custom template |
| Trust rule | unit | untrusted variable without sink filter rejected |
| JSON v1 compatibility | integration | `json-v1` equals legacy bytes |
| Baselines | integration | an existing baseline file still matches after `Finding` enrichment |
| Exit codes | integration | `TemplateError`/`ExtensionError` → 2; findings → 1; deep advisory → 0 |
| Lazy imports | unit | importing `docsentinel` and rendering `text` imports no spaCy and no extension code |
| Performance | integration | rendering the 358-document-scale synthetic report stays within 2× the pre-milestone render time (`scripts/bench_corpus.py` pattern) |

## Security review (`security-auditor`, blocks merge on CRITICAL)

Write `docs/security/` notes covering:

1. **Template as data:** no `eval`, no attribute traversal, no recursion bomb
   (node depth cap, loop output cap, total output size cap) -- add and test the caps.
2. **Escaping completeness:** every untrusted variable reaches a sink filter; the
   moved neutralization tables are byte-identical to the originals.
3. **Config-supplied template paths:** containment, symlink-out, size, encoding.
4. **`python:` extensions:** the invoker-only opt-in cannot be reached from a
   scanned repository's files; the module is not imported before the check; error
   messages do not leak paths unescaped.
5. **Extension output as untrusted:** extension-provided strings are tagged
   `untrusted` by default in text templates unless the extension declares
   otherwise and the declaration is itself reviewable.
6. **`value` / `details`** never carry document snippets.

## Tests (for `testing-expert`)

Implement the matrix above; use `/test-gap` afterwards and close any
risk-ranked gaps before the milestone closes.
