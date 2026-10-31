# Threat Model - Milestone 0007 Story 02.0 Template engine - 2026-10-31

Pre-implementation threat model for Story 02.0 (`telemetry/{loader,engine,filters}.py`).
It is normative input for Task 01 (loader) and Task 02 (renderer/filters) and must be
linked from both. Nothing below is implemented yet; evidence cites the contracts
(`docs/specs/report-template-format.md`, ADR 0003, the two task specs) and the
committed code they build on (`telemetry/model.py`, `reporting.py`,
`detectors/deprecated_refs.py`).

## Assets & trust boundaries

Assets: integrity of the terminal / CI log / GitHub workflow-command stream; the
existing control/bidi/zero-width neutralization guarantee (`reporting.py:40-120`);
host files outside the scan root; CI availability.

Threat actors: (A1) a contributor who controls the scanned checkout -- document
names and content (and so `path`, `message`, `value`), **and** `docsentinel.toml` /
`pyproject.toml`, so also `report_templates_dir` and every template file in it;
(A2) the invoker (argv, env), trusted like any argv path (spec §10) but able to pass
`model` from loosely controlled CI metadata.

Boundaries:

1. Scanned repo -> `ReportModel` context (untrusted strings: `doc.path`,
   `p.message`, `p.value`, `p.document_path`, `pending`; `model.py:73-74,86,94,126`).
2. Config-named path -> template loader (file gate, containment).
3. **Template file -> renderer.** A config-named template is A1-authored content;
   its literals, separators, `output.*` settings and loop structure are hostile input,
   not code-reviewed configuration.
4. Renderer output -> terminal / CI log / GHA command parser / JSON consumer.

## Findings

Severities are design-risk ratings; each turns into a mandatory mitigation (M-n) with
an owning task. No CRITICAL: the spec already fails closed on the main hazards. The
two HIGH items are gaps where a literal reading of the spec gives a bypass.

### [HIGH] T1 Trust is lost through loop aliases and container variables
- Vector / evidence: `CONTEXT_SCHEMA` tags `pending` as `list[str]` UNTRUSTED with no
  element schema (`model.py:126`), and gives `documents`, `documents_with_problems`,
  `findings`, `opt_in_off`, `problems` trust `None` (`model.py:97,123,130-133`). A loader
  that looks up a loop alias (`over: pending, as: reason`) and finds no element
  `Variable`, or that treats `None` as "not untrusted", accepts `{reason}`,
  `{pending|join(", ")}`, `{documents}` or `{doc.problems}` with no sink. `join`
  returns raw member strings, so this re-opens log forging / Trojan Source
  (CWE-117, CWE-150, CWE-1007). The current text sink already prints `pending` raw
  (`reporting.py:204`); its values are constants today, so that is not exploitable
  yet.
- Impact: untrusted control or bidi code points reach the terminal through a template
  that passes the loader.
- Mitigation:
  - **M1:** an element of a list inherits the list's trust.
  - **M2:** a `None`-trust container counts as untrusted when any descendant is untrusted.
  - **M3:** emitting a non-scalar (dict, or list not reduced by `join`/`len`/`json`) in a
    text position is a load-time `TemplateError`, so `str()`/`repr()` of a container
    is never output.
  - Owner: Task 01. Tests: `{reason}` over `pending` rejected and
    `{reason|neutralize}` accepted; `{pending|join(", ")}` rejected and
    `{pending|join(", ")|neutralize}` accepted; `{documents}` and `{doc.problems}`
    rejected; nested alias `{p.message}` inside `doc.problems` rejected.

### [HIGH] T2 Trust rule ignores filter order and output context
- Vector / evidence: spec §8 only asks for "a sink filter in its chain". Two problems:
  - (a) Order. `{p.message|neutralize|lower}` satisfies "in chain" but applies a
    transform after the sink. A future filter (`ext.*`, `default(x)` with a
    template-supplied argument) could add unsafe characters after neutralization.
  - (b) Context. The rule accepts any sink in any text template. In a GitHub template,
    `{doc.path|neutralize}` or `{doc.path|json}` in the `file=` property leaves `,` `:`
    `%` unencoded. A name like `a,title=Forged,line=1` or one containing `%0A` then
    forges annotation properties or splits the message after the runner unescapes it
    (CWE-74, CWE-117).
- Impact: forged or misattributed GitHub annotations from a custom or edited `github` template.
- Mitigation:
  - **M4:** the chain for an untrusted variable must **end** with a sink filter (a
    closed check, not "contains").
  - **M5:** the envelope declares the sink context (for example
    `output.sink: "terminal" | "github"`).
  - **M6:** under `github`, only `gha_property`/`gha_data` count as sinks. `neutralize`
    and `json` do not.
  - SHOULD: in a `github` line, a variable in the property segment (before the second
    `::`) requires `gha_property`. Implemented for every variable, trusted ones
    included (a trusted `model` id may carry `:`); an `append` loop continues an
    unknown line, so all its variables need `gha_property`.
  - Line start (security review): under `github`, every emitted line that carries a
    variable (`line` nodes, block-loop body lines, `one-line` and `append` loops) must
    start with literal text that, after trimming leading whitespace, is neither empty
    nor a lone `:`. Otherwise a finding message such as `::stop-commands::` would begin
    a line and run as a live workflow command.
  - Owner: Task 01 (rule), Task 02 (golden test that packaged `github.json` uses
    `gha_property` for `file=` and `gha_data` for the message). Tests:
    `{p.message|neutralize|upper}` rejected; `{doc.path|neutralize}` rejected in a
    github-sink template.

### [MEDIUM] T3 Template text is hostile but not validated
- Vector / evidence: a config-named template (A1) can put raw ESC, CR, bidi/zero-width
  characters or `\ud800` (valid JSON escape, lone surrogate) into `line.text`,
  `separator`, `prefix`/`suffix`, `output.join`, a JSON `indent` *string* (accepted by
  `json.dumps`), or a JSON literal with `ensure_ascii: false`. It can also print
  literal workflow commands (`::error`, `::stop-commands::`) or a forged
  "0 findings" line.
- Impact: terminal escape injection, a lone surrogate that makes stdout un-encodable
  (crash, exit-code confusion), forged CI annotations or summary lines (CWE-150, CWE-116).
- Mitigation:
  - **M7:** reject any template string (keys and values) containing a code point
    from the `neutralize` table (`reporting.py:59-64`), CR/LF included.
    `output.join` may only be `"\n"`.
  - **M8:** `output.indent` is `null` or an int in 0..8. `ensure_ascii` must be `true`
    for every v1 json template, custom ones included (or, if `false` is ever allowed,
    surrogates and C1/bidi must still be escaped).
  - Document that a repo-supplied template controls the report's literal content, and
    that the exit code, not the text, is authoritative.
  - SHOULD: write a one-line stderr note naming the non-packaged template in use
    (repudiation).
  - Owner: Task 01 (M7, M8 validation), Task 02 (pin `ensure_ascii`).

### [MEDIUM] T4 Template file gate: traversal, symlinks, special files, TOCTOU
- Vector / evidence:
  - Name resolution joins `report_templates_dir/<name>.json` (Task 01 §contract).
    A name like `../../x`, or `report_templates_dir` itself being a symlink or
    escaping the root, reads outside the root (CWE-22, CWE-59).
  - The DS115 gate this reuses does `os.stat` then `open`
    (`deprecated_refs.py:851-860`). A FIFO swapped in between blocks the scan
    (CWE-367).
  - `read(_MAX)` silently truncates a file that grows after the stat.
  - An injected `Config` bypasses `load_config` validation (same as DS115 R1).
- Mitigation:
  - **M9:** a packaged-or-dir name must match `^[a-z0-9]+(-[a-z0-9]+)*$`; any other
    source is a path. Packaged names resolve first and cannot be shadowed by
    `report_templates_dir`.
  - **M10:** a config-named file goes through `is_ds116_owned` ->
    `resolve_local_reference` RESOLVED -> `escapes_via_symlink`. These are checked on
    the **final joined file path** and on the directory, inside the loader (not only
    in `load_config`), before any open. No second resolver.
  - **M11:** open with `O_NOFOLLOW | O_NONBLOCK` where available, then `fstat` the fd
    for `S_ISREG` and size <= 256 KiB. Read `MAX + 1` bytes and reject (not truncate)
    if larger. Decode with strict UTF-8 and reject a BOM.
  - argv paths get the same regular-file/size/encoding gate but no containment.
  - Accepted residual risk: `O_NOFOLLOW` guards only the final path component, so an
    intermediate directory swapped for a symlink between the containment check and the
    open (TOCTOU) is not caught; and on Windows `os.O_NOFOLLOW` does not exist, so the
    flag is a no-op there. Both need write access to the scanned checkout during the
    scan, which already controls the template, so they are accepted rather than fixed
    with `openat`-style directory-fd walking.
  - Owner: Task 01. Tests:
    - mock: out-of-root dir, `../` name, symlink-out file and FIFO are refused
      without `open`;
    - a repo `text.json` in `report_templates_dir` does not override the packaged one;
    - a file that is MAX+1 bytes is rejected.

### [MEDIUM] T5 Parse and validation bombs
- Vector / evidence: inside 256 KiB a hostile template can contain:
  - about 260k nested `[` or a deeply nested `not` (`RecursionError` in `json.loads`
    or the recursive validator);
  - an int with more than 4300 digits (`ValueError`);
  - `NaN`/`Infinity` (accepted by `json.loads` by default);
  - duplicate keys.
- Impact: an uncaught traceback (raw template bytes can reach stderr) or a
  stack-overflow crash instead of exit 2 (CWE-674, CWE-400).
- Mitigation:
  - **M12:** `object_pairs_hook` rejects duplicates, and `parse_constant` rejects
    NaN/Infinity.
  - Wrap `json.loads` and validation so `RecursionError`, `ValueError` and
    `UnicodeDecodeError` become a bounded `TemplateError`.
  - Check structural depth before any recursion: node/condition nesting <= 32 and
    total nodes <= 10,000.
  - List-index segments (`{items.0}`) are non-negative decimals of at most 6 digits.
  - Filter arguments are quoted string literals of at most 256 chars, parsed without
    `eval`/`ast.literal_eval`.
  - Owner: Task 01. One negative test per item.

### [MEDIUM] T6 Output amplification at render time
- Vector / evidence: loops can nest freely. A loop over `findings`, inside a loop
  over `documents`, inside a loop over `findings` gives O(F^2 * D) lines (about 12.5M
  on the 358-document / 187-finding corpus in ADR 0003). `one-line` builds a single
  huge line, and JSON `$for` grows the same way (CWE-400, CWE-770).
- Mitigation:
  - **M13:** loop nesting depth <= 4, checked at load (Task 01).
  - The renderer stops with a `TemplateError` once output passes a fixed cap (for
    example 64 MiB of characters) or an iteration budget. It never truncates
    silently (Task 02).
  - Test: a nested-loop template over a synthetic context hits the cap and raises.

### [MEDIUM] T7 Template injection, introspection and operator confusion
- Vector / evidence:
  - A `message` containing `{run.id}` or `{doc.__class__}` must not be expanded.
  - A dotted path must not reach `getattr` (`{doc.keys}`, `{p.message.upper}`).
  - Context data embedded with `{"$var": "run"}` or by an extension could carry
    `$`-prefixed keys that a naive walker evaluates as operators (CWE-1336, CWE-94).
- Mitigation:
  - **M14:** substitution is single-pass. Substituted values are never re-scanned.
    No `str.format`, `format_map`, `%`, `eval`, or `getattr`; traversal is only
    `dict[key]` / `list[int]`.
  - Operators are evaluated on template nodes only, never on values returned by `$var`.
  - An unknown `$`-key in a template is a `TemplateError`, not a literal.
  - The renderer rejects any context node that is not JSON-shaped.
  - `ext.*` filters resolve only from the loaded-extension registry, never through
    `importlib` from template text.
  - Owner: Task 01 (load-time: `{doc.__class__}`, `{doc.keys}`, `$foo` rejected);
    Task 02 (a message with `{run.id}{{` renders literally; an object in the context
    raises `TemplateError`).

### [MEDIUM] T8 Invoker-supplied `model` is tagged trusted with no bound
- Vector / evidence: `model.py:129` tags `model` TRUSTED, and `ReportModel.build`
  copies it unchecked (`model.py:256`). Once Story 03.0 or 04.0 wires it from argv or
  env (CI often fills these from PR or commit metadata), it reaches the text and
  GitHub sinks unescaped (CWE-117).
- Mitigation:
  - **M15:** validate `model` where it enters, in `ReportModel.build`:
    `^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`, else raise `ValueError` (exit 2 in the
    CLI). Alternatively retag it UNTRUSTED. A trusted tag is only acceptable together
    with the bound.
  - Owner: prerequisite for `python-expert`, before or with Task 01. Task 01 test:
    `{model}` accepted unfiltered only while the bound exists; unit test that `build`
    rejects ESC, newline, U+202E and a 129-char value.

### [LOW] T9 Error messages leak or forge
- Vector / evidence: `TemplateError` echoes JSON paths built from hostile keys
  (`"varibles_used"` or an ESC-laden key), unknown variable text, and the template
  path. `str(OSError)` carries the absolute path (CWE-209, CWE-117).
- Mitigation:
  - **M16:** every echoed fragment goes through `filters.neutralize` and is bounded
    (80 chars, as in DS115 `_echo`).
  - Echo the configured value, never `realpath` or an absolute host path, and never
    `repr(exc)`.
  - `str(TemplateError)` is safe on its own, because library callers print it as well
    as `cli.py`.
  - Owner: Task 01. Test: a key containing ESC/U+202E plus a 1 KiB unknown variable
    gives a bounded, escaped message; a path refused by containment does not appear
    resolved.

### [LOW] T10 Cache mutation and staleness
- Vector / evidence: "frozen dataclasses" with `list`/`dict` fields can still be
  mutated in place, which poisons the `(name, mtime, size)` cache (Task 01 l.34).
- Mitigation:
  - **M17:** use only tuples and `MappingProxyType` inside the parsed template.
  - Cache only packaged templates, keyed by the resolved resource path.
  - Owner: Task 01. Test: mutating a returned template raises.

### [LOW] T11 Escape ambiguity (accepted)
- `neutralize` does not escape `\`, so a path that literally contains the text `\x1b`
  renders the same as a neutralized ESC. This spoofs the display but injects nothing,
  and it is pre-existing behaviour.
- Accept and document. The move must stay verbatim (Story DoD); Task 02 parity tests
  pin it.

### [INFO] Elevation / AI / secrets
- Templates are data-only, so Story 02.0 has no code-execution path; `python:`
  extensions are Story 04.0 and stay gated by `--allow-python-extensions`.
- There is no AI backend or prompt surface in this story.
- No secrets are handled, and the render path must not read env (Task 02 contract).
  Test by patching `open`, `os.stat` and `os.environ` access to raise during
  `render_template`.

## Mandatory test ownership

| Mitigation | Task |
|---|---|
| M1-M3 (trust propagation), M4-M6 (sink order/context), M7-M8 (literal hygiene), M9-M11 (file gate), M12 (parse bombs), M13 (loop depth), M14 load-time part, M16, M17 | 01 loader |
| M6 golden `github.json`, M8 `ensure_ascii` pin, M13 output cap, M14 render-time part, filter parity/sweep, no-I/O render | 02 renderer |
| M15 `model` bound | prerequisite (`model.py`), then 01 |

Hand fixes to `python-expert` and these tests to `testing-expert`.

## Verdict: PASS_WITH_FOLLOWUP

The design is sound: templates are data, the operator and filter sets are closed, and
the spec fails closed. The follow-ups are mandatory acceptance criteria, not
nice-to-haves. Story 02.0 must not merge to `master` until M1-M17 are implemented
and tested. A later review that finds a missing T1 or T2 mitigation in the code
escalates to **BLOCK**.
