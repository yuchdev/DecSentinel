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

## Re-review of T2 against 5b9704d (2026-10-31)

Probe: `validate_template` on crafted mappings (scratch script, no product edits).
Runner evidence: `actions/runner` `src/Runner.Common/ActionCommand.cs` (`TryParseV2`
trims leading whitespace then needs `::`; on failure `ActionCommandManager.TryProcessCommand`
falls back to legacy `TryParse`, which finds `##[` **anywhere** in the line via
`IndexOf` and accepts any registered command: `stop-commands`, `add-mask`,
`set-output`, `save-state`, `error`, `warning`, `debug`, `group`, ...).

Holds: line-start rule for `line` nodes, `group` bodies, block-loop bodies,
`one-line`/`append` (prefix counted); `""`/`":"`/NBSP/whitespace leads rejected
(Python `lstrip` is a superset of .NET `TrimStart`); trusted `model` at line start
rejected and its charset `[A-Za-z0-9._:/@+-]` cannot carry `#`/`[`/CR/LF;
`separator`/`prefix`/`suffix` cannot hold CR/LF (M7); `": {var}"` is harmless (V2
needs `::` after trimming).

### [HIGH] T2-R1 Legacy `##[cmd]` parser makes any non-V2 line with an untrusted value live
- Vector / evidence: `loader.py` `_emitted_text` only guards the line **start**.
  Accepted under `output.sink: "github"`:
  - plain lines: `"Finding: {p.message|gha_data}"`;
  - `append` after a plain line: `"Paths:"` + append `" - {doc.path|gha_property}"`;
  - command lines with no literal second `::`: `"::warning {p.message|gha_property}"`;
  - a variable in the command-name slot: `"::{p.message|gha_property}::{p.message|gha_data}"`.
  V2 rejects each of these lines (no `::` lead, no second `::`, or an unregistered
  name), so the runner falls back to the legacy parser. `gha_data`/`gha_property`
  encode `% CR LF` (`: ,`), but not `#`, `[` or `]`. A message, value or path holding
  `##[stop-commands]tok` (for example a DS101 target `[x](##[stop-commands]tok)`, or a
  file name) becomes a live command. A literal ending in `#`/`##` can also complete
  `##[` with the value (CWE-77/CWE-74, CWE-117).
- Impact: annotations from the rest of the job are suppressed (`stop-commands`),
  annotations are forged, secrets are masked (`add-mask`), and step outputs or state
  are poisoned (`set-output`/`save-state`). The exit code is not affected. Applies to
  custom github templates; the legacy `reporting._render_github` emits only
  well-formed V2 lines and is not affected.
- Mitigation (python-expert): under `github`, a line (or `append` continuation) that
  carries an **untrusted** variable must be a well-formed V2 command:
  - the leading `::`, then a **literal** command name from a closed allowlist
    (`error`/`warning`/`notice`/`debug`/`group`), so no variable may sit before the
    first space or the second `::`;
  - a **literal** second `::`;
  - untrusted variables only after `::name ` (with `gha_property`) or after the
    second `::` (with `gha_data`).
  Plain and other non-command lines, and `append` loops that cannot prove they
  continue such a line, may carry only trusted variables whose charset excludes
  `#[]` and CR/LF. Tests (testing-expert): the four accepted shapes above are
  rejected, and a `##[` split across a literal and a value is rejected.

### [LOW] T2-R2 `terminal` sink in Actions (accepted risk)
- `terminal` output does not target Actions. `neutralize` leaves `::` and `##[`
  alone, so `{doc.path|neutralize}: ...` (accepted) or a `##[...]` message is live
  when text output runs in a workflow. The legacy `--format text` has the same
  behaviour, so this is pre-existing. Any tool that prints untrusted text has it too.
  Accept it, and document in the user docs: use `--format github` or a
  github-sink template in Actions, or wrap text output in
  `::stop-commands::<random>`. No loader rule.

### Re-review verdict: BLOCK
The T2 mitigation is incomplete in code (T2-R1). Per the escalation clause above,
Story 02.0 stays out of `master` until T2-R1 is fixed and tested.

### Status update (python-expert, 2026-10-31)
- **T2-R1: mitigated.** `loader.py` `_emitted_text` now applies these rules under the
  `github` sink:
  - An untrusted variable is accepted only when the line opens with
    `_GHA_COMMAND_PATTERN`: ASCII spaces, then `::`, then a literal
    `error`/`warning`/`notice`/`debug`/`group`, then a literal space or `::`. The line
    must also hold a literal second `::`.
  - Plain lines and every `append` loop may carry only trusted variables.
  - An untrusted variable after the second `::` needs `gha_data`.
  - `_reject_hash_join` rejects a variable directly after a literal ending in `#`. This
    covers the loop prefix, and the item text plus separator of an inline loop.

  The line-start rule and `gha_property`-for-every-property-variable rule from 5b9704d
  are kept. The feature-reviewer one-line fix is also in: `::` markers in per-item text
  are counted from the prefix count. Tests in `tests/unit/test_telemetry_loader.py`:
  - `test_github_untrusted_variable_outside_command_line_is_rejected` covers the four
    vectors above, plus an unlisted name and a name glued to a variable.
  - `test_github_variable_after_hash_literal_is_rejected` covers the split `##[` case.
  - `test_github_command_data_needs_gha_data`.
  - `test_github_standard_command_is_accepted_in_every_placement`.
  - `test_github_one_line_full_command_text_still_checks_segments`.
- **T2-R2: accepted risk** (no loader rule). Spec §8 and
  `docs/user/tutorial/report.md` ("Hostile characters in paths and messages") now
  recommend `--format github` in Actions, or wrapping text output in
  `::stop-commands::<random>`.

### Re-attack of T2-R1 (security-auditor, 2026-10-31, at fcb9c42)
About 50 probes went through `validate_template`. No data-driven command or `##[` forgery was accepted.
- Trusted text values cannot carry `#`, `[`, `]`, CR or LF: `model` (charset), `run.id` (hex),
  `run.generated_at`, `profile` (enum), `notice`, `advisory`, and the rule/fault-class
  strings (checked against all 17 registered rules). `{enabled_rules|json}` and
  `{opt_in_off|json}` can start with `[`, but `##[` followed by them gives an unregistered name.
- Rejected: untrusted values through `default`/`lower`/`len`/`join`/`json`, then `gha_data`
  on a plain line; tab or `:` leads; `endgroup`/`groupx`/`ERROR`; a command with no second `::`;
  gha_data used as a property / gha_property used as data; any `append` that carries untrusted
  values; a `#` at the end of a prefix, an item, a separator or an append prefix.
- Inline `::` counting can only undercount (fail closed). A runner split earlier than the
  validator's split only moves variables from the property segment into the data segment.
- The standard shape is expressible: one `line` per severity, routed by
  `when {"var":"p.severity","eq":"error"|"warning"}`; `::group::{...|gha_data}` titles also pass.
- [INFO] `default('…')`/`join('…')` arguments are not covered by `_reject_hash_join`
  (`x{model|default('##')}[error]y` is accepted). They are author literals, the same as
  T3's accepted literal `##[`, so there is no new capability.
- [FOLLOW-UP] Extension variables (`ext.*`, and `telemetry_domains` values from the scanned
  repo's config) must be tagged untrusted when §9 lands, or they reopen T2-R1 on plain lines.
- [ASSUMPTION] The defense relies on runner V2 parsing not failing on a well-formed line
  (a failure falls back to legacy). gha_property escaping keeps properties parseable.

### Re-attack verdict: PASS (T2-R1 closed; follow-up above tracked for the extensions task)

## Story-close review of the renderer (security-auditor, 2026-10-31, at 60f520b)
Scope: `telemetry/engine.py` and `telemetry/filters.py`. Probes were scratch scripts run through
`validate_template` and `render_template`; no product code was edited.

Holds:
- M14: a value holding `{run.id}{{ {doc.path} $var %s` renders literally in text and in `$str`.
  Context data with `$var`/`$for` keys is embedded as data.
- JSON: a hostile path such as `"}, "forged": true, ...` plus a lone surrogate, NUL or U+2028
  round-trips as a single string value. Output is pure ASCII and keys come only from the template.
- M8: `ensure_ascii` is forced in the engine, and the loader also rejects `false`.
- Text backstop: a trusted value carrying ESC is refused.
- `neutralize`, `gha_property` and `gha_data` give the same output as the pre-move
  `reporting.py` (`60f520b~1`) on all 0x110000 code points, and the tables are equal.
- §7 escaping: `gha_property` encodes `% CR LF : ,` and `gha_data` encodes `% CR LF`. `#[]`
  are left as they are, which is covered by T2-R1. No Cc/Cs code point is left after `gha_data`.
- Error messages echo only template names and kind words. `TemplateError` is neutralized and
  capped at 512 characters.
- Purity: there are no I/O, environment or clock imports, and the purity mock test passes.

### [MEDIUM] R1 Output cap is charged only after a whole line or `$str` is built (CWE-400, CWE-770)
- Evidence: `engine.py:315-332` `_interpolate` joins every piece before `_emit` (`:441`) or
  `JsonStr` (`:534-535`) charges the budget. The `json`/`join` filter output is not capped.
- Probe: one 3.2 KB line `{documents|json}` x200 over a 1.1 MB corpus reached a 435 MB peak and
  took 22 s before the cap fired. With the cap lowered to 1 MB the peak was the same. A
  256 KiB template (about 16k repeats) scales this to tens of GB, so the process is killed by
  OOM instead of exiting 2.
- Mitigation (python-expert): charge each substituted piece as it is appended in
  `_interpolate`, and do not count it again in `_emit`/`JsonStr`.
- Test (testing-expert): a line that repeats `{documents|json}` raises as soon as the
  cumulative length passes the cap. Assert this with a monkeypatched cap and a peak-memory bound.

### [MEDIUM] R2 Quadratic `append` stays under both caps (CWE-407)
- Evidence: `engine.py:474-475` `lines[-1] += segment` copies the whole line for every append.
  CPython's in-place concat does not apply to a list item.
- Probe: a block loop of n items, each running an `append` with a 200-char prefix, took
  0.37 s at n=2000, 4.6 s at n=8000 and 115 s at n=32000. Output was only 6.5 MB, far under both
  caps. A nested `documents` x `findings` loop on the ADR 0003 corpus is about 67k appends, so
  the CI job hangs.
- Mitigation: buffer the open last line as a list of segments and join it once when the next
  line starts or rendering ends.
- Test: n=100k appends render in linear time (time bound or op-count).

### [LOW] R3 Library-supplied context escapes the error contract
- Evidence:
  - An int with more than 4300 digits makes `to_text`/`_scalar_text` (`filters.py:245,258`)
    raise a bare `ValueError`, not `TemplateError`.
  - A cyclic list/dict passes `_check_context` because it is de-duplicated by `id`. `_size`
    (`engine.py:236-254`) then loops forever on `$var`.
  - A shared-subtree DAG of depth 40 makes `_size` exponential (hang).
- Reachability: `ReportModel.build` cannot produce any of these, so only a direct
  `render_template` caller can.
- Mitigation:
  - Catch `ValueError` in `to_text`.
  - Reject cycles in `_check_context` (ancestor set).
  - Let `_size` stop early against the remaining budget, or memoize by `id`.

### [LOW] R4 Invisible code points outside the neutralize table (pre-existing, parity-locked)
- The text backstop and `neutralize` pass these through: U+00AD, U+180E, U+2060-U+2064,
  U+FFF9-U+FFFB, the Hangul fillers U+115F/U+1160/U+3164/U+FFA0, variation selectors, and
  tag characters U+E0000-U+E007F (invisible "ASCII smuggling").
- This injects no terminal command, but it can hide text in a path or message (CWE-451).
  Keep the move verbatim now. Widen the table in Story 03.0, and update the legacy sink and
  the parity tests in the same change.

### [INFO]
- `ensure_ascii` writes lone surrogates as `\udXXX` escapes. This is the same as JSON v1, but
  strict parsers (for example serde_json) reject them. Accepted.
- `reporting.neutralize_text(non-str)` now raises `TemplateError` instead of
  `AttributeError`. CLI callers pass `str`, so nothing changes for them.

### Story 02.0 verdict: PASS_WITH_FOLLOWUP
- No CRITICAL finding. Single-pass substitution, JSON structure, escaping parity and purity hold.
- R1 and R2 are gaps in M13 (render-time cap). M13 is a mandatory mitigation, so both must be
  fixed and tested before Story 02.0 merges to `master`.
- R3 and R4 are tracked follow-ups (R4 is for Story 03.0).

## Re-attack of the renderer caps (security-auditor, 2026-10-31, at 3c2f526)
Scope: `telemetry/engine.py`, `telemetry/filters.py` after the R1/R2/R3 fixes. The old probes
were re-run and new ones added (scratch scripts only; no product code edited).

Closed:
- **R1 closed.** One line `{documents|json}` x200 over a 1.1 MB corpus: with a 1 MB cap it now
  stops with a peak of about 0 MB (was 435 MB). With the 64 MiB cap it stops at a 67 MB peak.
  `join` over 100M characters, `join|json` and `json|json` are refused before they are built.
- **R2 closed.** `append` x n is linear: n=32000 now takes 1.7 s (was 115 s). 1M appends take 30 s.
- **R3 closed.** A self-cyclic list is rejected. A shared DAG of depth 40 stops at the cap
  instead of hanging. A 5000-digit int gives a `TemplateError` in text, `$str`, `$var` and
  `|json`. A 200k-deep list or dict gives a `TemplateError` (`RecursionError` is caught) in
  about 6 s.

### [MEDIUM] R5 Render CPU is not bounded: work that emits nothing is never charged (CWE-400, CWE-834)
- Evidence: `_Budget` counts only loop items (`engine.py:231-238`) and emitted characters
  (`:240-248`). Three kinds of work are not charged:
  - A `line`/`group`/`loop` whose `when` is false (`_nodes`, `:585-596`).
  - An inner loop over an empty list (`_loop`, `:613-626`).
  - `$if` false, `$omit_if` true, and the `null` it yields (`:679-701`).
- `_Budget.reserve` (`:257-267`) checks a `json`/`join` result against the remaining budget, but
  it never charges it. A result reduced by `len` is never charged at all.
- Probes (A1 template, loop nesting <= 4, nodes <= 10000):
  - 300x300 iterations x 100 false-`when` lines took 27 s, about 3 us per node. At 300x300 x 1000
    the run was killed by a 150 s CPU limit.
  - The bound is MAX_ITERATIONS x MAX_NODES = 5M x 10k node evaluations, about 40 hours. This
    needs only about 2236 documents nested twice, or 48 documents nested four times.
  - 1000x1000 x 50 inner loops over an empty list: 120 s, with zero output.
  - `{enabled_rules|json|len}` x200 on one line, each value 30M characters: 185 s and 1600 output
    characters. `join|len` took 110 s. Inside a loop this is multiplied by the number of
    iterations, with no limit.
  - The caps themselves are slow even when a render stays inside them:
    - 5M trivial text iterations: 27 s.
    - 5M trivial json `$for` iterations: about 65 s.
    - 64M empty lines: about 4 min and more than 1 GB, extrapolated from 13M lines in 49 s and
      245 MB.
- Impact: a contributor who controls the checkout and its template hangs the CI job until the
  job timeout (the GitHub default is 6 h), without crossing either cap. This is the same
  class as R2, which was merge-gating.
- Mitigation (python-expert):
  - Add a step budget, for example `MAX_STEPS` of about 20M, plus `_Budget.step()`. Charge one
    step for each text/json node visited, each condition node evaluated and each filter call,
    whether or not the node emits anything.
  - Charge the length of every materialized `json`/`join` result (and `lower`/`upper`) to a
    work budget, even when a later filter discards it. A separate `MAX_WORK_CHARS` of about
    4 x MAX_OUTPUT_CHARS would do.
  - Option: have the loader reject `json|len` and `join|len`, which have no use.
  - Product decision: consider lowering MAX_ITERATIONS to 1M and MAX_OUTPUT_CHARS to 16 MiB.
    Real reports are about 67k appends on the ADR 0003 corpus.
- Tests (testing-expert), each must raise `TemplateError` in bounded time (op-count or
  monkeypatched caps):
  - nested loops x 1000 false-`when` lines;
  - nested loops x empty inner loops;
  - `{x|json|len}` repeated on one line;
  - json `$for` x `$if` false.

### [LOW] R6 `ensure_ascii` expansion is only bounded after serialization (accepted)
- `_size` counts `len + 2` for a string. Serialization can be up to 12x longer (an astral code
  point becomes `\udXXX\udXXX`), and the final `len(rendered)` check fires only after the string
  is built.
- Probes:
  - 5.5M astral characters gave 66M of output, accepted and within the cap.
  - 30M astral characters (120 MB of input) were refused, with a 499 MB peak.
- The transient size is at most 12 x min(input, cap), about 800 MB, a constant factor of the
  input that is already in memory. Accepted. Optional hardening: when `not s.isascii()`, add
  the non-ASCII count x 5 to the estimate.

### Re-attack verdict: BLOCK (merge gate for Story 02.0)
- No CRITICAL. R1, R2 and R3 are fixed and verified, and R4 stays tracked for Story 03.0.
- R5 is an open gap in mandatory mitigation M13. A hostile template can still keep the CI job
  busy for hours while staying under both caps. By the rule already applied to R1/R2, Story 02.0
  stays out of `master` until R5 is fixed and has regression tests. R6 is accepted.
- This BLOCK comes from the M13 gate, not from a CRITICAL. After the step/work budget lands,
  the expected verdict is PASS.

### Status update (python-expert, 2026-10-31)
- **R5 fixed.** `_Budget` now has a step budget and a work budget (`telemetry/engine.py`):
  - `MAX_STEPS = 2_000_000`. One step is charged for each text/json node visited, each condition
    node evaluated (an `in` condition one more per operand), each loop item, each variable
    lookup and each filter call, whether or not anything is emitted.
  - `MAX_WORK_CHARS = 4 x MAX_OUTPUT_CHARS`. The length of every string a filter builds is
    charged, even when `len` discards it. `json`/`join` are refused before they are built when
    their estimate would pass the work budget.
  - Passing either budget raises `TemplateError` (`template work larger than N steps`,
    `filters built more than N characters`). The spec is unchanged and the loader still accepts
    `json|len`.
- Why 2M and not the suggested 20M: on the review machine one step costs about 2.5 us, so 20M
  steps would still allow about 50 s of render.
- Margin: a 358-document scan with 5000 findings costs about 120k steps under the
  severity-routing `github` template. That is 16x below the cap, and an integration test pins it
  under `MAX_STEPS // 10`. With 20000 findings it costs about 480k steps, 4x below. Because each
  loop item is also a step, `MAX_STEPS` now binds before `MAX_ITERATIONS`.
- Probes re-run at the fix (machine load about 18):
  - Every R5 shape now stops with `TemplateError` in 2-6 s. This covers false `when` lines,
    `any`/`in` conditions, empty inner loops, 13 empty lines per item, the nested append loop,
    `$for` x `$if` false and nested `$for` `$var`.
  - `json|len` x200 and `join|len` x200 at 30M characters each now stop in 2-3 s (were 185 s
    and 110 s).
  - The json `$for` probes take 15-23 s only under `tracemalloc`, and about 5 s without it.
- Regression tests (`tests/unit/test_telemetry_engine.py`):
  - Six non-emitting shapes run with a lowered step cap.
  - The 300x300 x 100 probe runs with the real cap.
  - An exact cap boundary.
  - `json|len`/`join|len`/`lower|len` with a lowered work cap, which also asserts how many
    builds happen.
  - The normal case under the work cap.
  - `tests/integration/test_template_renderer_report.py` pins the realistic-report margin.
  - The 32k-append test now uses a 10 s bound plus an exact count of segment starts and extends.
- **R6 accepted.** The transient `ensure_ascii` expansion is at most 12 x min(input, cap), a
  constant factor of a context that is already in memory. The final length check still refuses
  any output past the cap. The optional non-ASCII estimate is not implemented.

## Final re-audit of the renderer caps (security-auditor, 2026-10-31, at b308240)
- R5 is verified closed for every shape in its test list. Steps are charged on nodes,
  conditions, `in` operands (at most 256), loop items, lookups and filter calls. Filter chains are
  charged by step and by work. Repeated json `$var` of a large list is charged its full bounded
  size on every reference. The work budget (4 x 64 MiB) is cumulative, not resident: one filter
  result is still refused above the remaining output cap. That memory risk is accepted.
- Realistic margin: `tests/integration/test_template_renderer_report.py` passes (4 tests). At about
  120k steps the cap leaves about 16x headroom.

### [HIGH] R7 json `indent`/nesting amplification is charged at the compact size (CWE-400, CWE-770)
- Vector: `engine.py:725,769,774` charge `_size`, which is a compact lower bound. The real
  serialization is `json.dumps(..., indent=...)` at `engine.py:710`, and its length is checked only
  after it is fully built (`:713`). With `indent` 1..8, each nested level costs `depth x indent`
  more characters per line. A `$default` literal can be about 95 levels deep (`_MAX_RAW_DEPTH`) and
  is one node, so 2 steps per item.
- Evidence (scratchpad `r6_indent.py`, `r6_budget.py`): `$for` over a nested loop (480 x 480 docs)
  with `{"$var":"model","$default":[[...95...]]}` and `indent: 8` passes every budget: 460k/2M
  steps, 65.8M/67.1M chars. `json.dumps` would then build about 16.7 GB. Measured at 5000 items:
  59 s and 1.2 GB RSS before the final post-check refused the output. Template-only JsonArray
  nesting (depth 30) gives about 250x more characters than charged. The pure-Python encoder also
  spends about depth^2 generator hops per item. Separately, `_thaw` makes a fresh copy for each
  item and the `_sizes` memo pins every copy: 560 MB RSS at 20k items with compact output.
- Impact: one hostile template can OOM-kill or stall a CI job while every budget passes. This is
  the M13 gap that R5 was meant to close. R6 was accepted as a constant factor of in-memory
  context. R7 is a template-controlled factor of about 250-380x, so R6's rationale does not apply.
- Mitigation (python-expert): stream with `JSONEncoder(indent=..).iterencode` and charge each
  chunk against the remaining cap, aborting at the cap; this also closes R6. Charge steps for each
  container in a literal/default (or depth-weighted when `indent` is set). Thaw each `$default`
  once per node, not per item (cache by node id). Tests (testing-expert): the deep-`$default` x
  `$for` x `indent: 8` probe and the template-array depth-30 probe must raise `TemplateError`
  within bounded time and memory.

### Final verdict: BLOCK (M13 gate, no CRITICAL)
- R7 is a HIGH bypass of the render budget. Story 02.0 stays out of `master` until R7 is fixed and
  has regression tests. All other findings: R1-R3 and R5 closed, R4 tracked, R6 accepted.

### Status update (python-expert, 2026-10-31, R7)
- **R7 fixed.** `telemetry/engine.py` now streams json output through `_JsonStream`, an
  explicit-stack serializer with the same bytes as `json.dumps(indent, ensure_ascii=True,
  sort_keys)`. Each chunk is charged as it is produced, and passing `MAX_OUTPUT_CHARS` raises
  `TemplateError`. One chunk built through C `json.dumps` is a sub-tree whose worst case is at most
  1 MiB. This is any small sub-tree without `indent`, or a container of scalars with `indent`. This
  also closes R6.
- Each container inside a `$default` costs one step. A `$default` is thawed once per node and
  shared, not copied per item. Template arrays and objects are charged their brackets and commas.
- Probes at the fix: the deep-`$default` x 140x140 x `indent: 8` shape stops in 0.5-1.8 s at about
  90 MB RSS. Depth-30 template arrays x 60000 with `indent: 8` stop in about 4 s. The remaining
  memory is the evaluated body, which `MAX_STEPS` bounds.
- Regression tests in `tests/unit/test_telemetry_engine.py`: both R7 shapes run under a lowered
  cap with time and traced-peak bounds, and both fail on b308240. The tests also cover
  byte-identity with `json.dumps` across indent and `sort_keys`, the exact cap boundary, and
  thaw-once with step charging.
