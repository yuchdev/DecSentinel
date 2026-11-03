# Threat Model - Milestone 0007 Story 04.0 Extensions - 2026-11-03

Pre-implementation threat model for Story 04.0 (`telemetry/extensions.py`,
`telemetry/builtin/{domain,document_stats}.py`, the `telemetry_extensions` /
`telemetry_domains` config surface and the `--extension` / `--allow-python-extensions`
CLI surface). Nothing below is implemented yet. It is normative input for Task 01
(extension API, loader, trust gate) and Task 02 (`builtin:domain`,
`builtin:document_stats`), and both task specs should link it. Evidence cites the
contracts (`docs/specs/report-template-format.md` §6-§10, plan D5/D7, the two task specs,
Milestone 0006 Story 02.0 Task 01) and the committed code the story builds on.

The format and numbering follow
[threat-model-0007-template-engine-2026-10-31.md](/docs/security/threat-model-0007-template-engine-2026-10-31.md).
Mitigation numbers here (M1..) are local to this file. Template-engine mitigations are
cited as "TE-Mn".

## Assets & trust boundaries

Assets:
- CI host integrity: no code execution chosen by the scanned checkout, and CI secrets
  (`pull_request_target`, deploy tokens).
- Integrity of the terminal, CI log and GitHub workflow-command stream (T2-R1 guarantee).
- Integrity of the report and of `FaultEvent.domain` (hallucination-rate data).
- The exit code contract (`0/1/2`).
- CI availability.

Threat actors:
- **A1 (scanned checkout).** Controls document names and content, `docsentinel.toml` /
  `pyproject.toml` (so `telemetry_extensions`, `telemetry_domains`,
  `report_templates_dir` and every template in it), any `*.py` file or package in the
  checkout, and `[tool.pytest.ini_options]` / `.pre-commit-config.yaml`. If the checkout
  is a Python project installed with `uv sync`, it also controls its own
  editable-installed packages, which are importable from the DocSentinel venv.
- **A2 (invoker).** Controls argv and the environment. Trusted, but CI often sets env
  workflow-wide, including on jobs that run untrusted PR heads.
- **A3 (extension author).** Writes a `python:` extension. It is in-process code, so it
  runs with full code trust once it is admitted. Its *output* still carries A1 data
  (paths, messages) and must be treated as untrusted data.

Boundaries:
1. **Config / argv / env -> extension selection and trust gate.** The only boundary that
   decides whether code runs.
2. **Selected spec -> `importlib` -> module origin.** `sys.path` and the scan root.
3. **Core `ReportModel` -> hook arguments.** Read-only views.
4. **Hook return -> context `ext.<name>` subtree.** Untrusted JSON data that must be shape-
   and size-bounded.
5. **Extension filters -> loader trust rule -> text/GitHub sinks.**
6. **`telemetry_domains` (A1 config) -> `domain_for` -> `doc.domain`,
   `doc.ext.domain.*` and `FaultEvent.domain`.**
7. **Extension failure -> report path (exit 2) / event path (swallowed).**

## Findings

Severities rate the design as currently written. Each one maps to mandatory
mitigations with an owning task.

### [CRITICAL] T1 The repository chooses the code that the trust gate admits
- Vector / evidence:
  - Task 01 and spec §9 select extensions from `telemetry_extensions` in the repo config
    *and* from `--extension`. The gate (D5) is a boolean:
    `--allow-python-extensions` or `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1`. Once the gate
    is on, A1 picks *which* `python:<module>:<callable>` runs. CI sets env
    workflow-wide, and a team that needs one legitimate extension turns the gate on for
    every job, including `pull_request_target` jobs that check out the PR head with
    secrets. A PR then only edits `docsentinel.toml` (plus a module in the checkout, see
    T2) to execute code (CWE-94, CWE-829, CWE-15).
  - Task 01 reuses "the loader written for Milestone 0006's `python:` custom sink (one
    `importlib` helper, two callers)". The 0006 spec
    (`docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/01-typed-config-options.md:35-41`)
    selects `telemetry_sink = "python:<module>:<callable>"` from config and calls
    `<callable>()`. Its only protection is a sentence ("never from an untrusted checkout
    without opt-in"), with no concrete gate, flag or test. If the shared helper lands
    without the gate, or the gate lives only in `extensions.py`, a repo config **by
    itself** executes code through the sink path. That is exactly what spec §9 promises
    cannot happen.
  - `docsentinel/engine.py:128-129` (precedent for `DOCSENTINEL_DEEP_CONFIRM`) accepts
    `1/true/yes`. Copying that for a code-execution gate widens it silently.
- Impact: arbitrary code execution in CI with the job's secrets and token.
- Mitigation:
  - **M1 (spec decision, see D-A).** `python:` specs are accepted **only from argv**
    (`--extension python:...`, repeatable). In `telemetry_extensions`, any entry that is
    not `builtin:<name>` is a `ConfigError` at `load_config` (exit 2) whatever the gate
    says. The same applies to the 0006 `telemetry_sink`: `python:` is argv-only
    (`--telemetry-sink`). Alternative if the owner keeps config selection: the gate is
    an **exact allowlist of specs**
    (`--allow-python-extension SPEC`, repeatable;
    `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=SPEC[,SPEC]`), with no boolean form, and a
    config `python:` entry runs only if its spec string is byte-equal to an allowlisted
    one.
  - **M2.** `python:` needs the argv spec **and** the gate (`--allow-python-extensions`,
    or `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS` exactly equal to `"1"`; `true`, `yes`, ` 1`
    and an empty value are refused). Only `cli.py` reads the env var. The library API
    takes an explicit keyword (`allow_python_extensions: bool = False`), so
    `reporting.render`, `scan` and the pytest plugin never read the environment.
  - **M3.** The gate check lives **inside the single shared `importlib` helper**, which
    takes the gate decision as a required parameter (no default). It runs before any
    `import_module`, `find_spec` or `sys.modules` lookup. Both callers (Story 04.0
    extensions, 0006 sinks) go through it, and a test enumerates every
    `importlib.import_module` call site under `src/docsentinel/` (AST tripwire, like
    `test_reporting_has_no_format_literals.py`). Only the fixed, literal-argument sites
    in `deep_support.py`, `contradictions.py` and `_triples.py`, plus the helper, are
    allowed.
  - **M4.** A refused `python:` spec is an `ExtensionError` / `ConfigError` (exit 2) on
    **both** the report and the event path. Refusal is an authorization decision, not
    an emission failure, so the "swallowed on the event path" rule (T10) does not apply
    to it.
  - Owner: spec amendment (Task 01, spec §9, 0006 Story 02.0 Task 01), then Task 01.
  - Tests (mock `importlib.import_module` / `importlib.util.find_spec` to raise if
    called):
    - a config `python:` entry gives `ConfigError` with the flag, with the env var and
      with neither;
    - argv `python:` without the gate is refused with no import attempted;
    - env values `true`/`yes`/`1 `/`""` are refused;
    - the 0006 `telemetry_sink = "python:..."` in config is refused;
    - `render(...)` / `scan(...)` with `os.environ` patched to contain the env var still
      refuse when the keyword is false;
    - the importlib tripwire test fails when a new call site is added.

### [HIGH] T2 Import hijack: the scan root and the checkout are on the import path
- Vector / evidence: `importlib.import_module(<module>)` resolves through `sys.path` and
  `sys.modules` (CWE-427). In realistic invocations the A1 checkout is importable:
  - `python -m docsentinel` puts the cwd (usually the scan root) at `sys.path[0]`.
  - pytest (`-p docsentinel.pytest_plugin`) prepends rootdir/conftest dirs under the
    default `prepend` import mode.
  - `uv sync` in the scanned project installs it editable, so a `.pth` puts its `src/`
    on `sys.path` for the whole venv.
  - `PYTHONPATH=.` is common in CI.
  So the invoker's argv spec `python:company_ext.report:make`, meant to name an
  installed package, is shadowed by a PR that adds `company_ext/report.py` at the repo
  root. Even with M1 the invoker never chose that code. A module already in
  `sys.modules` (imported earlier by pytest from the checkout) is returned without any
  path check.
- Impact: the same as T1 (code execution chosen by A1), through a spec the invoker
  trusts.
- Mitigation:
  - **M5.** Spec grammar, checked before import:
    - module `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,15}$` (no leading
      dot, no relative import);
    - callable `^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){0,3}$` (no `_`-leading
      segment, so no dunders);
    - total length <= 256;
    - resolution by `getattr` on these validated segments only;
    - the resolved object must be callable; it is called with no arguments; the result
      must satisfy the `Extension` contract (T5/M13).
  - **M6.** Before executing the module, resolve it with `importlib.util.find_spec` for
    **every** dotted prefix, and also check an existing `sys.modules` entry's
    `__spec__.origin` / `__file__` / `submodule_search_locations`. Refuse (exit 2, nothing
    executed) when any origin or search location `realpath`s inside the scan root or
    the cwd. A namespace package, which has no origin, is refused when any of its
    search locations is inside. This does not apply when the invoker passes the explicit
    argv flag `--allow-repo-python-extensions` (owner decision D-B; recommended to
    offer it, off by default). Never mutate `sys.path` to do this: global state, and not
    safe for library callers.
    - *Amendment 2026-11-03 (close-review of Task 01, BLOCK findings 1-3, 7):* the
      boundary also includes the scan root's project roots, which are every
      ancestor (the root included) holding `.git`, `docsentinel.toml`,
      `doc_sentinel.toml` or `pyproject.toml` (amended 2026-11-03 by the
      re-verification below: previously only the nearest). Before any import, any `sys.path` entry
      inside the boundary refuses every `python:` spec. `''` and relative entries are
      resolved against the cwd. A prefix with no file location is refused unless it is
      builtin or frozen. After the import, the factories, the hooks and the render,
      a `sys.modules` before/after comparison fails the run (exit 2) when a new module
      lies inside. This is detection after the fact: the planted module has already
      run. `reporting.render` refuses a `python:` spec without `root=`. **Usability
      exemption** (auditor-approved; owner-approved by default because it does not
      reopen T2): a location or `sys.path` entry is never refused when both its
      absolute and its real path are under the running interpreter's own
      `site-packages` (`sysconfig` `purelib`/`platlib`). This covers a project-local
      `.venv` of the running interpreter. `PYTHONPATH` entries, the user site,
      editable `src/` directories added by `.pth` files and any `.venv` that is not the
      running interpreter stay refused. Residual: files committed under that
      `.venv/.../site-packages` path in the checkout are trusted (see R3).
    - *Amendment 2026-11-03 (security re-verification of Task 01, findings N1-N3):*
      - **N1.** Every marked ancestor of every spelling of the scan root (as given
        and canonical) is a project root, walked up to the filesystem root and
        bounded by 256 ancestors (past the bound: refused, never cut short). The
        scanned repository controls the markers under its own top: with "nearest
        ancestor", a `docs/.git` (even an empty file or a dangling link),
        `docs/pyproject.toml`, `docs/docsentinel.toml` or a scan root that is a link
        to `docs/` shrank the boundary to `<checkout>/docs` and dropped the checkout.
        An extra marker can now only enlarge the boundary. This fails closed more
        often: a marker high up the tree, for example a `~/.git` dotfiles
        repository, puts all of `~` (the user site and a user-installed interpreter
        included) inside the boundary, so `python:` extensions are refused there.
      - **N2.** The `sys.path` check is prevention, not only a pre-import gate: it
        runs again after every factory, before every report and event hook and at
        every `sys.modules` check. An extension that adds the checkout (cwd, scan
        root or a project root) to `sys.path`, at import time, in its factory or in
        a hook, fails the run (exit 2) before a later import can resolve through
        that entry. The `sys.modules` before/after check stays as best-effort
        detection of accidental imports; it trusts the location a module reports
        about itself, so a planted module that rewrites its own `__file__` /
        `__spec__.origin` defeats it (R3).
      - **N3.** The event path runs the `sys.modules` check after every event's
        hooks, unconditionally (a size-only shortcut missed a replaced entry).
  - Document: run the console script (not `python -m`), or `python -P`
    (`PYTHONSAFEPATH`); do not set `PYTHONPATH` to the checkout in untrusted-PR jobs.
  - `builtin:<name>` resolves through a **static** `dict` in
    `telemetry/builtin/__init__.py` (name -> fixed module path / class). The user string
    is never interpolated into an `import_module` argument, and an unknown name is
    refused before any import.
  - Owner: Task 01.
  - Tests:
    - a tmp scan root on `sys.path` with a planted `evilmod.py` that writes a sentinel
      file on import: `--extension python:evilmod:make` with the gate is refused and the
      sentinel does not exist;
    - the same check with a planted package whose parent is in-root while the leaf is
      out-of-root;
    - a pre-imported in-root module in `sys.modules` is refused;
    - `builtin:../x`, `builtin:os` and `builtin:__init__` are refused with
      `import_module` never called;
    - `python:.rel:x`, `python:os:__class__` and `python:m:_private` are refused at the
      grammar stage.

### [HIGH] T3 Extension filters launder trust (`sink: bool` self-declaration and trusted-input taint)
- Vector / evidence: Task 01 lets an extension filter declare `sink: bool`, and spec §8
  counts "an extension filter declared as a sink". The loader's trust rule decides
  sinks per output context (`FilterSpec.sinks`, `telemetry/loader.py:550-562`). The
  check is `self._sink in FILTERS[last].sinks` (`loader.py:1153`). Two bypasses:
  - (a) A boolean says nothing about the context. An extension filter "sink" that is
    counted under `output.sink: "github"` can return raw `::`, `,`, `%`, `##[` (the
    runner's legacy parser, T2-R1) on a command line. The text backstop
    (`telemetry/engine.py:836`) only rejects `neutralize`-table code points, so it
    catches none of these (CWE-74, CWE-117, CWE-77).
  - (b) Trust follows the *input* variable. `_check_ref` returns early for a trusted
    variable (`loader.py:1151-1152`). Under the github sink, plain lines and `append`
    loops may carry trusted variables. `{profile|ext.x.f}` therefore passes the loader
    while `ext.x.f` returns `##[stop-commands]tok`. A builtin filter's output is also
    computed code, not data with a known charset.
  - A python extension is already code-trusted, but a filter bug, or a filter that
    echoes A1 data it read from the context, has the same effect.
- Impact: forged or suppressed GitHub annotations, `add-mask` / `set-output` poisoning, and
  a reopened T2-R1.
- Mitigation:
  - **M7 (spec change).** Extension filters are **never sinks**. Drop `sink: bool` from
    the contract, or accept it only as `False`; `True` is an `ExtensionError`. The
    chain of an untrusted value must still **end** with a core sink (TE-M4).
  - **M8.** The output of any chain that contains an `ext.*` filter is **untrusted**,
    whatever the trust of its input. It is then subject to the full github rule set:
    well-formed command line only, `gha_property` / `gha_data` last.
  - **M9.** Extension filters are registered per render in an immutable registry built
    from the loaded extensions. They are never added to `loader.FILTERS` or
    `filters._FUNCTIONS`, and the existing `FILTER_NAMES == loader.FILTERS` parity test
    stays as it is. A name must be exactly `ext.<own name>.<filter>`, with `<filter>`
    matching `[a-z][a-z0-9_]{0,63}`; an extension cannot register a name under another
    extension or a core name. Each filter has a declared arity (0 or 1 quoted literal)
    and declared input kinds, so the loader checks it at load time.
  - **M10.** At runtime an extension filter must return a JSON scalar (`str` / `int` /
    finite `float` / `bool` / `None` of exact builtin type). Each call charges one step
    and its result length to `MAX_WORK_CHARS` (template-engine R5 budget). Any exception
    becomes a bounded `TemplateError` / `ExtensionError` (exit 2).
  - Owner: spec §7/§8 and Task 01 (amendment), then Task 01 code.
  - Tests:
    - a filter declared `sink: True` is refused at load;
    - `{p.message|ext.x.f}` is rejected in text (no core sink last);
    - `{profile|ext.x.f}` is rejected on a plain github line and accepted only as
      `::error ...::{profile|ext.x.f|gha_data}`;
    - a filter returning a dict, a `str` subclass, `NaN` or raising gives exit 2;
    - an extension registering `neutralize` or `ext.other.f` is refused.

### [HIGH] T4 `ext.*` data has no schema entry or trust tag yet
- Vector / evidence: `CONTEXT_SCHEMA` (`telemetry/model.py:124-149`) and
  `DOCUMENT_SCHEMA` / `PROBLEM_SCHEMA` (`model.py:74-105`) hold no `ext` member. The
  loader only reserves `ext` as an alias (`loader.py:998`). The values are A1-derived:
  `builtin:domain` returns `matched` (an A1 glob) and `name` (an A1 value), and
  `document_stats.worst_documents` returns document paths. An implementation that adds
  `ext` as `Variable("object", TRUSTED)` or `Variable("any", None)` with no fields could
  get it wrong. `_untrusted` (`loader.py:592-603`) does treat a `None` tag with no
  members as untrusted, but `TRUSTED` would emit hostile paths raw on terminal lines,
  and on plain github lines (T2-R1). This was already recorded as a FOLLOW-UP in the
  template-engine re-attack (`##[` on plain lines).
- Impact: log forging, Trojan Source and GitHub command injection through extension data.
- Mitigation:
  - **M11.** Add a dedicated value kind `any`, always `UNTRUSTED`. `ext` at run, document
    and problem level resolves as `object` whose members are only the names in the
    template's `requires_extensions`. Every deeper segment resolves to
    `Variable("any", UNTRUSTED)`, and trust is inherited by every descendant and list
    element (TE-M1/M2). `any` is accepted where a scalar is expected only with a
    render-time check: `to_text` already refuses containers (`filters.py:233-252`), and
    `$for` / `over` on a non-list `any` is a `TemplateError`. No extension and no
    template can mark any `ext.*` value trusted.
  - **M12.** A template that references `ext.<n>...` or a filter `ext.<n>.<f>` must list
    `<n>` in `requires_extensions`; otherwise it is a load-time `TemplateError`. The
    template is then statically checkable without the extensions loaded, and the
    render-time `_check_extensions` (`engine.py:1010-1023`) guarantees presence.
  - Owner: `model.py` / `loader.py` in Task 01.
  - Tests:
    - `{doc.ext.domain.name}` is rejected in text and accepted with `|neutralize`;
    - it is rejected on a plain github line and on an `append` loop;
    - `{doc.ext.domain}` is rejected as a container;
    - `{doc.ext.domain.name}` without `requires_extensions: ["domain"]` is rejected;
    - `$var` of a whole `ext` subtree holding `$var` / `$for` keys and an ESC/U+202E
      string renders as data, ASCII-escaped.

### [MEDIUM] T5 "Read-only views" are shallow, aliased, or bypassed by exotic types
- Vector / evidence:
  - `MappingProxyType` is shallow, so nested `list` / `dict` stay mutable.
  - `ReportModel.build` shares document dicts between `documents` and
    `documents_with_problems` (`model.py:269-270, 290-291`). A hook that mutates one
    view mutates both.
  - A hook can keep a reference to its *returned* tree and mutate it after validation:
    in a later hook call, or from a thread. That is a TOCTOU between the shape check and
    the render (CWE-367, CWE-471).
  - A returned `dict` subclass or `str` subclass can override `items`, `__len__`,
    `__str__` or `__eq__` so validation sees one thing and serialization another.
  - The extension object's `name` is read with `getattr`, and a property can return a
    different value each time.
- Impact: core data corrupted (counts, paths, severities) or validated data swapped
  before render. For a `python:` extension this is a robustness boundary, not a security
  boundary (see residual R1). For builtins and data-borne bugs it is integrity.
- Mitigation:
  - **M13.**
    - Hooks receive a **deep-frozen copy** built once per render: `MappingProxyType`
      over dicts and `tuple` for lists, recursively, and never the live context objects.
    - The copy is reused across hooks, but it does not alias the context that is
      rendered.
    - `name` is read **once**; it must be an exact `str` matching
      `_EXTENSION_PATTERN` (`loader.py:165`, `[a-z][a-z0-9_]{0,63}`); then it is stored.
    - Each hook is looked up once with `getattr(obj, hook, None)` and must be callable;
      a missing hook is a no-op.
  - **M14.** Each hook return is **copied into fresh builtin objects** during validation:
    exact `type(x) is dict / list / str / int / float / bool / None`, plus tuples
    accepted as lists. Subclasses are refused. Only the copy is attached, so later
    mutation of the original has no effect. Cycles are refused (ancestor set, as in
    `_check_context`, `engine.py:173-219`).
  - Owner: Task 01.
  - Tests:
    - mutating a nested list or dict inside a hook argument raises;
    - a hook that mutates its returned dict after return (second hook call) does not
      change the rendered report;
    - a `dict` subclass, a `str` subclass and a cyclic list are refused;
    - a `name` property that changes per access is read once.

### [MEDIUM] T6 Shape and size bounds are per hook only, and validation can itself be the DoS
- Vector / evidence:
  - Task 01 bounds depth to 8 and size to 1 MiB serialized *per hook*. Hooks run
    `1 + D + F` times per extension (run, documents, problems). With F = 100k findings
    the aggregate is unbounded in practice (about 100 GiB theoretical) before the engine
    budgets even see the context (CWE-400, CWE-770).
  - Measuring "serialized size" with `json.dumps` first builds the whole oversized
    string.
  - An `int` over 4300 digits makes `json.dumps` raise `ValueError` (template-engine R3
    class).
  - `NaN` and `inf` are not JSON.
  - Dict keys that are not strings, or are huge, are possible.
- Mitigation:
  - **M15.** The shape check is an iterative walk:
    - It counts estimated serialized size incrementally and stops at the limit, so it
      never serializes first.
    - Depth <= 8 is counted from the returned root.
    - Strings are exact `str` with no lone surrogates. Ints are bounded to
      `|x| <= 2**53`. Floats must be finite. Keys are exact `str`, <= 256 characters.
    - It caps container entries (for example <= 10k per container).
    - Per hook: <= 1 MiB.
  - **M16.** Per render and per extension, an **aggregate** cap on extension output
    (recommended 16 MiB), plus a global cap across all extensions (recommended 64 MiB,
    which equals `MAX_OUTPUT_CHARS`). Passing either is an `ExtensionError`. Rendering
    then charges extension values through the existing step, work and output budgets
    (`engine.py` `_Budget`) like any other context data, with no special casing.
  - Owner: Task 01.
  - Tests: depth 9, 1 MiB + 1, a 5000-digit int, `NaN`, a non-str key and a lone
    surrogate are each refused. A small per-problem return x many problems hits the
    aggregate cap; check this with a lowered cap and a bound on peak memory.

### [MEDIUM] T7 Hook runtime, recursion and `BaseException` escape the error model
- Vector / evidence:
  - Hooks are arbitrary Python and cannot be pre-empted safely: there is no portable
    thread kill, and `signal.alarm` works only on Unix in the main thread.
  - A hook can raise `RecursionError`, `MemoryError`, `SystemExit` or `GeneratorExit`.
    `SystemExit(0)` raised during the report would replace exit `1` (blocking findings)
    with `0`, an exit-code downgrade (CWE-703, CWE-755). A bare `except Exception` does
    not catch it.
  - Builtins doing O(D^2) or O(F*D) work (for example `worst_documents` recomputed per
    document) make large corpora slow.
- Mitigation:
  - **M17.** Wrap each hook call. `Exception` and `SystemExit` become `ExtensionError`
    on the report path and are swallowed on the event path (T10). `KeyboardInterrupt`
    propagates. The extension cannot pick the process exit code.
  - **M18.** Builtins are O(D + F) per render. `document_stats` computes
    `worst_documents` once, in `provide_run`, with a heap of size 5. The `domain_for`
    result is memoized per path. Pin it with an op-count or time-bounded test on 50k
    documents.
  - **M19 (SHOULD, decision D-C).** A cooperative cumulative wall-clock budget, checked
    with `time.monotonic()` between hook calls (for example 60 s per render). Passing it
    is an `ExtensionError` naming the extension. This bounds a slow finite extension
    but not an infinite single call (residual R2). It makes failure timing-dependent,
    so the owner decides.
  - Owner: Task 01 (M17, M19), Task 02 (M18).
  - Tests:
    - a hook raising `SystemExit(0)` with blocking findings gives exit 2, not 0;
    - `RecursionError` gives exit 2 with a bounded message;
    - `KeyboardInterrupt` propagates;
    - builtins on 50k synthetic documents stay within the bound.

### [MEDIUM] T8 `telemetry_domains` glob table: semantics, ReDoS, bounds
- Vector / evidence:
  - Task 02 says the globs "use the restricted literal/`?`/`*`/`**` subset already used
    by `documentation_naming_prefix_patterns`". That subset (`detectors/naming.py:210-247`)
    has **no `**`** and matches **one path component**. `**` and multi-segment matching
    are new code.
  - Under component semantics the documented fallback `"*" = "docs"` (spec §9 example)
    only matches top-level files. So `src/x.md` silently falls through, and its
    label then depends on undefined behaviour.
  - A naive `**` matcher (recursive backtracking), or translating the globs to `re`
    (`fnmatch.translate`, `(?:.*/)?`), is exponential on patterns like
    `**/a*a*a*a*b/**/x` against a deep `a/a/a/...` path (CWE-1333).
  - There are no count or length bounds.
  - An injected `Config` bypasses `load_config` (DS118 precedent).
  - The keys and values are A1 data that reach `FaultEvent.domain` and 0006 sinks.
- Mitigation:
  - **M20 (spec change).** Grammar:
    - The glob is split on `/`. `**` is allowed only as a whole segment and matches zero
      or more whole segments. `*` matches zero or more characters other than `/`. `?`
      matches exactly one character other than `/`. Every other character is a literal.
    - Refused: `[`, `]`, `{`, `}`, `\`, `!` at segment start, empty segments, `.` or `..`
      segments, a leading `/`, and any `neutralize`-table code point.
    - Matching is case-sensitive over the scan-root-relative POSIX path exactly as
      discovered (no NFC, no `realpath`, no filesystem access).
    - The catch-all is spelled `"**"`. When no glob matches, the result is
      `classify.DEFAULT_DOMAIN` (`"docs"`, `telemetry/classify.py:76`). Fix the spec §9
      example (`"*"` -> `"**"`).
  - **M21.** A non-regex, segment-wise dynamic-programming matcher, worst case
    O(#pattern-segments x #path-segments x segment cost). The per-segment matcher is the
    DS118 two-pointer walk (`_glob_matches`). No `re` compiled from user text and no
    `fnmatch`. Results are memoized per path.
  - **M22.** Bounds, checked in `load_config` **and** again in `domain_for` for an
    injected `Config` (fail closed with `ConfigError`):
    - <= 256 entries;
    - glob <= 256 characters and <= 32 segments;
    - a domain value matches `^[a-z][a-z0-9_-]{0,63}$` (ASCII; see D-D);
    - the table must be a TOML table of str -> str.
  - **M23.** Order: `tomllib` preserves document order and `load_config` reads a single
    file with no layering (`config.py:476-506`). Store the table as a `tuple` of
    `(glob, domain)` pairs at load, never a dict that a later merge could reorder. First
    match wins. Document that a TOML formatter that sorts keys changes the semantics
    (see D-E).
  - Owner: spec (M20), Task 02 (M21-M23), config in Task 02.
  - Tests:
    - first match wins;
    - `**` at depth 0 / 1 / 5;
    - `*` does not cross `/`;
    - `"*"` matches only top-level files and `"**"` matches all;
    - no match gives `"docs"`;
    - each refused grammar element gives `ConfigError`;
    - 257 entries, a 257-character glob, a 33-segment glob and an `Agent!` value are
      refused;
    - an injected `Config` with 10k entries raises `ConfigError` in `domain_for`;
    - the adversarial pattern x 4096-character path finishes within a time / op-count
      bound;
    - the order of the pyproject and the standalone table is preserved.

### [MEDIUM] T9 `doc.domain` shorthand collides with the core namespace and can be impersonated
- Vector / evidence:
  - Task 02 exposes `doc.domain` as a shorthand "when this extension is enabled" and says
    `json.json` "reads `doc.domain` with `$default`". In fact `json.json` emits the
    literal `"domain": "docs"` (`telemetry/templates/json.json:35`), and
    `DOCUMENT_SCHEMA` has no `domain` (`model.py:97-105`). The loader would reject
    `{"$var": "doc.domain"}` today.
  - A shorthand written *from extension output* breaks the namespacing rule ("cannot
    overwrite a core variable").
  - Extension names are self-declared (T5). A `python:` extension declaring
    `name = "domain"` satisfies `requires_extensions: ["domain"]` and fills
    `doc.ext.domain.*`. If the shorthand copies from `ext.domain`, it also forges
    `doc.domain`, and the report and `FaultEvent.domain` then disagree. That breaks the
    DoD "cannot disagree" (CWE-694).
- Mitigation:
  - **M24.** `domain` is a **core** document key, always present in `DOCUMENT_SCHEMA` as
    `str`, `UNTRUSTED`. The core provider sets it to `domain_for(path, config)` when
    `builtin:domain` is loaded and to `DEFAULT_DOMAIN` otherwise. It is never copied
    from any hook return. `json.json` switches to `{"$var": "doc.domain"}`, which stays
    byte-identical (`"docs"`) for default runs. The 0006 adapter calls the same
    `domain_for`.
  - **M25.** Every builtin name (`domain`, `document_stats`, and future ones) is
    **reserved**. A `python:` extension whose `name` is a builtin name is an
    `ExtensionError`, whether or not that builtin is loaded. Two extensions with the
    same name, or the same spec given twice, is an `ExtensionError`. Config entries and
    argv entries are merged in order, config first.
  - **M26.** An extension cannot add, replace or remove any core key at any level. It
    writes only `ext.<own name>`, `doc.ext.<own name>` and `p.ext.<own name>`. The
    merge step builds `ext` itself, so a hook return containing `"path"` or `"ext"`
    stays inside its own subtree.
  - Owner: Task 02 (M24), Task 01 (M25, M26).
  - Tests:
    - a `python:` extension named `domain` is refused;
    - `doc.domain` equals `FaultEvent.domain` for `.claude/agents/x.md` and `docs/x.md`
      (skip-gated until 0006 Story 03.0 is merged);
    - a hook returning `{"path": "forged"}` leaves `doc.path` unchanged;
    - the default `json.json` output is byte-identical before and after.

### [LOW] T10 Error model: leakage, partial output, silent event-path failure
- Vector / evidence:
  - `str(exc)` from a hook can carry A1 data (a document path with ESC or U+202E) or
    absolute host paths (`ImportError` / `ModuleNotFoundError` messages, `__file__`)
    (CWE-209, CWE-117).
  - An exception class name is attacker-chosen in `python:` code
    (`type("\x1b[2J", (Exception,), {})`).
  - If any report text reaches stdout before a hook fails, exit 2 comes with a partial
    report that looks complete.
  - "Swallowed on the event path" with no trace hides a broken extension forever
    (CWE-778), and an implementation that swallows on the report path too would fail
    open.
- Mitigation:
  - **M27.**
    - `ExtensionError` messages echo only the configured spec or the validated name,
      the hook name, the exception class `__qualname__` and up to 200 characters of
      `str(exc)`.
    - Each part is truncated, then passed through `filters.neutralize`, and the message
      is capped at 512 characters.
    - Never `repr(exc)`, a traceback, `realpath`, or a module `__file__`.
    - `str(ExtensionError)` is safe on its own (library callers print it).
    - The CLI prints `Scan failed:` (exit 2), as for `TemplateError`.
  - **M28.** The report context, including every hook, is fully built and rendered to a
    string before the first byte is written to stdout (the current
    `cli.py:388` render-then-print order must hold).
  - **M29.** Event path: hook `Exception` / `SystemExit` is swallowed, the event is
    emitted with core fields only, and **one** bounded, neutralized stderr warning
    is written per extension per run (not per event). Gate refusals and config errors
    are never swallowed (M4).
  - Owner: Task 01.
  - Tests:
    - a hook raising with an ESC / U+202E / 1 KiB message gives a bounded, escaped
      message that contains no absolute path;
    - stdout is empty when a hook fails;
    - on the event path one warning is written for 100 failing calls and the exit code
      is unaffected;
    - on the report path the same failure gives exit 2.

### [LOW] T11 `requires_extensions` check: identity, ordering, social engineering
- Vector / evidence:
  - Templates list *names* (`_EXTENSION_PATTERN`, `loader.py:875-892`), but selection
    uses *specs* (`builtin:x`, `python:m:c`). Without M25 a name can be satisfied by an
    impersonating extension.
  - Task 01 says the error should name "how to enable it". A hostile repo template
    whose `requires_extensions: ["evil"]` produces "enable with
    `--allow-python-extensions --extension python:...`" turns the tool into a social-
    engineering channel.
  - A template must never trigger loading.
  - The CLI resolves the template before the scan (`cli.py:130-134`), so the check
    order must be defined.
- Mitigation:
  - **M30.** Order: argv/config -> gate (M1-M4) -> resolve and instantiate extensions
    -> load and validate the template (M12) -> check `requires_extensions` against the
    loaded, validated names -> scan -> hooks -> render. The check compares exact names
    and **never** loads anything.
  - **M31.** The missing-extension message names the extension (neutralized). For a
    builtin name it suggests `--extension builtin:<name>` / `telemetry_extensions`. For
    a non-builtin name it says only that a `python:` extension providing that name must
    be supplied by the invoker, and links the docs. It never suggests
    `--allow-python-extensions` or a module path.
  - Owner: Task 01.
  - Tests:
    - a template that requires `domain` does not load `builtin:domain` by itself;
    - the message for `evil` contains no `--allow-python-extensions` and no `python:`;
    - a missing extension fails before the scan runs (no detector invoked).

### [LOW] T12 Side surfaces that could import or enable extensions
- Vector / evidence:
  - `doctor`, `rules`, `init` and `baseline` load config. If any of them "validates" an
    extension by importing it, merely running `doctor` on a checkout executes code.
  - The pytest plugin and pre-commit hooks run inside A1-controlled config
    (`addopts`, `[tool.pytest.ini_options]` env plugins, `.pre-commit-config.yaml`
    `args`).
  - Baselines and templates are JSON data that might grow an "extensions" key.
- Mitigation:
  - **M32.** Only `scan` with a report (and the 0006 emission path) resolves
    extensions. `doctor` lists configured specs (neutralized) and the gate state, and
    reports `python:` entries in config as an error (M1), without importing. The
    baseline loader and the template loader keep unknown-key rejection, so neither file
    can name an extension spec. `baseline` never runs hooks, so fingerprints are
    unaffected.
  - **M33.** The pytest plugin exposes no extension or gate option. A future one must
    take only explicit fixture/kwarg arguments, never ini/addopts. Document that pytest
    and pre-commit already execute repository-controlled code (conftest,
    `language: system`), so the gate adds no protection there (residual R4).
  - Owner: Task 01.
  - Tests:
    - `doctor` / `rules` / `init` / `baseline` with config `python:` entries and the
      gate env set never call `import_module` / `find_spec`;
    - a baseline or template carrying an `extensions` key is refused.

### [LOW] T13 Builtin correctness that becomes availability or integrity
- Vector / evidence:
  - `document_stats` computes `problems / (bytes / 1024)`. `bytes` is `None` for a
    finding path outside the inventory (DS204 Python sources, `model.py:256-264`), so
    the formula raises `TypeError` and every standard-profile scan with a DS204 finding
    exits 2.
  - Floats such as `-0.0`, and rounding near ties, can make output differ between
    platforms.
  - `domain` is self-reported by A1, so a repo can relabel `agent` documents as `docs`
    and skew aggregated hallucination metrics.
- Mitigation:
  - **M34.** `bytes is None` gives `problem_count_per_kb: null`, and the document is
    excluded from `worst_documents`. `bytes == 0` gives `0.0`. The value is
    `round(x, 3)` and cannot be NaN or inf by construction. Ties are broken by
    `(-density, path)`. The run-level list holds at most 5 entries.
  - Document `domain` as a repository-asserted label, not an authenticated attribute
    (residual R5).
  - Owner: Task 02.
  - Tests: an out-of-inventory finding, a zero-byte document, equal densities, and the
    same output bytes on two runs.

### [INFO] T14 Spec inconsistencies to fix before coding
- Task 01 says the name is "kebab/snake, `[a-z][a-z0-9_]*`". Hyphens cannot appear in a
  variable segment (`_SEGMENT_PATTERN`, `loader.py:166`), so a kebab name would be
  unreachable. Use exactly `^[a-z][a-z0-9_]{0,63}$` (M13).
- Spec §9 calls `--extension NAME`. The value is a spec (`builtin:x` / `python:m:c`).
- `ReportModel.build(extensions=...)` currently raises `NotImplementedError`
  (`model.py:249-250`). Task 01 replaces it, and `render_template(extensions=)` must
  receive the loaded *names* from the same registry, never from the template.

## Mandatory test ownership

| Mitigation | Owner |
|---|---|
| M1, M7, M20 and the T14 fixes (spec wording); M1/M3/M4 for the 0006 sink | spec amendment before coding; 0006 Story 02.0 Task 01 |
| M1-M6 (gate, helper, grammar, origin check), M7-M12 (filters, trust, `ext` schema), M13-M17, M19, M25-M33 | Task 01 |
| M18, M21-M24, M34 | Task 02 |

Hand fixes to `python-expert` and the listed tests to `testing-expert`.

## Residual risks (accepted, documented)

- **R1.** An admitted `python:` extension is full in-process code. It can monkeypatch
  `filters.neutralize`, `loader.FILTERS` or the exit path, and reach a
  `MappingProxyType`'s backing dict through `gc.get_referents`. M5-M17 protect against
  *data* and bugs, not against a malicious admitted extension. The trust boundary for
  code is the gate (M1-M6) alone. Extensions run in selection order in one process, so
  one extension can alter shared state that the next one sees. That state includes
  `sys.modules`, module globals and the frozen model's backing dicts. (Amended
  2026-11-03.) (Amended 2026-11-03, re-verification N3.) The `sys.modules` check
  cannot see what an admitted extension hides from it; these need the extension's own
  cooperation: importing a module and then deleting its `sys.modules` entry;
  `spec_from_file_location` + `exec_module` without inserting the module;
  `runpy.run_path`; scrubbing or rewriting a module's `__spec__`/`__file__`; and any
  import-and-delete done inside a single hook.
- **R2.** A single hook that never returns cannot be stopped in-process. The CI job
  timeout is the backstop.
- **R3.** M6's origin check is a point-in-time check. A checkout that is modified during
  the scan, between `find_spec` and exec, is not covered (the same accepted TOCTOU class
  as TE-M11). `.pth` files, `sitecustomize` and `PYTHONPATH` set by the invoker are
  outside DocSentinel's control. (Amended 2026-11-03.) A few cases are still out of
  reach:
  - the `sys.modules` before/after check is best-effort detection of accidental
    imports; it is defeated by a planted module that rewrites its own location
    (`__file__`/`__spec__.origin`), it detects a planted module only after it has
    run, and it skips entries that carry no location. (Amended 2026-11-03,
    re-verification N2: an in-boundary `sys.path` entry is now refused before
    later imports instead, see M6; the blind spots listed in R1 remain);
  - every marked ancestor of the scan root is in the boundary (re-verification N1),
    so a stray marker high up the tree (a `~/.git` dotfiles repository) refuses
    `python:` extensions for everything below it;
  - modules under the running interpreter's `site-packages` are exempt, even when that
    `.venv` lies inside the checkout and the checkout commits files there;
  - the stdlib is not exempt, so running from a cwd that contains the interpreter (for
    example `~` with a uv-managed Python) refuses `python:` extensions.
- **R4.** pytest and pre-commit run repository code already, so the gate is moot in those
  contexts.
- **R5.** `domain` labels are asserted by the repository (data integrity of aggregated
  telemetry, not security).
- **R6.** The T2-R1 defense still assumes the runner's V2 parser does not fail on a
  well-formed line (carried over unchanged).
- **Out of scope, flagged for 0006.** `telemetry_sink = "file:<path>"` / `"sqlite:<path>"`
  are specified as "not root-constrained" yet are read from the repo config. A hostile
  `docsentinel.toml` can therefore append to or create files anywhere the CI user can
  write (CWE-73). Make these argv-only too, or give them the same treatment as M1.

## Owner decisions

- **D-A (gate shape, required).** Either (recommended) `python:` is argv-only for both
  extensions and 0006 sinks, or config may name it only when an exact-spec allowlist on
  argv/env matches. Under both options the boolean
  `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1` alone must never admit a config-chosen
  module. Choosing argv-only changes spec §9, Task 01 "Selection" and the D5 wording.
- **D-B.** Whether to offer `--allow-repo-python-extensions` for extensions that live in
  the scanned checkout (refused by default under M6).
- **D-C.** Whether to add the cooperative wall-clock budget (M19). It is
  non-deterministic.
- **D-D.** The domain value charset (`^[a-z][a-z0-9_-]{0,63}$` recommended, the same
  vocabulary as 0006). A wider charset stays safe in reports (UNTRUSTED) but needs a
  separate review of 0006 sinks.
- **D-E.** Whether to replace the ordered TOML table with an order-explicit array
  (`[[telemetry_domains]] glob = ..., domain = ...`), which key-sorting formatters
  cannot reorder.

## Verdict: BLOCK (design as currently specified)

T1 is CRITICAL. As written, the boolean gate together with config-chosen modules, and
the ungated shared 0006 `python:` helper, let repository content select code to
execute. Task 01 must not implement the loader until D-A is decided and M1-M4, M7 and
M20 are written into spec §7-§9, Task 01, Task 02 and 0006 Story 02.0 Task 01. Once
those amendments land, the expected design verdict is PASS_WITH_FOLLOWUP, with M5-M34 as
mandatory acceptance criteria.

### Checklist for the security review at task close

Task 01:
1. The importlib tripwire passes, and the gate is enforced inside the shared helper.
   This covers the `python:` refusals in config, the env truthiness set and library
   env-independence (M1-M4).
2. The planted-module, in-root parent and pre-imported `sys.modules` probes execute
   nothing (M6). `builtin:` resolves only through the static table (M5).
3. Extension filters are never sinks. Chains containing them are tainted untrusted, and
   a `{profile|ext.x.f}` plain github line is rejected (M7-M10).
4. `ext.*` values are `any` / UNTRUSTED at every depth, and `ext.<n>` needs
   `requires_extensions` (M11-M12). Re-run the T2-R1 probe set with `ext` variables.
5. Deep-frozen arguments, copy-on-return, refusal of subclasses and cycles, and a name
   read once (M13-M14).
6. Per-hook and aggregate bounds are enforced incrementally (no `json.dumps` first), and
   rendering charges extension data to the existing budgets (M15-M16).
7. `SystemExit(0)` cannot downgrade exit 1; `KeyboardInterrupt` propagates (M17).
8. Error messages are bounded, neutralized and free of paths. stdout is empty on
   failure. The event path writes one warning and never swallows refusals (M27-M29).
9. Load order and the `requires_extensions` message contain no gate hint (M30-M31).
   `doctor` / `rules` / `init` / `baseline` never import (M32).

Task 02:
10. The glob grammar, `**` semantics, the `"**"` catch-all and the default fallback hold;
    the matcher has no regex; the bounds are re-checked for an injected `Config`; and
    the adversarial pattern finishes within the time bound (M20-M23).
11. `doc.domain` is a core UNTRUSTED key from `domain_for` only. Builtin names are
    reserved. Default `json.json` stays byte-identical, and the report and
    `FaultEvent.domain` are equal (M24-M26).
12. `document_stats` handles `bytes: null` and zero bytes, has a deterministic
    tie-break, and is O(D + F) (M18, M34).
13. The user guide states the trust model: R1-R4, D-A usage, no gate env on untrusted-PR
    jobs, and `python -P` / the console script.

Any missing T1-T4 mitigation found at task close escalates to **BLOCK**.
