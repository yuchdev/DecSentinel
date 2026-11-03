# Task 01 — Extension API, loader and trust gate

**Parent story:** [Story 04.0](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/README.md)  
**Proposed source:** `src/docsentinel/telemetry/extensions.py`  
**Threat model (normative):** [threat-model-0007-extensions-2026-11-03.md](/docs/security/threat-model-0007-extensions-2026-11-03.md)

## Required contract

```python
EXTENSION_NAME_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"   # == loader._EXTENSION_PATTERN; no hyphen

@runtime_checkable
class Extension(Protocol):
    name: str                                   # read once; exact str matching EXTENSION_NAME_PATTERN
    def provide_run(self, model: Mapping) -> Mapping | None: ...
    def provide_document(self, doc: Mapping, model: Mapping) -> Mapping | None: ...
    def provide_problem(self, problem: Mapping, doc: Mapping, model: Mapping) -> Mapping | None: ...
    def filters(self) -> Mapping[str, ExtensionFilter]: ...      # optional

@dataclass(frozen=True)
class ExtensionFilter:
    function: Callable[..., JsonScalar]   # returns exact str/int/finite float/bool/None
    arity: Literal[0, 1]                  # 0 or 1 quoted literal argument
    input_kinds: frozenset[str]           # declared input kinds, checked by the loader at load time

class ExtensionError(ValueError): ...    # exit 2 through the existing CLI handler
```

There is **no `sink` field** on `ExtensionFilter`: extension filters are never sinks
(M7). A filter object that exposes a truthy `sink` attribute is an `ExtensionError`.

Every hook is optional: each is looked up once with `getattr(obj, hook, None)` and
must be callable; a missing hook is a no-op (M13).

- **Read-only arguments (M13):** hooks receive a **deep-frozen copy** of the context,
  built once per render (`MappingProxyType` over dicts, `tuple` for lists,
  recursively). It is reused across hooks and never aliases the context that is
  rendered.
- **Copy-on-return (M14):** each hook return is copied into fresh builtin objects
  during validation. Exact `type(x) is dict/list/str/int/float/bool/None` only
  (tuples accepted as lists); subclasses and cycles are refused. Only the copy is
  attached, so later mutation of the original has no effect.
- **Namespacing (M26):** the merge step builds `ext` itself and attaches returned
  trees at `ext.<name>` (run), `doc.ext.<name>` and `p.ext.<name>`. An extension
  cannot add, replace or remove a core key at any level; a return containing
  `"path"` or `"ext"` stays inside its own subtree. `doc.domain` is a core key
  (Task 02, M24), never filled from a hook.
- **Names (M13, M25):** `name` must match `EXTENSION_NAME_PATTERN`. Every builtin
  name (`domain`, `document_stats`, future ones) is **reserved**: a `python:`
  extension using one is an `ExtensionError` whether or not that builtin is loaded.
  Two extensions with one name, or one spec given twice, is an `ExtensionError`.
- **Shape and size bounds (M15, M16):** an iterative walk that counts estimated
  serialized size incrementally and stops at the limit (never `json.dumps` first);
  depth <= 8 from the returned root; strings exact `str` with no lone surrogates;
  `|int| <= 2**53`; floats finite; keys exact `str` <= 256 characters; <= 10k entries
  per container; <= 1 MiB per hook. Aggregate caps per render: 16 MiB per extension
  and 64 MiB (`MAX_OUTPUT_CHARS`) across all extensions. Rendering then charges
  extension values to the existing `_Budget` step/work/output budgets.
- **Filters (M7-M10):** keys of `filters()` are full names, exactly
  `ext.<own name>.<filter>` with `<filter>` matching `[a-z][a-z0-9_]{0,63}`; any
  other key (a core name such as `neutralize`, or `ext.<other>.f`) is an
  `ExtensionError`. They live in an immutable per-render registry built from the
  loaded extensions and are **never** added to `loader.FILTERS` or
  `filters._FUNCTIONS` (the `FILTER_NAMES == loader.FILTERS` parity test is
  unchanged). They are never sinks, and any chain containing one is untrusted
  (spec §7/§8). At runtime each call must return a JSON scalar of exact builtin
  type, charges one step plus its result length to `MAX_WORK_CHARS`, and any
  exception becomes a bounded `TemplateError`/`ExtensionError` (exit 2).
- **Context schema (M11, M12):** `ext` is a new value kind `any`, always
  `UNTRUSTED` at every depth (spec §6). A template that references `ext.<n>...` or a
  filter `ext.<n>.<f>` must list `<n>` in `requires_extensions` (load-time
  `TemplateError`). `ReportModel.build(extensions=...)` replaces its
  `NotImplementedError`, and `render_template(extensions=)` receives the loaded
  *names* from the same registry, never from the template.

## Selection and trust gate (D5, owner decision D-A)

- **Spec grammar.** `--extension SPEC` (repeatable) takes a spec, not a name:
  `builtin:<name>` or `python:<module>:<callable>`.
- **Config is builtin-only (M1).** `telemetry_extensions = [...]` in
  `docsentinel.toml`/`pyproject.toml` may hold only `builtin:<name>` entries. Any
  other entry, including every `python:` spec, is a `ConfigError` at `load_config`
  (exit 2) whatever the gate says. The extension resolver re-checks an injected
  `Config` and refuses a non-`builtin:` entry the same way.
- **`python:` needs argv and the gate (M2).** A `python:` spec is accepted only from
  argv (`--extension python:...`) **and** only with the gate: the
  `--allow-python-extensions` flag, or `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS` exactly
  equal to `"1"` (`true`, `yes`, `" 1"`, `"1 "` and an empty value are refused).
  Only `cli.py` reads the environment variable. The gate cannot be set from config.
- **Library API is environment-free (M2).** `reporting.render` gains keyword-only
  `extensions: tuple[str, ...] = ()` (the argv-equivalent specs) and
  `allow_python_extensions: bool = False`. `render`, `scan` and the pytest plugin
  never read `os.environ`.
- **Shared importlib helper (M3).** One helper, shared with Milestone 0006's
  `python:` sink, proposed as:

  ```python
  def load_python_target(
      spec: str, *, allow_python: bool, root: Path, cwd: Path, origin_roots: Sequence[Path] = ()
  ) -> object
  ```

  `allow_python` is required with no default. The gate check runs first, before any
  `import_module`, `find_spec` or `sys.modules` lookup. An AST tripwire test
  enumerates every `importlib.import_module` call site under `src/docsentinel/`; only
  the helper and the fixed literal-argument sites in `deep_support.py`,
  `contradictions.py` and `_triples.py` are allowed. *Amendment 2026-11-03:* the
  tripwire flags every reference (not only calls) to a by-name import or code
  execution name (`import_module`, `__import__`, `find_spec`, `resolve_name`,
  `run_module`/`run_path`, `locate`, `entry_points`, `exec`, `eval`, ...), string
  literals naming them, `getattr`/`vars`/`__dict__` over an `importlib` module, and
  imports of `runpy`, `pydoc`, `pkgutil`, `importlib.metadata` and similar modules. The
  helper must be module-level with the gate as its first statement, before every
  gated reference. Allowed literal sites are listed as exact `(module, function,
  literal)` entries.
- **Target grammar (M5).** Module
  `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,15}$`, callable
  `^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){0,3}$`, total length <= 256,
  resolution by `getattr` on validated segments only; the resolved object must be
  callable and is called with no arguments; the result must satisfy `Extension`.
- **Origin check (M6).** Before executing a module, resolve it with
  `importlib.util.find_spec` for every dotted prefix and check any existing
  `sys.modules` entry's `__spec__.origin`/`__file__`/`submodule_search_locations`.
  Refuse (exit 2, nothing executed) when any origin or search location `realpath`s
  inside the scan root or the cwd; a namespace package is refused when any search
  location is inside. Never mutate `sys.path`.
  - *Amendment 2026-11-03 (security close-review of Task 01).* The boundary is the
    scan root, its project roots (every marked ancestor, the root included, holding
    `.git`, `docsentinel.toml`, `doc_sentinel.toml` or `pyproject.toml`; amended
    2026-11-03 from "nearest ancestor", see below) and the cwd. Before
    any import, a `sys.path` entry (`''` = cwd) inside the boundary refuses every
    `python:` spec. A prefix with no file location is refused unless it is builtin or
    frozen. After the import, the factories, the report hooks and the render, any
    module added to `sys.modules` since the first `python:` import whose location is
    inside fails the run (exit 2; detection after the fact). `reporting.render` needs
    `root=` for a `python:` spec. Exemption: a location or `sys.path` entry whose
    absolute *and* real path are both under the running interpreter's own
    `site-packages` (`sysconfig` `purelib`/`platlib`) is never refused, so a
    project-local `.venv` of the running interpreter works. `PYTHONPATH` entries, the
    user site, `.pth`-added directories (an editable `src/`) and any other `.venv`
    stay refused.
  - *Amendment 2026-11-03 (security re-verification of Task 01, N1-N3).* Every marked
    ancestor of every spelling of the scan root (as given and canonical) is a
    project root, walked to the filesystem root and bounded by 256 ancestors
    (refused past the bound), so a marker the repository plants under `docs/` can
    never drop the checkout from the boundary; this fails closed more often (a
    `~/.git` dotfiles repository puts all of `~` in the boundary). The `sys.path`
    check runs again after every factory, before every report and event hook and
    at every `sys.modules` check, so an extension that adds the checkout to
    `sys.path` fails the run (exit 2) before a later import resolves through it.
    The `sys.modules` check is best-effort detection of accidental imports,
    defeated by a planted module that rewrites its own location, and runs
    unconditionally on the event path.
  - *Amendment 2026-11-03 (third security re-verification of Task 01, F1, F2).*
    **F1:** the boundary anchors every spelling of the scan root the invoker
    supplied. `resolve_extensions` and `load_python_target` take `origin_roots`
    (absolute, unresolved paths; each an anchor whose marked ancestors are project
    roots too). The CLI passes `os.path.abspath(<root argument>)` (its parent for a
    file) next to the resolved directory, so a `<checkout>/docs` (or root file) that
    is a symlink out of the checkout cannot drop the checkout; templates and config
    keep the resolved directory. **F2:** extension filters are in the prevention
    set: the `sys.path`/`sys.modules` check also runs between each factory and its
    `filters()` hook, and every registered extension filter re-checks `sys.path`
    before each call through a guard bound to the run's `ModuleWatch`; the guard's
    `ExtensionError` propagates and is never turned into a filter or render failure.
    F3 (the `check_path` cache keyed on path strings) and F5 (tripwire spellings) are
    follow-ups recorded under the threat model's residual risks.
- **Builtins (M5).** `builtin:<name>` resolves through a static `dict` in
  `telemetry/builtin/__init__.py` (name -> fixed module/class). The user string is
  never interpolated into an `import_module` argument; an unknown name is refused
  before any import. `builtin:` never needs the gate.
- **Merge order (M25).** Config entries first, then argv entries, in order. Argv
  `builtin:` specs are merged into the effective `Config.telemetry_extensions`
  (via `dataclasses.replace`) before the scan so that `domain_for(path, config)`
  (Task 02) and the 0006 adapter decide from the same `Config`. `python:` specs
  never enter `Config`.
- **Refusal is never swallowed (M4).** A refused `python:` spec is an
  `ExtensionError`/`ConfigError` (exit 2) on **both** the report and the fault-event
  path.

## Load order and `requires_extensions` (M30, M31)

argv/config -> gate (M1-M4) -> resolve and instantiate extensions -> load and
validate the template (M12) -> check `requires_extensions` against the loaded,
validated names -> scan -> hooks -> render. The check compares exact names and
**never** loads anything; a missing extension fails before any detector runs.

A missing one is a `TemplateError` naming the extension (neutralized). For a builtin
name it suggests `--extension builtin:<name>` / `telemetry_extensions`. For a
non-builtin name it says only that a `python:` extension providing that name must
be supplied by the invoker, and links the docs. It never suggests
`--allow-python-extensions` or a module path.

## Error model (M17, M27-M29)

- Each hook call is wrapped. `Exception` and `SystemExit` become `ExtensionError` on
  the report path (exit 2, so `SystemExit(0)` cannot downgrade exit 1) and are
  swallowed on the event path. `KeyboardInterrupt` propagates. *Amendment
  2026-11-03 (F4):* only an exact `KeyboardInterrupt` propagates; an
  extension-defined subclass is wrapped like any other hook failure, so it cannot
  skip the wrapping or the final M6 check. The Milestone 0006 adapter must not catch
  `KeyboardInterrupt` around `EventHookGuard`.
- `ExtensionError` messages echo only the spec or validated name, the hook name, the
  exception class `__qualname__` and up to 200 characters of `str(exc)`; each part is
  truncated, then `filters.neutralize`d, and the message is capped at 512
  characters. Never `repr(exc)`, a traceback, `realpath` or a module `__file__`. The
  CLI prints `Scan failed:` (exit 2).
- The report context, including every hook, is fully built and rendered to a string
  before the first byte reaches stdout (keep the `cli.py` render-then-print order).
- Event path: a hook failure emits the event with core fields only and writes
  **one** bounded, neutralized stderr warning per extension per run. Gate refusals
  and config errors are never swallowed (M4).

## Side surfaces (M32, M33)

Only `scan` with a report (and the 0006 emission path) resolves extensions.
`doctor` lists configured specs (neutralized) and the gate state, and reports a
`python:` config entry as an error, without importing. `rules`, `init` and
`baseline` never import or run hooks. The baseline and template loaders keep
unknown-key rejection, so neither file can name an extension spec. The pytest plugin
exposes no extension or gate option; a future one takes only explicit fixture/kwarg
arguments, never ini/addopts.

## Contract changes and migration

| Component | Change | Migration |
|---|---|---|
| `config.py` | new `telemetry_extensions: tuple[str, ...] = ()`, builtin-only | additive, defaulted |
| `cli.py` | `--extension SPEC` (repeatable), `--allow-python-extensions`; the only env reader | additive |
| `reporting.render` | keyword-only `extensions`, `allow_python_extensions` | defaulted; existing callers unchanged |
| `telemetry/model.py`, `telemetry/loader.py` | `any` kind, `ext` schema, `requires_extensions` rule, per-render filter registry | additive; no packaged template references `ext` |
| Milestone 0006 `build_sink` | must call the shared helper with the gate; `python:` sink argv-only | see the note in [0006 Story 02.0 Task 01](/docs/roadmap/0006-fault-telemetry/02.0-config-and-cli-surface/01-typed-config-options.md) |

## Out of scope and accepted risks

- **D-B (out of scope):** there is no `--allow-repo-python-extensions`. The M6 refusal
  of in-root/in-cwd modules stands with no override.
- **D-C (accepted risk):** no wall-clock budget (M19 is not implemented). Only the
  step/work/output and size budgets bound extensions; a hook that never returns is
  stopped by the CI job timeout (residual R2).
- Residuals R1-R4 of the threat model are accepted and must be stated in the user
  guide (Task 02).

## Security requirements

This task must satisfy, and its close review checks (threat model checklist items
1-9): **M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M16, M17,
M25, M26, M27, M28, M29, M30, M31, M32, M33**. M19 is waived by D-C; the
`--allow-repo-python-extensions` exception in M6 is waived by D-B. Any missing T1-T4
mitigation (M1-M12) at close escalates to BLOCK.

## Security review hook

Because this loads user code, the task is not done until the `security-auditor`
agent has reviewed it (Story 05.0 Task 01 lists the checklist).

## Tests (for `testing-expert`)

Each case is the test list of the cited mitigation in the threat model.

- Mock (`importlib.import_module` / `importlib.util.find_spec` replaced to raise if
  called):
  - a config `python:` entry is a `ConfigError` with the flag, with the env var and
    with neither (M1);
  - argv `python:` without the gate is refused with no import attempted; accepted
    with the flag and with `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1` (M2);
  - env values `true`/`yes`/`1 `/`""` are refused (M2);
  - `render(...)`/`scan(...)` with the env var patched in still refuse when the
    keyword is false (M2);
  - `doctor`/`rules`/`init`/`baseline` with config `python:` entries and the env set
    never call `import_module`/`find_spec` (M32).
- Unit: the importlib tripwire fails when a new call site is added (M3).
- Unit: `python:.rel:x`, `python:os:__class__`, `python:m:_private` refused at the
  grammar stage; `builtin:../x`, `builtin:os`, `builtin:__init__` refused with
  `import_module` never called (M5).
- Integration: a planted in-root `evilmod.py` writing a sentinel on import, a
  package with an in-root parent, and a pre-imported in-root `sys.modules` entry are
  each refused and the sentinel does not exist (M6).
- Unit: a filter with `sink=True`, a filter named `neutralize` or `ext.other.f` are
  refused; `{p.message|ext.x.f}` rejected in text; `{profile|ext.x.f}` rejected on a
  plain github line and accepted only as `::error ...::{profile|ext.x.f|gha_data}`;
  a filter returning a dict, a `str` subclass, `NaN` or raising gives exit 2
  (M7-M10).
- Unit: `{doc.ext.domain.name}` rejected in text, accepted with `|neutralize`;
  rejected on a plain github line and in an `append` loop; `{doc.ext.domain}`
  rejected as a container; rejected without `requires_extensions: ["domain"]`;
  `$var` of an `ext` subtree holding `$var`/`$for` keys and ESC/U+202E renders as
  ASCII-escaped data (M11, M12).
- Unit: mutation of a nested hook argument raises; mutating a returned dict after
  return leaves the report unchanged; `dict`/`str` subclasses and a cyclic list are
  refused; a changing `name` property is read once (M13, M14).
- Unit: depth 9, 1 MiB + 1, a 5000-digit int, `NaN`, a non-str key and a lone
  surrogate are refused; a small per-problem return over many problems hits a
  lowered aggregate cap with bounded peak memory (M15, M16).
- Unit: `SystemExit(0)` with blocking findings gives exit 2; `RecursionError` gives
  exit 2 with a bounded message; an exact `KeyboardInterrupt` propagates and a
  subclass is wrapped (M17, F4).
- Unit: a python extension named `domain` is refused; a duplicate name or spec is
  refused; a hook returning `{"path": "forged"}` leaves `doc.path` unchanged (M25,
  M26).
- Unit: a hook raising with ESC/U+202E/1 KiB message yields a bounded, escaped
  message with no absolute path; stdout is empty when a hook fails; 100 failing
  event-path calls write one warning and leave the exit code alone; the same
  failure on the report path is exit 2 (M27-M29).
- Unit: a template requiring `domain` does not load `builtin:domain`; the message for
  `evil` contains no `--allow-python-extensions` and no `python:`; a missing
  extension fails before any detector runs (M30, M31).
- Unit: a baseline or template carrying an `extensions` key is refused (M32).
