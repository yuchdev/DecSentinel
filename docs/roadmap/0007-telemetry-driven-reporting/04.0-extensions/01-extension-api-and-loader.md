# Task 01 — Extension API, loader and trust gate

**Parent story:** [Story 04.0](/docs/roadmap/0007-telemetry-driven-reporting/04.0-extensions/README.md)  
**Proposed source:** `src/docsentinel/telemetry/extensions.py`

## Required contract

```python
@runtime_checkable
class Extension(Protocol):
    name: str                                   # kebab/snake, [a-z][a-z0-9_]*
    def provide_run(self, model: Mapping) -> Mapping | None: ...
    def provide_document(self, doc: Mapping, model: Mapping) -> Mapping | None: ...
    def provide_problem(self, problem: Mapping, doc: Mapping, model: Mapping) -> Mapping | None: ...
    def filters(self) -> Mapping[str, Filter]: ...      # optional
```

Every hook is optional (the loader wraps the object so missing hooks are no-ops).
Hooks receive **read-only** (deep-frozen / `MappingProxyType`) views, so an
extension cannot mutate core data.

- **Namespacing:** returned trees are attached at `ext.<name>` (run),
  `doc.ext.<name>` and `p.ext.<name>`; an extension has no way to name another
  location. Two extensions with one `name` → `ExtensionError`.
- **JSON-shape check:** returned values are validated recursively (str/int/float/
  bool/None/list/dict-with-str-keys, depth ≤ 8, ≤ 1 MiB serialized per hook);
  otherwise `ExtensionError`.
- **Filters:** namespaced `ext.<name>.<filter>`; must declare `sink: bool`. The
  loader uses it for the trust rule (spec §8).
- **Selection:** `telemetry_extensions = [...]` (config) and `--extension NAME`
  (repeatable). Resolution: `builtin:<name>` inside `docsentinel.telemetry.builtin`;
  `python:<module>:<callable>` via `importlib`, reusing the loader written for
  Milestone 0006's `python:` custom sink (one `importlib` helper, two callers).
- **Trust gate (D5):** `python:` is refused with `ExtensionError` unless
  `--allow-python-extensions` or `DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1`. The
  gate cannot be set from `docsentinel.toml`/`pyproject.toml`. `builtin:` never
  needs it.
- **Error model:** report path → `ExtensionError` (exit 2); fault-event path
  (0006) → swallowed. Messages are `neutralize`d and bounded.
- A template's `requires_extensions` is checked here; a missing one is a
  `TemplateError` naming the extension and how to enable it.

## Security review hook

Because this loads user code, the task is not done until the `security-auditor`
agent has reviewed it (Story 05.0 Task 01 lists the checklist).

## Tests (for `testing-expert`)

- Unit: namespace enforcement, duplicate name, non-JSON return, oversize return,
  read-only view (mutation raises), missing optional hooks.
- Mock: `importlib.import_module` replaced; refuses `python:` without opt-in, never
  imports the module when refused; accepts with the flag and with the env var; the
  config file alone cannot enable it.
- Unit: hook raising → report path exit-2 error, event path swallowed.
