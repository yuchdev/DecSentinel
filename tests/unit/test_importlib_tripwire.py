"""Importlib and trust-gate tripwires (Milestone 0007 Story 04.0 Task 01, threat model M2/M3).

``docs/security/threat-model-0007-extensions-2026-11-03.md`` M3: every dynamic import under
``src/docsentinel`` goes through the single shared helper
``docsentinel.telemetry.extensions.load_python_target``, which holds the ``python:`` trust gate.
The only other ``importlib.import_module`` call sites allowed are fixed string literals in the
modules that lazily import optional dependencies. ``find_spec`` is likewise confined to the helper
module and the literal availability probes. M2: only ``cli.py`` names the gate's environment
variable. Each tripwire is also run against a seeded violation so it cannot rot into a no-op.
Re-verification N4 (2026-11-03): string literals are checked after constant folding, reflection
(``getattr``/``vars``/``__dict__``/``__getattribute__``) over ``builtins`` and ``sys.modules[...]`` is
treated like reflection over ``importlib``, and a ``sys.modules`` lookup by a non-literal key is a
violation outside the helper module.
"""

import ast
from pathlib import Path
from typing import Optional

import pytest

import docsentinel

#: The package source tree.
_SRC = Path(docsentinel.__file__).resolve().parent

#: The shared helper: the only non-literal ``import_module`` site (M3). It must be a module-level
#: function whose first statement is the gate, and every gated reference must come after it.
_HELPER_MODULE = "telemetry/extensions.py"
_HELPER = "load_python_target"

#: Module-level functions of the helper module that may reference ``find_spec`` (the origin check);
#: each may itself be referenced only from the helper, after the gate.
_GATED_FUNCTIONS = {"find_spec": "_check_origins"}

#: Every fixed-literal dynamic import allowed outside the helper: ``(module, function, literal)``. The
#: threat model names ``deep_support.py``, ``contradictions.py`` and ``_triples.py``;
#: ``detectors/loader.py`` and ``detectors/standard/signatures.py`` predate it and import fixed
#: optional-dependency modules too. A new literal needs a new, reviewed entry here.
_LITERAL_SITES = frozenset(
    {
        ("deep_support.py", "import_module", "spacy"),
        ("deep_support.py", "import_module", "textacy"),
        ("deep_support.py", "import_module", "spacy.util"),
        ("detectors/contradictions.py", "import_module", "docsentinel.detectors._triples"),
        ("detectors/_triples.py", "import_module", "textacy.extract"),
        ("detectors/loader.py", "__import__", "docsentinel.detectors.standard"),
        ("detectors/loader.py", "import_module", "docsentinel.detectors.standard.corpus"),
        ("detectors/standard/signatures.py", "import_module", "docsig.messages"),
        ("detectors/standard/signatures.py", "import_module", "docsig"),
    }
)

#: Names that load or execute code by name. Any reference -- call, alias, attribute, bare name or
#: string literal (``getattr``/``vars``/``methodcaller`` spellings) -- is a violation unless allowed above.
_DYNAMIC_NAMES = frozenset(
    {
        "import_module",
        "__import__",
        "find_spec",
        "spec_from_file_location",
        "spec_from_loader",
        "module_from_spec",
        "exec_module",
        "load_module",
        "resolve_name",
        "run_module",
        "run_path",
        "locate",
        "entry_points",
        "EntryPoint",
        "_gcd_import",
        "zipimporter",
        "exec",
        "eval",
        # Re-verification N4 (2026-11-03): re-execution, code objects, lazy loaders, .pth/dictConfig
        # by-name construction and the C-API import.
        "reload",
        "get_code",
        "LazyLoader",
        "addsitedir",
        "dictConfig",
        "PyImport_ImportModule",
    }
)

#: Builtins flagged as bare names only (``re.compile`` stays legal).
_BARE_NAMES = frozenset({"compile", "__builtins__", "breakpoint"})

#: Modules whose import is itself a violation: each offers a by-name import or code execution.
_BANNED_MODULES = frozenset(
    {
        "runpy",
        "pydoc",
        "pkgutil",
        "zipimport",
        "imp",
        "pickle",
        "marshal",
        "importlib.metadata",
        "importlib._bootstrap",
        "importlib._bootstrap_external",
        "importlib.resources",
        # Re-verification N4 (2026-11-03): C-API access, pickle twins and statement runners.
        "ctypes",
        "_pickle",
        "shelve",
        "timeit",
        "code",
        "cProfile",
        "site",
    }
)

#: The gate's environment variable; only ``cli.py`` may name it (M2).
_GATE_ENV = "DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS"

#: Fragments that, in any string constant outside ``cli.py``, betray the gate variable being built.
_GATE_FRAGMENTS = ("ALLOW_PYTHON", "DOCSENTINEL_ALLOW")

#: Modules on the extension path that must never touch the environment at all (M2).
_NO_ENV_PREFIXES = ("reporting.py", "telemetry/")
_ENV_NAMES = frozenset({"environ", "environb", "getenv", "getenvb", "putenv", "unsetenv"})


def _scopes(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map every node to its innermost enclosing function, lambda or class node (the module itself at top)."""
    owner: dict[ast.AST, ast.AST] = {}
    stack: list[tuple[ast.AST, ast.AST]] = [(tree, tree)]
    while stack:
        node, current = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            current = node
        owner[node] = current
        stack.extend((child, current) for child in ast.iter_child_nodes(node))
    return owner


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map every node to its parent."""
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _referenced_name(node: ast.AST) -> str:
    """Return the dynamic-import name a node references, or ``""``."""
    if isinstance(node, ast.Name) and (node.id in _DYNAMIC_NAMES or node.id in _BARE_NAMES):
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in _DYNAMIC_NAMES:
        return node.attr
    return ""


def _literal_call(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> Optional[str]:
    """Return the literal argument when ``node`` is the callee of ``f("literal")``, else ``None``."""
    call = parents.get(node)
    if not isinstance(call, ast.Call) or call.func is not node or call.keywords or len(call.args) != 1:
        return None
    argument = call.args[0]
    return argument.value if isinstance(argument, ast.Constant) and isinstance(argument.value, str) else None


#: Modules whose namespace holds an import function; reflective access to them is a violation.
_GUARDED_MODULES = ("importlib", "builtins")


def _importlib_aliases(tree: ast.AST) -> set[str]:
    """Return the local names bound to an ``importlib`` or ``builtins`` module (or a name from one)."""
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _GUARDED_MODULES or alias.name.startswith(tuple(f"{m}." for m in _GUARDED_MODULES)):
                    aliases.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in _GUARDED_MODULES:
            aliases.update(alias.asname or alias.name for alias in node.names)
    return aliases


def _sys_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Return the local names bound to ``sys`` and those bound to ``sys.modules`` itself."""
    sys_names: set[str] = set()
    modules_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            sys_names.update(alias.asname or "sys" for alias in node.names if alias.name == "sys")
        elif isinstance(node, ast.ImportFrom) and node.module == "sys":
            modules_names.update(alias.asname or alias.name for alias in node.names if alias.name == "modules")
    return sys_names, modules_names


def _is_sys_modules(node: ast.AST, sys_names: set[str], modules_names: set[str]) -> bool:
    """Return whether ``node`` spells ``sys.modules`` (through any alias)."""
    if isinstance(node, ast.Name):
        return node.id in modules_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "modules"
        and isinstance(node.value, ast.Name)
        and node.value.id in sys_names
    )


def _is_literal(node: Optional[ast.AST]) -> bool:
    """Return whether ``node`` is a plain string constant."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _sys_modules_violation(node: ast.AST, sys_names: set[str], modules_names: set[str]) -> bool:
    """Return whether ``node`` looks a module up in ``sys.modules`` by a non-literal key."""
    if isinstance(node, ast.Subscript) and _is_sys_modules(node.value, sys_names, modules_names):
        return not _is_literal(node.slice)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("get", "pop", "setdefault")
        and _is_sys_modules(node.func.value, sys_names, modules_names)
    ):
        return not (node.args and _is_literal(node.args[0]))
    return False


def _is_guarded_target(
    node: Optional[ast.AST], aliases: set[str], sys_names: set[str], modules_names: set[str]
) -> bool:
    """Return whether ``node`` is an importlib/builtins module or any ``sys.modules`` lookup.

    ``sys.modules[...]``, ``sys.modules.get(...)`` and ``sys.modules`` itself all count, whatever the key, so
    reflective access through them is treated like access to an importlib alias.
    """
    if node is None:
        return False
    if isinstance(node, ast.Name) and node.id in aliases:
        return True
    if _is_sys_modules(node, sys_names, modules_names):
        return True
    if isinstance(node, ast.Subscript):
        return _is_sys_modules(node.value, sys_names, modules_names)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _is_sys_modules(node.func.value, sys_names, modules_names)
    )


def _reflection_violation(
    node: ast.AST, parents: dict[ast.AST, ast.AST], aliases: set[str], sys_names: set[str], modules_names: set[str]
) -> str:
    """Return the reflective access a node makes to a guarded module, or ``""``.

    Covers ``vars(x)``, ``getattr(x, <non-literal>)``, ``x.__dict__``, ``x.__getattribute__(...)`` and
    ``object.__getattribute__(x, ...)`` where ``x`` is an importlib/builtins alias or a ``sys.modules`` lookup.
    """

    def guarded(target: Optional[ast.AST]) -> bool:
        """Return whether ``target`` is an importlib/builtins alias or a ``sys.modules`` lookup."""
        return _is_guarded_target(target, aliases, sys_names, modules_names)

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("vars", "getattr"):
        target = node.args[0] if node.args else None
        literal = len(node.args) > 1 and _is_literal(node.args[1])
        if guarded(target) and (node.func.id == "vars" or not literal):
            return f"{node.func.id}() over an importlib/builtins module"
    if isinstance(node, ast.Attribute) and node.attr in ("__dict__", "__getattribute__"):
        if guarded(node.value):
            return f"{node.attr} of an importlib/builtins module"
        call = parents.get(node)
        if (
            node.attr == "__getattribute__"
            and isinstance(call, ast.Call)
            and call.func is node
            and call.args
            and guarded(call.args[0])
        ):
            return "__getattribute__ over an importlib/builtins module"
    return ""


def _banned(module: str) -> bool:
    """Return whether a dotted module path is a banned module or lies below one."""
    return any(module == banned or module.startswith(f"{banned}.") for banned in _BANNED_MODULES)


def _module_violations(relative: str, node: ast.AST) -> list[str]:
    """Return violations for importing a banned module or a dynamic-import name."""
    found: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            if _banned(alias.name):
                found.append(f"{relative}:{node.lineno}: import of {alias.name}")
    elif isinstance(node, ast.ImportFrom):
        module = "" if node.level else (node.module or "")
        for alias in node.names:
            dotted = f"{module}.{alias.name}"
            if module and (_banned(module) or _banned(dotted)):
                found.append(f"{relative}:{node.lineno}: import from {dotted}")
            elif alias.name in _DYNAMIC_NAMES or (alias.name == "*" and module.startswith(("importlib", "builtins"))):
                found.append(f"{relative}:{node.lineno}: from-import of a dynamic import function")
    return found


def _gate_end(function: ast.FunctionDef) -> Optional[int]:
    """Return the last line of the gate when it is the helper's first statement, else ``None``.

    The gate is ``if allow_python is not True: ... raise ...`` with no ``else``.
    """
    body = function.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    if not body or not isinstance(body[0], ast.If):
        return None
    gate = body[0]
    test = gate.test
    shaped = (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "allow_python"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.IsNot)
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is True
    )
    if not shaped or gate.orelse or not isinstance(gate.body[-1], ast.Raise):
        return None
    return gate.end_lineno


def _helper_violations(tree: ast.Module, relative: str, owner: dict[ast.AST, ast.AST]) -> list[str]:
    """Check the helper module: module-level helper, gate first, gated references after the gate."""
    found: list[str] = []
    top = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    nested = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {_HELPER, *_GATED_FUNCTIONS.values()}
        and top.get(node.name) is not node
    ]
    found.extend(f"{relative}:{node.lineno}: {node.name} is not a module-level function" for node in nested)
    helper = top.get(_HELPER)
    gate_end = _gate_end(helper) if helper is not None else None
    if helper is None or gate_end is None:
        return [*found, f"{relative}: {_HELPER} must be module-level and start with the allow_python gate"]
    for node in ast.walk(tree):
        name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
        if name == "import_module" or name in _GATED_FUNCTIONS.values():
            if owner.get(node) is not helper or node.lineno <= gate_end:
                found.append(f"{relative}:{node.lineno}: {name} outside {_HELPER} after its gate")
        elif name in _GATED_FUNCTIONS and owner.get(node) is not top.get(_GATED_FUNCTIONS[name]):
            found.append(f"{relative}:{node.lineno}: {name} outside {_GATED_FUNCTIONS[name]}")
    return found


def import_violations(relative: str, source: str) -> list[str]:
    """Return every disallowed dynamic-import site of one module.

    :param relative: The module path relative to the package root (POSIX).
    :param source: Its source text.
    :returns: ``relative:line: reason`` entries.
    """
    tree = ast.parse(source)
    owner = _scopes(tree)
    parents = _parents(tree)
    aliases = _importlib_aliases(tree)
    sys_names, modules_names = _sys_aliases(tree)
    helper_module = relative == _HELPER_MODULE
    found: list[str] = _helper_violations(tree, relative, owner) if helper_module else []
    found.extend(
        f"{relative}:{line}: string literal naming {value}"
        for line, value in _folded_strings(tree)
        if value in _DYNAMIC_NAMES
    )
    for node in ast.walk(tree):
        found.extend(_module_violations(relative, node))
        reflection = _reflection_violation(node, parents, aliases, sys_names, modules_names)
        if reflection:
            found.append(f"{relative}:{node.lineno}: {reflection}")
        if not helper_module and _sys_modules_violation(node, sys_names, modules_names):
            found.append(f"{relative}:{node.lineno}: sys.modules lookup by a non-literal key outside the shared helper")
        name = _referenced_name(node)
        if not name:
            continue
        if helper_module and (name == "import_module" or name in _GATED_FUNCTIONS):
            continue  # judged by _helper_violations
        literal = _literal_call(node, parents)
        if literal is not None and (relative, name, literal) in _LITERAL_SITES:
            continue
        found.append(f"{relative}:{node.lineno}: reference to {name} outside the shared helper")
    return found


def _folded_strings(tree: ast.AST) -> list[tuple[int, str]]:
    """Return every string constant, plus constant-folded ``+`` concatenations and f-strings."""

    def fold(node: ast.AST) -> Optional[str]:
        """Return the constant string value of ``node``, or ``None`` when it does not fold."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = fold(node.left), fold(node.right)
            return None if left is None or right is None else left + right
        if isinstance(node, ast.JoinedStr):
            parts = [fold(value) for value in node.values]
            return "".join(part for part in parts if part is not None)
        return None

    found = []
    for node in ast.walk(tree):
        value = fold(node)
        if value is not None:
            found.append((getattr(node, "lineno", 0), value))
    return found


def env_violations(relative: str, source: str) -> list[str]:
    """Return every gate-variable spelling outside ``cli.py``, and any env access on the extension path.

    :param relative: The module path relative to the package root.
    :param source: Its source text.
    :returns: ``relative:line: reason`` entries.
    """
    if relative == "cli.py":
        return []
    tree = ast.parse(source)
    found = [
        f"{relative}:{line}: names the gate variable"
        for line, value in _folded_strings(tree)
        if _GATE_ENV in value or any(fragment in value for fragment in _GATE_FRAGMENTS)
    ]
    if relative.startswith(_NO_ENV_PREFIXES):
        for node in ast.walk(tree):
            name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
            if name in _ENV_NAMES:
                found.append(f"{relative}:{node.lineno}: environment access on the extension path")
    return found


def _modules() -> list[tuple[str, str]]:
    """Return ``(relative path, source)`` for every module of the package."""
    return [
        (path.relative_to(_SRC).as_posix(), path.read_text(encoding="utf-8")) for path in sorted(_SRC.rglob("*.py"))
    ]


def test_import_module_has_one_dynamic_call_site():
    """
    [Unit] importlib tripwire: verifies the shared helper is the only dynamic import site (M3).

    Scenario:
        Given every module under src/docsentinel
        When their ASTs are scanned for import_module/__import__/find_spec/exec_module calls
        Then only the helper and fixed-literal optional-dependency sites remain, and the helper exists.

    Boundaries:
        - Focus: threat model T1/M3 single importlib helper holding the gate
        - Fixtures/params: none
        - Scope: static source scan

    On failure, first check:
        - a new ``importlib.import_module`` call: route it through ``load_python_target``
    """
    violations = [entry for relative, source in _modules() for entry in import_violations(relative, source)]
    helper_source = (_SRC / _HELPER_MODULE).read_text(encoding="utf-8")

    assert violations == []
    assert f"def {_HELPER}(" in helper_source


@pytest.mark.parametrize(
    "snippet",
    [
        "import importlib\n\ndef f(name):\n    return importlib.import_module(name)\n",
        "from importlib import import_module\n",
        "def f(name):\n    return __import__(name)\n",
        "import importlib.util\n\ndef f(name):\n    return importlib.util.find_spec(name)\n",
        "import importlib\n\ndef f():\n    return importlib.import_module('os')\n",
    ],
    ids=["dynamic", "from-import", "dunder-import", "find-spec", "literal-outside-allowlist"],
)
def test_tripwire_fires_on_a_new_call_site(snippet: str):
    """
    [Unit] importlib tripwire: verifies the scan reports a seeded call site (M3).

    Scenario:
        Given a module source adding one dynamic import in a non-allowlisted module
        When the tripwire scans it
        Then a violation is reported.

    Boundaries:
        - Focus: the tripwire cannot rot into a no-op
        - Fixtures/params: one seeded call per case
        - Scope: import_violations

    On failure, first check:
        - ``import_violations`` matching rules
    """
    assert import_violations("reporting.py", snippet)


def test_only_cli_names_the_gate_environment_variable():
    """
    [Unit] importlib tripwire: verifies only cli.py names DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS (M2).

    Scenario:
        Given every module under src/docsentinel
        When string constants are scanned
        Then the gate's env variable name appears as a constant only in cli.py, and a seeded one is caught.

    Boundaries:
        - Focus: the library API never reads the gate from the environment
        - Fixtures/params: none
        - Scope: static source scan

    On failure, first check:
        - a new ``os.environ`` read of the gate outside ``cli.py``
    """
    violations = [entry for relative, source in _modules() for entry in env_violations(relative, source)]

    assert violations == []
    assert env_violations("reporting.py", f"import os\nos.environ.get({_GATE_ENV!r})\n")
    assert any(_GATE_ENV in source for relative, source in _modules() if relative == "cli.py")


#: Close-review (2026-11-03) bypasses of the first tripwire, each seeded into ``reporting.py``.
_BYPASSES = {
    "getattr-literal": "import importlib\ndef f(n):\n    return getattr(importlib, 'import_module')(n)\n",
    "getattr-computed": "import importlib\ndef f(n, a):\n    return getattr(importlib, a)(n)\n",
    "alias-assignment": "import importlib\nim = importlib.import_module\ndef f(n):\n    return im(n)\n",
    "import-as": "import importlib as il\ndef f(n):\n    return il.import_module(n)\n",
    "pkgutil-resolve-name": "import pkgutil\ndef f(spec):\n    return pkgutil.resolve_name(spec)\n",
    "runpy-run-module": "import runpy\ndef f(n):\n    return runpy.run_module(n)\n",
    "runpy-run-path": "import runpy\ndef f(p):\n    return runpy.run_path(p)\n",
    "exec": "def f(n):\n    exec(f'import {n}')\n",
    "eval": "def f(n):\n    return eval(n)\n",
    "compile": "def f(n):\n    return compile(n, 'x', 'exec')\n",
    "entry-point-load": "from importlib.metadata import entry_points\ndef f(g):\n    return [e.load() for e in entry_points(group=g)]\n",
    "pydoc-locate": "import pydoc\ndef f(n):\n    return pydoc.locate(n)\n",
    "bootstrap-gcd-import": "import importlib._bootstrap as b\ndef f(n):\n    return b._gcd_import(n)\n",
    "builtins-import": "import builtins\ndef f(n):\n    return builtins.__import__(n)\n",
    "importlib-dunder-import": "import importlib\ndef f(n):\n    return importlib.__import__(n)\n",
    "star-import": "from importlib import *\ndef f(n):\n    return import_module(n)\n",
    "methodcaller": "import importlib, operator\ndef f(n):\n    return operator.methodcaller('import_module', n)(importlib)\n",
    "vars-subscript": "import importlib\ndef f(n):\n    return vars(importlib)['import_module'](n)\n",
    "module-dict": "import importlib\ndef f(n, k):\n    return importlib.__dict__[k](n)\n",
    "zipimport": "import zipimport\ndef f(p, n):\n    return zipimport.zipimporter(p).load_module(n)\n",
    "module-from-spec": (
        "import importlib.util as u\ndef f(p):\n    s = u.spec_from_file_location('m', p)\n"
        "    m = u.module_from_spec(s)\n    s.loader.exec_module(m)\n"
    ),
    "pickle-loads": "import pickle\ndef f(b):\n    return pickle.loads(b)\n",
    "dunder-builtins": "def f(n):\n    return __builtins__['__import__'](n)\n",
}


#: Re-verification (2026-11-03, finding N4, auditor probe p12) bypasses, each seeded into ``reporting.py``.
_BYPASSES_N4 = {
    "importlib-reload": "import importlib\ndef f(m):\n    return importlib.reload(m)\n",
    "from-importlib-reload": "from importlib import reload\ndef f(m):\n    return reload(m)\n",
    "sys-modules-subscript": "import sys\ndef f(n):\n    return sys.modules[n]\n",
    "sys-modules-get": "import sys\ndef f(n):\n    return sys.modules.get(n)\n",
    "from-sys-modules-subscript": "from sys import modules as m\ndef f(n):\n    return m[n]\n",
    "builtins-dict-folded": "import builtins\ndef f(n):\n    return builtins.__dict__['__imp' + 'ort__'](n)\n",
    "getattr-builtins-folded": "import builtins\ndef f(n):\n    return getattr(builtins, '__imp' + 'ort__')(n)\n",
    "getattr-sys-modules-entry": "import sys\ndef f(n, x):\n    return getattr(sys.modules['importlib'], x)(n)\n",
    "object-getattribute": "import importlib\ndef f(n, x):\n    return object.__getattribute__(importlib, x)(n)\n",
    "module-getattribute": "import importlib\ndef f(n, x):\n    return importlib.__getattribute__(x)(n)\n",
    "ctypes-pyimport": "import ctypes\ndef f(n):\n    return ctypes.pythonapi.PyImport_ImportModule(n.encode())\n",
    "ctypes-submodule": "import ctypes.util\ndef f(n):\n    return ctypes.util.find_library(n)\n",
    "logging-dictconfig": (
        "import logging.config\ndef f(n):\n    logging.config.dictConfig({'version': 1, 'handlers': {'h': {'()': n}}})\n"
    ),
    "site-addsitedir": "import site\ndef f(p):\n    site.addsitedir(p)\n",
    "timeit": "import timeit\ndef f(s):\n    return timeit.timeit(s, number=1)\n",
    "code-interpreter": "import code\ndef f(s):\n    code.InteractiveInterpreter().runsource(s)\n",
    "cprofile-run": "import cProfile\ndef f(s):\n    cProfile.run(s)\n",
    "shelve-open": "import shelve\ndef f(p):\n    return dict(shelve.open(p))\n",
    "underscore-pickle": "import _pickle\ndef f(b):\n    return _pickle.loads(b)\n",
    "source-loader-get-code": (
        "import importlib.machinery, types\ndef f(p):\n"
        "    c = importlib.machinery.SourceFileLoader('m', p).get_code('m')\n    types.FunctionType(c, {})()\n"
    ),
    "lazy-loader": "import importlib.util\ndef f(l):\n    return importlib.util.LazyLoader.factory(l)\n",
    "attrgetter-folded": (
        "import operator, importlib.machinery as m\ndef f(n):\n    return operator.attrgetter('find_' + 'spec')(m.PathFinder)(n)\n"
    ),
    "loader-getattr-folded": "def f(n):\n    L = __loader__\n    return getattr(L, 'load_' + 'module')(n)\n",
}


@pytest.mark.parametrize("snippet", list(_BYPASSES_N4.values()), ids=list(_BYPASSES_N4))
def test_tripwire_catches_the_re_verification_bypasses(snippet: str):
    """
    [Unit] importlib tripwire: verifies each re-verification (N4) bypass spelling is reported (M3).

    Scenario:
        Given a module source using reload, a C-API or statement-runner module, a non-literal sys.modules lookup,
            reflection over builtins/sys.modules, or a concatenated dynamic-import name
        When the tripwire scans it as reporting.py
        Then a violation is reported.

    Boundaries:
        - Focus: re-verification finding N4 (auditor probe p12)
        - Fixtures/params: one bypass per case
        - Scope: import_violations

    On failure, first check:
        - ``_DYNAMIC_NAMES``, ``_BANNED_MODULES``, ``_folded_strings`` and the reflection/sys.modules rules
    """
    assert import_violations("reporting.py", snippet)


def test_sys_modules_rule_allows_literal_keys_and_the_helper_module():
    """
    [Unit] importlib tripwire: verifies a literal sys.modules key passes and the helper module may look up by name.

    Scenario:
        Given ``sys.modules['docsentinel']`` in reporting.py, and ``sys.modules.get(prefix)`` in the helper module
        When the tripwire scans each
        Then neither yields a sys.modules violation, while ``sys.modules[n]`` in reporting.py does.

    Boundaries:
        - Focus: re-verification finding N4 edge case (non-literal keys only, outside the helper module only)
        - Fixtures/params: none
        - Scope: import_violations

    On failure, first check:
        - ``_sys_modules_violation`` and the ``helper_module`` exemption in ``import_violations``
    """
    literal = import_violations("reporting.py", "import sys\nx = sys.modules['docsentinel']\n")
    helper = import_violations(_HELPER_MODULE, "import sys\ndef g(prefix):\n    return sys.modules.get(prefix)\n")
    dynamic = import_violations("reporting.py", "import sys\ndef g(n):\n    return sys.modules[n]\n")

    assert literal == []
    assert not [entry for entry in helper if "sys.modules" in entry]
    assert [entry for entry in dynamic if "sys.modules" in entry]


@pytest.mark.parametrize("snippet", list(_BYPASSES.values()), ids=list(_BYPASSES))
def test_tripwire_catches_every_known_bypass(snippet: str):
    """
    [Unit] importlib tripwire: verifies each close-review bypass spelling is reported (M3).

    Scenario:
        Given a module source using one alternative route to a by-name import or code execution
        When the tripwire scans it as reporting.py
        Then a violation is reported.

    Boundaries:
        - Focus: close-review finding 4 (auditor probe p05): references, aliases, literals, banned modules
        - Fixtures/params: one bypass per case
        - Scope: import_violations

    On failure, first check:
        - ``_DYNAMIC_NAMES``, ``_BANNED_MODULES`` and the alias/literal rules in ``import_violations``
    """
    assert import_violations("reporting.py", snippet)


_HELPER_BYPASSES = {
    "nested-helper": (
        "import importlib\ndef other(n):\n    def load_python_target():\n"
        "        return importlib.import_module(n)\n    return load_python_target()\n"
    ),
    "import-before-gate": (
        "import importlib\ndef load_python_target(spec, *, allow_python, root, cwd):\n"
        "    m = importlib.import_module(spec)\n    if allow_python is not True:\n        raise ValueError\n"
        "    return m\n"
    ),
    "gate-not-first": (
        "import importlib\ndef load_python_target(spec, *, allow_python, root, cwd):\n    x = 1\n"
        "    if allow_python is not True:\n        raise ValueError\n    return importlib.import_module(spec)\n"
    ),
    "truthy-gate": (
        "import importlib\ndef load_python_target(spec, *, allow_python, root, cwd):\n"
        "    if not allow_python:\n        raise ValueError\n    return importlib.import_module(spec)\n"
    ),
    "import-in-lambda": (
        "import importlib\ndef load_python_target(spec, *, allow_python, root, cwd):\n"
        "    if allow_python is not True:\n        raise ValueError\n    return (lambda: importlib.import_module(spec))()\n"
    ),
    "second-function": (
        "import importlib\ndef load_python_target(spec, *, allow_python, root, cwd):\n"
        "    if allow_python is not True:\n        raise ValueError\n    return importlib.import_module(spec)\n"
        "def other(n):\n    return importlib.import_module(n)\n"
    ),
    "find-spec-outside-origin-check": (
        "import importlib.util\ndef load_python_target(spec, *, allow_python, root, cwd):\n"
        "    if allow_python is not True:\n        raise ValueError\n    return importlib.util.find_spec(spec)\n"
    ),
    "origin-check-called-before-gate": (
        "import importlib, importlib.util\ndef _check_origins(m, b):\n    importlib.util.find_spec(m)\n"
        "def load_python_target(spec, *, allow_python, root, cwd):\n    _check_origins(spec, None)\n"
        "    if allow_python is not True:\n        raise ValueError\n    return importlib.import_module(spec)\n"
    ),
}


@pytest.mark.parametrize("snippet", list(_HELPER_BYPASSES.values()), ids=list(_HELPER_BYPASSES))
def test_helper_rules_catch_misplaced_imports_in_the_helper_module(snippet: str):
    """
    [Unit] importlib tripwire: verifies the helper must be module-level with the gate dominating the import (M3).

    Scenario:
        Given a helper-module source with a nested helper, an import before or around the gate, a weaker gate,
            or a find_spec outside the origin check
        When the tripwire scans it as telemetry/extensions.py
        Then a violation is reported.

    Boundaries:
        - Focus: close-review finding 4 (helper naming and gate dominance)
        - Fixtures/params: one misplacement per case
        - Scope: import_violations helper rules

    On failure, first check:
        - ``_helper_violations`` and ``_gate_end``
    """
    assert import_violations(_HELPER_MODULE, snippet)


def test_literal_sites_are_exact_and_a_new_literal_is_caught():
    """
    [Unit] importlib tripwire: verifies allowed literal imports are exact (module, function, literal) entries.

    Scenario:
        Given an allowed literal import in deep_support.py and a new literal in the same module
        When the tripwire scans each
        Then the listed literal passes and the unlisted one is reported.

    Boundaries:
        - Focus: explicit allowlist (finding 4 "keep allowed fixed-literal sites explicit")
        - Fixtures/params: none
        - Scope: import_violations

    On failure, first check:
        - ``_LITERAL_SITES``
    """
    assert import_violations("deep_support.py", "import importlib\nimportlib.import_module('spacy')\n") == []
    assert import_violations("deep_support.py", "import importlib\nimportlib.import_module('os')\n")


@pytest.mark.parametrize(
    "snippet",
    [
        "import os\nos.environ.get('DOCSENTINEL_' + 'ALLOW_PYTHON_EXTENSIONS')\n",
        "import os\nos.environ.get('DOCSENTINEL_ALLOW_' + 'PYTHON_' + 'EXTENSIONS')\n",
        "import os\nos.environ.get('DOCSENTINEL_' 'ALLOW_PYTHON_EXTENSIONS')\n",
        "import os\np = 'DOCSENTINEL'\nos.environ.get(f'{p}_ALLOW_PYTHON_EXTENSIONS')\n",
        "import os\nos.getenv(''.join(['DOCSENTINEL', '_ALLOW', '_PYTHON_EXTENSIONS']))\n",
        "import os\nv = os.environ\n",
    ],
    ids=["two-part", "three-part", "implicit-concat", "f-string", "join", "environ-reference"],
)
def test_env_tripwire_catches_built_names_and_env_access(snippet: str):
    """
    [Unit] importlib tripwire: verifies a concatenated gate-variable name or any env access is caught (M2).

    Scenario:
        Given reporting.py source building the gate variable name in pieces, or touching os.environ at all
        When the env tripwire scans it
        Then a violation is reported.

    Boundaries:
        - Focus: close-review finding 4 (env-var tripwire missed concatenated names)
        - Fixtures/params: one spelling per case
        - Scope: env_violations

    On failure, first check:
        - ``_folded_strings``, ``_GATE_FRAGMENTS`` and ``_ENV_NAMES``
    """
    assert env_violations("reporting.py", snippet)
