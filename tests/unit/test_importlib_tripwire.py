"""Importlib and trust-gate tripwires (Milestone 0007 Story 04.0 Task 01, threat model M2/M3).

``docs/security/threat-model-0007-extensions-2026-11-03.md`` M3: every dynamic import under
``src/docsentinel`` goes through the single shared helper
``docsentinel.telemetry.extensions.load_python_target``, which holds the ``python:`` trust gate.
The only other ``importlib.import_module`` call sites allowed are fixed string literals in the
modules that lazily import optional dependencies. ``find_spec`` is likewise confined to the helper
module and the literal availability probes. M2: only ``cli.py`` names the gate's environment
variable. Each tripwire is also run against a seeded violation so it cannot rot into a no-op.
"""

import ast
from pathlib import Path

import pytest

import docsentinel

#: The package source tree.
_SRC = Path(docsentinel.__file__).resolve().parent

#: The shared helper: the only non-literal ``import_module`` site (M3).
_HELPER = ("telemetry/extensions.py", "load_python_target")

#: Modules allowed to call ``import_module`` with a fixed string literal. The threat model names
#: ``deep_support.py``, ``contradictions.py`` and ``_triples.py``; ``detectors/loader.py`` and
#: ``detectors/standard/signatures.py`` predate it and import fixed optional-dependency modules too.
_LITERAL_SITES = frozenset(
    {
        "deep_support.py",
        "detectors/contradictions.py",
        "detectors/_triples.py",
        "detectors/loader.py",
        "detectors/standard/signatures.py",
    }
)

#: Modules allowed to call ``find_spec`` (the helper module only).
_FIND_SPEC_SITES = frozenset({"telemetry/extensions.py"})

#: The gate's environment variable; only ``cli.py`` may name it (M2).
_GATE_ENV = "DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS"


def _call_name(node: ast.Call) -> str:
    """Return the called attribute or bare function name, or ``""``."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def _enclosing_functions(tree: ast.AST) -> dict[ast.AST, str]:
    """Map every node to the name of the innermost enclosing function."""
    owner: dict[ast.AST, str] = {}
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        node, current = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current = node.name
        owner[node] = current
        stack.extend((child, current) for child in ast.iter_child_nodes(node))
    return owner


def import_violations(relative: str, source: str) -> list[str]:
    """Return every disallowed dynamic-import site of one module.

    :param relative: The module path relative to the package root (POSIX).
    :param source: Its source text.
    :returns: ``relative:line: reason`` entries.
    """
    tree = ast.parse(source)
    owner = _enclosing_functions(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in ("importlib", "importlib.util"):
            names = {alias.name for alias in node.names}
            if names & {"import_module", "find_spec", "__import__"}:
                found.append(f"{relative}:{node.lineno}: from-import of a dynamic import function")
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in ("import_module", "__import__"):
            literal = (
                len(node.args) == 1
                and not node.keywords
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            )
            if name == "import_module" and (relative, owner.get(node, "")) == _HELPER:
                continue
            if not (literal and relative in _LITERAL_SITES):
                found.append(f"{relative}:{node.lineno}: {name} outside the shared helper")
        elif name in ("find_spec", "spec_from_file_location", "exec_module", "load_module"):
            literal = len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
            if relative not in _FIND_SPEC_SITES and not (name == "find_spec" and literal):
                found.append(f"{relative}:{node.lineno}: {name} outside the shared helper")
    return found


def env_violations(relative: str, source: str) -> list[str]:
    """Return every string constant equal to the gate's env variable outside ``cli.py``.

    :param relative: The module path relative to the package root.
    :param source: Its source text.
    :returns: ``relative:line`` entries.
    """
    if relative == "cli.py":
        return []
    return [
        f"{relative}:{node.lineno}"
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Constant) and node.value == _GATE_ENV
    ]


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
    helper_source = (_SRC / _HELPER[0]).read_text(encoding="utf-8")

    assert violations == []
    assert f"def {_HELPER[1]}(" in helper_source


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
