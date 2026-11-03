"""M6 origin probes with real planted modules (Milestone 0007 Story 04.0 Task 01).

Threat model ``docs/security/threat-model-0007-extensions-2026-11-03.md`` T2/M6: with the gate open,
a ``python:`` spec whose module (or any dotted parent, or a namespace search location, or an already
imported ``sys.modules`` entry) lies inside the scan root or the current directory is refused before
it executes. Every planted module writes a sentinel file when imported; the sentinel must never
appear. The real import machinery is used; the module directories are put on ``sys.path`` the way
``python -m``, pytest or ``PYTHONPATH=.`` would.
"""

import itertools
import os
import sys
import types
from collections.abc import Iterator
from pathlib import Path

import pytest

from docsentinel.config import Config
from docsentinel.telemetry.extensions import ExtensionError, load_python_target, resolve_extensions

_COUNTER = itertools.count()


@pytest.fixture
def layout(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Path]]:
    """Return separate root, cwd and outside directories, all on ``sys.path``; chdir into cwd."""
    dirs = {name: tmp_path_factory.mktemp(name) for name in ("root", "cwd", "outside")}
    monkeypatch.chdir(dirs["cwd"])
    for name in ("root", "cwd", "outside"):
        monkeypatch.syspath_prepend(str(dirs[name]))
    before = set(sys.modules)
    yield dirs
    for name in set(sys.modules) - before:
        if name.startswith("ds_m6_"):
            sys.modules.pop(name, None)


def _unique(stem: str) -> str:
    """Return a module name unique to this session."""
    return f"ds_m6_{stem}_{next(_COUNTER)}"


def _plant(directory: Path, relative: str, sentinel: Path, body: str = "") -> Path:
    """Write a module that creates ``sentinel`` when imported."""
    target = directory / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n{body}", encoding="utf-8"
    )
    return target


def _load(spec: str, layout: dict[str, Path]) -> object:
    """Run the shared helper with the gate open."""
    return load_python_target(spec, allow_python=True, root=layout["root"], cwd=layout["cwd"])


@pytest.mark.parametrize("where", ["root", "cwd"])
def test_planted_module_in_root_or_cwd_is_refused_and_never_runs(where: str, layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies an in-root or in-cwd module is refused unexecuted (M6).

    Scenario:
        Given ``evilmod.py`` planted in the scan root (or the cwd), importable from sys.path
        When ``python:evilmod:make`` is loaded with the gate open
        Then an ExtensionError is raised, the sentinel file does not exist and the module is not imported.

    Boundaries:
        - Focus: import hijack through the checkout (T2)
        - Fixtures/params: root and cwd placements
        - Scope: load_python_target with the real import machinery

    On failure, first check:
        - ``extensions._check_origins`` and ``_is_inside``
    """
    name = _unique("evilmod")
    sentinel = layout["outside"] / f"{name}.sentinel"
    _plant(layout[where], f"{name}.py", sentinel, "def make():\n    return None\n")

    with pytest.raises(ExtensionError, match="inside the scan root or the current directory") as caught:
        _load(f"python:{name}:make", layout)

    assert not sentinel.exists()
    assert name not in sys.modules
    assert str(layout[where]) not in str(caught.value)


def test_package_with_an_in_root_parent_is_refused_before_the_parent_runs(layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies a dotted spec is refused when its parent package is in-root (M6).

    Scenario:
        Given a package whose ``__init__.py`` is in the root and whose leaf module is outside
        When ``python:<pkg>.leaf:make`` is loaded with the gate open
        Then it is refused and neither the parent nor the leaf ran.

    Boundaries:
        - Focus: every dotted prefix is checked, outermost first
        - Fixtures/params: none
        - Scope: load_python_target

    On failure, first check:
        - the prefix loop in ``extensions._check_origins``
    """
    name = _unique("pkg")
    parent_sentinel = layout["outside"] / f"{name}.parent"
    leaf_sentinel = layout["outside"] / f"{name}.leaf"
    leaf_dir = layout["outside"] / "leafdir"
    _plant(leaf_dir, "leaf.py", leaf_sentinel, "def make():\n    return None\n")
    _plant(layout["root"], f"{name}/__init__.py", parent_sentinel, f"__path__.append({str(leaf_dir)!r})\n")

    with pytest.raises(ExtensionError, match="inside the scan root"):
        _load(f"python:{name}.leaf:make", layout)

    assert not parent_sentinel.exists() and not leaf_sentinel.exists()


def test_namespace_package_with_an_in_root_location_is_refused(layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies a namespace package spanning the root is refused (M6).

    Scenario:
        Given a namespace package (no ``__init__``) with portions in the outside directory and in the root
        When its outside leaf is loaded with the gate open
        Then it is refused because one search location is inside the root, and the leaf never ran.

    Boundaries:
        - Focus: namespace packages have no origin; their search locations are checked
        - Fixtures/params: none
        - Scope: load_python_target

    On failure, first check:
        - ``extensions._spec_locations`` submodule_search_locations handling
    """
    name = _unique("ns")
    sentinel = layout["outside"] / f"{name}.leaf"
    (layout["root"] / name).mkdir()
    _plant(layout["outside"], f"{name}/leaf.py", sentinel, "def make():\n    return None\n")

    with pytest.raises(ExtensionError, match="inside the scan root"):
        _load(f"python:{name}.leaf:make", layout)

    assert not sentinel.exists()


def test_preimported_in_root_module_is_refused(layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] extension origin check: verifies an in-root module already in sys.modules is refused (M6).

    Scenario:
        Given a module object whose ``__file__`` is in the root, already present in sys.modules
        When it is loaded with the gate open
        Then it is refused and its callable is never resolved or called.

    Boundaries:
        - Focus: sys.modules is checked, not just find_spec
        - Fixtures/params: none
        - Scope: load_python_target

    On failure, first check:
        - ``extensions._module_locations``
    """
    name = _unique("pre")
    calls: list[int] = []
    module = types.ModuleType(name)
    module.__file__ = str(layout["root"] / f"{name}.py")
    module.make = lambda: calls.append(1)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, name, module)

    with pytest.raises(ExtensionError, match="inside the scan root"):
        _load(f"python:{name}:make", layout)
    assert calls == []


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are not available")
def test_in_root_symlink_to_an_outside_module_is_refused(layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies an in-root symlink to an outside file is still refused (M6).

    Scenario:
        Given ``<root>/<name>.py`` symlinked to a module file outside the root and cwd
        When it is loaded with the gate open
        Then it is refused (the location as written is in-root) and the target never ran.

    Boundaries:
        - Focus: the checkout choosing existing code through a symlink
        - Fixtures/params: none
        - Scope: load_python_target

    On failure, first check:
        - the lexical candidate in ``extensions._is_inside``
    """
    name = _unique("link")
    sentinel = layout["outside"] / f"{name}.sentinel"
    target = _plant(layout["outside"] / "hidden", "real.py", sentinel, "def make():\n    return None\n")
    (layout["root"] / f"{name}.py").symlink_to(target)

    with pytest.raises(ExtensionError, match="inside the scan root"):
        _load(f"python:{name}:make", layout)
    assert not sentinel.exists()


def test_outside_module_loads_and_resolves_its_callable(layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies a module outside root and cwd loads through the helper (M5, M6).

    Scenario:
        Given an outside module defining ``factories.make`` returning an extension
        When ``python:<module>:factories.make`` is resolved with the gate open
        Then the extension loads and the sentinel shows the module ran exactly as expected.

    Boundaries:
        - Focus: normal case of the gate, origin check and dotted callable path
        - Fixtures/params: none
        - Scope: resolve_extensions

    On failure, first check:
        - the ``getattr`` loop in ``extensions.load_python_target``
    """
    name = _unique("good")
    sentinel = layout["outside"] / f"{name}.sentinel"
    body = (
        "from types import SimpleNamespace\n"
        "class factories:\n"
        "    @staticmethod\n"
        "    def make():\n"
        "        return SimpleNamespace(name='good', provide_run=lambda model: {'ok': True})\n"
    )
    _plant(layout["outside"], f"{name}.py", sentinel, body)

    loaded = resolve_extensions(
        (f"python:{name}:factories.make",),
        config=Config(),
        allow_python=True,
        root=layout["root"],
        cwd=layout["cwd"],
    )

    assert loaded.names == ("good",)
    assert sentinel.exists()


def test_missing_module_and_missing_callable_are_bounded_errors(layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies a missing module or attribute is an ExtensionError without paths.

    Scenario:
        Given a spec naming a module that does not exist, and one naming a missing attribute of an outside module
        When each is loaded with the gate open
        Then each raises an ExtensionError that echoes no absolute path.

    Boundaries:
        - Focus: invalid input and M27 path hygiene
        - Fixtures/params: none
        - Scope: load_python_target

    On failure, first check:
        - error construction in ``extensions.load_python_target``
    """
    name = _unique("plain")
    _plant(layout["outside"], f"{name}.py", layout["outside"] / f"{name}.sentinel")

    with pytest.raises(ExtensionError, match="not found"):
        _load(f"python:{_unique('absent')}:make", layout)
    with pytest.raises(ExtensionError, match="callable not found") as caught:
        _load(f"python:{name}:make", layout)
    assert str(layout["outside"]) not in str(caught.value)
