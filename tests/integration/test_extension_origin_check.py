"""M6 origin probes with real planted modules (Milestone 0007 Story 04.0 Task 01).

Threat model ``docs/security/threat-model-0007-extensions-2026-11-03.md`` T2/M6: with the gate open,
a ``python:`` spec is refused before it executes when a ``sys.path`` entry lies inside the scan root,
its project root or the current directory, or when its module (or any dotted parent, or a namespace
search location, or an already imported ``sys.modules`` entry) lies there; and a run fails when an
admitted extension imports a module from there. Every planted module writes a sentinel file when
imported; the sentinel must never appear where the refusal precedes the import. The real import
machinery is used; module directories are put on ``sys.path`` the way ``python -m``, pytest or
``PYTHONPATH=.`` would. Tests marked "origin layer" disable the ``sys.path`` layer (as a custom finder
or ``.pth`` hook would bypass it) to pin the per-module check behind it.
"""

import itertools
import os
import sys
import types
from collections.abc import Iterator
from pathlib import Path

import pytest

from docsentinel.config import Config
from docsentinel.models import Document, ScanResult
from docsentinel.reporting import render
from docsentinel.telemetry import extensions
from docsentinel.telemetry.extensions import ExtensionError, load_python_target, project_roots, resolve_extensions

_COUNTER = itertools.count()


@pytest.fixture
def layout(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Path]]:
    """Return separate root, cwd and outside directories, only ``outside`` on ``sys.path``; chdir into cwd."""
    dirs = {name: tmp_path_factory.mktemp(name) for name in ("root", "cwd", "outside")}
    monkeypatch.chdir(dirs["cwd"])
    monkeypatch.syspath_prepend(str(dirs["outside"]))
    before = set(sys.modules)
    yield dirs
    for name in set(sys.modules) - before:
        if name.startswith("ds_m6_"):
            sys.modules.pop(name, None)


@pytest.fixture
def origin_layer(layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Put root and cwd on ``sys.path`` too, with the ``sys.path`` layer disabled (origin layer only)."""
    for name in ("root", "cwd"):
        monkeypatch.syspath_prepend(str(layout[name]))
    monkeypatch.setattr(extensions, "_check_import_path", lambda boundary, cwd: None)
    return layout


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


@pytest.mark.parametrize("layer", ["sys.path", "origin"])
@pytest.mark.parametrize("where", ["root", "cwd"])
def test_planted_module_in_root_or_cwd_is_refused_and_never_runs(
    where: str, layer: str, layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
):
    """
    [Integration] extension origin check: verifies an in-root or in-cwd module is refused unexecuted (M6).

    Scenario:
        Given ``evilmod.py`` planted in the scan root (or the cwd), importable from sys.path
        When ``python:evilmod:make`` is loaded with the gate open
        Then an ExtensionError is raised, the sentinel file does not exist and the module is not imported,
        whether the sys.path layer or (with it disabled) the per-module origin layer refuses it.

    Boundaries:
        - Focus: import hijack through the checkout (T2)
        - Fixtures/params: root and cwd placements; each refusal layer
        - Scope: load_python_target with the real import machinery

    On failure, first check:
        - ``extensions._check_import_path``, ``_check_origins`` and ``_Boundary.refuses``
    """
    name = _unique("evilmod")
    sentinel = layout["outside"] / f"{name}.sentinel"
    _plant(layout[where], f"{name}.py", sentinel, "def make():\n    return None\n")
    monkeypatch.syspath_prepend(str(layout[where]))
    if layer == "origin":
        monkeypatch.setattr(extensions, "_check_import_path", lambda boundary, cwd: None)

    with pytest.raises(
        ExtensionError, match="inside the scan root, its project root or the current directory"
    ) as caught:
        _load(f"python:{name}:make", layout)

    assert not sentinel.exists()
    assert name not in sys.modules
    assert str(layout[where]) not in str(caught.value)


def test_package_with_an_in_root_parent_is_refused_before_the_parent_runs(origin_layer: dict[str, Path]):
    layout = origin_layer
    """
    [Integration] extension origin check: verifies a dotted spec is refused when its parent package is in-root (M6).

    Scenario:
        Given a package whose ``__init__.py`` is in the root and whose leaf module is outside
        When ``python:<pkg>.leaf:make`` is loaded with the gate open
        Then it is refused and neither the parent nor the leaf ran.

    Boundaries:
        - Focus: every dotted prefix is checked, outermost first
        - Fixtures/params: none
        - Scope: load_python_target, origin layer

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


def test_namespace_package_with_an_in_root_location_is_refused(origin_layer: dict[str, Path]):
    layout = origin_layer
    """
    [Integration] extension origin check: verifies a namespace package spanning the root is refused (M6).

    Scenario:
        Given a namespace package (no ``__init__``) with portions in the outside directory and in the root
        When its outside leaf is loaded with the gate open
        Then it is refused because one search location is inside the root, and the leaf never ran.

    Boundaries:
        - Focus: namespace packages have no origin; their search locations are checked
        - Fixtures/params: none
        - Scope: load_python_target, origin layer

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
def test_in_root_symlink_to_an_outside_module_is_refused(origin_layer: dict[str, Path]):
    layout = origin_layer
    """
    [Integration] extension origin check: verifies an in-root symlink to an outside file is still refused (M6).

    Scenario:
        Given ``<root>/<name>.py`` symlinked to a module file outside the root and cwd
        When it is loaded with the gate open
        Then it is refused (the location as written is in-root) and the target never ran.

    Boundaries:
        - Focus: the checkout choosing existing code through a symlink
        - Fixtures/params: none
        - Scope: load_python_target, origin layer

    On failure, first check:
        - the lexical candidate in ``extensions._Boundary.refuses``
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


# --------------------------------------------------------------------------- close-review regressions (2026-11-03)


def _plant_extension(directory: Path, name: str, sentinel: Path, body: str) -> None:
    """Write an outside extension module whose import, factory or hook runs ``body`` parts."""
    _plant(directory, f"{name}.py", sentinel, body)


@pytest.mark.parametrize("entry", ["", "."], ids=["empty-entry", "relative-entry"])
def test_cwd_entry_on_sys_path_refuses_before_any_import(
    entry: str, layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
):
    """
    [Integration] extension origin check: verifies a '' or relative sys.path entry (python -m / -c) refuses (M6).

    Scenario:
        Given ``sys.path`` starting with ``''`` (or ``.``) as ``python -m`` and ``python -c`` set it,
            an outside extension that does ``import <helper>`` and a ``<helper>.py`` planted in the cwd
        When the outside extension is loaded with the gate open
        Then an ExtensionError names sys.path, and neither the extension nor the planted helper ran.

    Boundaries:
        - Focus: close-review finding 1 (transitive import of a planted cwd module)
        - Fixtures/params: the empty and the relative spelling of the cwd entry
        - Scope: load_python_target with the real import machinery

    On failure, first check:
        - ``extensions._check_import_path`` handling of ``''`` and relative entries
    """
    helper = _unique("csvlike")
    ext = _unique("goodext")
    helper_sentinel = layout["outside"] / f"{helper}.sentinel"
    ext_sentinel = layout["outside"] / f"{ext}.sentinel"
    _plant(layout["cwd"], f"{helper}.py", helper_sentinel)
    _plant_extension(layout["outside"], ext, ext_sentinel, f"import {helper}\ndef make():\n    return None\n")
    monkeypatch.syspath_prepend(entry)

    with pytest.raises(ExtensionError, match=r"sys\.path"):
        _load(f"python:{ext}:make", layout)

    assert not helper_sentinel.exists() and not ext_sentinel.exists()


def test_checkout_on_pythonpath_after_an_outside_extension_is_refused(
    layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
):
    """
    [Integration] extension origin check: verifies PYTHONPATH=<out>:<repo> refuses a transitive import (M6).

    Scenario:
        Given ``sys.path`` = [outside, root] (``PYTHONPATH=<out>:<repo>``), an outside extension that imports
            ``helperlib_x`` and ``helperlib_x.py`` planted in the root
        When the outside extension is resolved with the gate open
        Then the run is refused before anything is imported and no sentinel exists.

    Boundaries:
        - Focus: close-review finding 1 (auditor repro c8b-transitive-pp)
        - Fixtures/params: none
        - Scope: resolve_extensions

    On failure, first check:
        - ``extensions._check_import_path``
    """
    helper = _unique("helperlib_x")
    ext = _unique("goodext")
    helper_sentinel = layout["outside"] / f"{helper}.sentinel"
    ext_sentinel = layout["outside"] / f"{ext}.sentinel"
    _plant(layout["root"], f"{helper}.py", helper_sentinel)
    _plant_extension(layout["outside"], ext, ext_sentinel, f"import {helper}\ndef make():\n    return None\n")
    monkeypatch.syspath_prepend(str(layout["root"]))
    monkeypatch.syspath_prepend(str(layout["outside"]))

    with pytest.raises(ExtensionError, match=r"sys\.path"):
        resolve_extensions(
            (f"python:{ext}:make",), config=Config(), allow_python=True, root=layout["root"], cwd=layout["cwd"]
        )

    assert not helper_sentinel.exists() and not ext_sentinel.exists()


def _sneaky_body(root: Path, helper: str, stage: str) -> str:
    """Return an outside extension that adds ``root`` to sys.path and imports ``helper`` at ``stage``."""
    sneak = f"    import sys\n    sys.path.insert(0, {str(root)!r})\n    import {helper}\n"
    return (
        "from types import SimpleNamespace\n"
        f"def _sneak():\n{sneak}"
        + ("_sneak()\n" if stage == "import" else "")
        + "def _run(model):\n"
        + ("    _sneak()\n" if stage == "hook" else "")
        + "    return {'ok': True}\n"
        + "def make():\n"
        + ("    _sneak()\n" if stage == "factory" else "")
        + "    return SimpleNamespace(name='sneaky', provide_run=_run)\n"
    )


_DOC = ScanResult(
    profile="fast", documents=(Document("a.md", 1),), findings=(), enabled_rules=(), pending=(), notice=""
)


@pytest.mark.parametrize("stage", ["import", "factory", "hook"])
def test_module_imported_from_the_checkout_during_the_run_fails_the_run(
    stage: str, layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
):
    """
    [Integration] extension origin check: verifies a planted module imported by an admitted extension fails the run.

    Scenario:
        Given an outside extension that, at import time, in its factory or in its run hook, puts the root on
            sys.path itself and imports a helper planted there
        When the report is rendered with the gate open
        Then an ExtensionError naming the helper (never its path) is raised and no report is produced.

    Boundaries:
        - Focus: close-review finding 1 (the sys.modules before/after comparison)
        - Fixtures/params: the import, factory and hook stages
        - Scope: reporting.render over resolve_extensions, the hooks and the ModuleWatch

    On failure, first check:
        - ``extensions.ModuleWatch.check`` and its call sites (helper, resolve_extensions, hooks, render)
    """
    helper = _unique("planted")
    ext = _unique("sneaky")
    _plant(layout["root"], f"{helper}.py", layout["outside"] / f"{helper}.sentinel")
    _plant_extension(
        layout["outside"], ext, layout["outside"] / f"{ext}.sentinel", _sneaky_body(layout["root"], helper, stage)
    )
    monkeypatch.setattr(sys, "path", list(sys.path))

    with pytest.raises(ExtensionError, match=f"module {helper} was imported during the run") as caught:
        render(_DOC, extensions=(f"python:{ext}:make",), allow_python_extensions=True, root=layout["root"])

    assert str(layout["root"]) not in str(caught.value)


def test_extension_importing_only_outside_modules_renders(layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies an extension importing stdlib and outside modules is accepted.

    Scenario:
        Given an outside extension that imports ``csv`` and an outside helper at import time and in its hook
        When the report is rendered with the gate open
        Then the render succeeds (the ModuleWatch accepts modules outside the boundary).

    Boundaries:
        - Focus: normal case of finding 1's after-the-fact check (no false positive)
        - Fixtures/params: none
        - Scope: reporting.render

    On failure, first check:
        - ``extensions.ModuleWatch.check`` and ``_Boundary.refuses``
    """
    helper = _unique("outhelper")
    ext = _unique("tidy")
    _plant(layout["outside"], f"{helper}.py", layout["outside"] / f"{helper}.sentinel")
    body = (
        "import csv\nfrom types import SimpleNamespace\n"
        f"def _run(model):\n    import {helper}\n    return {{'ok': True}}\n"
        "def make():\n    return SimpleNamespace(name='tidy', provide_run=_run)\n"
    )
    _plant_extension(layout["outside"], ext, layout["outside"] / f"{ext}.sentinel", body)

    report = render(_DOC, "json", extensions=(f"python:{ext}:make",), allow_python_extensions=True, root=layout["root"])

    assert '"documents"' in report


def _checkout(layout: dict[str, Path], marker: str) -> tuple[Path, Path]:
    """Make ``root`` a checkout with ``marker`` and a ``docs/`` subdirectory; return (checkout, docs)."""
    checkout = layout["root"]
    if marker == ".git":
        (checkout / ".git").mkdir()
    else:
        (checkout / marker).write_text("", encoding="utf-8")
    docs = checkout / "docs" / "guide"
    docs.mkdir(parents=True)
    return checkout, docs


@pytest.mark.parametrize("marker", [".git", "docsentinel.toml", "doc_sentinel.toml", "pyproject.toml"])
def test_scanning_a_subdirectory_still_covers_the_checkout(
    marker: str, layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch
):
    """
    [Integration] extension origin check: verifies the project root of a subdirectory scan is an anchor (M6).

    Scenario:
        Given a checkout marked by ``marker`` with ``evilmod.py`` at its top, put on sys.path
            (``PYTHONPATH=<repo>``), the cwd elsewhere, and the scan root ``<repo>/docs/guide``
        When ``python:evilmod:make`` is loaded with the gate open
        Then it is refused and evilmod never ran, by the sys.path layer and by the origin layer alone.

    Boundaries:
        - Focus: close-review finding 2 (auditor repro: scan <repo>/docs from elsewhere)
        - Fixtures/params: each project-root marker
        - Scope: load_python_target

    On failure, first check:
        - ``extensions.project_roots`` and ``PROJECT_ROOT_MARKERS``
    """
    checkout, docs = _checkout(layout, marker)
    name = _unique("evilmod")
    sentinel = layout["outside"] / f"{name}.sentinel"
    _plant(checkout, f"{name}.py", sentinel, "def make():\n    return None\n")
    monkeypatch.syspath_prepend(str(checkout))

    with pytest.raises(ExtensionError, match=r"sys\.path"):
        load_python_target(f"python:{name}:make", allow_python=True, root=docs, cwd=layout["cwd"])
    monkeypatch.setattr(extensions, "_check_import_path", lambda boundary, cwd: None)
    with pytest.raises(ExtensionError, match="its project root"):
        load_python_target(f"python:{name}:make", allow_python=True, root=docs, cwd=layout["cwd"])

    assert not sentinel.exists()


def test_project_root_is_the_nearest_marked_ancestor(layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies project_roots picks the nearest marker and none without one.

    Scenario:
        Given an outer directory with ``.git`` holding an inner one with ``pyproject.toml`` and a ``docs`` below it,
            and a separate unmarked directory
        When project_roots is asked for ``inner/docs``, ``inner`` and the unmarked directory
        Then it returns ``inner`` twice (the scan root itself counts) and nothing for the unmarked tree.

    Boundaries:
        - Focus: finding 2 normal and edge cases
        - Fixtures/params: none
        - Scope: project_roots

    On failure, first check:
        - the ancestor walk in ``extensions.project_roots``
    """
    outer = layout["root"]
    (outer / ".git").mkdir()
    inner = outer / "inner"
    (inner / "docs").mkdir(parents=True)
    (inner / "pyproject.toml").write_text("", encoding="utf-8")

    assert os.path.realpath(inner) in {os.path.realpath(p) for p in project_roots(inner / "docs")}
    assert {os.path.realpath(p) for p in project_roots(inner)} == {os.path.realpath(inner)}
    assert all(os.path.realpath(p) != os.path.realpath(outer) for p in project_roots(inner / "docs"))
    assert project_roots(layout["outside"]) == ()


def test_sys_modules_entry_without_a_location_is_refused(layout: dict[str, Path], monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] extension origin check: verifies a locationless sys.modules entry is refused (M6, finding 7).

    Scenario:
        Given a module object in sys.modules with no ``__spec__``, ``__file__`` or ``__path__`` (an in-root module
            that dropped its location)
        When it is loaded with the gate open
        Then it is refused and its callable is never resolved.

    Boundaries:
        - Focus: close-review finding 7 (auditor probe p06 ghostmod)
        - Fixtures/params: none
        - Scope: load_python_target

    On failure, first check:
        - ``extensions._refuse_module`` and ``_is_fileless_by_design``
    """
    name = _unique("ghost")
    calls: list[int] = []
    module = types.ModuleType(name)
    module.make = lambda: calls.append(1)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, name, module)

    with pytest.raises(ExtensionError, match="no file location"):
        _load(f"python:{name}:make", layout)
    assert calls == []


def test_builtin_module_without_a_file_is_accepted(layout: dict[str, Path]):
    """
    [Integration] extension origin check: verifies a builtin module (no file by design) still resolves (M6).

    Scenario:
        Given the builtin ``sys`` module, which has no file location
        When ``python:sys:getrecursionlimit`` is loaded with the gate open
        Then the callable is returned.

    Boundaries:
        - Focus: edge case of finding 7 (builtin/frozen exemption)
        - Fixtures/params: none
        - Scope: load_python_target

    On failure, first check:
        - ``extensions._is_fileless_by_design``
    """
    assert _load("python:sys:getrecursionlimit", layout) is sys.getrecursionlimit
