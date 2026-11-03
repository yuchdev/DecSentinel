"""CLI report extensions over a live DS101 scan (Milestone 0007 Story 04.0 Task 01).

The scan root is the ``ds101/dangling_file_link`` case: one error-severity dangling link, so a
normal scan exits ``1``. A ``calc`` builtin is patched into the static table (nothing is imported)
and a template requiring it is passed with ``--template``. Pins threat model
``docs/security/threat-model-0007-extensions-2026-11-03.md`` M17 (exit-code integrity), M25 (argv
builtins merged into the effective Config), M28 (nothing on stdout when a hook fails) and M30/M31
(a missing extension fails before any detector runs).
"""

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from docsentinel import cli
from docsentinel.telemetry import builtin
from tests.asset_helpers import AssetCase, load_asset_case

ESC = chr(0x1B)


def _template(directory: Path, requires: list[str]) -> Path:
    """Write a terminal text template printing ``ext.calc.count`` and each ``p.ext.calc.tag``."""
    lines: list[dict[str, Any]] = [
        {"type": "line", "text": "count={ext.calc.count|neutralize}", "variables_used": ["ext.calc.count"]},
        {
            "type": "loop",
            "over": "findings",
            "as": "p",
            "body": [{"type": "line", "text": "tag={p.ext.calc.tag|neutralize}", "variables_used": ["p.ext.calc.tag"]}],
        },
    ]
    raw = {
        "template_version": 1,
        "name": "calc-report",
        "type": "text",
        "requires_extensions": requires,
        "lines": lines,
    }
    path = directory / "calc-report.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _install(monkeypatch: pytest.MonkeyPatch, **hooks: Any) -> None:
    """Register a ``calc`` builtin built from ``hooks``."""
    monkeypatch.setattr(
        builtin, "BUILTIN_EXTENSIONS", MappingProxyType({"calc": lambda: SimpleNamespace(name="calc", **hooks)})
    )


def _healthy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Register a working ``calc`` builtin."""
    _install(
        monkeypatch,
        provide_run=lambda model: {"count": len(model["findings"])},
        provide_problem=lambda problem, doc, model: {"tag": ESC + problem["rule"]},
    )


@pytest.fixture
def scans(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Record the Config every ``cli.scan`` call receives, and run the real scan."""
    seen: list[Any] = []
    real = cli.scan

    def recording(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("config"))
        return real(*args, **kwargs)

    monkeypatch.setattr(cli, "scan", recording)
    return seen


@pytest.mark.parametrize("source", ["argv", "config"])
def test_builtin_extension_data_reaches_the_report(
    source: str,
    asset_case: Callable[[str, str], AssetCase],
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    scans: list[Any],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report extensions cli ds101: verifies a builtin from argv or config feeds the report (M25).

    Scenario:
        Given a DS101 root and a ``calc`` builtin selected by ``--extension builtin:calc`` or telemetry_extensions
        When ``docsentinel scan --template calc-report.json`` runs
        Then the report shows the run and problem data neutralized, the exit code stays 1, and the scan saw
        ``telemetry_extensions == ("builtin:calc",)``.

    Boundaries:
        - Focus: end-to-end normal case; argv builtins merged into the effective Config
        - Fixtures/params: selection source
        - Scope: in-process CLI call

    On failure, first check:
        - the extension block of ``cli.main`` scan branch
    """
    root = asset_case("ds101", "dangling_file_link").root
    _healthy(monkeypatch)
    template = _template(tmp_path_factory.mktemp("tpl"), ["calc"])
    argv = ["scan", str(root), "--template", str(template)]
    if source == "argv":
        argv += ["--extension", "builtin:calc"]
    else:
        (root / "docsentinel.toml").write_text('telemetry_extensions = ["builtin:calc"]\n', encoding="utf-8")

    code = cli.main(argv)
    captured = capsys.readouterr()

    assert code == 1, captured.err
    assert captured.out.splitlines() == ["count=1", "tag=\\x1bDS101"]
    assert [config.telemetry_extensions for config in scans] == [("builtin:calc",)]


@pytest.mark.parametrize("raised", [SystemExit(0), RecursionError("deep"), RuntimeError(ESC + "x" * 2000)])
def test_failing_hook_is_exit_two_with_empty_stdout(
    raised: BaseException,
    asset_case: Callable[[str, str], AssetCase],
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report extensions cli ds101: verifies a failing hook is exit 2, never a downgraded 0 (M17, M28).

    Scenario:
        Given blocking DS101 findings and a ``calc`` problem hook raising SystemExit(0), RecursionError or
        a RuntimeError with an ESC/1 KiB message
        When ``docsentinel scan`` renders the calc template
        Then it exits 2, stdout is empty, and stderr is one bounded, neutralized ``Scan failed:`` line.

    Boundaries:
        - Focus: exit-code integrity and render-then-print order
        - Fixtures/params: one exception per case
        - Scope: in-process CLI call

    On failure, first check:
        - ``extensions._call`` and the CLI's except clause
    """
    root = asset_case("ds101", "dangling_file_link").root

    def hook(problem: Any, doc: Any, model: Any) -> None:
        raise raised

    _install(monkeypatch, provide_problem=hook)
    template = _template(tmp_path_factory.mktemp("tpl"), ["calc"])

    code = cli.main(["scan", str(root), "--template", str(template), "--extension", "builtin:calc"])
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert captured.err.startswith("Scan failed: extension calc: provide_problem failed:")
    assert ESC not in captured.err and len(captured.err) < 600


def test_missing_extension_fails_before_any_detector_runs(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path_factory: pytest.TempPathFactory,
    scans: list[Any],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report extensions cli ds101: verifies requires_extensions is checked before the scan (M30, M31).

    Scenario:
        Given a template requiring ``calc`` and ``evil`` and no extension selected
        When ``docsentinel scan --template`` runs
        Then it exits 2 before ``scan`` is called, and the message never hints at the python gate.

    Boundaries:
        - Focus: load order and the social-engineering-free message
        - Fixtures/params: recorded ``cli.scan``
        - Scope: in-process CLI call

    On failure, first check:
        - ``check_template`` call before ``scan`` in ``cli.main``
    """
    root = asset_case("ds101", "dangling_file_link").root
    template = _template(tmp_path_factory.mktemp("tpl"), ["calc", "evil"])

    code = cli.main(["scan", str(root), "--template", str(template)])
    captured = capsys.readouterr()

    assert code == 2 and captured.out == ""
    assert scans == []
    assert "evil" in captured.err
    assert "--allow-python-extensions" not in captured.err and "python:" not in captured.err


def test_python_extension_named_like_a_builtin_is_refused_on_the_cli(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    scans: list[Any],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report extensions cli ds101: verifies a gated python: extension named ``domain`` is refused (M25).

    Scenario:
        Given an outside module whose factory returns an extension named ``domain``
        When ``docsentinel scan --extension python:<mod>:make --allow-python-extensions`` runs
        Then it exits 2 with a reservation error before the scan.

    Boundaries:
        - Focus: builtin impersonation through the CLI
        - Fixtures/params: module on sys.path outside root and cwd
        - Scope: in-process CLI call

    On failure, first check:
        - the reserved-name check in ``extensions._admit``
    """
    root = asset_case("ds101", "dangling_file_link").root
    modules = tmp_path_factory.mktemp("site")
    name = "ds_cli_domain_impersonator"
    (modules / f"{name}.py").write_text(
        "from types import SimpleNamespace\ndef make():\n    return SimpleNamespace(name='domain')\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))
    monkeypatch.delitem(sys.modules, name, raising=False)

    code = cli.main(["scan", str(root), "--extension", f"python:{name}:make", "--allow-python-extensions"])
    captured = capsys.readouterr()

    assert code == 2 and captured.out == ""
    assert "reserved" in captured.err
    assert scans == []


# --------------------------------------------------------------------------- close-review regressions (2026-11-03)

_EXITER = """
class _Meta(type):
    def __getattribute__(cls, attribute):
        if attribute == "__qualname__":
            raise SystemExit(0)
        return type.__getattribute__(cls, attribute)

class _Evil(Exception, metaclass=_Meta):
    pass

class _Exiter:
    name = "exiter"
    def provide_run(self, model):
        raise _Evil("x")

def make():
    return _Exiter()
"""


def test_hook_exception_whose_qualname_raises_system_exit_is_exit_two(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report extensions cli ds101: verifies a SystemExit(0) from an exception's class name cannot pass.

    Scenario:
        Given a scan with a blocking DS101 finding and an outside python: extension whose run hook raises an
            exception whose metaclass raises SystemExit(0) when ``__qualname__`` is read
        When ``docsentinel scan --extension python:<mod>:make --allow-python-extensions`` runs
        Then it exits 2 with nothing on stdout, never 0.

    Boundaries:
        - Focus: close-review finding 5 (auditor repro c10-metaclass-exit0: exit 0 with a blocking finding)
        - Fixtures/params: module on sys.path outside root and cwd
        - Scope: in-process CLI call

    On failure, first check:
        - ``extensions._qualname``
    """
    root = asset_case("ds101", "dangling_file_link").root
    modules = tmp_path_factory.mktemp("site")
    name = "ds_cli_qualname_exiter"
    (modules / f"{name}.py").write_text(_EXITER, encoding="utf-8")
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))
    monkeypatch.delitem(sys.modules, name, raising=False)

    code = cli.main(["scan", str(root), "--extension", f"python:{name}:make", "--allow-python-extensions"])
    captured = capsys.readouterr()

    assert code == 2 and captured.out == ""
    assert "provide_run failed: <exception>" in captured.err


def test_subdirectory_scan_with_the_checkout_on_pythonpath_is_refused(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    scans: list[Any],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report extensions cli ds101: verifies scanning <repo>/docs still refuses <repo>/evilmod.py (M6).

    Scenario:
        Given a git checkout whose ``docs/`` holds the DS101 case and whose top holds ``evilmod.py``, the checkout
            on sys.path (``PYTHONPATH=<repo>``) and the cwd elsewhere
        When ``docsentinel scan <repo>/docs --extension python:evilmod:make --allow-python-extensions`` runs
        Then it exits 2 before the scan, evilmod never ran and nothing is on stdout.

    Boundaries:
        - Focus: close-review finding 2 (auditor repro: subdirectory scan from elsewhere)
        - Fixtures/params: ``.git`` marker
        - Scope: in-process CLI call

    On failure, first check:
        - ``extensions.project_roots``
    """
    checkout = tmp_path_factory.mktemp("checkout")
    (checkout / ".git").mkdir()
    docs = load_asset_case("ds101", "dangling_file_link", checkout / "docs").root
    sentinel = tmp_path_factory.mktemp("sentinel") / "ran"
    name = "ds_cli_subdir_evilmod"
    (checkout / f"{name}.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('ran')\ndef make():\n    return None\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(checkout))
    monkeypatch.chdir(tmp_path_factory.mktemp("elsewhere"))
    monkeypatch.delitem(sys.modules, name, raising=False)

    code = cli.main(["scan", str(docs), "--extension", f"python:{name}:make", "--allow-python-extensions"])
    captured = capsys.readouterr()

    assert code == 2 and captured.out == ""
    assert "project root" in captured.err
    assert not sentinel.exists()
    assert scans == []


# --------------------------------------------------------------------------- re-verification regressions N1/N2 (2026-11-03)

#: Auditor repro w8: a marker the scanned repo plants under ``docs/`` (or a scan root that is a link to ``docs/``).
_PLANTED_MARKERS = (
    "none",
    "empty-git-file",
    "dangling-git-link",
    "pyproject.toml",
    "docsentinel.toml",
    "doc_sentinel.toml",
    "symlinked-root",
    "link-out-dir",
    "link-out-file",
)


@pytest.fixture
def fresh_modules() -> Any:
    """Forget every ``ds_cli_`` module a test imported."""
    before = set(sys.modules)
    yield
    for name in set(sys.modules) - before:
        if name.startswith("ds_cli_"):
            sys.modules.pop(name, None)


@pytest.mark.parametrize("planted", _PLANTED_MARKERS)
def test_marker_planted_under_docs_never_shrinks_the_boundary(
    planted: str,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    scans: list[Any],
    capsys: pytest.CaptureFixture[str],
    fresh_modules: Any,
):
    """
    [Integration] report extensions cli ds101: verifies a marker planted under docs/ cannot admit <repo>/src (M6).

    Scenario:
        Given a git checkout whose ``src/`` holds an extension that writes a sentinel on import, ``src/`` on sys.path
            (``PYTHONPATH=<repo>/src``), the cwd elsewhere, and ``docs/`` (the DS101 case) carrying a planted marker
            -- none, an empty ``.git`` file, a dangling ``.git`` link, ``pyproject.toml``, ``docsentinel.toml``,
            ``doc_sentinel.toml``, or a ``.git`` file with the scan root given as a symlink to ``docs/``; or (third
            re-verification F1, auditor fixture w14) ``<repo>/docs`` itself a symlink to a directory outside the
            checkout, scanned as that directory or as a file inside it
        When ``docsentinel scan <root> --extension python:<ext>:make --allow-python-extensions`` runs
        Then it exits 2 before the scan, nothing is on stdout and the extension never ran.

    Boundaries:
        - Focus: re-verification finding N1 (auditor repro w8, one row per marker) and third re-verification F1
          (the CLI must anchor the unresolved root spelling, not only the resolved one)
        - Fixtures/params: one planted marker per case; ``none`` is the control
        - Scope: in-process CLI call

    On failure, first check:
        - ``extensions.project_roots`` (every marked ancestor, not the nearest)
        - for ``link-out-*``: the ``origin_root`` the scan branch of ``cli.main`` passes to ``_report_extensions``
    """
    checkout = tmp_path_factory.mktemp("checkout")
    (checkout / ".git").mkdir()
    if planted.startswith("link-out"):
        linked = load_asset_case("ds101", "dangling_file_link", tmp_path_factory.mktemp("linked") / "docs").root
        os.symlink(linked, checkout / "docs")
        docs = checkout / "docs"
    else:
        docs = load_asset_case("ds101", "dangling_file_link", checkout / "docs").root
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    sentinel = tmp_path_factory.mktemp("sentinel") / "ran"
    name = f"ds_cli_company_ext_{planted.replace('-', '_').replace('.', '_')}"
    (checkout / "src").mkdir()
    (checkout / "src" / f"{name}.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('ran')\n"
        "class E:\n    name = 'company'\ndef make():\n    return E()\n",
        encoding="utf-8",
    )
    root = docs
    if planted in ("empty-git-file", "symlinked-root"):
        (docs / ".git").write_text("", encoding="utf-8")
    elif planted == "dangling-git-link":
        os.symlink(checkout / "does-not-exist", docs / ".git")
    elif planted not in ("none", "link-out-dir", "link-out-file"):
        (docs / planted).write_text("", encoding="utf-8")
    if planted == "symlinked-root":
        root = elsewhere / "link"
        os.symlink(docs, root)
    elif planted == "link-out-file":
        root = docs / "README.md"
    monkeypatch.syspath_prepend(str(checkout / "src"))
    monkeypatch.chdir(elsewhere)

    code = cli.main(["scan", str(root), "--extension", f"python:{name}:make", "--allow-python-extensions"])
    captured = capsys.readouterr()

    assert code == 2 and captured.out == ""
    assert "sys.path" in captured.err
    assert not sentinel.exists()
    assert name not in sys.modules
    assert scans == []


@pytest.mark.parametrize("inserted", ["cwd", "root"])
def test_factory_putting_the_checkout_on_sys_path_fails_before_the_hook(
    inserted: str,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fresh_modules: Any,
):
    """
    [Integration] report extensions cli ds101: verifies sys.path is re-checked after the factory (M6, N2).

    Scenario:
        Given an honest out-of-checkout extension whose factory does ``sys.path.insert(0, <cwd or scan root>)`` and
            whose run hook does ``import <helper>``, and a planted helper there that writes a sentinel and rewrites
            its own ``__file__``/``__spec__.origin`` to the interpreter's site-packages (auditor repro w13), the cwd
            being the git checkout
        When ``docsentinel scan <repo>/docs --extension python:<ext>:make --allow-python-extensions`` runs
        Then it exits 2 naming sys.path, nothing is on stdout, the factory ran but the hook and the helper never did.

    Boundaries:
        - Focus: re-verification finding N2 (prevention instead of location-trusting detection)
        - Fixtures/params: the cwd and the scan root as the inserted entry
        - Scope: in-process CLI call

    On failure, first check:
        - the per-factory ``watch.check()`` in ``extensions.resolve_extensions`` and ``ModuleWatch.check_path``
    """
    checkout = tmp_path_factory.mktemp("checkout")
    (checkout / ".git").mkdir()
    docs = load_asset_case("ds101", "dangling_file_link", checkout / "docs").root
    outside = tmp_path_factory.mktemp("outside")
    sentinels = tmp_path_factory.mktemp("sentinel")
    helper = f"ds_cli_company_helpers_{inserted}"
    ext = f"ds_cli_honest_ext_{inserted}"
    target = checkout if inserted == "cwd" else docs
    (target / f"{helper}.py").write_text(
        "import pathlib, sysconfig\n"
        f"pathlib.Path({str(sentinels / 'helper')!r}).write_text('x')\n"
        f"fake = sysconfig.get_path('purelib') + '/{helper}.py'\n"
        "__file__ = fake\n__spec__.origin = fake\n",
        encoding="utf-8",
    )
    (outside / f"{ext}.py").write_text(
        "import os, pathlib, sys\n"
        "class E:\n    name = 'honest'\n    def provide_run(self, model):\n"
        f"        pathlib.Path({str(sentinels / 'hook')!r}).write_text('x')\n"
        f"        import {helper}\n        return {{'v': 1}}\n"
        "def make():\n"
        f"    pathlib.Path({str(sentinels / 'factory')!r}).write_text('x')\n"
        f"    sys.path.insert(0, {'os.getcwd()' if inserted == 'cwd' else repr(str(docs))})\n"
        "    return E()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.syspath_prepend(str(outside))
    monkeypatch.chdir(checkout)

    code = cli.main(["scan", str(docs), "--extension", f"python:{ext}:make", "--allow-python-extensions"])
    captured = capsys.readouterr()

    assert code == 2 and captured.out == ""
    assert "sys.path" in captured.err
    assert (sentinels / "factory").exists()
    assert not (sentinels / "hook").exists() and not (sentinels / "helper").exists()
    assert helper not in sys.modules
