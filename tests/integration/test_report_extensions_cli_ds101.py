"""CLI report extensions over a live DS101 scan (Milestone 0007 Story 04.0 Task 01).

The scan root is the ``ds101/dangling_file_link`` case: one error-severity dangling link, so a
normal scan exits ``1``. A ``calc`` builtin is patched into the static table (nothing is imported)
and a template requiring it is passed with ``--template``. Pins threat model
``docs/security/threat-model-0007-extensions-2026-11-03.md`` M17 (exit-code integrity), M25 (argv
builtins merged into the effective Config), M28 (nothing on stdout when a hook fails) and M30/M31
(a missing extension fails before any detector runs).
"""

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from docsentinel import cli
from docsentinel.telemetry import builtin
from tests.asset_helpers import AssetCase

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
