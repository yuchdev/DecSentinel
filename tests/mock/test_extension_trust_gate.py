"""Trust-gate tests with the import machinery replaced (Milestone 0007 Story 04.0 Task 01).

``importlib.import_module`` and ``importlib.util.find_spec`` are wrapped so every requested module
name is recorded; the planted extension module names below never exist, so any attempt to resolve
one is visible. Threat model ``docs/security/threat-model-0007-extensions-2026-11-03.md`` M1, M2,
M4 and M32.
"""

import importlib
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from docsentinel import cli
from docsentinel.config import Config, ConfigError, load_config
from docsentinel.engine import scan
from docsentinel.models import ScanResult
from docsentinel.reporting import render
from docsentinel.telemetry.extensions import ExtensionError, resolve_extensions

#: The planted module the gate must never resolve.
EVIL = "ds_planted_evil_ext"
#: A module the mocked machinery pretends is installed outside the root and cwd.
GOOD = "ds_mocked_good_ext"
GATE_ENV = cli.ALLOW_PYTHON_EXTENSIONS_ENV

_EMPTY = ScanResult(profile="fast", documents=(), findings=(), enabled_rules=(), pending=(), notice="")


@pytest.fixture
def imports(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    """Record every import_module/find_spec request; serve ``GOOD`` from outside, refuse the rest of ours."""
    requested: list[str] = []
    real_import = importlib.import_module
    real_find = importlib.util.find_spec
    outside = tmp_path_factory.mktemp("site") / f"{GOOD}.py"
    module = types.ModuleType(GOOD)
    module.__file__ = str(outside)
    module.make = lambda: SimpleNamespace(name="good", provide_run=lambda model: {"ok": True})  # type: ignore[attr-defined]

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        requested.append(name)
        if name == GOOD:
            return module
        if name.startswith("ds_"):
            raise AssertionError(f"import_module({name}) must not be called")
        return real_import(name, *args, **kwargs)

    def fake_find(name: str, *args: Any, **kwargs: Any) -> Any:
        requested.append(name)
        if name == GOOD:
            return importlib.machinery.ModuleSpec(GOOD, None, origin=str(outside))
        if name.startswith("ds_"):
            raise AssertionError(f"find_spec({name}) must not be called")
        return real_find(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake_import)
    monkeypatch.setattr(importlib.util, "find_spec", fake_find)
    monkeypatch.delitem(sys.modules, GOOD, raising=False)
    monkeypatch.delenv(GATE_ENV, raising=False)
    return requested


def _ours(requested: list[str]) -> list[str]:
    """Return the recorded requests for planted/mocked extension modules."""
    return [name for name in requested if name.startswith("ds_")]


def _project(root: Path, entries: str) -> Path:
    """Write a docsentinel.toml with the given telemetry_extensions array literal and one document."""
    (root / "docsentinel.toml").write_text(f"telemetry_extensions = {entries}\n", encoding="utf-8")
    (root / "README.md").write_text("# Title\n\nText.\n", encoding="utf-8")
    return root


# --------------------------------------------------------------------------- M1 config is builtin-only


@pytest.mark.parametrize("gate", ["none", "flag", "env"])
def test_config_python_entry_is_a_config_error_whatever_the_gate(
    gate: str,
    imports: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Mock] extension gate: verifies a python: entry in config is a ConfigError with the flag, env or neither (M1).

    Scenario:
        Given a docsentinel.toml naming ``python:<planted>:make``
        When ``docsentinel scan`` runs with no gate, with --allow-python-extensions and with the env var
        Then each run exits 2 with ``Scan failed:`` and the planted module is never looked up.

    Boundaries:
        - Focus: threat model T1/M1 (the repository cannot choose code)
        - Fixtures/params: gate mode; recorded import machinery
        - Scope: CLI scan

    On failure, first check:
        - ``config.validate_telemetry_extensions``
    """
    root = _project(tmp_path, f'["python:{EVIL}:make"]')
    argv = ["scan", str(root)]
    if gate == "flag":
        argv.append("--allow-python-extensions")
    if gate == "env":
        monkeypatch.setenv(GATE_ENV, "1")

    code = cli.main(argv)
    captured = capsys.readouterr()

    assert code == 2
    assert captured.err.startswith("Scan failed:") and "builtin" in captured.err
    assert EVIL not in captured.err
    assert captured.out == ""
    assert _ours(imports) == []


@pytest.mark.parametrize("entry", ['["python:m:f"]', '["builtin:../x"]', '["other:x"]', '"builtin:calc"', "[3]"])
def test_load_config_refuses_non_builtin_entries(entry: str, tmp_path: Path):
    """
    [Mock] extension gate: verifies load_config refuses every non-builtin telemetry_extensions entry (M1).

    Scenario:
        Given a python:, a malformed builtin, an unknown prefix, a bare string and a non-string entry
        When load_config runs
        Then each raises ConfigError without echoing the value.

    Boundaries:
        - Focus: config validation
        - Fixtures/params: one entry per case
        - Scope: load_config

    On failure, first check:
        - ``config.validate_telemetry_extensions``
    """
    (tmp_path / "docsentinel.toml").write_text(f"telemetry_extensions = {entry}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="telemetry_extensions") as caught:
        load_config(tmp_path)
    assert "python:m:f" not in str(caught.value)


def test_load_config_accepts_builtin_entries_in_order(tmp_path: Path):
    """
    [Mock] extension gate: verifies builtin entries load in configured order, from pyproject too (M1, M25).

    Scenario:
        Given ``[tool.doc_sentinel] telemetry_extensions = ["builtin:b", "builtin:a"]`` and a duplicate case
        When load_config runs
        Then the tuple keeps the order, and a duplicate entry is a ConfigError.

    Boundaries:
        - Focus: normal case and duplicate edge
        - Fixtures/params: none
        - Scope: load_config

    On failure, first check:
        - ``config._load_extra_options``
    """
    (tmp_path / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\ntelemetry_extensions = ["builtin:b", "builtin:a"]\n', encoding="utf-8"
    )
    assert load_config(tmp_path).telemetry_extensions == ("builtin:b", "builtin:a")
    assert Config().telemetry_extensions == ()
    (tmp_path / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\ntelemetry_extensions = ["builtin:a", "builtin:a"]\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="repeats"):
        load_config(tmp_path)


# --------------------------------------------------------------------------- M2 argv + gate


def test_argv_python_spec_without_the_gate_is_refused_before_any_import(
    imports: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """
    [Mock] extension gate: verifies --extension python:... without the gate is refused, nothing resolved (M2, M4).

    Scenario:
        Given ``--extension python:<planted>:make`` and no gate
        When ``docsentinel scan`` runs
        Then it exits 2, stdout is empty, and no import machinery is called for the module.

    Boundaries:
        - Focus: argv alone is not enough
        - Fixtures/params: recorded import machinery
        - Scope: CLI scan

    On failure, first check:
        - the gate check at the top of ``extensions.load_python_target``
    """
    root = _project(tmp_path, "[]")

    code = cli.main(["scan", str(root), "--extension", f"python:{EVIL}:make"])
    captured = capsys.readouterr()

    assert code == 2
    assert "refused" in captured.err and captured.out == ""
    assert _ours(imports) == []


@pytest.mark.parametrize("gate", ["flag", "env"])
def test_argv_python_spec_with_the_gate_is_accepted(
    gate: str,
    imports: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Mock] extension gate: verifies a python: spec runs with --allow-python-extensions or the env var exactly 1 (M2).

    Scenario:
        Given a module that the mocked machinery locates outside the root and cwd
        When ``docsentinel scan --extension python:<module>:make`` runs with the flag, or with the env var ``1``
        Then the scan succeeds and the module was located before it was imported.

    Boundaries:
        - Focus: the two gate forms
        - Fixtures/params: gate mode
        - Scope: CLI scan

    On failure, first check:
        - ``cli._python_extensions_allowed``
    """
    root = _project(tmp_path, "[]")
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))
    argv = ["scan", str(root), "--extension", f"python:{GOOD}:make"]
    if gate == "flag":
        argv.append("--allow-python-extensions")
    else:
        monkeypatch.setenv(GATE_ENV, "1")

    code = cli.main(argv)
    captured = capsys.readouterr()

    assert code == 0, captured.err
    assert _ours(imports) == [GOOD, GOOD]  # find_spec, then import_module


@pytest.mark.parametrize("value", ["true", "yes", "1 ", " 1", "", "01", "TRUE", "on"])
def test_env_values_other_than_exactly_one_are_refused(
    value: str, imports: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """
    [Mock] extension gate: verifies the env gate opens only for exactly ``"1"`` (M2).

    Scenario:
        Given DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS set to a truthy-looking value other than ``1``
        When ``docsentinel scan --extension python:...`` runs
        Then it exits 2 and nothing is located or imported.

    Boundaries:
        - Focus: no DOCSENTINEL_DEEP_CONFIRM-style truthiness widening
        - Fixtures/params: one value per case
        - Scope: CLI scan

    On failure, first check:
        - ``cli._python_extensions_allowed``
    """
    root = _project(tmp_path, "[]")
    monkeypatch.setenv(GATE_ENV, value)

    assert cli.main(["scan", str(root), "--extension", f"python:{GOOD}:make"]) == 2
    assert "refused" in capsys.readouterr().err
    assert _ours(imports) == []


def test_library_api_ignores_the_environment(imports: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Mock] extension gate: verifies render/scan/resolve_extensions refuse with the env var set and the keyword false (M2).

    Scenario:
        Given DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1 in the environment
        When ``render(..., extensions=("python:...",))``, ``resolve_extensions(allow_python=False)`` and ``scan``
        run without the keyword
        Then render and the resolver raise ExtensionError, scan never touches extensions, and nothing is imported.

    Boundaries:
        - Focus: the library API is environment-free
        - Fixtures/params: env var patched in
        - Scope: reporting.render, resolve_extensions, engine.scan

    On failure, first check:
        - that ``reporting.render`` passes ``allow_python_extensions`` and nothing reads ``os.environ``
    """
    monkeypatch.setenv(GATE_ENV, "1")
    _project(tmp_path, "[]")

    with pytest.raises(ExtensionError, match="refused"):
        render(_EMPTY, extensions=(f"python:{GOOD}:make",), root=tmp_path)
    with pytest.raises(ExtensionError, match="refused"):
        resolve_extensions((f"python:{GOOD}:make",), config=Config(), allow_python=False, root=tmp_path, cwd=tmp_path)
    with pytest.raises(ExtensionError, match="refused"):
        resolve_extensions((f"python:{GOOD}:make",), config=Config(), allow_python=1, root=tmp_path, cwd=tmp_path)  # type: ignore[arg-type]
    scan(tmp_path)
    assert _ours(imports) == []


def test_render_with_a_config_python_entry_is_a_config_error(imports: list[str], tmp_path: Path):
    """
    [Mock] extension gate: verifies render() refuses an injected Config naming python: even with the keyword (M1).

    Scenario:
        Given ``Config(telemetry_extensions=("python:...",))`` and ``allow_python_extensions=True``
        When render runs
        Then ConfigError is raised and nothing is imported.

    Boundaries:
        - Focus: injected Config re-check on the report path
        - Fixtures/params: recorded import machinery
        - Scope: reporting.render

    On failure, first check:
        - ``resolve_extensions`` re-validating ``config.telemetry_extensions``
    """
    settings = Config(telemetry_extensions=(f"python:{EVIL}:make",))
    with pytest.raises(ConfigError):
        render(_EMPTY, config=settings, allow_python_extensions=True, root=tmp_path)
    assert _ours(imports) == []


# --------------------------------------------------------------------------- M32 side surfaces


@pytest.mark.parametrize("command", ["doctor", "rules", "init", "baseline"])
def test_side_commands_never_resolve_extensions(
    command: str,
    imports: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Mock] extension gate: verifies doctor/rules/init/baseline never import a configured extension (M32).

    Scenario:
        Given a pyproject naming ``python:<planted>:make`` in telemetry_extensions and the gate env set
        When each side command runs in that directory
        Then the planted module is never located or imported, and doctor reports the entry as an error.

    Boundaries:
        - Focus: running a side command on a hostile checkout executes nothing
        - Fixtures/params: one command per case
        - Scope: CLI side commands

    On failure, first check:
        - ``cli._doctor_extension_lines`` and the baseline branch of ``cli.main``
    """
    (tmp_path / "pyproject.toml").write_text(
        f'[tool.doc_sentinel]\ntelemetry_extensions = ["python:{EVIL}:make"]\n', encoding="utf-8"
    )
    (tmp_path / "README.md").write_text("# Title\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(GATE_ENV, "1")
    argv = {
        "doctor": ["doctor"],
        "rules": ["rules"],
        "init": ["init", str(tmp_path), "--yes"],
        "baseline": ["baseline", str(tmp_path)],
    }

    code = cli.main(argv[command])
    captured = capsys.readouterr()

    assert _ours(imports) == []
    if command == "doctor":
        assert code == 0
        assert "python extensions gate: on" in captured.out
        assert "report extensions (telemetry_extensions): error:" in captured.out
        assert EVIL not in captured.out
    if command == "baseline":
        assert code == 2 and "telemetry_extensions" in captured.err


def test_doctor_lists_builtin_specs_and_a_closed_gate(
    imports: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """
    [Mock] extension gate: verifies doctor lists configured builtin specs and the closed gate (M32).

    Scenario:
        Given telemetry_extensions = ["builtin:domain"] and no gate env
        When ``docsentinel doctor`` runs
        Then it prints the spec and ``gate: off`` without importing anything.

    Boundaries:
        - Focus: doctor reporting
        - Fixtures/params: none
        - Scope: CLI doctor

    On failure, first check:
        - ``cli._doctor_extension_lines``
    """
    (tmp_path / "docsentinel.toml").write_text('telemetry_extensions = ["builtin:domain"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out

    assert "python extensions gate: off" in out
    assert "report extensions (telemetry_extensions): builtin:domain" in out
    assert _ours(imports) == []
