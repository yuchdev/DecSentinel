"""The pytest plugin never reaches ``python:`` extensions (Story 05.0 Task 01, threat model M32).

Closes checklist item 7 and follow-up (c) of ``docs/security/threat-model-0007-closure-2026-11-04.md``:
``tests/mock/test_extension_trust_gate.py`` covers the M32 side surfaces doctor/rules/init/baseline
but not the ``docsentinel_scan`` fixture. Here a scanned repository controls *everything* the plugin
sees: its ``pyproject.toml`` enables the plugin through ``addopts`` and names a ``python:`` extension
in ``[tool.doc_sentinel]``, a module with that name sits on the repository's own import path and
writes a sentinel when imported, and the invoker's environment has the gate variable set to ``1``.
The plugin runs in a real child ``pytest`` process so its configuration and import path are exactly
the hostile repository's.
"""

import os
import subprocess
import sys
from pathlib import Path

#: The planted extension module name; the repository root puts it on ``sys.path``.
_PLANTED = "ds_plugin_planted_ext"
_GATE_ENV = "DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS"


def _repository(root: Path, extensions: str, test_body: str) -> Path:
    """Write a hostile repository: plugin via addopts, the given extensions, a planted module and one test.

    :param root: The repository directory to create.
    :param extensions: The TOML array literal for ``telemetry_extensions``.
    :param test_body: The body of ``test_docs`` (receives ``docsentinel_scan``).
    :returns: The sentinel path the planted module writes when imported.
    """
    root.mkdir()
    sentinel = root.parent / "planted.ran"
    (root / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        'addopts = "-p docsentinel.pytest_plugin -p no:cacheprovider"\n\n'
        "[tool.doc_sentinel]\n"
        f"telemetry_extensions = {extensions}\n",
        encoding="utf-8",
    )
    (root / f"{_PLANTED}.py").write_text(
        f"open({str(sentinel)!r}, 'w').write('ran')\n\ndef make():\n    return None\n", encoding="utf-8"
    )
    (root / "README.md").write_text("# Title\n\n[dead](./missing.md)\n", encoding="utf-8")
    (root / "test_docs.py").write_text(
        f"import sys\n\n\ndef test_docs(docsentinel_scan):\n{test_body}", encoding="utf-8"
    )
    return sentinel


def _run_pytest(root: Path) -> subprocess.CompletedProcess[str]:
    """Run the hostile repository's pytest with the gate env set and no inherited pytest options."""
    env = {key: value for key, value in os.environ.items() if not key.startswith(("PYTEST_", "DOCSENTINEL_"))}
    env[_GATE_ENV] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "test_docs.py"],
        capture_output=True,
        text=True,
        cwd=root,
        env=env,
        check=False,
        timeout=120,
    )


def test_plugin_refuses_a_python_extension_named_by_the_scanned_repository(tmp_path: Path):
    """
    [Integration] pytest plugin extension gate: verifies a repo-configured python: extension is a ConfigError.

    Scenario:
        Given a repository whose pyproject enables the plugin and names ``python:<planted>:make`` in
            telemetry_extensions, the planted module importable from the repository root, and the gate env set
        When its pytest session requests the ``docsentinel_scan`` fixture
        Then the fixture fails with a ConfigError about telemetry_extensions, and the planted module never ran.

    Boundaries:
        - Focus: M32 plugin half: config in a scanned repository cannot reach python:, whatever the env gate says
        - Fixtures/params: hostile repository built in the test body
        - Scope: one child pytest process

    On failure, first check:
        - ``config.validate_telemetry_extensions`` (builtin only) and that ``pytest_plugin`` still calls ``scan``
    """
    root = tmp_path / "repo"
    sentinel = _repository(root, f'["python:{_PLANTED}:make"]', "    pass\n")

    completed = _run_pytest(root)

    output = completed.stdout + completed.stderr
    assert completed.returncode == 1, output
    assert "ConfigError" in output and "telemetry_extensions" in output
    assert "1 error" in output
    assert not sentinel.exists()


def test_plugin_scan_with_builtin_extensions_never_imports_the_planted_module(tmp_path: Path):
    """
    [Integration] pytest plugin extension gate: verifies the fixture scans without importing any extension module.

    Scenario:
        Given the same hostile repository but with ``telemetry_extensions = ["builtin:domain"]`` and the gate env set
        When its test uses ``docsentinel_scan``
        Then the fixture returns the real scan (the dangling DS101 link), the planted module -- importable
            from the child session (``find_spec`` finds it) -- is not in its ``sys.modules``, and its sentinel
            was never written.

    Boundaries:
        - Focus: the plugin exposes a ScanResult only; it resolves no extension and honours no gate
        - Fixtures/params: hostile repository built in the test body
        - Scope: one child pytest process

    On failure, first check:
        - whether ``pytest_plugin`` gained a render/extension path
    """
    root = tmp_path / "repo"
    body = (
        "    import importlib.util\n"
        f"    assert importlib.util.find_spec({_PLANTED!r}) is not None  # reachable, so the check is real\n"
        f"    assert {_PLANTED!r} not in sys.modules\n"
        "    assert [finding.rule for finding in docsentinel_scan.findings] == ['DS101']\n"
        "    assert docsentinel_scan.findings[0].path == 'README.md'\n"
    )
    sentinel = _repository(root, '["builtin:domain"]', body)

    completed = _run_pytest(root)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "1 passed" in completed.stdout
    assert not sentinel.exists()
