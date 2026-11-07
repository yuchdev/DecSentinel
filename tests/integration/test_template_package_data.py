"""The packaged report templates ship as package data (Milestone 0007, Story 03.0 Task 01).

Hatchling's ``packages = ["src/docsentinel"]`` includes non-Python files, so the five templates under
``docsentinel/telemetry/templates`` must reach both the installed package and the built wheel/sdist.
"""

import shutil
import subprocess
import tarfile
import zipfile
from importlib import resources
from pathlib import Path

import pytest

#: The template files Story 03.0 Task 01 ships.
_TEMPLATES: frozenset[str] = frozenset({"text.json", "github.json", "json.json", "json-v1.json", "json-documents.json"})

#: Repository root (the project ``uv build`` builds).
_REPO_ROOT: Path = Path(__file__).resolve().parents[2]


def test_templates_are_package_resources():
    """
    [Integration] template package data: verifies the templates resolve through ``importlib.resources``.

    Scenario:
        Given the installed ``docsentinel.telemetry`` package
        When its ``templates`` resource directory is listed
        Then it holds the five standard template files.

    Boundaries:
        - Focus: resource lookup independent of the source checkout layout
        - Fixtures/params: none
        - Scope: package resources only

    On failure, first check:
        - Whether a template file was renamed or removed
    """
    directory = resources.files("docsentinel.telemetry").joinpath("templates")
    names = {entry.name for entry in directory.iterdir() if entry.name.endswith(".json")}

    assert _TEMPLATES <= names


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not on PATH")
def test_built_wheel_and_sdist_contain_the_templates(tmp_path: Path):
    """
    [Integration] template package data: verifies ``uv build`` puts the templates in the wheel and sdist.

    Scenario:
        Given the repository
        When ``uv build --offline`` writes a wheel and an sdist to a temporary directory
        Then both archives list the five ``telemetry/templates/*.json`` files.

    Boundaries:
        - Focus: hatchling package-data inclusion of non-Python files
        - Fixtures/params: tmp_path; skipped without uv, or when the offline build backend is not cached
        - Scope: the build artifacts only

    On failure, first check:
        - ``[tool.hatch.build.targets.wheel]`` and any new exclude pattern in ``pyproject.toml``
    """
    completed = subprocess.run(
        ["uv", "build", "--offline", "--no-progress", "--out-dir", str(tmp_path)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if completed.returncode != 0 and "offline" in (completed.stderr + completed.stdout).lower():
        pytest.skip("the build backend is not cached for an offline build")
    assert completed.returncode == 0, completed.stderr[-2000:]

    (wheel,) = tmp_path.glob("*.whl")
    (sdist,) = tmp_path.glob("*.tar.gz")
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = {Path(name).name for name in archive.namelist() if "docsentinel/telemetry/templates/" in name}
    with tarfile.open(sdist) as archive:
        sdist_names = {Path(name).name for name in archive.getnames() if "src/docsentinel/telemetry/templates/" in name}

    assert _TEMPLATES <= wheel_names
    assert _TEMPLATES <= sdist_names
