"""M6 site-packages exemption with the interpreter layout replaced (Milestone 0007 Story 04.0 Task 01).

Amendment of 2026-11-03 to threat model ``docs/security/threat-model-0007-extensions-2026-11-03.md``
M6: a module location or ``sys.path`` entry is exempt from the origin refusal only when both its
absolute and its canonical path lie under the running interpreter's own ``site-packages``
(``sysconfig`` ``purelib``/``platlib``). ``sysconfig.get_path`` is replaced so that a project-local
``.venv`` inside the scan root plays the running interpreter's environment; the real import machinery
loads the planted modules. Every planted module writes a sentinel file when imported.
"""

import itertools
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from docsentinel.config import Config
from docsentinel.models import Document, ScanResult
from docsentinel.reporting import render
from docsentinel.telemetry import extensions
from docsentinel.telemetry.extensions import ExtensionError, load_python_target, resolve_extensions

_COUNTER = itertools.count()

_DOC = ScanResult(
    profile="fast", documents=(Document("a.md", 1),), findings=(), enabled_rules=(), pending=(), notice=""
)


@pytest.fixture
def venv(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Path]]:
    """Return a scan root holding a project-local ``.venv`` reported as the running interpreter's own."""
    root = tmp_path_factory.mktemp("checkout")
    (root / "pyproject.toml").write_text("", encoding="utf-8")
    site = root / ".venv" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    cwd = tmp_path_factory.mktemp("cwd")
    sentinels = tmp_path_factory.mktemp("sentinels")
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(extensions.sysconfig, "get_path", lambda key, *args, **kwargs: str(site))
    monkeypatch.setattr(sys, "path", [str(site), *(entry for entry in sys.path if entry)])
    before = set(sys.modules)
    yield {"root": root, "site": site, "cwd": cwd, "sentinels": sentinels}
    for name in set(sys.modules) - before:
        if name.startswith("ds_site_"):
            sys.modules.pop(name, None)


def _unique(stem: str) -> str:
    """Return a module name unique to this session."""
    return f"ds_site_{stem}_{next(_COUNTER)}"


def _plant(directory: Path, name: str, sentinel: Path, body: str = "") -> Path:
    """Write ``<name>.py`` creating ``sentinel`` when imported."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{name}.py"
    target.write_text(f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('ran')\n{body}", encoding="utf-8")
    return target


def test_extension_installed_in_the_running_interpreters_venv_inside_the_root_loads(venv: dict[str, Path]):
    """
    [Mock] extension site-packages: verifies the running interpreter's own project-local venv is exempt (M6).

    Scenario:
        Given an extension and a helper installed in ``<root>/.venv/.../site-packages``, which sysconfig reports
            as the running interpreter's, and that directory on sys.path
        When the report is rendered with the gate open, the hook importing the helper
        Then the extension loads and renders (the sys.path check, the origin check and the ModuleWatch all exempt it).

    Boundaries:
        - Focus: the 2026-11-03 usability amendment (normal case)
        - Fixtures/params: sysconfig.get_path replaced
        - Scope: reporting.render with the real import machinery

    On failure, first check:
        - ``extensions._own_site_packages`` and ``_Boundary.exempt``
    """
    helper = _unique("helper")
    name = _unique("installed")
    _plant(venv["site"], helper, venv["sentinels"] / helper)
    body = (
        "from types import SimpleNamespace\n"
        f"def _run(model):\n    import {helper}\n    return {{'ok': True}}\n"
        "def make():\n    return SimpleNamespace(name='installed', provide_run=_run)\n"
    )
    _plant(venv["site"], name, venv["sentinels"] / name, body)

    report = render(_DOC, "json", extensions=(f"python:{name}:make",), allow_python_extensions=True, root=venv["root"])

    assert '"documents"' in report
    assert (venv["sentinels"] / name).exists() and (venv["sentinels"] / helper).exists()


@pytest.mark.parametrize("directory", ["other-venv/lib/site-packages", "src", ".venv-old/lib/site-packages"])
def test_other_in_root_import_directories_are_still_refused(
    directory: str, venv: dict[str, Path], monkeypatch: pytest.MonkeyPatch
):
    """
    [Mock] extension site-packages: verifies only the running interpreter's site-packages is exempt (M6).

    Scenario:
        Given an in-root directory on sys.path that is not the running interpreter's site-packages: another venv,
            an editable ``src/`` added by a .pth file, a stale venv
        When a module from it is loaded with the gate open
        Then it is refused by the sys.path check and never ran.

    Boundaries:
        - Focus: the amendment keeps refusing PYTHONPATH, .pth-added and foreign venv directories (invalid input)
        - Fixtures/params: one directory per case
        - Scope: load_python_target

    On failure, first check:
        - ``extensions._check_import_path`` and ``_Boundary.exempt``
    """
    folder = venv["root"] / directory
    name = _unique("foreign")
    _plant(folder, name, venv["sentinels"] / name, "def make():\n    return None\n")
    monkeypatch.setattr(sys, "path", [str(folder), *sys.path])

    with pytest.raises(ExtensionError, match=r"sys\.path"):
        load_python_target(f"python:{name}:make", allow_python=True, root=venv["root"], cwd=venv["cwd"])
    assert not (venv["sentinels"] / name).exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are not available")
def test_link_in_site_packages_to_an_in_root_file_is_refused(venv: dict[str, Path]):
    """
    [Mock] extension site-packages: verifies the exemption needs the canonical path in site-packages too (M6).

    Scenario:
        Given ``<site-packages>/<name>.py`` symlinked to ``<root>/evil.py``
        When it is resolved with the gate open
        Then it is refused (its real path is in the root, outside site-packages) and evil.py never ran.

    Boundaries:
        - Focus: edge case of the amendment (absolute path exempt, canonical path not)
        - Fixtures/params: none
        - Scope: resolve_extensions

    On failure, first check:
        - the realpath half of ``extensions._Boundary.exempt``
    """
    name = _unique("linked")
    real = _plant(venv["root"], f"{name}_real", venv["sentinels"] / name, "def make():\n    return None\n")
    (venv["site"] / f"{name}.py").symlink_to(real)

    with pytest.raises(ExtensionError, match="its project root"):
        resolve_extensions(
            (f"python:{name}:make",), config=Config(), allow_python=True, root=venv["root"], cwd=venv["cwd"]
        )
    assert not (venv["sentinels"] / name).exists()
