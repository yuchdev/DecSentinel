"""Report rendering imports no spaCy and no extension code (Story 05.0 Task 01).

Closes checklist item 6 of ``docs/security/threat-model-0007-closure-2026-11-04.md``:
``test_import_isolation.py`` proves only that a fast *scan* leaves spaCy unloaded. Here a fresh
isolated interpreter (``-I``) imports :mod:`docsentinel` and renders every packaged template through
the CLI and through the library ``render`` call, from a repository whose config enables the builtin
extensions, with the ``python:`` gate environment variable set and a planted extension module
importable from ``sys.path`` that writes a sentinel when imported. No ``python:`` spec is requested,
so the planted module must never load, and the only modules the run may add are the standard
library and :mod:`docsentinel` itself.
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from docsentinel.telemetry.loader import packaged_template_names

#: The probe: snapshot ``sys.modules``, render every template, report what was added.
_PROBE = textwrap.dedent(
    """
    import contextlib, io, json, os, pathlib, sys
    before = set(sys.modules)
    base, mode, names = pathlib.Path(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3])
    sys.path.insert(0, str(base / "site"))
    os.environ["DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS"] = "1"
    root = base / "repo"
    codes = {}
    if mode == "cli":
        from docsentinel import cli
        for name in names:
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                codes[name] = [cli.main(["scan", str(root), "--format", name]), len(out.getvalue()), err.getvalue()]
    else:
        from docsentinel import scan
        from docsentinel.config import load_config
        from docsentinel.reporting import render
        settings = load_config(root)
        result = scan(root, config=settings)
        for name in names:
            codes[name] = [0, len(render(result, name, config=settings, root=root)), ""]
    added = sorted({name.split(".")[0] for name in set(sys.modules) - before})
    print(json.dumps({
        "codes": codes,
        "foreign": [name for name in added if name not in sys.stdlib_module_names and name != "docsentinel"],
        "planted_loaded": "ds_iso_planted_ext" in sys.modules,
        "planted_ran": (base / "planted.ran").exists(),
        "heavy": [name for name in ("spacy", "textacy", "sklearn", "textstat", "docsig") if name in sys.modules],
    }))
    """
)


def _layout(base: Path) -> None:
    """Write the repository (builtin extensions on, one dangling link) and the planted module."""
    site = base / "site"
    site.mkdir()
    (site / "ds_iso_planted_ext.py").write_text(
        f"open({str(base / 'planted.ran')!r}, 'w').write('ran')\n\ndef make():\n    return None\n",
        encoding="utf-8",
    )
    root = base / "repo"
    root.mkdir()
    (root / "README.md").write_text("# Title\n\n[dead](./missing.md)\n", encoding="utf-8")
    (root / "docsentinel.toml").write_text(
        'telemetry_extensions = ["builtin:domain", "builtin:document_stats"]\n\n'
        '[[telemetry_domains]]\nglob = "**"\ndomain = "guides"\n',
        encoding="utf-8",
    )


def _probe(base: Path, mode: str) -> dict[str, object]:
    """Run the probe in a fresh isolated interpreter and return its JSON report."""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", _PROBE, str(base), mode, json.dumps(packaged_template_names())],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(completed.stdout)


def _assert_isolated(report: dict[str, object]) -> None:
    """Assert the probe rendered every template and loaded nothing foreign."""
    codes = report["codes"]
    assert isinstance(codes, dict) and sorted(codes) == sorted(packaged_template_names())
    for name, (code, length, err) in codes.items():
        assert err == "", f"{name}: {err}"
        assert length > 0, f"{name} rendered nothing"
        assert code in (0, 1), f"{name}: exit {code}"
    assert report["planted_loaded"] is False
    assert report["planted_ran"] is False
    assert report["heavy"] == []
    assert report["foreign"] == []


def test_cli_render_of_every_template_imports_no_spacy_and_no_extension_module(tmp_path: Path):
    """
    [Integration] report import isolation: verifies a CLI render loads only stdlib and docsentinel.

    Scenario:
        Given a repository enabling builtin:domain and builtin:document_stats, the python: gate env set to 1,
            and a planted extension module on ``sys.path`` that writes a sentinel when imported
        When ``docsentinel scan --format <name>`` renders every packaged template in a fresh ``-I`` interpreter
        Then each render succeeds (exit 1, the dangling link), the planted module is neither in ``sys.modules``
            nor executed, and no spaCy/textacy/standard dependency or any other non-stdlib top-level module
            was imported.

    Boundaries:
        - Focus: lazy imports of the reporting path (matrix row "Lazy imports"); no python: spec requested
        - Fixtures/params: tmp layout built in the test body
        - Scope: one isolated interpreter

    On failure, first check:
        - the ``foreign``/``heavy`` lists the probe prints, then any new eager import in ``telemetry/``
        - whether ``resolve_extensions`` started importing anything for builtin specs
    """
    _layout(tmp_path)

    report = _probe(tmp_path, "cli")

    _assert_isolated(report)
    assert report["codes"]["text"][0] == 1  # type: ignore[index]


def test_library_render_of_every_template_imports_no_spacy_and_no_extension_module(tmp_path: Path):
    """
    [Integration] report import isolation: verifies ``scan`` + ``reporting.render`` load only stdlib and docsentinel.

    Scenario:
        Given the same repository, gate env and planted module
        When ``from docsentinel import scan`` and ``reporting.render(result, name, config=..., root=...)`` render
            every packaged template in a fresh ``-I`` interpreter
        Then the planted module never loads or runs and nothing but stdlib and docsentinel was imported
            (the library ignores the gate env var).

    Boundaries:
        - Focus: the library entry point, which has no argv gate at all
        - Fixtures/params: tmp layout built in the test body
        - Scope: one isolated interpreter

    On failure, first check:
        - ``reporting.render`` extension resolution with an empty ``extensions`` argument
    """
    _layout(tmp_path)

    _assert_isolated(_probe(tmp_path, "library"))
