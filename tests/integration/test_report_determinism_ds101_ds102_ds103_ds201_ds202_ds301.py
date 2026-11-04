"""Report determinism across processes, roots and hash seeds (Story 05.0 Task 01).

Closes checklist item 3 of ``docs/security/threat-model-0007-closure-2026-11-04.md``: until now only
unit tests rendered one in-memory result twice. Here every packaged template renders a live
``docsentinel scan`` per profile in two separate interpreters that differ in ``PYTHONHASHSEED``
and in the absolute location of the scan root (two copies of the same tree), so set or dict
ordering, absolute paths and per-process caches cannot hide behind one warm process. Standard
skips without its extras and deep skips without the spaCy model (``deep_support.deep_ready``).
The tree composes ``ds101/dangling_file_link``, ``ds102/stray_comment_file`` and
``ds103/unresolvable_path_file`` at the root with ``ds201/dense_document``,
``ds202/identical_paragraphs`` and ``ds301/number_contradiction`` in subdirectories.
"""

import importlib.util
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from docsentinel import deep_support
from docsentinel.telemetry.loader import packaged_template_names
from tests.asset_helpers import load_asset_case

#: ``scan`` arguments per profile; deep needs the explicit heuristic confirmation.
_PROFILE_ARGS: dict[str, tuple[str, ...]] = {
    "fast": ("--profile", "fast"),
    "standard": ("--profile", "standard"),
    "deep": ("--profile", "deep", "--i-understand-deep-is-heuristic"),
}

#: Renders every named template of one root and profile in this interpreter; prints a JSON map.
_DRIVER = textwrap.dedent(
    """
    import contextlib, io, json, sys
    from docsentinel import cli

    root, profile_args, names = sys.argv[1], json.loads(sys.argv[2]), json.loads(sys.argv[3])
    reports = {}
    for name in names:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["scan", root, *profile_args, "--format", name])
        reports[name] = {"code": code, "out": out.getvalue(), "err": err.getvalue()}
    sys.stdout.write(json.dumps(reports))
    """
)


def _standard_installed() -> bool:
    """Return whether the standard-profile extras are importable (without importing them)."""
    return all(importlib.util.find_spec(name) is not None for name in ("sklearn", "textstat", "docsig"))


def _tree(destination: Path) -> Path:
    """Materialize the composed fast/standard/deep tree under ``destination`` and return it."""
    load_asset_case("ds101", "dangling_file_link", destination)
    load_asset_case("ds102", "stray_comment_file", destination)
    load_asset_case("ds103", "unresolvable_path_file", destination)
    load_asset_case("ds201", "dense_document", destination / "standard" / "complexity")
    load_asset_case("ds202", "identical_paragraphs", destination / "standard" / "duplicates")
    load_asset_case("ds301", "number_contradiction", destination / "deep")
    return destination


def _render_all(root: Path, profile: str, seed: str) -> dict[str, dict[str, object]]:
    """Render every packaged template of ``root`` in a fresh interpreter with ``PYTHONHASHSEED=seed``.

    :param root: The scan root.
    :param profile: The profile key of :data:`_PROFILE_ARGS`.
    :param seed: The hash seed for the child interpreter.
    :returns: ``{template: {"code", "out", "err"}}``.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("DOCSENTINEL_")}
    env["PYTHONHASHSEED"] = seed
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _DRIVER,
            str(root),
            json.dumps(_PROFILE_ARGS[profile]),
            json.dumps(packaged_template_names()),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        cwd=root,
        check=True,
    )
    return json.loads(completed.stdout)


@pytest.mark.parametrize("profile", sorted(_PROFILE_ARGS))
def test_every_packaged_template_is_byte_identical_across_processes_and_roots(profile: str, tmp_path: Path):
    """
    [Integration] report determinism: verifies two scans give identical output for every template and profile.

    Scenario:
        Given two copies of the same composed tree at different absolute paths
        When each copy is scanned and rendered with every packaged template in its own interpreter, with
            ``PYTHONHASHSEED`` 1 and 2 respectively
        Then exit codes, stdout and stderr are identical per template, no absolute root path leaks into a
            report, and the run is not vacuous (fast finds DS101/DS102/DS103, standard a DS2xx finding).

    Boundaries:
        - Focus: determinism of the whole CLI -> scan -> ReportModel -> template path (spec §1)
        - Fixtures/params: one profile per case; standard/deep skip when extras or the spaCy model are missing
        - Scope: two subprocesses per profile, each rendering all packaged templates

    On failure, first check:
        - which template differs, then set/dict iteration in ``ReportModel.build`` or the detector
        - whether ``report_include_run_meta`` became the default (it adds run.id/generated_at)
    """
    if profile == "standard" and not _standard_installed():
        pytest.skip("standard extras are not installed")
    if profile == "deep" and not deep_support.deep_ready():
        pytest.skip("deep extras or the spaCy model are not installed")
    first_root = _tree(tmp_path / "first" / "repo")
    second_root = _tree(tmp_path / "second-location" / "nested" / "repo")

    first = _render_all(first_root, profile, seed="1")
    second = _render_all(second_root, profile, seed="2")

    assert sorted(first) == sorted(packaged_template_names())
    for name in packaged_template_names():
        assert first[name] == second[name], f"{profile}/{name} differs between runs"
        assert first[name]["err"] == ""
        report = str(first[name]["out"])
        assert str(tmp_path) not in report and str(first_root) not in report
    rules = json.dumps(json.loads(str(first["json-v1"]["out"]))["findings"])
    if profile == "fast":
        assert first["text"]["code"] == 1
        assert all(code in rules for code in ("DS101", "DS102", "DS103"))
    if profile == "standard":
        assert "DS20" in rules
    if profile == "deep":
        assert first["text"]["code"] == 0
