"""CLI exit-code matrix, ``--format`` with ``--strict``/``--baseline``, and ``doctor`` template dirs (Story 05.0 Task 01).

Closes checklist items 5 and 8 of ``docs/security/threat-model-0007-closure-2026-11-04.md`` (the 03.0
follow-up (d)): every packaged template keeps the exit code of the scan (findings 1, warnings only 0
unless ``--strict``, baselined findings 0, deep advisory 0), an unknown builtin extension is an
``ExtensionError`` that exits 2 before the scan without any patched registry, and ``doctor`` reports a
``report_templates_dir`` that escapes the root lexically or through a symlink as unavailable without
listing or opening anything outside. The tree is ``ds101/dangling_file_link`` (one error) and
``ds102/stray_comment_file`` (one warning). Deep cannot run without the spaCy model, so the deep case
wraps ``cli.scan`` to return a deep result carrying an error-severity DS301 candidate.
"""

import dataclasses
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from docsentinel import cli
from docsentinel.models import Finding
from docsentinel.telemetry.loader import packaged_template_names
from tests.asset_helpers import AssetCase, load_asset_case

ESC = chr(0x1B)


def _tree(asset_case: Callable[[str, str], AssetCase], *, error: bool = True) -> Path:
    """Return a root with the DS102 warning and, when ``error``, the DS101 error too."""
    if error:
        root = asset_case("ds101", "dangling_file_link").root
        load_asset_case("ds102", "stray_comment_file", root)
        return root
    return asset_case("ds102", "stray_comment_file").root


def _problems(report: str) -> list[dict[str, Any]]:
    """Return every problem of a schema-2 ``json`` report."""
    return [problem for document in json.loads(report)["documents"] for problem in document["problems"]]


@pytest.mark.parametrize("name", packaged_template_names())
def test_strict_turns_warnings_into_exit_1_for_every_template(
    name: str, asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] report cli exit codes ds101 ds102: verifies ``--format`` combined with ``--strict``.

    Scenario:
        Given a root whose only finding is a DS102 warning
        When ``scan --format <name>`` runs with and without ``--strict``
        Then the exit code is 0 without and 1 with ``--strict``, stderr is empty, the report is printed both
            times, and in the default JSON the problem's outcome is ``advisory`` then ``rejected``.

    Boundaries:
        - Focus: the template choice never changes the exit code; strict reaches the report model
        - Fixtures/params: ds102/stray_comment_file; every packaged template
        - Scope: in-process CLI calls

    On failure, first check:
        - ``cli._exit_code`` and the ``strict=`` argument passed to ``reporting.render``
    """
    root = _tree(asset_case, error=False)

    lenient = cli.main(["scan", str(root), "--format", name])
    lenient_out = capsys.readouterr()
    strict = cli.main(["scan", str(root), "--format", name, "--strict"])
    strict_out = capsys.readouterr()

    assert (lenient, strict) == (0, 1)
    assert lenient_out.err == strict_out.err == ""
    assert "comment.md" in lenient_out.out and "comment.md" in strict_out.out
    if name == "json":
        assert [problem["outcome"] for problem in _problems(lenient_out.out)] == ["advisory"]
        assert [problem["outcome"] for problem in _problems(strict_out.out)] == ["rejected"]


@pytest.mark.parametrize("name", packaged_template_names())
def test_baseline_suppresses_findings_and_exit_code_for_every_template(
    name: str, asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] report cli exit codes ds101 ds102: verifies ``--format`` combined with ``--baseline``.

    Scenario:
        Given a root with a DS101 error and a DS102 warning, recorded by ``docsentinel baseline``
        When ``scan --format <name> --baseline <file>`` runs, also with ``--strict``
        Then both exit 0, the report names neither finding, and without the baseline the same scan exits 1.

    Boundaries:
        - Focus: baseline filtering happens before rendering, for every template
        - Fixtures/params: ds101/dangling_file_link + ds102/stray_comment_file; every packaged template
        - Scope: in-process CLI calls

    On failure, first check:
        - ``engine.scan`` baseline filtering and the ``--baseline`` override in ``cli.main``
    """
    root = _tree(asset_case)
    baseline = root.parent / "known.json"
    assert cli.main(["baseline", str(root), "--output", str(baseline)]) == 0
    capsys.readouterr()

    unfiltered = cli.main(["scan", str(root), "--format", name])
    capsys.readouterr()
    filtered = cli.main(["scan", str(root), "--format", name, "--baseline", str(baseline)])
    filtered_out = capsys.readouterr()
    strict = cli.main(["scan", str(root), "--format", name, "--baseline", str(baseline), "--strict"])
    strict_out = capsys.readouterr()

    assert (unfiltered, filtered, strict) == (1, 0, 0)
    assert filtered_out.err == strict_out.err == ""
    for report in (filtered_out.out, strict_out.out):
        assert "dangling" not in report and "stray" not in report.lower()
        if name == "json":
            assert _problems(report) == []


@pytest.mark.parametrize("name", packaged_template_names())
def test_deep_findings_are_advisory_exit_0_for_every_template(
    name: str,
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] report cli exit codes ds101 ds102: verifies deep candidates exit 0, even with ``--strict``.

    Scenario:
        Given ``cli.scan`` returning a deep result with an error-severity DS301 candidate (the spaCy model is
            not needed)
        When ``scan --profile deep --i-understand-deep-is-heuristic --format <name>`` runs, also with ``--strict``
        Then both exit 0, the candidate is in the report, and the text report carries the advisory banner.

    Boundaries:
        - Focus: matrix row "deep advisory -> 0" through the real CLI and every template
        - Fixtures/params: ds101/dangling_file_link as the root; the scan result is substituted
        - Scope: in-process CLI calls with ``cli.scan`` wrapped

    On failure, first check:
        - the deep branch of ``cli._exit_code`` and ``ADVISORY_BANNER`` in the report model
    """
    root = asset_case("ds101", "dangling_file_link").root
    candidate = Finding(
        rule="DS301", path="README.md", message="candidate contradiction: 3 vs 4", severity="error", line=1
    )
    real = cli.scan

    def deep_result(*args: Any, **kwargs: Any) -> Any:
        """Run the real scan, then present it as a deep run with one candidate."""
        result = real(*args, **{**kwargs, "config": dataclasses.replace(kwargs["config"], profile="fast")})
        return dataclasses.replace(result, profile="deep", findings=(candidate,), enabled_rules=("DS301",))

    monkeypatch.setattr(cli, "scan", deep_result)
    args = ["scan", str(root), "--profile", "deep", "--i-understand-deep-is-heuristic", "--format", name]

    lenient = cli.main(args)
    lenient_out = capsys.readouterr()
    strict = cli.main([*args, "--strict"])
    strict_out = capsys.readouterr()

    assert (lenient, strict) == (0, 0)
    assert lenient_out.err == strict_out.err == ""
    assert "candidate contradiction" in lenient_out.out
    if name == "text":
        assert "heuristic candidates for review" in lenient_out.out


def test_unknown_builtin_extension_exits_2_before_the_scan(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """
    [Integration] report cli exit codes ds101 ds102: verifies an ExtensionError from the real registry exits 2.

    Scenario:
        Given the unpatched builtin registry and a hostile ``--extension builtin:nope`` / malformed spec
        When ``docsentinel scan`` runs
        Then each exits 2 with empty stdout, a single neutralized ``Scan failed:`` line, and no scan ran.

    Boundaries:
        - Focus: matrix row "ExtensionError -> 2" without a patched builtin table
        - Fixtures/params: ds101/dangling_file_link
        - Scope: in-process CLI calls with ``cli.scan`` recorded

    On failure, first check:
        - ``ExtensionError`` in the exception tuple of the ``scan`` branch of ``cli.main``
    """
    root = asset_case("ds101", "dangling_file_link").root
    calls: list[object] = []
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: calls.append(args))

    unknown = cli.main(["scan", str(root), "--extension", "builtin:nope"])
    unknown_out = capsys.readouterr()
    malformed = cli.main(["scan", str(root), "--extension", f"builtin:x{ESC}[31m\nforged"])
    malformed_out = capsys.readouterr()

    assert (unknown, malformed) == (2, 2)
    assert unknown_out.out == malformed_out.out == ""
    assert unknown_out.err.startswith("Scan failed: unknown builtin extension")
    assert malformed_out.err.startswith("Scan failed: ") and malformed_out.err.count("\n") == 1
    assert ESC not in malformed_out.err
    assert calls == []


class _FileAccess:
    """Records every path opened or listed through ``os.open``/``os.scandir``/``os.listdir``."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch):
        """Wrap the three calls."""
        self.paths: list[str] = []
        for name in ("open", "scandir", "listdir"):
            monkeypatch.setattr(os, name, self._wrap(getattr(os, name)))

    def _wrap(self, real: Callable[..., Any]) -> Callable[..., Any]:
        """Return ``real`` recording its first argument."""

        def recorded(path: Any = ".", *args: Any, **kwargs: Any) -> Any:
            """Record the path, then call through."""
            self.paths.append(os.path.realpath(os.fsdecode(path)) if not isinstance(path, int) else "<fd>")
            return real(path, *args, **kwargs)

        return recorded

    def under(self, directory: Path) -> list[str]:
        """Return the recorded paths at or below ``directory``."""
        base = os.path.realpath(directory)
        return [path for path in self.paths if path == base or path.startswith(base + os.sep)]


@pytest.mark.parametrize("kind", ["lexical", "symlink", "hostile-symlink-name"])
def test_doctor_reports_an_escaping_template_dir_without_touching_it(
    kind: str,
    asset_case: Callable[[str, str], AssetCase],
    tmp_path_factory: pytest.TempPathFactory,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] report cli exit codes ds101 ds102: verifies doctor with an escaping ``report_templates_dir``.

    Scenario:
        Given templates outside the scan root, and a config naming them via a ``../`` relative path, via an
            in-root symlink to them, or via a symlink whose name carries ESC and a line feed
        When ``docsentinel doctor`` runs in the root
        Then it exits 0, lists the packaged templates, reports the directory as unavailable on one neutralized
            line, never lists an outside template name, and never opens or lists anything outside the root.

    Boundaries:
        - Focus: 03.0 follow-up (d): doctor applies the same containment gate as scan
        - Fixtures/params: ds101/dangling_file_link + report/template_dir moved outside the root
        - Scope: in-process CLI call with os.open/scandir/listdir recorded

    On failure, first check:
        - ``cli._doctor_template_lines`` and the containment gate of ``loader.available_templates``
    """
    if kind != "lexical" and not hasattr(os, "symlink"):
        pytest.skip("symlinks are not available")
    root = asset_case("ds101", "dangling_file_link").root
    outside = tmp_path_factory.mktemp("outside")
    load_asset_case("report", "template_dir", outside)
    assert not os.path.realpath(outside).startswith(os.path.realpath(root) + os.sep)
    link = {"lexical": None, "symlink": "linked", "hostile-symlink-name": f"t{ESC}[31m\nforged"}[kind]
    if link is None:
        setting = os.path.relpath(outside / "templates", root).replace(os.sep, "/")
    else:
        try:
            (root / link).symlink_to(outside / "templates", target_is_directory=True)
        except OSError:
            pytest.skip("filesystem refused the symlink name")
        setting = link
    (root / "docsentinel.toml").write_text(f"report_templates_dir = {json.dumps(setting)}\n", encoding="utf-8")
    monkeypatch.chdir(root)
    access = _FileAccess(monkeypatch)

    code = cli.main(["doctor"])

    out = capsys.readouterr().out
    lines = out.split("\n")
    assert code == 0
    assert "report templates (packaged): github, json, json-documents, json-v1, text" in lines
    unavailable = [line for line in lines if line.startswith("report templates (report_templates_dir): ")]
    assert len(unavailable) == 1 and "unavailable: " in unavailable[0]
    assert "mini" not in out and "dup-key" not in out
    assert ESC not in out and "\nforged" not in out
    assert access.under(outside) == []
