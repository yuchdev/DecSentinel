"""``docsentinel scan --output PATH`` over a live DS101 scan.

``--output`` (alias ``-o``) writes the rendered report to a file instead of standard output. The
file holds exactly what standard output would have carried, the exit code still reflects the
findings, and a write failure is a ``Scan failed:`` line with exit code ``2``. The scan root is the
``ds101/dangling_file_link`` case (one dangling link, exit code ``1``).
"""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from docsentinel import cli
from tests.asset_helpers import AssetCase


@pytest.mark.parametrize("flag", ["--output", "-o"])
def test_scan_output_writes_report_file_instead_of_stdout(
    flag: str,
    asset_case: Callable[[str, str], AssetCase],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli output ds101: verifies --output/-o moves the report from stdout to a file.

    Scenario: scan a root with one dangling link once to stdout and once with the output flag.
    Boundaries: the file content equals the stdout report byte for byte; stdout stays empty.
    On failure, first check: the report is still printed, the file differs from stdout, or the exit code changes.
    """
    root = asset_case("ds101", "dangling_file_link").root
    assert cli.main(["scan", str(root), "--format", "json"]) == 1
    expected = capsys.readouterr().out

    target = tmp_path / "out" / "nested" / "report.json"
    assert cli.main(["scan", str(root), "--format", "json", flag, str(target)]) == 1
    captured = capsys.readouterr()

    assert captured.out == ""
    assert target.read_bytes() == expected.encode("utf-8")
    assert json.loads(target.read_text(encoding="utf-8"))["schema_version"] == 2


def test_scan_output_relative_path_resolves_against_cwd(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli output ds101: verifies a relative --output path resolves against the cwd.

    Scenario: run from a working directory distinct from the scan root with a relative output path.
    Boundaries: the file lands under the cwd, not under the scan root.
    On failure, first check: the report is written relative to the scan root or not at all.
    """
    root = asset_case("ds101", "dangling_file_link").root
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    assert cli.main(["scan", str(root), "--output", "report.txt"]) == 1
    capsys.readouterr()

    assert (workdir / "report.txt").is_file()
    assert not (root / "report.txt").exists()


def test_scan_output_overwrites_existing_file(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli output ds101: verifies --output replaces an existing file's content.

    Scenario: pre-populate the output file with stale text, then scan into it.
    Boundaries: no stale bytes survive; the file holds only the new report.
    On failure, first check: the report is appended to the stale content.
    """
    root = asset_case("ds101", "dangling_file_link").root
    target = tmp_path / "report.json"
    target.write_text("stale" * 1000, encoding="utf-8")

    cli.main(["scan", str(root), "--format", "json", "--output", str(target)])
    capsys.readouterr()

    assert "stale" not in target.read_text(encoding="utf-8")
    json.loads(target.read_text(encoding="utf-8"))


def test_scan_output_to_directory_fails_with_exit_2(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli output ds101: verifies an unwritable --output target is a scan failure.

    Scenario: point --output at an existing directory.
    Boundaries: exit code 2 with a ``Scan failed:`` line on stderr; nothing on stdout.
    On failure, first check: the error escapes as a traceback, or the findings exit code is returned.
    """
    root = asset_case("ds101", "dangling_file_link").root

    assert cli.main(["scan", str(root), "--output", str(tmp_path)]) == 2
    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err.startswith("Scan failed:")


def test_scan_output_not_written_on_template_failure(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli output ds101: verifies a template error leaves no output file behind.

    Scenario: request an unknown template name with --output.
    Boundaries: exit code 2 and the output path is never created.
    On failure, first check: an empty or partial report file is left on disk.
    """
    root = asset_case("ds101", "dangling_file_link").root
    target = tmp_path / "report.txt"

    assert cli.main(["scan", str(root), "--format", "no-such-template", "--output", str(target)]) == 2
    capsys.readouterr()

    assert not target.exists()
