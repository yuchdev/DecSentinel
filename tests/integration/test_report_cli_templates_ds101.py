"""CLI report cut-over over a live DS101 scan (Milestone 0007 Story 03.0 Task 02).

``docsentinel scan`` renders only through templates: ``--format`` names a packaged template or one
in ``report_templates_dir``, ``--template PATH`` renders an invoker-supplied file and wins over
``--format``, and ``--show-clean-documents`` lists clean documents in the text report. Every
template failure is a ``Scan failed:`` line on stderr with exit code ``2``. The scan root is the
``ds101/dangling_file_link`` case (one dangling link), composed with ``ds101/clean_document`` for a
clean document and ``report/template_dir`` for repository templates.
"""

import importlib.util
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from docsentinel import cli, deep_support
from docsentinel.telemetry.loader import packaged_template_names
from tests.asset_helpers import AssetCase, load_asset_case

ESC = chr(0x1B)


def _standard_installed() -> bool:
    """Return whether the standard-profile extras are importable (without importing them)."""
    return all(importlib.util.find_spec(name) is not None for name in ("sklearn", "textstat", "docsig"))


#: ``scan`` arguments per profile; deep needs the explicit heuristic confirmation.
_PROFILE_ARGS: dict[str, tuple[str, ...]] = {
    "fast": ("--profile", "fast"),
    "standard": ("--profile", "standard"),
    "deep": ("--profile", "deep", "--i-understand-deep-is-heuristic"),
}


def _composed_root(asset_case: Callable[[str, str], AssetCase]) -> Path:
    """Return a root with one dangling-link README and one clean document.

    :param asset_case: The asset loader fixture.
    :returns: The scan root.
    """
    root = asset_case("ds101", "dangling_file_link").root
    clean = root / "guide"
    clean.mkdir()
    load_asset_case("ds101", "clean_document", clean)
    return root


@pytest.mark.parametrize("profile", sorted(_PROFILE_ARGS))
@pytest.mark.parametrize("name", packaged_template_names())
def test_scan_renders_every_packaged_template_on_each_profile(
    name: str,
    profile: str,
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli templates ds101: verifies every packaged template renders a live scan per profile.

    Scenario:
        Given a scan root with a dangling link and a clean document
        When ``docsentinel scan --format <name>`` runs for each packaged template under each profile
        Then it exits with the profile's normal code, prints the report, and JSON templates parse.

    Boundaries:
        - Focus: ``--format`` resolves packaged template names end to end (CLI -> scan -> render)
        - Fixtures/params: parametrized over the packaged names and the three profiles; standard and deep
          skip when their extras (or the spaCy model) are missing
        - Scope: in-process CLI call

    On failure, first check:
        - ``cli._report_template`` and ``reporting.render``
        - Whether a packaged template stopped validating (the loader names the failing node)
    """
    if profile == "standard" and not _standard_installed():
        pytest.skip("standard extras are not installed")
    if profile == "deep" and not deep_support.deep_ready():
        pytest.skip("deep extras or model are not installed")
    root = _composed_root(asset_case)

    exit_code = cli.main(["scan", str(root), *_PROFILE_ARGS[profile], "--format", name])

    captured = capsys.readouterr()
    assert exit_code == (1 if profile == "fast" else 0), captured.err
    assert captured.err == ""
    if name.startswith("json"):
        json.loads(captured.out)
    if profile == "fast" and name in ("text", "github"):
        assert "README.md" in captured.out


def test_default_json_is_schema_2_and_json_v1_is_schema_1(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli templates ds101: verifies ``--format json`` is schema 2 and ``json-v1`` schema 1.

    Scenario:
        Given a fast scan with one dangling link and a clean document
        When it is rendered with ``--format json`` and with ``--format json-v1``
        Then the default carries ``schema_version`` 2 with every document (clean included) and the
            legacy one carries ``schema_version`` 1 with a flat ``findings`` list.

    Boundaries:
        - Focus: decision D1 (the default JSON moves to schema 2; the old bytes stay under json-v1)
        - Fixtures/params: ds101/dangling_file_link + ds101/clean_document
        - Scope: in-process CLI calls

    On failure, first check:
        - The ``schema_version`` members of ``templates/json.json`` and ``templates/json-v1.json``
    """
    root = _composed_root(asset_case)

    assert cli.main(["scan", str(root), "--format", "json"]) == 1
    current = json.loads(capsys.readouterr().out)
    assert cli.main(["scan", str(root), "--format", "json-v1"]) == 1
    legacy = json.loads(capsys.readouterr().out)

    assert current["schema_version"] == 2
    assert sorted(document["path"] for document in current["documents"]) == ["README.md", "guide/clean.md"]
    assert [problem["rule"] for document in current["documents"] for problem in document["problems"]] == ["DS101"]
    assert legacy["schema_version"] == 1
    assert [finding["rule"] for finding in legacy["findings"]] == ["DS101"]


def test_show_clean_documents_lists_clean_documents_in_text(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli templates ds101: verifies ``--show-clean-documents`` and its config option.

    Scenario:
        Given a scan root with a dangling-link README and a clean ``guide/clean.md``
        When the text report is rendered by default, with ``--show-clean-documents``, and with
            ``report_show_clean_documents = true`` in ``docsentinel.toml``
        Then the clean document is hidden by default and listed (with its size) in the other two runs.

    Boundaries:
        - Focus: decision D2 (text hides clean documents unless asked)
        - Fixtures/params: ds101/dangling_file_link + ds101/clean_document; a config file written in the test
        - Scope: in-process CLI calls

    On failure, first check:
        - The ``show_clean_documents`` loops of ``templates/text.json``
        - The ``report_show_clean_documents`` override in ``cli.main``
    """
    root = _composed_root(asset_case)

    cli.main(["scan", str(root)])
    hidden = capsys.readouterr().out.split("\n")
    cli.main(["scan", str(root), "--show-clean-documents"])
    shown = capsys.readouterr().out.split("\n")
    (root / "docsentinel.toml").write_text("report_show_clean_documents = true\n", encoding="utf-8")
    cli.main(["scan", str(root)])
    configured = capsys.readouterr().out.split("\n")

    assert not any(line.startswith("guide/clean.md") for line in hidden)
    assert any(line.startswith("guide/clean.md (") and line.endswith(" bytes)") for line in shown)
    assert configured == shown
    assert any(line.startswith("  error: README.md: ") for line in shown)


def test_template_path_wins_over_format(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli templates ds101: verifies ``--template PATH`` renders a user template file.

    Scenario:
        Given the ``report/template_dir`` ``mini.json`` template copied next to a dangling-link scan root
        When ``scan --format json --template <mini.json>`` runs
        Then the report is the mini template's layout, not schema-2 JSON.

    Boundaries:
        - Focus: ``--template`` precedence and the invoker-path file gate
        - Fixtures/params: ds101/dangling_file_link + report/template_dir
        - Scope: in-process CLI call

    On failure, first check:
        - The ``template_path`` branch of ``cli._report_template``
    """
    root = asset_case("ds101", "dangling_file_link").root
    asset_case("report", "template_dir")

    exit_code = cli.main(["scan", str(root), "--format", "json", "--template", str(root / "templates" / "mini.json")])

    lines = capsys.readouterr().out.split("\n")
    assert exit_code == 1
    assert lines[0] == "Profile: fast"
    assert lines[1].startswith("README.md:")


def test_report_templates_dir_adds_format_names(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli templates ds101: verifies ``report_templates_dir`` templates are selectable.

    Scenario:
        Given ``report_templates_dir = "templates"`` over the ``report/template_dir`` templates
        When ``scan --format mini`` and ``scan --format text`` run
        Then ``mini`` renders from the directory and ``text`` still renders the packaged template
            (the directory's ``text.json`` cannot shadow it).

    Boundaries:
        - Focus: free-form ``--format`` choices computed from the discovered templates
        - Fixtures/params: ds101/dangling_file_link + report/template_dir; config written in the test
        - Scope: in-process CLI calls

    On failure, first check:
        - ``loader.available_templates`` and the packaged-first rule of ``loader._load_by_name``
    """
    root = asset_case("ds101", "dangling_file_link").root
    asset_case("report", "template_dir")
    (root / "docsentinel.toml").write_text('report_templates_dir = "templates"\n', encoding="utf-8")

    assert cli.main(["scan", str(root), "--format", "mini"]) == 1
    mini = capsys.readouterr().out
    assert cli.main(["scan", str(root), "--format", "text"]) == 1
    text = capsys.readouterr().out

    assert mini.startswith("Profile: fast\nREADME.md:")
    assert text.startswith("Schema version: 1\nProfile: fast\n")


@pytest.mark.parametrize(
    ("extra_args", "config", "expected"),
    [
        (("--format", "nope"), None, "unknown --format 'nope'; choose from: github, json"),
        (("--format", "../x.json"), None, "unknown --format"),
        (("--format", "mini"), None, "unknown --format 'mini'"),
        (("--format", "dup-key"), 'report_templates_dir = "templates"\n', "dup-key"),
        (("--template", "templates/typo-key.json"), None, "typo-key.json"),
        (("--template", "missing.json"), None, "could not be read"),
        (("--format", "text"), 'report_templates_dir = "../outside"\n', "report_templates_dir must stay within"),
        (("--format", "text"), 'report_templates_dir = "missing-dir"\n', "report_templates_dir"),
    ],
    ids=[
        "unknown-name",
        "path-as-format",
        "dir-template-not-configured",
        "invalid-dir-template",
        "invalid-template-path",
        "missing-template-path",
        "dir-escapes-root",
        "dir-missing",
    ],
)
def test_template_errors_exit_2_with_scan_failed(
    extra_args: tuple[str, ...],
    config: str,
    expected: str,
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] report cli templates ds101: verifies every template failure is ``Scan failed:`` with exit 2.

    Scenario:
        Given a scan root with repository templates (some deliberately invalid)
        When ``scan`` names an unknown format, a path as a format, an invalid or missing template, or a
            ``report_templates_dir`` that escapes the root or does not exist
        Then the exit code is 2, stdout is empty, and stderr is one ``Scan failed:`` line naming the problem.

    Boundaries:
        - Focus: the exit-2 error path for template and template-directory errors
        - Fixtures/params: ds101/dangling_file_link + report/template_dir; one case per failure kind
        - Scope: in-process CLI calls; relative ``--template`` paths resolve from the scan root (chdir)

    On failure, first check:
        - The exception tuple of the ``scan`` branch in ``cli.main``
        - The ``TemplateError`` text raised by the loader for the case
    """
    root = asset_case("ds101", "dangling_file_link").root
    asset_case("report", "template_dir")
    if config is not None:
        (root / "docsentinel.toml").write_text(config, encoding="utf-8")
    monkeypatch.chdir(root)

    exit_code = cli.main(["scan", str(root), *extra_args])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err.startswith("Scan failed: ")
    assert expected in captured.err
    assert captured.err.count("\n") == 1


def test_template_error_line_is_neutralized(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] report cli templates ds101: verifies a hostile ``--format`` value is echoed inertly.

    Scenario:
        Given a ``--format`` value carrying ESC and a line feed
        When the scan fails because no such template exists
        Then stderr holds visible escapes and no raw control byte, on a single line.

    Boundaries:
        - Focus: template errors pass through ``neutralize_text`` (threat model M16)
        - Fixtures/params: ds101/dangling_file_link
        - Scope: in-process CLI call

    On failure, first check:
        - Whether the ``Scan failed:`` line still calls ``neutralize_text``
    """
    root = asset_case("ds101", "dangling_file_link").root

    exit_code = cli.main(["scan", str(root), "--format", f"x{ESC}[31m\nforged"])

    err = capsys.readouterr().err
    assert exit_code == 2
    assert ESC not in err
    assert err.count("\n") == 1


def test_doctor_lists_templates(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] report cli templates ds101: verifies ``doctor`` lists packaged and directory templates.

    Scenario:
        Given a working directory whose ``docsentinel.toml`` sets ``report_templates_dir = "templates"``
        When ``docsentinel doctor`` runs, and again after the directory setting is broken
        Then it lists the packaged names and the directory-only names, and reports the broken
            setting on one line while still exiting 0.

    Boundaries:
        - Focus: ``_doctor_template_lines``
        - Fixtures/params: ds101/dangling_file_link + report/template_dir
        - Scope: in-process CLI calls with ``chdir``

    On failure, first check:
        - ``loader.packaged_template_names`` / ``available_templates``
    """
    root = asset_case("ds101", "dangling_file_link").root
    asset_case("report", "template_dir")
    (root / "docsentinel.toml").write_text('report_templates_dir = "templates"\n', encoding="utf-8")
    monkeypatch.chdir(root)

    assert cli.main(["doctor"]) == 0
    lines = capsys.readouterr().out.split("\n")
    (root / "docsentinel.toml").write_text('report_templates_dir = "nowhere"\n', encoding="utf-8")
    assert cli.main(["doctor"]) == 0
    broken = capsys.readouterr().out.split("\n")

    assert "report templates (packaged): github, json, json-documents, json-v1, text" in lines
    assert "report templates (report_templates_dir): dup-key, json-mini, mini, typo-key, wrong-stem" in lines
    assert any(line.startswith("report templates (report_templates_dir): unavailable: ") for line in broken)
