"""Execute the examples of ``docs/user/tutorial/custom-reports.md`` (Milestone 0007 Story 04.0 Task 02).

The guide's configuration, templates and ``python:`` extension are taken verbatim from its fenced
code blocks and run against the ``ds101/custom_reports_guide`` case (``README.md``,
``docs/setup.md``) with ``ds101/custom_reports_guide_agent`` composed under ``.claude/agents/``.
The printed output must equal the output blocks of the guide, so the documentation cannot rot.
Relies on threat model ``docs/security/threat-model-0007-extensions-2026-11-03.md`` M2/M6 (the
documented gate and an extension module outside the checkout) and M24 (``doc.domain``).
"""

import json
import re
import sys
from pathlib import Path

import pytest

from docsentinel import cli
from tests.asset_helpers import load_asset_case

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "user" / "tutorial" / "custom-reports.md"
_FENCE = re.compile(r"^```(\w+)\n(.*?)^```$", re.MULTILINE | re.DOTALL)


def _blocks(language: str, marker: str) -> list[str]:
    """Return the guide's fenced blocks of ``language`` that contain ``marker``."""
    text = GUIDE.read_text(encoding="utf-8")
    return [body for lang, body in _FENCE.findall(text) if lang == language and marker in body]


def _one(language: str, marker: str) -> str:
    """Return the single guide block of ``language`` containing ``marker``."""
    found = _blocks(language, marker)
    assert len(found) == 1, f"expected one {language} block containing {marker!r}, found {len(found)}"
    return found[0]


@pytest.fixture
def guide_root(tmp_path: Path) -> Path:
    """Materialize the guide's example repository with the guide's ``docsentinel.toml``."""
    root = load_asset_case("ds101", "custom_reports_guide", tmp_path / "repo").root
    load_asset_case("ds101", "custom_reports_guide_agent", root / ".claude" / "agents")
    (root / "docsentinel.toml").write_text(_one("toml", "[[telemetry_domains]]"), encoding="utf-8")
    return root


def test_worked_template_example_prints_the_documented_output(
    guide_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] custom reports guide ds101: verifies the ``--template`` walkthrough prints what the guide shows.

    Scenario:
        Given the guide's example repository, its ``docsentinel.toml`` and its ``domain-summary.json`` template
        When ``docsentinel scan --template domain-summary.json`` runs from the repository root
        Then stdout equals the guide's ``text`` output block and the exit code is 1.

    Boundaries:
        - Focus: documentation accuracy of the template walkthrough and the domain table
        - Fixtures/params: guide blocks extracted verbatim
        - Scope: in-process CLI call

    On failure, first check:
        - whether the guide or the template behaviour changed; update the guide's output block deliberately
    """
    template = tmp_path / "domain-summary.json"
    template.write_text(_one("json", '"name": "domain-summary"'), encoding="utf-8")
    assert "docsentinel scan --template domain-summary.json" in _one("bash", "domain-summary.json")
    monkeypatch.chdir(guide_root)

    code = cli.main(["scan", "--template", str(template)])
    captured = capsys.readouterr()

    assert code == 1, captured.err
    assert captured.out == _one("text", "finding(s) in")


def test_python_extension_walkthrough_prints_the_documented_output(
    guide_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] custom reports guide ds101: verifies the ``python:`` extension walkthrough runs as documented (M2, M6).

    Scenario:
        Given the guide's ``density_report.py`` in a directory outside the checkout on sys.path, its
        ``density-report.json`` template, and the cwd outside the checkout
        When ``docsentinel scan <repo> --template density-report.json --extension python:density_report:make
        --allow-python-extensions`` runs
        Then stdout equals the guide's JSON output block, the exit code is 1, and without the gate it is refused.

    Boundaries:
        - Focus: the end-to-end extension example and the documented trust gate
        - Fixtures/params: guide blocks extracted verbatim; module on sys.path outside root and cwd
        - Scope: in-process CLI calls

    On failure, first check:
        - whether the guide or the extension contract changed; update the guide deliberately
    """
    modules = tmp_path / "ext"
    modules.mkdir()
    (modules / "density_report.py").write_text(_one("python", "class DensityExtension"), encoding="utf-8")
    template = tmp_path / "density-report.json"
    template.write_text(_one("json", '"name": "density-report"'), encoding="utf-8")
    command = _one("bash", "python:density_report:make")
    assert "--allow-python-extensions" in command and "--template density-report.json" in command
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.delitem(sys.modules, "density_report", raising=False)
    argv = ["scan", str(guide_root), "--template", str(template), "--extension", "python:density_report:make"]

    refused = cli.main(argv)
    refusal = capsys.readouterr()
    code = cli.main([*argv, "--allow-python-extensions"])
    captured = capsys.readouterr()
    monkeypatch.delitem(sys.modules, "density_report", raising=False)

    assert refused == 2 and refusal.out == ""
    assert code == 1, captured.err
    expected = _one("json", '"worst": [')
    assert captured.out == expected
    assert json.loads(captured.out)["worst"] == [".claude/agents/reviewer.md", "docs/setup.md"]


def test_guide_links_the_spec_the_threat_model_and_the_example():
    """
    [Integration] custom reports guide ds101: verifies the guide states the trust model and cross-links its sources.

    Scenario:
        Given the guide text
        When its links and trust-model section are inspected
        Then it links the template spec, the threat model and ``examples/telemetry-domains.toml``, and names the
        gate, ``python -P``, the console script and residuals R1-R5.

    Boundaries:
        - Focus: threat model checklist item 13
        - Fixtures/params: none
        - Scope: documentation text

    On failure, first check:
        - the "Trust model" section of the guide
    """
    text = GUIDE.read_text(encoding="utf-8")

    for target in (
        "/docs/specs/report-template-format.md",
        "/docs/security/threat-model-0007-extensions-2026-11-03.md",
        "/examples/telemetry-domains.toml",
    ):
        assert f"]({target})" in text
    for phrase in ("--allow-python-extensions", "DOCSENTINEL_ALLOW_PYTHON_EXTENSIONS=1", "`-P`", "console script"):
        assert phrase in text
    assert all(f"**R{number}.**" in text for number in range(1, 6))
