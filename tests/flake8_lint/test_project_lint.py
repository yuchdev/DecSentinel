"""Pytest lint gate for Flakeforge X-rules."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import get_type_hints

import docsig
import pytest
from flakeforge.config import load_config
from flakeforge.testing import assert_lint_clean

from docsentinel.telemetry import extensions

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_project_lint_reports_x_rule_violations_without_baseline():
    """
    [Integration] flakeforge lint: verifies project lint gate reports X-rule violations without baseline.

    Scenario:
        Given the project contains flakeforge X-rule checks
        When pytest executes this lint gate
        Then violations are reported directly instead of being hidden by baseline suppression.

    Boundaries:
        - Focus: enforce project-wide X-rule visibility during pytest runs
        - Fixtures/params: none
        - Scope: lints src/tests/scripts using configured rules, with baseline disabled

    On failure, first check:
        - The reported X-rule locations and messages
        - Whether violations are pre-existing debt that still needs cleanup
        - pyproject.toml [tool.flakeforge] configuration
    """
    config = load_config(cwd=REPO_ROOT).merge(baseline="")
    assert_lint_clean(
        REPO_ROOT / "src",
        REPO_ROOT / "tests",
        REPO_ROOT / "scripts",
        config=config,
    )


def test_extensions_docsig_and_flakeforge_are_clean(capsys: pytest.CaptureFixture[str]):
    """[Integration] extensions: verifies actual source passes docsig and Flakeforge together.

    Scenario:
        Given the actual extensions.py source, not a synthetic annotation sample
        When both tools check it with no disabled diagnostics
        Then the docsig report is empty and Flakeforge reports no violations.

    Boundaries:
        - Focus: regression for six SIG501 findings without introducing X-rule violations
        - Fixtures/params: capsys captures the real docsig report
        - Scope: actual extension source and configured Flakeforge rules, without a baseline

    On failure, first check:
        - The six void return annotations and the captured docsig diagnostics

    :param capsys: Capture the real docsig report, including any unexpected diagnostics.
    """
    source = REPO_ROOT / "src/docsentinel/telemetry/extensions.py"
    status = docsig.docsig(string=source.read_text(encoding="utf-8"), no_ansi=True)
    report = capsys.readouterr()
    assert status == 0, report.out + report.err
    assert report.out == ""
    assert report.err == ""
    assert_lint_clean(source, config=load_config(cwd=REPO_ROOT).merge(baseline=""))


@pytest.mark.parametrize(
    "function",
    [
        extensions.ModuleWatch.check_path,
        extensions.ModuleWatch.check,
        extensions.LoadedExtensions.check_modules,
        extensions.LoadedExtensions.check_import_path,
        extensions.check_template,
        extensions.apply_report_hooks,
    ],
)
def test_extension_void_annotations_resolve_to_none_type(function: Callable[..., object]):
    """[Unit] extensions: verifies forward annotations retain the semantic void contract.

    Scenario:
        Given each of the six extension functions, including early-return paths
        When Python resolves its forward return annotation
        Then the resolved type is NoneType, not a string or a value-bearing type.

    Boundaries:
        - Focus: semantic equivalence of quoted None annotations
        - Fixtures/params: all six changed entry points
        - Scope: Python type hint resolution without calling security-sensitive hooks

    On failure, first check:
        - The return annotation on the parameterized function

    :param function: An extension entry point requiring an explicit void annotation.
    """
    assert get_type_hints(function)["return"] is type(None)
