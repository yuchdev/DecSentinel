"""Integration tests for CLI report rendering over text assets in ``tests/assets/ds101``."""

from collections.abc import Callable

import pytest

from docsentinel import cli
from tests.asset_helpers import AssetCase


def test_cli_accepts_github_format_choice(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] reporting ds101: verifies cli accepts github format choice.

    Scenario:
        Given test inputs and fixtures for cli accepts github format choice
        When test_cli_accepts_github_format_choice executes the target flow
        Then the expected outcome for cli accepts github format choice is confirmed.

    Boundaries:
        - Focus: cli accepts github format choice
        - Fixtures/params: asset_case, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli accepts github format choice
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting ds101
    """
    case = asset_case("ds101", "clean_document")

    exit_code = cli.main(["scan", str(case.root), "--format", "github"])

    assert exit_code == 0
    assert capsys.readouterr().out == "\n"


def test_cli_scan_with_findings_and_github_format(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] reporting ds101: verifies cli scan with findings and github format.

    Scenario:
        Given test inputs and fixtures for cli scan with findings and github format
        When test_cli_scan_with_findings_and_github_format executes the target flow
        Then the expected outcome for cli scan with findings and github format is confirmed.

    Boundaries:
        - Focus: cli scan with findings and github format
        - Fixtures/params: asset_case, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli scan with findings and github format
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting ds101
    """
    case = asset_case("ds101", "dangling_file_link")

    exit_code = cli.main(["scan", str(case.root), "--format", "github"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert out.startswith("::error file=README.md,line=1,col=11,title=DS101::")
