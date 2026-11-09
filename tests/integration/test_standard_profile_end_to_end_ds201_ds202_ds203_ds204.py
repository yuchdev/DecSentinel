"""End-to-end tests for the standard profile (DS201-DS204) over composed text assets from ``tests/assets``."""

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("textstat")
pytest.importorskip("sklearn")
pytest.importorskip("docsig")

from docsentinel.cli import main
from docsentinel.config import Config
from docsentinel.detectors.standard import corpus
from docsentinel.engine import scan
from tests.asset_helpers import AssetCase


@pytest.fixture
def standard_profile_tree(asset_case: Callable[[str, str], AssetCase]) -> tuple[Path, Path, Path]:
    """Compose a dense and a clean Markdown document from the DS201 assets."""
    dense = asset_case("ds201", "dense_document")
    clean = asset_case("ds201", "clean_document")
    return dense.root, dense.path("dense.md"), clean.path("clean.md")


def test_importing_engine_does_not_register_ds201():
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies importing engine does not register ds201.

    Scenario:
        Given test inputs and fixtures for importing engine does not register ds201
        When test_importing_engine_does_not_register_ds201 executes the target flow
        Then the expected outcome for importing engine does not register ds201 is confirmed.

    Boundaries:
        - Focus: importing engine does not register ds201
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to importing engine does not register ds201
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    code = (
        "import sys\n"
        "import docsentinel.engine\n"
        "from docsentinel.rules import RULES\n"
        "assert 'DS201' not in RULES, 'DS201 registered eagerly on engine import'\n"
        "assert 'DS202' not in RULES, 'DS202 registered eagerly on engine import'\n"
        "assert 'DS203' not in RULES, 'DS203 registered eagerly on engine import'\n"
        "assert 'DS204' not in RULES, 'DS204 registered eagerly on engine import'\n"
        "assert 'DS201' not in docsentinel.engine.ANALYZERS\n"
        "assert 'DS202' not in docsentinel.engine.ANALYZERS\n"
        "assert 'DS203' not in docsentinel.engine.ANALYZERS\n"
        "assert 'DS204' not in docsentinel.engine.ANALYZERS\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_standard_scan_detects_complex_document(
    standard_profile_tree: tuple[Path, Path, Path],
):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies standard scan detects complex document.

    Scenario:
        Given test inputs and fixtures for standard scan detects complex document
        When test_standard_scan_detects_complex_document executes the target flow
        Then the expected outcome for standard scan detects complex document is confirmed.

    Boundaries:
        - Focus: standard scan detects complex document
        - Fixtures/params: standard_profile_tree
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan detects complex document
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    root, _, _ = standard_profile_tree
    result = scan(root, config=Config(profile="standard"))
    assert tuple((finding.rule, finding.path) for finding in result.findings) == (("DS201", "dense.md"),)
    assert result.enabled_rules == ("DS201", "DS202", "DS203", "DS204")
    assert result.notice == "4 standard rule(s) evaluated."
    assert result.pending == ()


def test_clean_project_standard_scan(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies clean project standard scan.

    Scenario:
        Given test inputs and fixtures for clean project standard scan
        When test_clean_project_standard_scan executes the target flow
        Then the expected outcome for clean project standard scan is confirmed.

    Boundaries:
        - Focus: clean project standard scan
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to clean project standard scan
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds201", "clean_document")

    result = scan(case.root, config=Config(profile="standard"))

    assert result.findings == ()
    assert result.enabled_rules == ("DS201", "DS202", "DS203", "DS204")
    assert result.notice == "4 standard rule(s) evaluated."
    assert "not implemented" not in result.notice
    assert result.pending == ()


def test_ignore_narrows_standard_set(
    standard_profile_tree: tuple[Path, Path, Path],
):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies ignore narrows standard set.

    Scenario:
        Given test inputs and fixtures for ignore narrows standard set
        When test_ignore_narrows_standard_set executes the target flow
        Then the expected outcome for ignore narrows standard set is confirmed.

    Boundaries:
        - Focus: ignore narrows standard set
        - Fixtures/params: standard_profile_tree
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to ignore narrows standard set
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    root, _, _ = standard_profile_tree
    result = scan(root, config=Config(profile="standard", ignore=("DS2",)))
    assert result.findings == ()
    assert result.enabled_rules == ()
    assert result.pending == ("all standard rules were excluded by select/ignore",)
    assert result.notice == "All standard rules were excluded by select/ignore."


def test_fast_profile_scan_ignores_standard_detectors(
    standard_profile_tree: tuple[Path, Path, Path],
):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies fast profile scan ignores standard detectors.

    Scenario:
        Given test inputs and fixtures for fast profile scan ignores standard detectors
        When test_fast_profile_scan_ignores_standard_detectors executes the target flow
        Then the expected outcome for fast profile scan ignores standard detectors is confirmed.

    Boundaries:
        - Focus: fast profile scan ignores standard detectors
        - Fixtures/params: standard_profile_tree
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to fast profile scan ignores standard detectors
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    root, _, _ = standard_profile_tree
    result = scan(root, config=Config(profile="fast"))
    assert result.findings == ()
    assert result.enabled_rules == (
        "DS101",
        "DS102",
        "DS103",
        "DS104",
        "DS105",
        "DS106",
        "DS108",
        "DS109",
        "DS110",
        "DS112",
        "DS113",
        "DS114",
        "DS115",
        "DS116",
        "DS117",
        "DS118",
    )
    assert (
        result.notice
        == "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
    )
    assert "DS201" not in result.enabled_rules
    assert "DS204" not in result.enabled_rules


def test_standard_scan_exit_code_zero_for_warning_only(
    standard_profile_tree: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies standard scan exit code zero for warning only.

    Scenario:
        Given test inputs and fixtures for standard scan exit code zero for warning only
        When test_standard_scan_exit_code_zero_for_warning_only executes the target flow
        Then the expected outcome for standard scan exit code zero for warning only is confirmed.

    Boundaries:
        - Focus: standard scan exit code zero for warning only
        - Fixtures/params: standard_profile_tree, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan exit code zero for warning only
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    root, _, _ = standard_profile_tree
    assert main(["scan", str(root), "--profile", "standard"]) == 0
    captured = capsys.readouterr()
    assert "warning: dense.md: Readability grade level" in captured.out


def test_standard_scan_exit_code_one_under_strict(
    standard_profile_tree: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies standard scan exit code one under strict.

    Scenario:
        Given test inputs and fixtures for standard scan exit code one under strict
        When test_standard_scan_exit_code_one_under_strict executes the target flow
        Then the expected outcome for standard scan exit code one under strict is confirmed.

    Boundaries:
        - Focus: standard scan exit code one under strict
        - Fixtures/params: standard_profile_tree, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan exit code one under strict
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    root, _, _ = standard_profile_tree
    assert main(["scan", str(root), "--profile", "standard", "--strict"]) == 1
    captured = capsys.readouterr()
    assert "warning: dense.md: Readability grade level" in captured.out


def test_standard_scan_reports_duplicate_and_low_info(asset_case: Callable[[str, str], AssetCase]):
    # a.md and b.md duplicate each other, c.md is distinct, filler.md is low-information.
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies standard scan reports duplicate and low info.

    Scenario:
        Given test inputs and fixtures for standard scan reports duplicate and low info
        When test_standard_scan_reports_duplicate_and_low_info executes the target flow
        Then the expected outcome for standard scan reports duplicate and low info is confirmed.

    Boundaries:
        - Focus: standard scan reports duplicate and low info
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan reports duplicate and low info
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    duplicates = asset_case("ds202", "duplicate_tool_paragraph")
    asset_case("ds203", "filler_with_distinct_paragraph")

    corpus.build_corpus_model.cache_clear()
    result = scan(duplicates.root, config=Config(profile="standard"))
    corpus.build_corpus_model.cache_clear()

    findings_summary = tuple((f.rule, f.path) for f in result.findings)
    assert ("DS202", "b.md") in findings_summary
    assert ("DS203", "filler.md") in findings_summary
    assert len(result.findings) == 2
    assert result.enabled_rules == ("DS201", "DS202", "DS203", "DS204")
    assert result.notice == "4 standard rule(s) evaluated."


def test_corpus_model_built_once_per_scan(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies corpus model built once per scan.

    Scenario:
        Given test inputs and fixtures for corpus model built once per scan
        When test_corpus_model_built_once_per_scan executes the target flow
        Then the expected outcome for corpus model built once per scan is confirmed.

    Boundaries:
        - Focus: corpus model built once per scan
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to corpus model built once per scan
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds202", "duplicate_tool_paragraph")

    corpus.build_corpus_model.cache_clear()
    with patch.object(
        corpus.TfidfVectorizer, "fit_transform", autospec=True, side_effect=corpus.TfidfVectorizer.fit_transform
    ) as mock_fit:
        result = scan(case.root, config=Config(profile="standard"))
        scan(case.root, config=Config(profile="standard"))
        assert mock_fit.call_count == 2
        assert "DS202" in result.enabled_rules
        assert "DS203" in result.enabled_rules
        assert "DS204" in result.enabled_rules
    corpus.build_corpus_model.cache_clear()


def test_standard_enabled_rules_are_all_four(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies standard enabled rules are all four.

    Scenario:
        Given test inputs and fixtures for standard enabled rules are all four
        When test_standard_enabled_rules_are_all_four executes the target flow
        Then the expected outcome for standard enabled rules are all four is confirmed.

    Boundaries:
        - Focus: standard enabled rules are all four
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard enabled rules are all four
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds201", "clean_document")

    result = scan(case.root, config=Config(profile="standard"))

    assert result.enabled_rules == ("DS201", "DS202", "DS203", "DS204")
    assert result.notice == "4 standard rule(s) evaluated."


def test_select_narrows_to_single_corpus_rule(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies select narrows to single corpus rule.

    Scenario:
        Given test inputs and fixtures for select narrows to single corpus rule
        When test_select_narrows_to_single_corpus_rule executes the target flow
        Then the expected outcome for select narrows to single corpus rule is confirmed.

    Boundaries:
        - Focus: select narrows to single corpus rule
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to select narrows to single corpus rule
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds202", "duplicate_tool_paragraph")

    result = scan(case.root, config=Config(profile="standard", select=("DS202",)))

    assert result.enabled_rules == ("DS202",)
    assert result.notice == "1 standard rule(s) evaluated."
    assert "DS201" not in result.enabled_rules
    assert "DS203" not in result.enabled_rules
    assert "DS204" not in result.enabled_rules
    assert len(result.findings) == 1
    assert result.findings[0].rule == "DS202"
    assert result.findings[0].path == "b.md"


def test_standard_scan_reports_signature_finding(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies standard scan reports signature finding.

    Scenario:
        Given test inputs and fixtures for standard scan reports signature finding
        When test_standard_scan_reports_signature_finding executes the target flow
        Then the expected outcome for standard scan reports signature finding is confirmed.

    Boundaries:
        - Focus: standard scan reports signature finding
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan reports signature finding
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds204", "compute_nonexistent_param")
    asset_case("ds201", "clean_document")

    result = scan(case.root, config=Config(profile="standard"))

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule == "DS204"
    assert finding.path == "src/pkg/bad.py"
    assert finding.severity == "error"
    assert "compute: SIG202" in finding.message
    assert result.enabled_rules == ("DS201", "DS202", "DS203", "DS204")
    assert result.notice == "4 standard rule(s) evaluated."


def test_standard_scan_exit_code_one_for_ds204_error(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies standard scan exit code one for ds204 error.

    Scenario:
        Given test inputs and fixtures for standard scan exit code one for ds204 error
        When test_standard_scan_exit_code_one_for_ds204_error executes the target flow
        Then the expected outcome for standard scan exit code one for ds204 error is confirmed.

    Boundaries:
        - Focus: standard scan exit code one for ds204 error
        - Fixtures/params: asset_case, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan exit code one for ds204 error
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds204", "compute_nonexistent_param")
    asset_case("ds201", "clean_document")

    assert main(["scan", str(case.root), "--profile", "standard"]) == 1
    captured = capsys.readouterr()
    assert "error: src/pkg/bad.py:1: compute: SIG202" in captured.out


def test_ds204_coexists_with_corpus_detectors(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies ds204 coexists with corpus detectors.

    Scenario:
        Given test inputs and fixtures for ds204 coexists with corpus detectors
        When test_ds204_coexists_with_corpus_detectors executes the target flow
        Then the expected outcome for ds204 coexists with corpus detectors is confirmed.

    Boundaries:
        - Focus: ds204 coexists with corpus detectors
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to ds204 coexists with corpus detectors
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds204", "calculate_extra_param_in_package")
    asset_case("ds202", "duplicate_tool_paragraph")

    corpus.build_corpus_model.cache_clear()
    result = scan(case.root, config=Config(profile="standard"))
    corpus.build_corpus_model.cache_clear()

    finding_rules = tuple((f.rule, f.path) for f in result.findings)
    assert ("DS204", "src/pkg/bad.py") in finding_rules
    assert ("DS202", "b.md") in finding_rules
    assert len(result.findings) == 2


def test_select_ds204_only_skips_corpus_build(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies select ds204 only skips corpus build.

    Scenario:
        Given test inputs and fixtures for select ds204 only skips corpus build
        When test_select_ds204_only_skips_corpus_build executes the target flow
        Then the expected outcome for select ds204 only skips corpus build is confirmed.

    Boundaries:
        - Focus: select ds204 only skips corpus build
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to select ds204 only skips corpus build
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds204", "calculate_extra_param")
    asset_case("ds202", "duplicate_tool_paragraph")

    corpus.build_corpus_model.cache_clear()
    with patch.object(
        corpus.TfidfVectorizer,
        "fit_transform",
        autospec=True,
        side_effect=corpus.TfidfVectorizer.fit_transform,
    ) as mock_fit:
        result = scan(case.root, config=Config(profile="standard", select=("DS204",)))
        assert mock_fit.call_count == 0

    corpus.build_corpus_model.cache_clear()
    assert result.enabled_rules == ("DS204",)
    assert result.notice == "1 standard rule(s) evaluated."
    assert "DS202" not in result.enabled_rules
    assert "DS203" not in result.enabled_rules
    assert len(result.findings) == 1
    assert result.findings[0].rule == "DS204"
    assert result.findings[0].path == "src/bad.py"


def test_clean_project_standard_scan_is_zero_findings_evaluated(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard profile end to end ds201 ds202 ds203 ds204: verifies clean project standard scan is zero findings evaluated.

    Scenario:
        Given test inputs and fixtures for clean project standard scan is zero findings evaluated
        When test_clean_project_standard_scan_is_zero_findings_evaluated executes the target flow
        Then the expected outcome for clean project standard scan is zero findings evaluated is confirmed.

    Boundaries:
        - Focus: clean project standard scan is zero findings evaluated
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to clean project standard scan is zero findings evaluated
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by standard profile end to end ds201 ds202 ds203 ds204
    """
    case = asset_case("ds204", "clean_add_function")
    asset_case("ds201", "clean_document")

    result = scan(case.root, config=Config(profile="standard"))

    assert result.findings == ()
    assert result.enabled_rules == ("DS201", "DS202", "DS203", "DS204")
    assert result.notice == "4 standard rule(s) evaluated."
    assert result.pending == ()
