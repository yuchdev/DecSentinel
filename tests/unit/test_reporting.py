"""Tests for reporting format rendering and CLI format options."""

import json

import pytest

from docsentinel.models import Finding, ScanResult
from docsentinel.reporting import render
from docsentinel.telemetry.filters import gha_data, gha_property


def test_github_format_renders_error_and_warning_levels() :
    """
    [Unit] reporting: verifies github format renders error and warning levels.

    Scenario:
        Given test inputs and fixtures for github format renders error and warning levels
        When test_github_format_renders_error_and_warning_levels executes the target flow
        Then the expected outcome for github format renders error and warning levels is confirmed.

    Boundaries:
        - Focus: github format renders error and warning levels
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to github format renders error and warning levels
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(
            Finding(rule="DS101", path="README.md", message="Broken link", severity="error", line=10),
            Finding(rule="DS102", path="guide.md", message="Stray comment", severity="warning", line=20),
        ),
        enabled_rules=("DS101", "DS102"),
        pending=(),
    )
    rendered = render(result, "github")
    assert rendered == ("::error file=README.md,line=10,title=DS101::Broken link\n::warning file=guide.md,line=20,title=DS102::Stray comment")


def test_github_format_includes_known_line() :
    """
    [Unit] reporting: verifies github format includes known line.

    Scenario:
        Given test inputs and fixtures for github format includes known line
        When test_github_format_includes_known_line executes the target flow
        Then the expected outcome for github format includes known line is confirmed.

    Boundaries:
        - Focus: github format includes known line
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to github format includes known line
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS101", path="docs/intro.md", message="Dangling link", severity="error", line=7),),
        enabled_rules=("DS101",),
        pending=(),
    )
    assert render(result, "github") == "::error file=docs/intro.md,line=7,title=DS101::Dangling link"


def test_github_format_omits_unknown_line_and_column() :
    """
    [Unit] reporting: verifies github format omits unknown line and column.

    Scenario:
        Given test inputs and fixtures for github format omits unknown line and column
        When test_github_format_omits_unknown_line_and_column executes the target flow
        Then the expected outcome for github format omits unknown line and column is confirmed.

    Boundaries:
        - Focus: github format omits unknown line and column
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to github format omits unknown line and column
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(
            Finding(rule="DS103", path="docs/ref.md", message="Unresolvable path", severity="warning", line=None),
        ),
        enabled_rules=("DS103",),
        pending=(),
    )
    rendered = render(result, "github")
    assert rendered == "::warning file=docs/ref.md,title=DS103::Unresolvable path"
    assert "line=" not in rendered
    assert "col=" not in rendered
    assert "column=" not in rendered


def test_github_format_with_no_findings_is_empty_string() :
    """
    [Unit] reporting: verifies github format with no findings is empty string.

    Scenario:
        Given test inputs and fixtures for github format with no findings is empty string
        When test_github_format_with_no_findings_is_empty_string executes the target flow
        Then the expected outcome for github format with no findings is empty string is confirmed.

    Boundaries:
        - Focus: github format with no findings is empty string
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to github format with no findings is empty string
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(),
        enabled_rules=("DS101", "DS102"),
        pending=(),
    )
    assert render(result, "github") == ""


def test_unknown_severity_maps_to_warning_level() :
    """
    [Unit] reporting: verifies unknown severity maps to warning level.

    Scenario:
        Given test inputs and fixtures for unknown severity maps to warning level
        When test_unknown_severity_maps_to_warning_level executes the target flow
        Then the expected outcome for unknown severity maps to warning level is confirmed.

    Boundaries:
        - Focus: unknown severity maps to warning level
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to unknown severity maps to warning level
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    for severity in ("notice", "info", "critical", "suggestion", "custom", ""):
        result = ScanResult(
            profile="fast",
            documents=(),
            findings=(Finding(rule="DS999", path="file.md", message="Some finding", severity=severity, line=1),),
            enabled_rules=("DS999",),
            pending=(),
        )
        assert render(result, "github") == "::warning file=file.md,line=1,title=DS999::Some finding"


def test_gha_level_error_maps_to_error() :
    """
    [Unit] reporting: verifies gha level error maps to error.

    Scenario:
        Given test inputs and fixtures for gha level error maps to error
        When test_gha_level_error_maps_to_error executes the target flow
        Then the expected outcome for gha level error maps to error is confirmed.

    Boundaries:
        - Focus: gha level error maps to error
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to gha level error maps to error
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS999", path="file.md", message="Some finding", severity="error", line=1),),
        enabled_rules=("DS999",),
        pending=(),
    )
    assert render(result, "github") == "::error file=file.md,line=1,title=DS999::Some finding"


def test_github_format_escapes_message_newlines_carriage_returns_and_percents() :
    """
    [Unit] reporting: verifies github format escapes message newlines carriage returns and percents.

    Scenario:
        Given test inputs and fixtures for github format escapes message newlines carriage returns and percents
        When test_github_format_escapes_message_newlines_carriage_returns_and_percents executes the target flow
        Then the expected outcome for github format escapes message newlines carriage returns and percents is confirmed.

    Boundaries:
        - Focus: github format escapes message newlines carriage returns and percents
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to github format escapes message newlines carriage returns and percents
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    message_with_injection = "Line 1\n::set-output name=injected::evil\r\nProgress: 100% complete %0A not decoded"
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS101", path="doc.md", message=message_with_injection, severity="error", line=5),),
        enabled_rules=("DS101",),
        pending=(),
    )
    rendered = render(result, "github")
    assert "\n" not in rendered
    assert "\r" not in rendered
    assert rendered == (
        "::error file=doc.md,line=5,title=DS101::Line 1%0A::set-output name=injected::evil%0D%0A"
        "Progress: 100%25 complete %250A not decoded"
    )


def test_github_format_escapes_property_delimiters() :
    """
    [Unit] reporting: verifies github format escapes property delimiters.

    Scenario:
        Given test inputs and fixtures for github format escapes property delimiters
        When test_github_format_escapes_property_delimiters executes the target flow
        Then the expected outcome for github format escapes property delimiters is confirmed.

    Boundaries:
        - Focus: github format escapes property delimiters
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to github format escapes property delimiters
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    path_with_delimiters = "docs/file,name:with%delims\r\nand,more.md"
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(
            Finding(rule="DS101", path=path_with_delimiters, message="Problem found", severity="error", line=12),
        ),
        enabled_rules=("DS101",),
        pending=(),
    )
    rendered = render(result, "github")
    assert "\n" not in rendered
    assert "\r" not in rendered
    assert rendered == ("::error file=docs/file%2Cname%3Awith%25delims%0D%0Aand%2Cmore.md,line=12,title=DS101::Problem found")


def test_escape_helpers_order_and_behavior() :
    """
    [Unit] reporting: verifies escape helpers order and behavior.

    Scenario:
        Given test inputs and fixtures for escape helpers order and behavior
        When test_escape_helpers_order_and_behavior executes the target flow
        Then the expected outcome for escape helpers order and behavior is confirmed.

    Boundaries:
        - Focus: escape helpers order and behavior
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to escape helpers order and behavior
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    assert gha_data("%\r\n") == "%25%0D%0A"
    assert gha_data("%0A") == "%250A"
    assert gha_property("%\r\n:,") == "%25%0D%0A%3A%2C"
    assert gha_property("%2C%3A") == "%252C%253A"


def test_render_unsupported_format_raises_value_error() :
    """
    [Unit] reporting: verifies render unsupported format raises value error.

    Scenario:
        Given test inputs and fixtures for render unsupported format raises value error
        When test_render_unsupported_format_raises_value_error executes the target flow
        Then the expected outcome for render unsupported format raises value error is confirmed.

    Boundaries:
        - Focus: render unsupported format raises value error
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to render unsupported format raises value error
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(),
        enabled_rules=(),
        pending=(),
    )
    with pytest.raises(ValueError, match="unknown template: invalid"):
        render(result, "invalid")
    with pytest.raises(ValueError, match="unknown template"):
        render(result, "../escape.json")  # a format is a name, never a path to open


def test_render_text_and_json_formats() :
    """
    [Unit] reporting: verifies render text and json formats.

    Scenario:
        Given test inputs and fixtures for render text and json formats
        When test_render_text_and_json_formats executes the target flow
        Then the expected outcome for render text and json formats is confirmed.

    Boundaries:
        - Focus: render text and json formats
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to render text and json formats
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS101", path="README.md", message="Broken link", severity="error", line=10),),
        enabled_rules=("DS101",),
        pending=("manual check",),
    )
    text_rendered = render(result, "text")
    assert "Profile: fast" in text_rendered
    assert "error: README.md: Broken link" in text_rendered
    assert "Pending: manual check" in text_rendered

    json_rendered = render(result, "json")
    assert '"profile": "fast"' in json_rendered
    assert '"rule": "DS101"' in json_rendered
    assert '"rule": "DS101"' in render(result, "json-v1")


def test_github_format_preserves_unicode_and_special_characters() :
    """
    [Unit] reporting: verifies github format preserves unicode and special characters.

    Scenario:
        Given test inputs and fixtures for github format preserves unicode and special characters
        When test_github_format_preserves_unicode_and_special_characters executes the target flow
        Then the expected outcome for github format preserves unicode and special characters is confirmed.

    Boundaries:
        - Focus: github format preserves unicode and special characters
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to github format preserves unicode and special characters
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(
            Finding(
                rule="DS101",
                path="docs/guide_日本語.md",
                message="Broken anchor ⚠️ -> #섹션",
                severity="error",
                line=42,
            ),
        ),
        enabled_rules=("DS101",),
        pending=(),
    )
    rendered = render(result, "github")
    assert rendered == "::error file=docs/guide_日本語.md,line=42,title=DS101::Broken anchor ⚠️ -> #섹션"


def test_json_output_includes_schema_version() :
    """
    [Unit] reporting: verifies json output includes schema version.

    Scenario:
        Given test inputs and fixtures for json output includes schema version
        When test_json_output_includes_schema_version executes the target flow
        Then the expected outcome for json output includes schema version is confirmed.

    Boundaries:
        - Focus: json output includes schema version
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to json output includes schema version
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(),
        enabled_rules=(),
        pending=(),
    )
    payload = json.loads(render(result, "json"))
    assert payload["schema_version"] == 2  # decision D1: the default json is schema 2
    assert list(payload.keys())[0] == "schema_version"
    legacy = json.loads(render(result, "json-v1"))
    assert legacy["schema_version"] == 1
    assert list(legacy.keys())[0] == "schema_version"


def test_text_output_includes_schema_version_line() :
    """
    [Unit] reporting: verifies text output includes schema version line.

    Scenario:
        Given test inputs and fixtures for text output includes schema version line
        When test_text_output_includes_schema_version_line executes the target flow
        Then the expected outcome for text output includes schema version line is confirmed.

    Boundaries:
        - Focus: text output includes schema version line
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to text output includes schema version line
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(),
        enabled_rules=(),
        pending=(),
    )
    rendered = render(result, "text")
    lines = rendered.splitlines()
    assert lines[0] == "Schema version: 1"


def test_schema_version_defaults_to_one_for_direct_construction() :
    """
    [Unit] reporting: verifies schema version defaults to one for direct construction.

    Scenario:
        Given test inputs and fixtures for schema version defaults to one for direct construction
        When test_schema_version_defaults_to_one_for_direct_construction executes the target flow
        Then the expected outcome for schema version defaults to one for direct construction is confirmed.

    Boundaries:
        - Focus: schema version defaults to one for direct construction
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to schema version defaults to one for direct construction
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(),
        enabled_rules=(),
        pending=(),
    )
    assert result.schema_version == 1

    custom_result = ScanResult(
        schema_version=2,
        profile="fast",
        documents=(),
        findings=(),
        enabled_rules=(),
        pending=(),
    )
    assert custom_result.schema_version == 2


def test_json_output_includes_finding_line() :
    """
    [Unit] reporting: verifies json output includes finding line.

    Scenario:
        Given test inputs and fixtures for json output includes finding line
        When test_json_output_includes_finding_line executes the target flow
        Then the expected outcome for json output includes finding line is confirmed.

    Boundaries:
        - Focus: json output includes finding line
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to json output includes finding line
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result_with_line = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS101", path="README.md", message="Broken link", severity="error", line=42),),
        enabled_rules=("DS101",),
        pending=(),
    )
    payload_with_line = json.loads(render(result_with_line, "json"))
    assert payload_with_line["documents"][0]["problems"][0]["line"] == 42
    assert json.loads(render(result_with_line, "json-v1"))["findings"][0]["line"] == 42

    result_without_line = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS101", path="README.md", message="Broken link", severity="error", line=None),),
        enabled_rules=("DS101",),
        pending=(),
    )
    payload_without_line = json.loads(render(result_without_line, "json"))
    assert payload_without_line["documents"][0]["problems"][0]["line"] is None
    assert json.loads(render(result_without_line, "json-v1"))["findings"][0]["line"] is None


def test_deep_run_with_findings_shows_advisory_banner_text() :
    """
    [Unit] reporting: verifies deep run with findings shows advisory banner text.

    Scenario:
        Given test inputs and fixtures for deep run with findings shows advisory banner text
        When test_deep_run_with_findings_shows_advisory_banner_text executes the target flow
        Then the expected outcome for deep run with findings shows advisory banner text is confirmed.

    Boundaries:
        - Focus: deep run with findings shows advisory banner text
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep run with findings shows advisory banner text
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="deep",
        documents=(),
        findings=(Finding(rule="DS301", path="a.md", message="candidate contradiction", severity="warning"),),
        enabled_rules=("DS301",),
        pending=(),
        notice="1 deep rule(s) evaluated (heuristic, advisory-only).",
    )
    rendered = render(result, "text")
    assert "Deep findings are heuristic candidates for review - they do not fail the build." in rendered


def test_deep_run_with_findings_advisory_in_json() :
    """
    [Unit] reporting: verifies deep run with findings advisory in json.

    Scenario:
        Given test inputs and fixtures for deep run with findings advisory in json
        When test_deep_run_with_findings_advisory_in_json executes the target flow
        Then the expected outcome for deep run with findings advisory in json is confirmed.

    Boundaries:
        - Focus: deep run with findings advisory in json
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep run with findings advisory in json
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="deep",
        documents=(),
        findings=(Finding(rule="DS301", path="a.md", message="candidate contradiction", severity="warning"),),
        enabled_rules=("DS301",),
        pending=(),
        notice="1 deep rule(s) evaluated (heuristic, advisory-only).",
    )
    banner = "Deep findings are heuristic candidates for review - they do not fail the build."
    assert json.loads(render(result, "json"))["run"]["advisory"] == banner
    assert json.loads(render(result, "json-v1"))["advisory"] == banner


def test_fast_run_has_no_advisory_banner() :
    """
    [Unit] reporting: verifies fast run has no advisory banner.

    Scenario:
        Given test inputs and fixtures for fast run has no advisory banner
        When test_fast_run_has_no_advisory_banner executes the target flow
        Then the expected outcome for fast run has no advisory banner is confirmed.

    Boundaries:
        - Focus: fast run has no advisory banner
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to fast run has no advisory banner
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS101", path="a.md", message="Broken link", severity="error"),),
        enabled_rules=("DS101",),
        pending=(),
    )
    assert "Deep findings are heuristic candidates" not in render(result, "text")
    assert json.loads(render(result, "json"))["run"]["advisory"] is None
    assert "advisory" not in json.loads(render(result, "json-v1"))


def test_deep_run_without_findings_no_banner() :
    """
    [Unit] reporting: verifies deep run without findings no banner.

    Scenario:
        Given test inputs and fixtures for deep run without findings no banner
        When test_deep_run_without_findings_no_banner executes the target flow
        Then the expected outcome for deep run without findings no banner is confirmed.

    Boundaries:
        - Focus: deep run without findings no banner
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep run without findings no banner
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by reporting
    """
    result = ScanResult(
        profile="deep",
        documents=(),
        findings=(),
        enabled_rules=("DS301",),
        pending=(),
        notice="1 deep rule(s) evaluated (heuristic, advisory-only).",
    )
    assert "Deep findings are heuristic candidates" not in render(result, "text")
    assert json.loads(render(result, "json"))["run"]["advisory"] is None
    assert "advisory" not in json.loads(render(result, "json-v1"))
