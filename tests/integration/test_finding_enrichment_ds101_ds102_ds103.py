"""Integration tests for ``Finding`` enrichment (``column``/``value``/``type``) in DS101-DS103.

Milestone 0007 Story 01.0 Task 02: the three original fast detectors populate the optional report
fields over text assets from ``tests/assets``; the enrichment never changes finding equality or the
schema-1 JSON report.
"""

import json
from collections.abc import Callable

from docsentinel.config import Config
from docsentinel.detectors import comments, links, paths
from docsentinel.engine import evaluated_notice, scan
from docsentinel.reporting import render
from docsentinel.telemetry.model import ReportModel
from tests.asset_helpers import AssetCase


def _enrichment(findings: tuple) -> list[tuple]:
    """Project findings onto ``(line, column, value, type)`` for compact assertions."""
    return [(finding.line, finding.column, finding.value, finding.type) for finding in findings]


def test_ds101_dangling_link_carries_target_column_value_and_type(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] finding enrichment ds101: verifies a dangling link reports its target, column and type.

    Scenario:
        Given a document whose first line is ``[missing](missing.md)``
        When DS101 runs
        Then the finding has value ``missing.md``, column 11 and type ``dangling link``.

    Boundaries:
        - Focus: DS101 enrichment of a dangling file link
        - Fixtures/params: asset ds101/dangling_link_file
        - Scope: detector output only

    On failure, first check:
        - The column arithmetic in ``links.check_document``
    """
    case = asset_case("ds101", "dangling_link_file")

    findings = links.detect(case.root, case.documents("dangling.md"))

    assert _enrichment(findings) == [(1, 11, "missing.md", "dangling link")]
    assert findings[0].value in findings[0].message


def test_ds101_column_counts_stripped_code_spans_and_leading_whitespace(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] finding enrichment ds101: verifies columns refer to the raw line, not the code-span-stripped one.

    Scenario:
        Given a line with an inline code span, a link whose destination has leading spaces and a title,
            and a same-file anchor link
        When DS101 runs
        Then each finding's column points at the first character of its target in the original line.

    Boundaries:
        - Focus: offset mapping across removed code spans and destination whitespace
        - Fixtures/params: asset ds101/link_column_after_code_span
        - Scope: detector output only

    On failure, first check:
        - ``links._strip_code_spans`` offset list and the lstrip adjustment
    """
    case = asset_case("ds101", "link_column_after_code_span")

    findings = links.detect(case.root, case.documents("README.md"))

    assert _enrichment(findings) == [
        (2, 26, "gone.md", "dangling link"),
        (2, 51, "#nope", "dangling anchor"),
    ]
    assert [finding.message for finding in findings] == [
        "dangling link -> gone.md",
        "missing anchor '#nope' in this file",
    ]


def test_ds101_missing_anchor_in_other_file_value_is_full_target(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] finding enrichment ds101: verifies a cross-file missing anchor echoes the full target as value.

    Scenario:
        Given ``[x](other.md#nope)`` where ``other.md`` lacks the heading
        When DS101 runs
        Then the finding is a ``dangling anchor`` whose value is ``other.md#nope``.

    Boundaries:
        - Focus: value/type for the cross-file anchor branch
        - Fixtures/params: asset ds101/missing_anchor_other_file
        - Scope: detector output only

    On failure, first check:
        - The ``value=target`` argument in the cross-file anchor branch
    """
    case = asset_case("ds101", "missing_anchor_other_file")

    findings = links.detect(case.root, case.documents("README.md"))

    assert [(finding.value, finding.type) for finding in findings] == [("other.md#nope", "dangling anchor")]
    assert findings[0].column == 5


def test_ds102_stray_comment_column_and_type(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] finding enrichment ds102: verifies stray comments report their opening column and type.

    Scenario:
        Given a comment at the start of a line and one in the middle of a line
        When DS102 runs on each
        Then the columns are 1 and 11, the type is ``stray html comment`` and no snippet is copied to value.

    Boundaries:
        - Focus: DS102 column/type enrichment; value stays None (the message is a snippet)
        - Fixtures/params: assets ds102/stray_comment_file and ds102/comment_mid_line_column
        - Scope: detector output only

    On failure, first check:
        - The column arithmetic in ``comments.detect``
    """
    start_case = asset_case("ds102", "stray_comment_file")
    mid_case = asset_case("ds102", "comment_mid_line_column")

    at_start = comments.detect(start_case.root, start_case.documents("comment.md"))
    mid_line = comments.detect(mid_case.root, mid_case.documents("README.md"))

    assert _enrichment(at_start) == [(1, 1, None, "stray html comment")]
    assert _enrichment(mid_line) == [(3, 11, None, "stray html comment")]


def test_ds103_unresolvable_path_value_column_and_type(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] finding enrichment ds103: verifies an unresolvable path reports the span text, column and type.

    Scenario:
        Given path-like code spans at column 6 of line 1 and column 14 of line 3
        When DS103 runs on each
        Then value is the span text, the column points inside the backticks and the type is ``unresolvable path``.

    Boundaries:
        - Focus: DS103 enrichment, including a non-path span earlier on the same line
        - Fixtures/params: assets ds103/unresolvable_path_file and ds103/path_column_mid_line
        - Scope: detector output only

    On failure, first check:
        - The column arithmetic in ``paths.detect``
    """
    first = asset_case("ds103", "unresolvable_path_file")
    mid = asset_case("ds103", "path_column_mid_line")

    at_start = paths.detect(first.root, first.documents("path.md"))
    mid_line = paths.detect(mid.root, mid.documents("README.md"))

    assert _enrichment(at_start) == [(1, 6, "nonexistent/path.py", "unresolvable path")]
    assert _enrichment(mid_line) == [(3, 14, "missing/tool.sh", "unresolvable path")]


def test_scan_enrichment_reaches_report_model_but_not_v1_json(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] finding enrichment ds101 ds102 ds103: verifies enriched fields reach the report model only.

    Scenario:
        Given a composed fast-profile tree triggering DS101, DS102 and DS103 once each
        When it is scanned, rendered as schema-1 JSON and built into a ReportModel
        Then the JSON findings carry exactly the five v1 keys while the model problems carry the enrichment.

    Boundaries:
        - Focus: end-to-end flow from detectors through ``scan`` to both report surfaces
        - Fixtures/params: assets ds101/dangling_link_file, ds102/stray_comment_file, ds103/unresolvable_path_file
        - Scope: fast profile scan of a temporary tree

    On failure, first check:
        - ``reporting._schema_v1_dict`` exclusions and ``ReportModel`` problem fields
    """
    root = asset_case("ds101", "dangling_link_file").root
    asset_case("ds102", "stray_comment_file")
    asset_case("ds103", "unresolvable_path_file")
    config = Config(select=("DS101", "DS102", "DS103"))

    result = scan(root, config=config)
    legacy = json.loads(render(result, "json"))
    context = ReportModel.build(result, config)

    assert {key for finding in legacy["findings"] for key in finding} == {"rule", "path", "message", "severity", "line"}
    assert "rules_evaluated" not in legacy
    assert "opt_in_off" not in legacy
    assert [(p["rule"], p["column"], p["value"], p["type"]) for p in context["findings"]] == [
        ("DS101", 11, "missing.md", "dangling link"),
        ("DS102", 1, None, "stray html comment"),
        ("DS103", 6, "nonexistent/path.py", "unresolvable path"),
    ]
    assert context["rules_evaluated"] == 3
    assert context["notice"] == result.notice == "3 fast rule(s) evaluated."


def test_scan_records_structured_opt_in_diagnostics(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] finding enrichment ds101: verifies scan stores the diagnostics the notice is built from.

    Scenario:
        Given a fast-profile tree scanned with DS101 plus two opt-in rules whose policies are off
        When the scan runs
        Then ``rules_evaluated`` is 1, ``opt_in_off`` names both rules with their options, and the legacy
            notice is the string built from those two fields.

    Boundaries:
        - Focus: ``engine.scan`` populating ``rules_evaluated``/``opt_in_off``
        - Fixtures/params: asset ds101/dangling_link_file
        - Scope: fast profile scan of a temporary tree

    On failure, first check:
        - The ``opt_in_off`` comprehension in ``engine.scan``
    """
    root = asset_case("ds101", "dangling_link_file").root

    result = scan(root, config=Config(select=("DS101", "DS110", "DS112")))

    assert result.rules_evaluated == 1
    assert result.opt_in_off == (("DS110", "require_fence_languages"), ("DS112", "navigation_indexes"))
    assert result.notice == evaluated_notice("fast", result.rules_evaluated, result.opt_in_off)
    assert result.notice == (
        "1 fast rule(s) evaluated; opt-in rule(s) not enabled: "
        "DS110 (set require_fence_languages), DS112 (set navigation_indexes)."
    )


def test_scan_without_active_rules_keeps_zero_diagnostics(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] finding enrichment ds101: verifies an all-excluded scan leaves the diagnostics at their defaults.

    Scenario:
        Given a fast-profile tree whose every rule is ignored
        When the scan runs
        Then ``rules_evaluated`` is 0, ``opt_in_off`` is empty and the legacy exclusion notice is unchanged.

    Boundaries:
        - Focus: the no-active-rules branch of ``engine.scan``
        - Fixtures/params: asset ds101/dangling_link_file
        - Scope: fast profile scan of a temporary tree

    On failure, first check:
        - Initialisation of the diagnostics before the ``active_codes`` branch
    """
    root = asset_case("ds101", "dangling_link_file").root

    result = scan(root, config=Config(ignore=("DS",)))

    assert (result.rules_evaluated, result.opt_in_off) == (0, ())
    assert result.notice == "All fast rules were excluded by select/ignore."
