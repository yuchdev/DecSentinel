"""DS101 on a line holding two links to the same missing target (Milestone 0007, Story 03.0 Task 01).

The CanonixEngine GitHub report repeated ``::error file=README.md,line=12::dangling link ->
/docs/adr/README.md`` on consecutive lines. Its ``docs/README.md`` line 12 is a table row with two links
(``[adr/]`` and ``[README.md]``) to that same target, so two findings are correct. This module pins
that shape: one finding per link, told apart by ``column``, and no report-layer deduplication.
"""

from collections.abc import Callable

from docsentinel import scan
from docsentinel.config import Config
from docsentinel.detectors import links
from docsentinel.telemetry.engine import render_template
from docsentinel.telemetry.loader import load_template
from docsentinel.telemetry.model import ReportModel
from tests.asset_helpers import AssetCase

#: The case reproducing the CanonixEngine table row.
_CASE: str = "two_links_same_target_one_line"


def test_two_links_to_one_target_yield_two_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] two links one line ds101: verifies each link is reported once, with its own column.

    Scenario:
        Given a table row with two links to ``/docs/adr/README.md`` and a third to another missing file
        When DS101 runs over the document
        Then it reports three findings on line 5, two with the repeated target at distinct columns.

    Boundaries:
        - Focus: DS101 one-finding-per-link behaviour (not a duplicate emission)
        - Fixtures/params: the ``ds101/two_links_same_target_one_line`` asset
        - Scope: the detector only

    On failure, first check:
        - Whether DS101 started deduplicating per line or emitting the same link twice
        - DS101 column computation for links after a table pipe
    """
    case = asset_case("ds101", _CASE)

    findings = links.detect(case.root, case.documents("README.md"))

    repeated = [finding for finding in findings if finding.value == "/docs/adr/README.md"]
    assert [finding.line for finding in findings] == [5, 5, 5]
    assert [finding.column for finding in repeated] == [10, 45]
    assert len({(finding.line, finding.column) for finding in findings}) == len(findings)


def test_github_template_keeps_both_annotations_distinct_by_column(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] two links one line ds101: verifies the github report keeps both annotations, told apart by col.

    Scenario:
        Given a scan of the two-links case
        When it is rendered with the packaged github template
        Then both annotations for the repeated target are present and differ only in ``col``.

    Boundaries:
        - Focus: the report layer never hides or merges findings
        - Fixtures/params: the ``ds101/two_links_same_target_one_line`` asset
        - Scope: scan plus rendering

    On failure, first check:
        - Whether ``github.json`` lost its ``col`` branch
    """
    case = asset_case("ds101", _CASE)
    result = scan(case.root, config=Config(select=("DS101",)))

    lines = render_template(load_template("github"), ReportModel.build(result, Config())).split("\n")

    assert lines[:2] == [
        "::error file=README.md,line=5,col=10,title=DS101::dangling link -> /docs/adr/README.md",
        "::error file=README.md,line=5,col=45,title=DS101::dangling link -> /docs/adr/README.md",
    ]
    assert len(lines) == 3
