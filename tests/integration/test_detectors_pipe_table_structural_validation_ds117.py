"""Integration tests for DS117 over committed Markdown assets in ``tests/assets/ds117``.

This is Story 08.0 Task 03. Every one of the 15 committed scenarios is loaded in
isolation through the ``asset_case`` fixture and asserted against an explicit,
checked-in expectation table (never against whatever the analyzer currently
emits). Coverage spans the pure ``detect`` entry point, the shared ``scan``
engine, ``select``/``ignore`` (exact and prefix), baseline suppression, the
text/json/github reports, the CLI exit-code mapping for a warning rule,
cross-rule isolation from the rest of the fast profile, config propagation
through both ``docsentinel.toml`` and ``[tool.doc_sentinel]`` for the three
DS117 options (``table_enable``, ``table_strict_cells``, ``table_dialect``), the
output-injection safety of its messages, and the linear-time requirement on
adversarial single-line and multi-line pipe floods.

Cross-rule ownership is proven explicitly rather than hidden. On the committed
default fixtures no sibling fast rule fires, so :data:`EXPECTED_SIBLINGS` is
empty and asserted to stay empty under a full fast scan; the two interesting
splits are asserted directly instead. A table is section content, so a
table-only section never triggers DS106; and an invalid-looking table inside a
code fence is DS109/DS110 territory, so DS117 stays silent there.

Two deliberate boundary facts are pinned. The committed ``invalid_alignment_marker``
fixture uses ``-:-`` (a misplaced colon) rather than the ``:--:`` the fixture
matrix text names, because ``:--:`` is in fact valid GFM centre alignment inside
this supported subset; this recorded deviation is pinned by a table of
delimiter-cell variants. And a pipe inside an inline code span does **not** split
a cell in DS117, unlike GitHub's own table parser -- a documented limitation in
``docs/dev/markdown_dialect.md`` pinned by an explanatory test below.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from docsentinel import baseline, cli, models
from docsentinel.config import Config, ConfigError
from docsentinel.detectors import tables
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.timing_helpers import assert_scales_linearly

#: Scenarios whose committed Markdown has no DS117 table problem under the shipped
#: ``Config()`` defaults (dialect ``gfm-subset``, strict cells on, rule enabled).
#: Each must leave the rule registered and executed yet report zero findings of
#: its own.
CLEAN_CASES: tuple[str, ...] = (
    "aligned_three_column_table",
    "code_span_contains_pipe",
    "empty_cell_is_valid",
    "escaped_pipe_cell_text",
    "html_table_not_parsed",
    "optional_outer_pipes",
    "pipes_in_regular_paragraph",
    "table_inside_code_fence",
    "valid_two_column_table",
)

#: Scenarios that each yield one or more DS117 ``warning`` findings, mapped to the
#: exact one-based source line(s) of the offending row(s) and a message-evidence
#: substring. These values are fixed by the committed fixture bytes and the Task 02
#: spec, not derived from the analyzer. ``multiple_broken_tables`` deliberately
#: yields exactly two findings (one per broken table) in ascending source order.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[int, ...], str]] = {
    "extra_body_cell": ((5,), "table body row has 3 cells; the header declares 2"),
    "missing_delimiter_cell": ((4,), "table delimiter row has 2 cells; the header declares 3"),
    "invalid_alignment_marker": ((4,), "malformed alignment marker"),
    "missing_body_cell": ((5,), "table body row has 1 cell; the header declares 2"),
    "multiple_broken_tables": ((5, 9), "the header declares 2"),
    "crlf_table_line_positions": ((5,), "table body row has 3 cells; the header declares 2"),
}

#: All 15 promised scenarios in a stable order for parametrization.
ALL_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: The full fast-profile rule set, in registry order, run alongside DS117.
FAST_RULE_ORDER: tuple[str, ...] = (
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

#: The legitimate non-DS117 findings a full fast scan adds on these fixtures. On
#: the committed default fixtures no sibling fast rule fires at all: the valid
#: tables are ordinary section content (so DS106 is silent), the fenced fixture's
#: fence is well formed and carries a ``text`` info string (so DS109/DS110 are
#: silent), and the HTML-table fixture is plain prose. The empty mapping is
#: asserted explicitly under a full scan so a future sibling regression cannot
#: hide behind DS117's own findings. It is empty *today*: if a newly registered
#: fast rule (a future DS11x/DS12x) legitimately fires on one of these fixtures,
#: add that ``(rule, line)`` pair here rather than loosening the assertion.
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {}

#: Delimiter-cell markers DS117 accepts as a valid alignment marker within its
#: supported GFM subset (optional leading/trailing colon around a dash run).
#: ``:--:`` is included because centre alignment is valid GFM, documenting why the
#: committed ``invalid_alignment_marker`` fixture had to use ``-:-`` instead.
CLEAN_MARKERS: tuple[str, ...] = (":--:", ":-:", "--:", ":--", "---", ":-", "-:")

#: Delimiter-cell markers DS117 rejects as malformed (a colon that is not a single
#: leading or trailing colon around one dash run).
MALFORMED_MARKERS: tuple[str, ...] = ("-:-", "--::", "::-")


def _ds117(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS117 findings from a mixed finding tuple, preserving order."""
    return tuple(finding for finding in findings if finding.rule == "DS117")


def _fast_codes() -> tuple[str, ...]:
    """Return the live fast-profile rule codes in registry order.

    Prefix-selection expectations are computed from this live set rather than a
    hard-coded tuple so the assertions stay correct if a future DS11x/DS12x fast
    rule is registered.
    """
    return tuple(rule.code for rule in rules_for_profile("fast"))


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors pipe table structural validation ds117: verifies the local catalog totals.

    Scenario:
        Given the committed ds117 asset directories and this suite's expectation table
        When clean and finding scenarios are counted
        Then there are exactly 9 clean, 6 finding and 15 total scenarios, matching Task 02.

    Boundaries:
        - Focus: this file's expectation table is complete and non-overlapping
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in both CLEAN_CASES and FINDING_EXPECTATIONS
    """
    assert len(CLEAN_CASES) == 9
    assert len(FINDING_EXPECTATIONS) == 6
    assert len(set(ALL_CASES)) == 15
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)


def test_ds117_is_registered_as_an_exact_fast_rule():
    """
    [Integration] detectors pipe table structural validation ds117: verifies fast-profile registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS117 is present with its warning severity and title.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.tables registered DS117 on import
        - Whether DS117 drifted to another profile or severity
    """
    fast_codes = {rule.code for rule in rules_for_profile("fast")}
    assert "DS117" in fast_codes
    rule = next(rule for rule in rules_for_profile("fast") if rule.code == "DS117")
    assert rule.severity == "warning"
    assert rule.title == "Malformed GFM pipe-table structure"


@pytest.mark.parametrize("case", ALL_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies detect per committed case.

    Scenario:
        Given one committed ds117 scenario materialized into a fresh tmp_path
        When tables.detect runs over its README.md with shipped defaults
        Then clean cases yield no finding and finding cases yield exactly the expected DS117
        warnings at the expected one-based row line(s) carrying the expected message evidence,
        in stable ascending source order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes, one case per run
        - Fixtures/params: parametrized over all 15 scenarios; asset_case

    On failure, first check:
        - The expected line(s)/message in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte)
    """
    loaded = asset_case("ds117", case)
    findings = tables.detect(loaded.root, loaded.documents("README.md"))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    expected_lines, evidence = FINDING_EXPECTATIONS[case]
    assert len(findings) == len(expected_lines)
    assert tuple(finding.line for finding in findings) == expected_lines
    for finding in findings:
        assert finding.rule == "DS117"
        assert finding.severity == "warning"
        assert finding.path == "README.md"
        assert evidence in finding.message


@pytest.mark.parametrize("case", ALL_CASES)
def test_scan_isolates_ds117_from_other_fast_rules(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies full fast-scan isolation.

    Scenario:
        Given one committed ds117 scenario scanned under the full fast profile
        When the engine runs the whole fast rule set together
        Then no sibling fast rule fires on any committed fixture (EXPECTED_SIBLINGS is empty and
        asserted so), DS117 ran (clean cases prove execution via enabled_rules with zero own
        findings) and finding cases emit exactly the expected DS117 warnings.

    Boundaries:
        - Focus: cross-rule ownership - a malformed table is DS117's alone, with no cascade or noise
        - Fixtures/params: parametrized over all 15 scenarios; asset_case

    On failure, first check:
        - Whether another fast rule regressed and now fires on table content/fenced tables
        - Whether a new sibling finding appeared beyond the documented EXPECTED_SIBLINGS set
        - Whether DS117 dropped out of enabled_rules (a clean result must mean it ran)
    """
    result = scan(loaded_root := asset_case("ds117", case).root, config=Config(profile="fast"))

    assert result.enabled_rules == FAST_RULE_ORDER
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS117")
    assert siblings == EXPECTED_SIBLINGS.get(case, ()), result.findings
    own = _ds117(result.findings)

    if case in CLEAN_CASES:
        assert own == ()
    else:
        expected_lines, evidence = FINDING_EXPECTATIONS[case]
        assert tuple(finding.line for finding in own) == expected_lines
        assert all(evidence in finding.message for finding in own)
    assert loaded_root.is_dir()


@pytest.mark.parametrize("marker", CLEAN_MARKERS)
def test_supported_delimiter_markers_are_clean(marker: str):
    """
    [Integration] detectors pipe table structural validation ds117: verifies the accepted marker subset.

    Scenario:
        Given a one-column table whose delimiter cell is each supported alignment marker
        When check_text evaluates it
        Then no finding is produced - optional single leading and/or trailing colons around a dash
        run (including centre alignment ':--:') are valid GFM in this supported subset.

    Boundaries:
        - Focus: pins the supported marker subset so the recorded ':--:'-vs-'-:-' fixture deviation
          is an explicit, documented ruling rather than an accident
        - Fixtures/params: parametrized over every clean marker

    On failure, first check:
        - The _VALID_MARKER_RE pattern in tables.py
        - Whether a colon placement regressed from accepted to rejected
    """
    text = f"| h |\n| {marker} |\n| v |\n"
    assert tables.check_text(text, "README.md") == ()


@pytest.mark.parametrize("marker", MALFORMED_MARKERS)
def test_malformed_delimiter_markers_are_flagged(marker: str):
    """
    [Integration] detectors pipe table structural validation ds117: verifies the rejected marker subset.

    Scenario:
        Given a one-column table whose delimiter cell is each malformed alignment marker
        When check_text evaluates it
        Then exactly one DS117 finding fires on the delimiter row (line 2) naming a malformed marker -
        a colon that is neither a lone leading nor trailing colon around one dash run.

    Boundaries:
        - Focus: pins the rejected marker subset alongside the accepted one
        - Fixtures/params: parametrized over every malformed marker

    On failure, first check:
        - The _VALID_MARKER_RE pattern and _has_malformed_marker in tables.py
        - Whether the finding moved off the delimiter row's line 2
    """
    text = f"| h |\n| {marker} |\n| v |\n"
    findings = tables.check_text(text, "README.md")
    assert len(findings) == 1
    assert findings[0].line == 2
    assert "malformed alignment marker" in findings[0].message


def test_ds106_and_ds117_interplay_table_is_content(tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: verifies a table counts as section content.

    Scenario:
        Given a leaf section whose only body is a well-formed pipe table
        When the full fast profile scans it
        Then DS106 reports nothing (the table is visible content) and DS117 reports nothing (the table
        is well formed), proving the two rules do not cascade on a table-only section.

    Boundaries:
        - Focus: the documented DS106 (section content) vs DS117 (table structure) interplay
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether DS106 began treating a table body as empty content
        - Whether DS117 fired on a consistent table
    """
    (tmp_path / "README.md").write_text("# Title\n\n## Data\n\n| A | B |\n| --- | --- |\n| 1 | 2 |\n", encoding="utf-8")

    result = scan(tmp_path, config=Config(profile="fast"))

    assert [finding.rule for finding in result.findings if finding.rule in ("DS106", "DS117")] == []


def test_ds109_and_ds117_split_table_inside_fence(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies DS117 ignores fenced tables.

    Scenario:
        Given the table_inside_code_fence fixture whose invalid-looking table sits inside a labelled
        ```text fence
        When the full fast profile scans it
        Then DS117 reports nothing - a table-looking block inside a code fence is DS109/DS110 territory,
        not a real table - and because the fence is well formed with an info string, DS109/DS110 are
        silent too, so the scan is entirely clean.

    Boundaries:
        - Focus: the DS109/DS110 fence mask keeps DS117 from inventing fake fenced-table findings
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether _fenced_lines still masks the fence span for DS117
        - Whether DS109/DS110 regressed on a well-formed labelled fence
    """
    case = asset_case("ds117", "table_inside_code_fence")

    result = scan(case.root, config=Config(profile="fast"))

    assert _ds117(result.findings) == ()
    assert result.findings == ()


def test_pipe_in_code_span_does_not_split_cell_unlike_github(tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: pins the code-span pipe limitation.

    Scenario:
        Given a two-column table whose first body cell is an inline code span containing a pipe
        (``| `a | b` | note |``)
        When detect runs over it
        Then DS117 reports nothing, because it protects pipes inside code spans and so counts two
        cells in that body row, matching the header.

    Boundaries:
        - Focus: a documented divergence from GitHub. GitHub's own table parser splits a table row on
          pipes *before* inline parsing, so GitHub would see three cells here and treat the code span
          as broken; DS117 deliberately does not reproduce that quirk (see docs/dev/markdown_dialect.md).
        - Fixtures/params: tmp_path

    On failure, first check:
        - The code-span protection in tables._split_logical_cells via the shared backtick-run index
        - Whether the limitation note in docs/dev/markdown_dialect.md still matches this behaviour
    """
    (tmp_path / "README.md").write_text(
        "# Spans\n\n| Syntax | Meaning |\n| --- | --- |\n| `a | b` | note |\n", encoding="utf-8"
    )

    assert tables.detect(tmp_path, (models.Document("README.md", 1),)) == ()


def test_finding_points_at_offending_body_row_not_the_first(tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: verifies the offending row is reported.

    Scenario:
        Given a table with one valid body row followed by one broken body row
        When detect runs over it
        Then the single finding points at the broken row (line 4), not at the first body row (line 3),
        proving the detector reports the offending row rather than the start of the table body.

    Boundaries:
        - Focus: one-based line fidelity for a mismatch that is not the first body row
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether _row_finding is called per body row with that row's own line
        - Whether the loop collapsed onto the first body row's line
    """
    (tmp_path / "README.md").write_text("| A | B |\n| --- | --- |\n| 1 | 2 |\n| 3 | 4 | 5 |\n", encoding="utf-8")

    findings = tables.detect(tmp_path, (models.Document("README.md", 1),))

    assert [finding.line for finding in findings] == [4]
    assert "table body row has 3 cells; the header declares 2" in findings[0].message


#: Table-shaped markup that opens a block construct DS117 does not parse. The header
#: line is a bullet/ordered list item, a block quote, or a four-space-indented code
#: block, so per the spec the block is a non-table and yields no finding rather than
#: a guessed one. Each body deliberately carries a cell-count mismatch that *would*
#: fire if the line were parsed as a table row, so a zero result proves the
#: non-table ruling rather than an accidentally consistent table.
_NON_TABLE_BLOCKS: dict[str, str] = {
    "bullet_list_item": "# T\n\n- | A | B |\n  | --- | --- |\n  | 1 | 2 | 3 |\n",
    "star_list_item": "# T\n\n* | A | B |\n  | --- | --- |\n  | 1 | 2 | 3 |\n",
    "ordered_list_item": "# T\n\n1. | A | B |\n   | --- | --- |\n   | 1 | 2 | 3 |\n",
    "block_quote": "# T\n\n> | A | B |\n> | --- |\n> | 1 | 2 | 3 |\n",
    "four_space_indent": "# T\n\n    | A | B |\n    | --- | --- |\n    | 1 | 2 | 3 |\n",
}


@pytest.mark.parametrize("case", sorted(_NON_TABLE_BLOCKS))
def test_block_prefixed_table_shaped_lines_are_not_tables(case: str, tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: verifies block constructs are non-tables.

    Scenario:
        Given table-shaped markup whose header line opens a list item, block quote, or four-space
        indented code block, each with a body row that mismatches its header cell count
        When detect runs over it
        Then DS117 reports nothing, because an unsupported block construct is treated as a non-table
        rather than a guessed table (spec: 'treat unsupported block constructs as non-tables').

    Boundaries:
        - Focus: the documented list/blockquote/indented non-table boundary (see docs/dev/markdown_dialect.md)
        - Fixtures/params: parametrized over each block-prefixed shape; tmp_path

    On failure, first check:
        - The _is_block_prefixed guard applied to the header/delimiter/body lines in check_text
        - Whether a list/blockquote marker leaked in as a logical cell
    """
    (tmp_path / "README.md").write_text(_NON_TABLE_BLOCKS[case], encoding="utf-8")

    assert tables.detect(tmp_path, (models.Document("README.md", 1),)) == ()


def test_shallow_indented_table_is_still_detected(tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: verifies a 0-3 space table still fires.

    Scenario:
        Given a broken table indented by three spaces (within the non-code-block indent range)
        When detect runs over it
        Then DS117 still reports the mismatched body row, proving the non-table guard rejects only
        four-space (code-block) indentation and block markers, not an ordinary shallow indent.

    Boundaries:
        - Focus: the indent threshold boundary - three spaces is still a table, four is not
        - Fixtures/params: tmp_path

    On failure, first check:
        - The ``>= 4`` indent threshold in _is_block_prefixed
    """
    (tmp_path / "README.md").write_text("# T\n\n   | A | B |\n   | --- | --- |\n   | 1 | 2 | 3 |\n", encoding="utf-8")

    findings = tables.detect(tmp_path, (models.Document("README.md", 1),))

    assert [finding.line for finding in findings] == [5]


def test_select_narrows_to_ds117_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies select activates only DS117.

    Scenario:
        Given a finding scenario scanned with select pinned to DS117
        When the engine resolves the active rule set
        Then only DS117 is enabled and its single expected finding is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS117 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds117", "extra_body_cell")

    result = scan(case.root, config=Config(profile="fast", select=("DS117",)))

    assert result.enabled_rules == ("DS117",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS117", 5)]


def test_prefix_select_includes_ds117(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies DS11/DS1 prefixes select DS117.

    Scenario:
        Given a finding scenario scanned with a prefix selector
        When it is scanned with the genuine prefix ``DS11`` and then the whole-set prefix ``DS1``
        Then ``DS11`` matches exactly the fast DS11x rules (DS110, DS112, DS113, DS114, DS115, DS116
        and DS117 today) and ``DS1`` matches the entire fast set, DS117 staying active and reporting
        its finding in both.

    Boundaries:
        - Focus: prefix selector matching for DS117, robust to future DS11x/DS12x registrations by
          computing the expected set from the live fast registry rather than hard-coding codes
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast codes
        - Whether DS117 was excluded despite a matching prefix
    """
    case = asset_case("ds117", "extra_body_cell")
    fast_codes = _fast_codes()

    narrow = scan(case.root, config=Config(profile="fast", select=("DS11",)))
    expected_ds11 = tuple(code for code in fast_codes if code.startswith("DS11"))
    assert narrow.enabled_rules == expected_ds11
    assert "DS117" in expected_ds11 and "DS110" in expected_ds11
    assert [finding.line for finding in _ds117(narrow.findings)] == [5]

    whole = scan(case.root, config=Config(profile="fast", select=("DS1",)))
    assert whole.enabled_rules == fast_codes
    assert [finding.line for finding in _ds117(whole.findings)] == [5]


def test_ignore_suppresses_ds117(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies ignore removes DS117.

    Scenario:
        Given a finding scenario scanned with DS117 ignored
        When the engine resolves the active rule set
        Then DS117 is absent from enabled_rules and contributes no finding.

    Boundaries:
        - Focus: ignore precedence for a fast rule, proving the detector is genuinely gated off
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules ignore precedence over the default select
        - Whether a DS117 finding survived the ignore
    """
    case = asset_case("ds117", "extra_body_cell")

    result = scan(case.root, config=Config(profile="fast", ignore=("DS117",)))

    assert "DS117" not in result.enabled_rules
    assert _ds117(result.findings) == ()


def test_prefix_ignore_semantics_for_ds117(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies DS11/DS1/DS2 prefix ignore.

    Scenario:
        Given a finding scenario scanned under the fast profile
        When it is ignored once by the prefix ``DS11``, once by ``DS1`` and once by ``DS2``
        Then ``DS11`` drops exactly the fast DS11x rules (DS110, DS112, DS113, DS114, DS115, DS116 and DS117) so DS117 goes silent while
        the other fast rules survive; ``DS1`` matches every fast rule so the whole set drops; and
        ``DS2`` matches no fast rule so DS117 stays active and still reports its finding.

    Boundaries:
        - Focus: matches_selector prefix ignore semantics, computed from the live fast registry so a
          future DS11x/DS12x registration cannot silently invalidate the assertion
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast codes
        - Whether a non-matching prefix (DS2) wrongly suppressed DS117
    """
    case = asset_case("ds117", "extra_body_cell")
    fast_codes = _fast_codes()

    narrow = scan(case.root, config=Config(profile="fast", ignore=("DS11",)))
    assert narrow.enabled_rules == tuple(code for code in fast_codes if not code.startswith("DS11"))
    assert "DS117" not in narrow.enabled_rules
    assert _ds117(narrow.findings) == ()

    whole = scan(case.root, config=Config(profile="fast", ignore=("DS1",)))
    assert whole.enabled_rules == ()
    assert _ds117(whole.findings) == ()

    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",)))
    assert unaffected.enabled_rules == fast_codes
    assert [finding.line for finding in _ds117(unaffected.findings)] == [5]


def test_baseline_suppresses_known_ds117_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies baseline suppression round-trips.

    Scenario:
        Given a finding scenario whose two DS117 findings are recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then both previously known DS117 findings are filtered out while the first scan still reports them.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS117 findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS117 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds117", "multiple_broken_tables")
    first = scan(case.root, config=Config(profile="fast", select=("DS117",)))
    assert len(_ds117(first.findings)) == 2

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS117",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds117(suppressed.findings) == ()


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies text/json/github report stability.

    Scenario:
        Given a DS117 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS117 warning deterministically (schema v1 json,
        a ::warning annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS117 warning across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path and line
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds117", "extra_body_cell")
    result = scan(case.root, config=Config(profile="fast", select=("DS117",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "warning: README.md: table body row has 3 cells; the header declares 2" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS117"]
    assert payload["findings"][0]["rule"] == "DS117"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] == 5

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=README.md,line=5,title=DS117::")


def test_cli_fast_json_scan_reports_ds117_warning_and_exit_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors pipe table structural validation ds117: verifies the CLI fast json warning path.

    Scenario:
        Given a finding scenario scanned via the CLI with --profile fast --format json
        When the command runs without --strict
        Then it prints a JSON report containing the DS117 warning at line 5 and exits 0,
        because a bare warning is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the JSON report still includes the DS117 finding
    """
    case = asset_case("ds117", "missing_body_cell")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds117 = [finding for finding in payload["findings"] if finding["rule"] == "DS117"]
    assert len(ds117) == 1
    finding = ds117[0]
    assert finding["path"] == "README.md"
    assert finding["severity"] == "warning"
    assert finding["line"] == 5
    assert "the header declares 2" in finding["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds117_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors pipe table structural validation ds117: verifies --strict promotes the warning.

    Scenario:
        Given a finding scenario scanned via the CLI under the fast profile with --strict
        When the command runs
        Then the DS117 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The _exit_code strict branch for non-deep profiles
        - Whether DS117 still produces a finding under the strict run
    """
    case = asset_case("ds117", "multiple_broken_tables")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors pipe table structural validation ds117: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario with no finding from any fast rule scanned via the CLI
        When the command runs under the fast profile
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: non-blocking exit code when DS117 and its siblings find nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS117 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds117", "valid_two_column_table")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds117_under_fast(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies `docsentinel rules` lists DS117.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS117 and its title appear under the fast profile.

    Boundaries:
        - Focus: rules-command surfacing of DS117
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS117
        - The rules-command formatting for fast rules
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS117: Malformed GFM pipe-table structure" in captured.out


def test_standalone_toml_table_enable_false_silences_ds117(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies docsentinel.toml table_enable.

    Scenario:
        Given a finding fixture with a standalone docsentinel.toml setting table_enable=false
        When scan discovers that config (no injected Config)
        Then the loaded flag reaches DS117 and it reports nothing, while the rule stays registered -
        proving a disabled policy does not masquerade as an evaluated clean result.

    Boundaries:
        - Focus: config discovery and propagation of table_enable via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads table_enable from docsentinel.toml
        - Whether table_enable false short-circuits check_text before scanning
    """
    case = asset_case("ds117", "extra_body_cell")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\ntable_enable = false\n', encoding="utf-8")

    result = scan(case.root)

    assert "DS117" in result.enabled_rules
    assert _ds117(result.findings) == ()


def test_pyproject_table_table_enable_false_silences_ds117(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies [tool.doc_sentinel] table_enable.

    Scenario:
        Given a finding fixture with a pyproject.toml [tool.doc_sentinel] table setting table_enable=false
        When scan discovers that config
        Then the flag reaches DS117 and it reports nothing, proving the table-sourced value gates the rule.

    Boundaries:
        - Focus: config discovery and propagation of table_enable via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] table_enable
        - Whether the engine forwards the discovered Config to DS117
    """
    case = asset_case("ds117", "multiple_broken_tables")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\ntable_enable = false\n', encoding="utf-8"
    )

    assert _ds117(scan(case.root).findings) == ()


def test_table_strict_cells_false_relaxes_cell_counts_but_keeps_markers(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies the non-strict cell policy.

    Scenario:
        Given the extra_body_cell, missing_body_cell and invalid_alignment_marker fixtures scanned with
        table_strict_cells=false
        When DS117 runs
        Then both the extra-cell and the missing-cell count mismatches are silenced (non-strict relaxes
        every cell-count finding, for long rows as well as short ones), while the malformed alignment
        marker still fires because a bad marker is structural regardless of the strict policy.

    Boundaries:
        - Focus: exactly which findings survive under non-strict - cell counts relax, markers do not
        - Fixtures/params: asset_case

    On failure, first check:
        - The strict gate on the cell-count branch of _row_finding
        - That _has_malformed_marker stays outside the strict gate
    """
    relaxed = Config(profile="fast", select=("DS117",), table_strict_cells=False)

    extra = scan(asset_case("ds117", "extra_body_cell").root, config=relaxed)
    assert _ds117(extra.findings) == ()

    missing = scan(asset_case("ds117", "missing_body_cell").root, config=relaxed)
    assert _ds117(missing.findings) == ()

    marker = scan(asset_case("ds117", "invalid_alignment_marker").root, config=relaxed)
    assert [finding.line for finding in _ds117(marker.findings)] == [4]
    assert "malformed alignment marker" in marker.findings[0].message


def test_standalone_toml_table_strict_cells_false_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies docsentinel.toml table_strict_cells.

    Scenario:
        Given the missing_body_cell fixture with a standalone docsentinel.toml setting
        table_strict_cells=false
        When scan discovers that config
        Then the relaxed policy reaches DS117 and the short body row is no longer flagged.

    Boundaries:
        - Focus: config discovery and propagation of table_strict_cells via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads table_strict_cells from docsentinel.toml
        - Whether the value reaches the strict gate in check_text
    """
    case = asset_case("ds117", "missing_body_cell")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\ntable_strict_cells = false\n', encoding="utf-8")

    assert _ds117(scan(case.root).findings) == ()


def test_pyproject_table_table_strict_cells_false_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies [tool.doc_sentinel] table_strict_cells.

    Scenario:
        Given the missing_body_cell fixture with a pyproject.toml [tool.doc_sentinel] table setting
        table_strict_cells=false
        When scan discovers that config
        Then the relaxed policy reaches DS117 and the short body row is no longer flagged.

    Boundaries:
        - Focus: config discovery and propagation of table_strict_cells via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] table_strict_cells
        - Whether the value reaches the strict gate in check_text
    """
    case = asset_case("ds117", "missing_body_cell")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\ntable_strict_cells = false\n', encoding="utf-8"
    )

    assert _ds117(scan(case.root).findings) == ()


def test_pyproject_table_supported_table_dialect_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies [tool.doc_sentinel] table_dialect.

    Scenario:
        Given a finding fixture with a pyproject.toml [tool.doc_sentinel] table naming the supported
        table_dialect 'gfm-subset'
        When scan discovers that config
        Then the dialect reaches DS117 and it still reports its finding, proving the table-sourced
        dialect value is read and forwarded (the loader's allowlist rejection is exercised separately).

    Boundaries:
        - Focus: config discovery and propagation of table_dialect via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] table_dialect
        - Whether the engine forwards the discovered Config to DS117
    """
    case = asset_case("ds117", "extra_body_cell")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\ntable_dialect = "gfm-subset"\n', encoding="utf-8"
    )

    assert [finding.line for finding in _ds117(scan(case.root).findings)] == [5]


def test_pyproject_table_unsupported_table_dialect_rejected_at_load_time(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies [tool.doc_sentinel] dialect rejection.

    Scenario:
        Given a pyproject.toml [tool.doc_sentinel] table naming a table_dialect outside the supported
        vocabulary
        When scan loads that config
        Then a ConfigError naming table_dialect is raised, proving the enum allowlist guards the
        [tool.doc_sentinel] path too.

    Boundaries:
        - Focus: the config allowlist rejects an unsupported table_dialect via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - The _ENUM_OPTIONS vocabulary for table_dialect in config.py
        - Whether [tool.doc_sentinel] values bypass the allowlist
    """
    case = asset_case("ds117", "extra_body_cell")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\ntable_dialect = "commonmark"\n', encoding="utf-8"
    )

    with pytest.raises(ConfigError, match="table_dialect"):
        scan(case.root)


def test_unsupported_table_dialect_rejected_at_load_time(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies an unsupported dialect is rejected.

    Scenario:
        Given a docsentinel.toml naming a table_dialect outside the supported vocabulary
        When scan loads that config
        Then a ConfigError naming table_dialect is raised rather than silently falling back, because the
        loader allowlist fixes the single supported 'gfm-subset' value.

    Boundaries:
        - Focus: the config allowlist rejects an unsupported table_dialect at load time (standalone file)
        - Fixtures/params: asset_case

    On failure, first check:
        - The _ENUM_OPTIONS vocabulary for table_dialect in config.py
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds117", "extra_body_cell")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\ntable_dialect = "commonmark"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="table_dialect"):
        scan(case.root)


def test_unsupported_table_dialect_is_silent_in_detector(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies an unsupported dialect gates the rule.

    Scenario:
        Given a finding fixture and an injected Config naming a table_dialect DS117 cannot validate
        When detect runs with that config (bypassing the loader's allowlist)
        Then DS117 emits no confident diagnostics, proving the dialect setting is load-bearing inside the
        rule and an inapplicable dialect never masquerades as an evaluated clean result.

    Boundaries:
        - Focus: the dialect guard inside the detector, distinct from the loader's allowlist
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether check_text short-circuits for a dialect other than the supported one
        - Whether an injected Config field reaches detect
    """
    case = asset_case("ds117", "extra_body_cell")

    findings = tables.detect(case.root, case.documents("README.md"), config=Config(table_dialect="commonmark"))

    assert findings == ()


@pytest.mark.parametrize("option", ["table_enable", "table_strict_cells"])
def test_invalid_non_bool_table_option_raises_config_error(option: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies non-bool options are rejected.

    Scenario:
        Given a docsentinel.toml that sets a boolean DS117 option to a non-boolean value
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects non-boolean table_enable/table_strict_cells (standalone file)
        - Fixtures/params: parametrized over both boolean options; asset_case

    On failure, first check:
        - The _require_bool validation for the named option
        - Whether a non-boolean value was coerced instead of raising
    """
    case = asset_case("ds117", "extra_body_cell")
    (case.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = "yes"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(case.root)


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies repeated scans are stable.

    Scenario:
        Given a two-finding scenario scanned twice over the same materialized root
        When the two DS117 finding tuples are compared
        Then they are equal and report lines 5 and 9, so the detector holds no order-dependent state.

    Boundaries:
        - Focus: determinism of DS117 over a real asset tree, with asserted line counts
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Ordering stability of the physical-line scan
    """
    case = asset_case("ds117", "multiple_broken_tables")

    first = scan(case.root, config=Config(profile="fast", select=("DS117",)))
    second = scan(case.root, config=Config(profile="fast", select=("DS117",)))

    assert first.findings == second.findings
    assert [finding.line for finding in _ds117(first.findings)] == [5, 9]


def test_crlf_line_numbers_point_at_the_offending_row(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors pipe table structural validation ds117: verifies CRLF line fidelity.

    Scenario:
        Given the crlf_table_line_positions fixture whose CRLF-terminated broken body row sits on line 5
        When detect runs over it
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input for the offending table row
        - Fixtures/params: asset_case

    On failure, first check:
        - CRLF handling in split_physical_lines
        - That the reported line is the broken body row, not the header
    """
    case = asset_case("ds117", "crlf_table_line_positions")

    findings = tables.detect(case.root, case.documents("README.md"))

    assert len(findings) == 1
    assert findings[0].line == 5
    assert "table body row has 3 cells; the header declares 2" in findings[0].message


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes inside a broken table
        When a fast scan reads it
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in tables._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"| A | B |\n| --- | --- |\n| \xff\xfe | x | y |\n")

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS117",)))


def test_symlinked_markdown_file_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: verifies a symlinked target file is skipped.

    Scenario:
        Given a symlink pointing at a Markdown file with a broken table
        When that symlink is scanned directly
        Then the engine refuses to inventory the symlinked file rather than following it.

    Boundaries:
        - Focus: the engine's symlink safety for a directly selected file path
        - Fixtures/params: tmp_path

    On failure, first check:
        - The symlink guard in engine.scan for selected files
        - Whether symlinks are silently followed into the scan
    """
    target = tmp_path / "real.md"
    target.write_text("| A | B |\n| --- | --- |\n| 1 | 2 | 3 |\n", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    with pytest.raises(ValueError, match="Symlinked files are not inventoried"):
        scan(link, config=Config(profile="fast", select=("DS117",)))


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors pipe table structural validation ds117: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When detect runs over every finding scenario (whose bodies contain table markup)
        Then all expected findings are still produced, proving DS117 opens no socket, makes no
        connection and never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS117 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS117 ever constructs a socket."""
        raise AssertionError("DS117 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS117 ever opens an outbound connection."""
        raise AssertionError("DS117 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS117 ever launches a subprocess."""
        raise AssertionError("DS117 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case, (expected_lines, _evidence) in FINDING_EXPECTATIONS.items():
        loaded = asset_case("ds117", case)
        findings = tables.detect(loaded.root, loaded.documents("README.md"))
        assert tuple(finding.line for finding in findings) == expected_lines


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors pipe table structural validation ds117: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS117 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported,
        proving the fast DS117 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS117's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether tables or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.detectors import tables\n"
        "assert tables.check_text('| A | B |\\n| --- | --- |\\n| 1 | 2 | 3 |\\n', 'README.md')\n"
        "heavy = sorted(m for m in ('sklearn', 'textstat', 'docsig', 'spacy', 'textacy') if m in sys.modules)\n"
        "print(','.join(heavy))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", probe],
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.strip() == ""


def test_hostile_cell_content_cannot_inject_into_text_or_github_output(tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: verifies hostile cells cannot inject output.

    Scenario:
        Given a broken table whose body cells carry an ESC byte, a workflow-command payload, a literal
        '%0A' and an over-long cell, with the row holding one more cell than the header
        When the scan result is rendered as text and as GitHub workflow commands
        Then DS117 reports exactly one cell-count finding whose message is purely structural (a count,
        never the raw cell text), so the text output is a single line with no raw ESC and the GitHub
        output is exactly one ``::warning`` line - no second workflow command can be smuggled in.

    Boundaries:
        - Focus: output-injection safety of DS117 messages, which by design never echo arbitrary cell
          content (only bounded, repr-escaped delimiter snippets for malformed markers)
        - Fixtures/params: tmp_path

    On failure, first check:
        - That the cell-count message stays count-only and never interpolates cell text
        - reporting._escape_data percent/newline handling for the github format
    """
    hostile = "evil\x1b[31m::error file=/etc/passwd::pwned%0Amore" + "x" * 200
    (tmp_path / "README.md").write_text(f"| A | B |\n| --- | --- |\n| {hostile} | x | y |\n", encoding="utf-8")

    result = scan(tmp_path, config=Config(profile="fast", select=("DS117",)))
    own = _ds117(result.findings)
    assert len(own) == 1
    assert "the header declares 2" in own[0].message
    assert "\x1b" not in own[0].message  # the structural message never echoes the hostile cell

    text = render(result, "text")
    assert "\x1b" not in text
    finding_lines = [line for line in text.splitlines() if "the header declares 2" in line]
    assert len(finding_lines) == 1

    github = render(result, "github")
    github_lines = github.splitlines()
    assert len(github_lines) == 1
    assert github_lines[0].startswith("::warning file=README.md,line=3,title=DS117::")
    assert "\x1b" not in github


def _single_line_flood(unit: str) -> Callable[[int], str]:
    """Return a builder repeating ``unit`` ``scale`` times on one physical line."""

    def build(scale: int) -> str:
        """Return ``unit`` repeated ``scale`` times on one newline-terminated line."""
        return (unit * scale) + "\n"

    return build


def _many_broken_two_row_tables(scale: int, terminator: str = "\n") -> str:
    """Return ``scale`` independent broken tables, each a header/delimiter/over-long body row."""
    parts: list[str] = []
    for _ in range(scale):
        parts += ["| A | B |", "| --- | --- |", "| 1 | 2 | 3 |", ""]
    return terminator.join(parts) + terminator


#: A representative subset of adversarial shapes mapped to a builder and the exact
#: finding-count formula. This integration suite only proves detect() routes real files
#: through to check_text with exact counts and no super-linear blow-up over the file
#: path; the full algorithmic shape coverage -- every single-line flood, wide rows, long
#: dash markers, blockquote/list non-tables and the prose and alternating shapes -- lives
#: in tests/unit/test_detectors_tables_adversarial.py and is not duplicated here. The
#: single-line flood (count 0) sits beside the broken-table shapes (count scale) so a zero
#: can never be a dead detector, and CR/CRLF are kept because terminator splitting is a
#: detect() concern.
ADVERSARIAL_SHAPES: dict[str, tuple[Callable[[int], str], Callable[[int], int]]] = {
    "single_line_pipe_flood": (_single_line_flood("|"), lambda _scale: 0),
    "many_broken_two_row_tables": (_many_broken_two_row_tables, lambda scale: scale),
    "cr_only_broken_tables": (lambda scale: _many_broken_two_row_tables(scale, "\r"), lambda scale: scale),
    "crlf_broken_tables": (lambda scale: _many_broken_two_row_tables(scale, "\r\n"), lambda scale: scale),
}


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL_SHAPES))
def test_adversarial_input_stays_bounded(shape: str, tmp_path: Path):
    """
    [Integration] detectors pipe table structural validation ds117: verifies linear-time adversarial handling.

    Scenario:
        Given large pipe-table adversarial documents of one representative shape - a single-line flood
        of '|', many broken two-row tables, and CR-only and CRLF broken-table floods
        When detect routes a doubling input series through the shared scaling helper (small sizes: the
        algorithmic shape coverage lives in tests/unit/test_detectors_tables_adversarial.py)
        Then every scale produces the exact deterministic finding count (0 for the single-line flood,
        one-per-table for the broken-table shapes, so the pass is never vacuous) and the scaling stays
        under the shared linear bound.

    Boundaries:
        - Focus: detect() routing of real files through check_text with bounded CPU time (contract F)
        - Non-goal: fence boundaries - this input is deliberately non-fenced table/pipe markup
        - Fixtures/params: parametrized over the representative adversarial shapes; tmp_path

    On failure, first check:
        - Any accidentally quadratic scan of the line list or per-table re-splitting
        - That the exact finding count for this shape still holds at every scale
        - CR-only and CRLF line splitting in split_physical_lines
    """
    build, expected_count = ADVERSARIAL_SHAPES[shape]

    def _build(scale: int) -> tuple[models.Document, ...]:
        """Write the shape's document at ``scale`` and return its Document (untimed)."""
        path = tmp_path / f"{shape}_{scale}.md"
        path.write_text(build(scale), encoding="utf-8", newline="")
        return (models.Document(path.name, path.stat().st_size),)

    assert_scales_linearly(
        _build,
        lambda documents: tables.detect(tmp_path, documents),
        (250, 500, 1_000, 2_000),
        expected_count=expected_count,
        label=f"ds117-{shape}",
    )
