"""Integration tests for DS106 over committed Markdown assets in ``tests/assets/ds106``.

This is Story 04.0 Task 03. Every one of the 14 committed scenarios is loaded in
isolation through the ``asset_case`` fixture and asserted against an explicit,
checked-in expectation table (never against whatever the analyzer currently
emits). Coverage spans the pure ``detect`` entry point, the shared ``scan``
engine, ``select``/``ignore`` (exact and prefix), baseline suppression, the
text/json/github reports, the CLI exit-code mapping for a warning rule,
cross-rule isolation from DS101-DS105/DS109, config propagation through both
``docsentinel.toml`` and ``[tool.doc_sentinel]`` for all four DS106 options, and
the linear-time requirement on adversarial (non-fenced, multi-line) input.

Cross-rule overlaps are proven explicitly rather than hidden. DS106 legitimately
coexists with other fast rules on four committed fixtures, so each such sibling
finding is modelled in :data:`EXPECTED_SIBLINGS` and asserted, never suppressed:
``comment_only_section`` carries a real multi-line HTML comment owned by DS102;
``html_tag_only_section`` names an explicit anchor that shadows its heading slug
(DS104); and the image/link in ``image_only_leaf_section`` / ``inline_link_body_text``
point at absent targets that DS101 rightly reports. On the committed default
fixtures DS105 (heading hierarchy) does not actually fire, so no DS105 sibling is
expected; the DS106/DS105 ownership split is instead asserted directly in a
dedicated test. See ``docs/dev/markdown_dialect.md`` for the supported dialect.

The marker-word tests pin a ruling on a question the written spec left open:
DS106 does NOT treat the words ``TODO``/``TBD``/``FIXME``/``WIP`` as non-content.
Under ``placeholder_content_policy = "ignore"`` only HTML comments and whitespace
are non-content, so a section containing such a word has visible content and is
not flagged; detecting the markers themselves is DS119's territory ("DS119 finds
markers; DS106 checks visible section content regardless of both").
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
from docsentinel.detectors import sections
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.timing_helpers import assert_scales_linearly

#: Scenarios whose committed Markdown has no empty leaf section under the shipped
#: ``Config()`` defaults (policy ``leaf``, placeholders ignored, images counted,
#: ``empty_section_min_text_chars = 0``). Each must leave DS106 registered and
#: executed yet report zero findings of its own.
CLEAN_CASES: tuple[str, ...] = (
    "leaf_section_with_prose",
    "parent_with_child_section",
    "image_only_leaf_section",
    "nonempty_fenced_example",
    "inline_link_body_text",
    "table_only_section",
    "horizontal_rule_then_text",
)

#: Scenarios that each yield one or more DS106 ``warning`` findings, mapped to the
#: exact one-based source line(s) of the offending heading(s) and a message-evidence
#: substring. These values are fixed by the committed fixtures and the Task 02 spec,
#: not derived from the analyzer. ``multiple_empty_leaf_sections`` deliberately
#: yields exactly two findings, one per terminal empty leaf, in ascending line order.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[int, ...], str]] = {
    "empty_terminal_heading": ((5,), "has no visible content"),
    "comment_only_section": ((5,), "has no visible content"),
    "whitespace_separator_only": ((5,), "has no visible content"),
    "blank_fence_content": ((3,), "has no visible content"),
    "nested_empty_child": ((5,), "has no visible content"),
    "html_tag_only_section": ((3,), "has no visible content"),
    "multiple_empty_leaf_sections": ((3, 5), "has no visible content"),
}

#: All 14 promised scenarios in a stable order for parametrization.
ALL_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: The full fast-profile rule set, in registry order, run alongside DS106.
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

#: The legitimate non-DS106 findings a full fast scan adds on these fixtures, each
#: owned by its rightful rule. ``comment_only_section`` holds a real HTML comment
#: (DS102, line 7). ``html_tag_only_section`` declares ``<a id="placeholder">`` that
#: collides with the generated slug of ``## Placeholder`` (DS104, line 5). The image
#: in ``image_only_leaf_section`` and the link in ``inline_link_body_text`` both point
#: at absent local targets that DS101 reports (line 5); the image is also a missing
#: local asset that DS113 reports at the same line (DS113 owns images regardless of
#: extension, while the plain Markdown link in ``inline_link_body_text`` stays DS101's
#: alone). Every other case must leave the sibling rules silent, proving an
#: empty-section problem never cascades across rules. DS105 does not fire on any
#: committed default fixture, so it is never a sibling.
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {
    "comment_only_section": (("DS102", 7),),
    "html_tag_only_section": (("DS104", 5),),
    "image_only_leaf_section": (("DS101", 5), ("DS113", 5)),
    "inline_link_body_text": (("DS101", 5),),
}


def _ds106(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS106 findings from a mixed finding tuple, preserving order."""
    return tuple(finding for finding in findings if finding.rule == "DS106")


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors contentless section detection ds106: verifies the local catalog totals.

    Scenario:
        Given the committed ds106 asset directories and this suite's expectation table
        When clean and finding scenarios are counted
        Then there are exactly 7 clean, 7 finding and 14 total scenarios, matching Task 02.

    Boundaries:
        - Focus: this file's expectation table is complete and non-overlapping
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in both CLEAN_CASES and FINDING_EXPECTATIONS
    """
    assert len(CLEAN_CASES) == 7
    assert len(FINDING_EXPECTATIONS) == 7
    assert len(set(ALL_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)


def test_ds106_is_registered_as_an_exact_fast_rule():
    """
    [Integration] detectors contentless section detection ds106: verifies fast-profile registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS106 is present with its warning severity and title.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.sections registered DS106 on import
        - Whether DS106 drifted to another profile or severity
    """
    fast_codes = {rule.code for rule in rules_for_profile("fast")}
    assert "DS106" in fast_codes
    rule = next(rule for rule in rules_for_profile("fast") if rule.code == "DS106")
    assert rule.severity == "warning"
    assert rule.title == "Empty or contentless sections"


@pytest.mark.parametrize("case", ALL_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies detect per committed case.

    Scenario:
        Given one committed ds106 scenario materialized into a fresh tmp_path
        When sections.detect runs over its README.md with shipped defaults
        Then clean cases yield no finding and finding cases yield exactly the expected DS106
        warnings at the expected one-based heading line(s) carrying the expected message evidence,
        in stable ascending source order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes, one case per run
        - Fixtures/params: parametrized over all 14 scenarios; asset_case

    On failure, first check:
        - The expected line(s)/message in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte)
    """
    loaded = asset_case("ds106", case)
    findings = sections.detect(loaded.root, loaded.documents("README.md"))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    expected_lines, evidence = FINDING_EXPECTATIONS[case]
    assert len(findings) == len(expected_lines)
    assert tuple(finding.line for finding in findings) == expected_lines
    for finding in findings:
        assert finding.rule == "DS106"
        assert finding.severity == "warning"
        assert finding.path == "README.md"
        assert evidence in finding.message


@pytest.mark.parametrize("case", ALL_CASES)
def test_scan_isolates_ds106_from_other_fast_rules(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies full fast-scan isolation.

    Scenario:
        Given one committed ds106 scenario scanned under the full fast profile
        When the engine runs DS101-DS105, DS106 and DS109 together
        Then sibling rules add only the documented expected finding(s) (DS102/DS104/DS101 own the
        real comment/anchor/link overlaps), DS106 ran (clean cases prove execution via enabled_rules
        with zero own findings) and finding cases emit exactly the expected DS106 warnings.

    Boundaries:
        - Focus: cross-rule ownership - an empty section is DS106's alone, documented overlaps aside
        - Fixtures/params: parametrized over all 14 scenarios; asset_case

    On failure, first check:
        - Whether DS101-DS105/DS109 regressed and now fire on section content
        - Whether a new sibling finding appeared beyond the documented EXPECTED_SIBLINGS overlaps
        - Whether DS106 dropped out of enabled_rules (a clean result must mean it ran)
    """
    result = scan(loaded_root := asset_case("ds106", case).root, config=Config(profile="fast"))

    assert result.enabled_rules == FAST_RULE_ORDER
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS106")
    assert siblings == EXPECTED_SIBLINGS.get(case, ()), result.findings
    own = _ds106(result.findings)

    if case in CLEAN_CASES:
        assert own == ()
    else:
        expected_lines, evidence = FINDING_EXPECTATIONS[case]
        assert tuple(finding.line for finding in own) == expected_lines
        assert all(evidence in finding.message for finding in own)
    assert loaded_root.is_dir()


def test_ds105_and_ds106_ownership_split(tmp_path: Path):
    """
    [Integration] detectors contentless section detection ds106: verifies the DS105/DS106 boundary.

    Scenario:
        Given a document whose heading both skips a level (H1 -> H3) and introduces an empty section
        When the full fast profile scans it
        Then DS105 reports only the level skip and DS106 reports only the empty section: DS106 never
        claims the hierarchy skip and DS105 never claims the missing content.

    Boundaries:
        - Focus: the documented DS105 (heading hierarchy) vs DS106 (section content) ownership split
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether DS106 began reporting heading-level skips (DS105's job)
        - Whether DS105 began reporting empty bodies (DS106's job)
    """
    (tmp_path / "README.md").write_text("# Guide\n\nIntro prose.\n\n### Orphan\n", encoding="utf-8")

    result = scan(tmp_path, config=Config(profile="fast"))

    ds105 = [(finding.line, finding.message) for finding in result.findings if finding.rule == "DS105"]
    ds106 = [(finding.line, finding.message) for finding in result.findings if finding.rule == "DS106"]
    assert len(ds105) == 1
    assert ds105[0][0] == 5
    assert "skips a level" in ds105[0][1]
    assert len(ds106) == 1
    assert ds106[0][0] == 5
    assert "has no visible content" in ds106[0][1]
    assert all("skips a level" not in message for _line, message in ds106)
    assert all("visible content" not in message for _line, message in ds105)


def test_select_narrows_to_ds106_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies select activates only DS106.

    Scenario:
        Given a finding scenario scanned with select pinned to DS106
        When the engine resolves the active rule set
        Then only DS106 is enabled and its single expected finding is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS106 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds106", "empty_terminal_heading")

    result = scan(case.root, config=Config(profile="fast", select=("DS106",)))

    assert result.enabled_rules == ("DS106",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS106", 5)]


def test_prefix_select_includes_ds106(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies the DS1 prefix selects DS106.

    Scenario:
        Given a two-finding scenario scanned with the DS1 prefix selector
        When the active rule set is resolved
        Then DS106 is among the enabled rules and still reports both findings.

    Boundaries:
        - Focus: prefix selector matching for DS106
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS1 against DS106
        - Whether DS106 was excluded despite the prefix
    """
    case = asset_case("ds106", "multiple_empty_leaf_sections")

    result = scan(case.root, config=Config(profile="fast", select=("DS1",)))

    assert "DS106" in result.enabled_rules
    assert [finding.line for finding in _ds106(result.findings)] == [3, 5]


def test_ignore_suppresses_ds106(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies ignore removes DS106.

    Scenario:
        Given a finding scenario scanned with DS106 ignored
        When the engine resolves the active rule set
        Then DS106 is absent from enabled_rules and contributes no finding.

    Boundaries:
        - Focus: ignore precedence for a fast rule, proving the detector is genuinely gated off
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules ignore precedence over the default select
        - Whether a DS106 finding survived the ignore
    """
    case = asset_case("ds106", "empty_terminal_heading")

    result = scan(case.root, config=Config(profile="fast", ignore=("DS106",)))

    assert "DS106" not in result.enabled_rules
    assert _ds106(result.findings) == ()


def test_prefix_ignore_semantics_for_ds106(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies DS10/DS2 prefix ignore semantics.

    Scenario:
        Given a two-finding scenario scanned under the fast profile
        When it is scanned once with the genuine prefix ignore ``DS10`` and once with the
            non-matching prefix ``DS2``
        Then ``DS10`` matches the DS10x fast rules (DS101-DS106 and DS109, but not DS110) - so
            effective_rules (ignore taking precedence) drops DS106 along with them - while ``DS2``
            matches no fast rule and leaves DS106 active and still reporting both expected lines.

    Boundaries:
        - Focus: matches_selector prefix semantics, distinct from the exact-code ignore test
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS10 against every fast DS10x code
        - Whether a non-matching prefix (DS2) wrongly suppressed DS106
    """
    case = asset_case("ds106", "multiple_empty_leaf_sections")

    # "DS10" is a prefix of every current fast rule code (DS101-DS106 and DS109 all
    # begin "DS10"), so today it drops the whole fast set. Assert the prefix semantics
    # directly - every DS10x rule is gone, DS106 included - rather than hard-coding
    # emptiness, so this stays correct if a future DS11x fast rule (which "DS10" would
    # not match) is registered.
    suppressed = scan(case.root, config=Config(profile="fast", ignore=("DS10",)))
    assert "DS106" not in suppressed.enabled_rules
    assert all(not code.startswith("DS10") for code in suppressed.enabled_rules)
    assert _ds106(suppressed.findings) == ()

    # "DS2" matches no fast rule, so DS106 stays active and keeps reporting.
    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",)))
    assert "DS106" in unaffected.enabled_rules
    assert [finding.line for finding in _ds106(unaffected.findings)] == [3, 5]


def test_baseline_suppresses_known_ds106_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies baseline suppression round-trips.

    Scenario:
        Given a finding scenario whose two DS106 findings are recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then both previously known DS106 findings are filtered out while the first scan still reports them.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS106 findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS106 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds106", "multiple_empty_leaf_sections")
    first = scan(case.root, config=Config(profile="fast", select=("DS106",)))
    assert len(_ds106(first.findings)) == 2

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS106",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds106(suppressed.findings) == ()


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies text/json/github report stability.

    Scenario:
        Given a DS106 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS106 warning deterministically (schema v1 json,
        a ::warning annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS106 warning across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path and line
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds106", "empty_terminal_heading")
    result = scan(case.root, config=Config(profile="fast", select=("DS106",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "warning: README.md: empty section: 'Appendix' has no visible content" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS106"]
    assert payload["findings"][0]["rule"] == "DS106"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] == 5

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=README.md,line=5,title=DS106::")


def test_cli_fast_json_scan_reports_ds106_warning_and_exit_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors contentless section detection ds106: verifies the CLI fast json warning path.

    Scenario:
        Given a finding scenario scanned via the CLI with --profile fast --format json
        When the command runs without --strict
        Then it prints a JSON report containing the DS106 warning at line 5 and exits 0,
        because a bare warning is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the JSON report still includes the DS106 finding
    """
    case = asset_case("ds106", "empty_terminal_heading")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds106 = [finding for finding in payload["findings"] if finding["rule"] == "DS106"]
    assert len(ds106) == 1
    finding = ds106[0]
    assert finding["path"] == "README.md"
    assert finding["severity"] == "warning"
    assert finding["line"] == 5
    assert "has no visible content" in finding["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds106_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors contentless section detection ds106: verifies --strict promotes the warning.

    Scenario:
        Given a finding scenario scanned via the CLI under the fast profile with --strict
        When the command runs
        Then the DS106 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The _exit_code strict branch for non-deep profiles
        - Whether DS106 still produces a finding under the strict run
    """
    case = asset_case("ds106", "multiple_empty_leaf_sections")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors contentless section detection ds106: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario with no finding from any fast rule scanned via the CLI
        When the command runs under the fast profile
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: non-blocking exit code when DS106 and its siblings find nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS106 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds106", "leaf_section_with_prose")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds106_under_fast(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors contentless section detection ds106: verifies `docsentinel rules` lists DS106.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS106 and its title appear under the fast profile.

    Boundaries:
        - Focus: rules-command surfacing of DS106
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS106
        - The rules-command formatting for fast rules
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS106: Empty or contentless sections" in captured.out


def test_empty_section_policy_all_flags_parent_that_leaf_skips(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies leaf/all/off policy semantics.

    Scenario:
        Given the parent_with_child_section fixture (empty H1/H2 parents over a content-bearing H3)
        When it is scanned under each empty_section_policy value
        Then the default 'leaf' inspects only the H3 leaf and reports nothing, 'all' additionally
        flags both empty parents (H1 'Guide' line 1 and H2 'Configuration' line 3), and 'off'
        disables the rule entirely.

    Boundaries:
        - Focus: the three-way section-membership policy; 'all' flags parents 'leaf' deliberately skips
        - Fixtures/params: asset_case

    On failure, first check:
        - _checked_indices leaf-vs-all heading selection
        - Whether 'off' short-circuits before any section is inspected
    """
    case = asset_case("ds106", "parent_with_child_section")

    leaf = scan(case.root, config=Config(profile="fast", select=("DS106",), empty_section_policy="leaf"))
    assert _ds106(leaf.findings) == ()

    everything = scan(case.root, config=Config(profile="fast", select=("DS106",), empty_section_policy="all"))
    assert [finding.line for finding in _ds106(everything.findings)] == [1, 3]

    disabled = scan(case.root, config=Config(profile="fast", select=("DS106",), empty_section_policy="off"))
    assert _ds106(disabled.findings) == ()


def test_placeholder_content_policy_count_vs_ignore(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies the placeholder content policy.

    Scenario:
        Given the comment_only_section fixture whose only body is a lone HTML comment
        When it is scanned under placeholder_content_policy 'ignore' and then 'count'
        Then 'ignore' (the default) strips the comment and reports the empty section at line 5, while
        'count' lets the comment register as content so DS106 reports nothing - the exact behaviour
        the spec promises for a section carrying only a comment/placeholder.

    Boundaries:
        - Focus: whether HTML comments/placeholders count as content is load-bearing inside the rule
        - Fixtures/params: asset_case

    On failure, first check:
        - _visible_text comment handling gated on count_placeholders
        - Whether the policy actually reaches check_text
    """
    case = asset_case("ds106", "comment_only_section")

    ignored = scan(case.root, config=Config(profile="fast", select=("DS106",), placeholder_content_policy="ignore"))
    assert [finding.line for finding in _ds106(ignored.findings)] == [5]

    counted = scan(case.root, config=Config(profile="fast", select=("DS106",), placeholder_content_policy="count"))
    assert _ds106(counted.findings) == ()


def test_image_content_counts_true_vs_false(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies the image_content_counts option.

    Scenario:
        Given the image_only_leaf_section fixture whose only body is a single image
        When it is scanned with image_content_counts true and then false
        Then the default true treats the image as meaningful content (no finding), while false strips
        the image so the section becomes contentless and DS106 reports it at line 3.

    Boundaries:
        - Focus: an image as sole section content, gated by image_content_counts
        - Fixtures/params: asset_case

    On failure, first check:
        - _build_masks image_lines population gated on image_content_counts
        - Whether the option reaches check_text
    """
    case = asset_case("ds106", "image_only_leaf_section")

    counted = scan(case.root, config=Config(profile="fast", select=("DS106",), image_content_counts=True))
    assert _ds106(counted.findings) == ()

    uncounted = scan(case.root, config=Config(profile="fast", select=("DS106",), image_content_counts=False))
    assert [finding.line for finding in _ds106(uncounted.findings)] == [3]


def test_empty_section_min_text_chars_positive_is_deferred(tmp_path: Path):
    """
    [Integration] detectors contentless section detection ds106: pins the min_text_chars behaviour.

    Scenario:
        Given a section whose only body is two visible characters ('ok')
        When it is scanned with empty_section_min_text_chars 0 (default) and then 5
        Then the default accepts the two characters as content (no finding), while a positive threshold
        treats the short body as contentless and reports it at line 3.

    Boundaries:
        - Focus: the current effect of empty_section_min_text_chars, which Task 01 marks "positive
          values deferred to DS203 quality policy" - this test documents the shipped behaviour so the
          deferral is an explicit decision, not an accident
        - Fixtures/params: tmp_path

    On failure, first check:
        - The ``text_chars <= minimum`` comparison in check_text
        - Whether the config value reaches the detector unchanged
    """
    (tmp_path / "README.md").write_text("# Title\n\n## Short\n\nok\n", encoding="utf-8")

    default = sections.detect(tmp_path, (models.Document("README.md", 1),), Config(empty_section_min_text_chars=0))
    assert default == ()

    thresholded = sections.detect(tmp_path, (models.Document("README.md", 1),), Config(empty_section_min_text_chars=5))
    assert [finding.line for finding in thresholded] == [3]


def test_standalone_toml_empty_section_policy_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies docsentinel.toml empty_section_policy.

    Scenario:
        Given the parent_with_child_section fixture with a standalone docsentinel.toml setting
        empty_section_policy='all'
        When scan discovers that config (no injected Config)
        Then the loaded policy reaches DS106 and it flags both empty parents at lines 1 and 3.

    Boundaries:
        - Focus: config discovery and propagation of empty_section_policy via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads empty_section_policy from docsentinel.toml
        - Whether the engine forwards the discovered Config to DS106
    """
    case = asset_case("ds106", "parent_with_child_section")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\nempty_section_policy = "all"\n', encoding="utf-8")

    result = scan(case.root)

    assert [finding.line for finding in _ds106(result.findings)] == [1, 3]


def test_standalone_toml_placeholder_content_policy_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies docsentinel.toml placeholder policy.

    Scenario:
        Given the comment_only_section fixture with a standalone docsentinel.toml setting
        placeholder_content_policy='count'
        When scan discovers that config
        Then the comment now counts as content and DS106 reports nothing.

    Boundaries:
        - Focus: config discovery and propagation of placeholder_content_policy via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads placeholder_content_policy from docsentinel.toml
        - Whether the value reaches _visible_text
    """
    case = asset_case("ds106", "comment_only_section")
    (case.root / "docsentinel.toml").write_text(
        'profile = "fast"\nplaceholder_content_policy = "count"\n', encoding="utf-8"
    )

    assert _ds106(scan(case.root).findings) == ()


def test_standalone_toml_image_content_counts_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies docsentinel.toml image_content_counts.

    Scenario:
        Given the image_only_leaf_section fixture with a standalone docsentinel.toml setting
        image_content_counts=false
        When scan discovers that config
        Then the image no longer counts and DS106 reports the contentless section at line 3.

    Boundaries:
        - Focus: config discovery and propagation of image_content_counts via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads image_content_counts from docsentinel.toml
        - Whether the value reaches _build_masks
    """
    case = asset_case("ds106", "image_only_leaf_section")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\nimage_content_counts = false\n', encoding="utf-8")

    assert [finding.line for finding in _ds106(scan(case.root).findings)] == [3]


def test_standalone_toml_min_text_chars_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies docsentinel.toml min_text_chars.

    Scenario:
        Given the leaf_section_with_prose fixture (short one-line section bodies) with a standalone
        docsentinel.toml setting a large empty_section_min_text_chars
        When scan discovers that config
        Then the raised threshold reclassifies every short leaf body as contentless, so DS106 reports
        the two leaf headings at lines 5 and 9 - proving the integer option reaches the rule.

    Boundaries:
        - Focus: config discovery and propagation of empty_section_min_text_chars via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads empty_section_min_text_chars from docsentinel.toml
        - Whether the value reaches the ``text_chars <= minimum`` comparison
    """
    case = asset_case("ds106", "leaf_section_with_prose")
    assert _ds106(scan(case.root, config=Config(profile="fast", select=("DS106",))).findings) == ()

    (case.root / "docsentinel.toml").write_text(
        'profile = "fast"\nempty_section_min_text_chars = 500\n', encoding="utf-8"
    )

    assert [finding.line for finding in _ds106(scan(case.root).findings)] == [5, 9]


def test_pyproject_table_empty_section_policy_off_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies [tool.doc_sentinel] policy off.

    Scenario:
        Given a finding fixture with a pyproject.toml [tool.doc_sentinel] table turning
        empty_section_policy off
        When scan discovers that config
        Then DS106 reports nothing, proving the table-sourced 'off' value gates the rule.

    Boundaries:
        - Focus: config discovery and propagation of empty_section_policy via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] empty_section_policy
        - Whether 'off' short-circuits check_text
    """
    case = asset_case("ds106", "multiple_empty_leaf_sections")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nempty_section_policy = "off"\n', encoding="utf-8"
    )

    assert _ds106(scan(case.root).findings) == ()


def test_pyproject_table_placeholder_content_policy_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies [tool.doc_sentinel] placeholder policy.

    Scenario:
        Given the comment_only_section fixture with a pyproject.toml [tool.doc_sentinel] table setting
        placeholder_content_policy='count'
        When scan discovers that config
        Then the comment counts as content and DS106 reports nothing.

    Boundaries:
        - Focus: config discovery and propagation of placeholder_content_policy via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] placeholder_content_policy
        - Whether the value reaches _visible_text
    """
    case = asset_case("ds106", "comment_only_section")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nplaceholder_content_policy = "count"\n', encoding="utf-8"
    )

    assert _ds106(scan(case.root).findings) == ()


def test_pyproject_table_image_content_counts_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies [tool.doc_sentinel] image_content_counts.

    Scenario:
        Given the image_only_leaf_section fixture with a pyproject.toml [tool.doc_sentinel] table
        setting image_content_counts=false
        When scan discovers that config
        Then the image no longer counts and DS106 reports the contentless section at line 3.

    Boundaries:
        - Focus: config discovery and propagation of image_content_counts via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] image_content_counts
        - Whether the value reaches _build_masks
    """
    case = asset_case("ds106", "image_only_leaf_section")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nimage_content_counts = false\n', encoding="utf-8"
    )

    assert [finding.line for finding in _ds106(scan(case.root).findings)] == [3]


def test_pyproject_table_min_text_chars_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies [tool.doc_sentinel] min_text_chars.

    Scenario:
        Given the leaf_section_with_prose fixture with a pyproject.toml [tool.doc_sentinel] table
        setting a large empty_section_min_text_chars
        When scan discovers that config
        Then the raised threshold reclassifies the short leaf bodies as contentless, so DS106 reports
        lines 5 and 9.

    Boundaries:
        - Focus: config discovery and propagation of empty_section_min_text_chars via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] empty_section_min_text_chars
        - Whether the value reaches the ``text_chars <= minimum`` comparison
    """
    case = asset_case("ds106", "leaf_section_with_prose")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nempty_section_min_text_chars = 500\n', encoding="utf-8"
    )

    assert [finding.line for finding in _ds106(scan(case.root).findings)] == [5, 9]


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("empty_section_policy", '"sometimes"'),
        ("placeholder_content_policy", '"maybe"'),
        ("image_content_counts", '"yes"'),
        ("empty_section_min_text_chars", "-1"),
    ],
)
def test_invalid_ds106_option_raises_config_error(option: str, value: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml that sets one DS106 option to an invalid value (unknown enum member,
        non-boolean, or negative integer)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects invalid values for every DS106 option (standalone file)
        - Fixtures/params: parametrized over the four options; asset_case

    On failure, first check:
        - The _require_enum/_require_bool/min_text_chars validation for the named option
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds106", "empty_terminal_heading")
    (case.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(case.root)


def test_placeholder_markers_are_visible_content(tmp_path: Path):
    """
    [Integration] detectors contentless section detection ds106: verifies markers count as content.

    Scenario:
        Given sections whose only body is a bare marker word, a marker followed by prose, or a word
        that merely embeds a marker's letters
        When each is scanned under placeholder_content_policy 'ignore' and 'count'
        Then every such body is visible prose a reader sees, so DS106 reports nothing under BOTH
        policies - a lone 'TODO' or 'Wip', 'TODO: write the intro', 'tbdx' and 'wipe' are all content.
        By contrast a comment-only section is flagged under 'ignore' and clean under 'count', so the
        count/ignore difference still demonstrates a real, comment-only effect.

    Boundaries:
        - Focus: the loop-owner ruling that DS106 checks visible content only; marker detection is
          DS119's territory, so a visible word like 'TODO' is never stripped
        - Fixtures/params: tmp_path

    On failure, first check:
        - That _visible_text no longer strips TODO/TBD/FIXME/WIP markers under either policy
        - That the comment-only section still distinguishes ignore (flagged) from count (clean)
    """

    def _lines(body: str, **kwargs: object) -> list[int]:
        """Return the DS106 finding lines for a single section whose body is ``body``."""
        (tmp_path / "README.md").write_text(f"# Title\n\n## Section\n\n{body}\n", encoding="utf-8")
        config = Config(profile="fast", select=("DS106",), **kwargs)  # type: ignore[arg-type]
        return [finding.line for finding in _ds106(scan(tmp_path, config=config).findings)]

    for policy in ("ignore", "count"):
        # Visible marker words are content a reader sees, so nothing is flagged under either policy.
        assert _lines("TODO", placeholder_content_policy=policy) == []
        assert _lines("Wip", placeholder_content_policy=policy) == []
        assert _lines("TODO: write the intro", placeholder_content_policy=policy) == []
        assert _lines("tbdx", placeholder_content_policy=policy) == []
        assert _lines("wipe", placeholder_content_policy=policy) == []

    # The remaining count/ignore difference is comments only: a comment-only body is empty under
    # ignore but counts under count.
    assert _lines("<!-- forthcoming -->", placeholder_content_policy="ignore") == [3]
    assert _lines("<!-- forthcoming -->", placeholder_content_policy="count") == []


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors contentless section detection ds106: verifies repeated scans are stable.

    Scenario:
        Given a two-finding scenario scanned twice over the same materialized root
        When the two DS106 finding tuples are compared
        Then they are equal and report lines 3 and 5, so the detector holds no order-dependent state.

    Boundaries:
        - Focus: determinism of DS106 over a real asset tree, with asserted line counts
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Ordering stability of the shared scanner's heading list
    """
    case = asset_case("ds106", "multiple_empty_leaf_sections")

    first = scan(case.root, config=Config(profile="fast", select=("DS106",)))
    second = scan(case.root, config=Config(profile="fast", select=("DS106",)))

    assert first.findings == second.findings
    assert [finding.line for finding in _ds106(first.findings)] == [3, 5]


def test_crlf_line_numbers_point_at_the_empty_heading(tmp_path: Path):
    """
    [Integration] detectors contentless section detection ds106: verifies CRLF line fidelity.

    Scenario:
        Given a CRLF-terminated document whose trailing empty section heading sits on line 5
        When detect runs over it
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input for the empty section's heading
        - Fixtures/params: tmp_path

    On failure, first check:
        - CRLF handling in the shared scanner's line splitting
        - That the reported line is the empty heading, not its parent
    """
    (tmp_path / "README.md").write_bytes(b"# Title\r\n\r\nIntro prose.\r\n\r\n## Empty\r\n")

    findings = sections.detect(tmp_path, (models.Document("README.md", 1),))

    assert len(findings) == 1
    assert findings[0].line == 5
    assert "has no visible content" in findings[0].message


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors contentless section detection ds106: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes inside an otherwise empty section
        When a fast scan reads it
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in sections._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"# Title\n\n## Section\n\n\xff\xfe\n")

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS106",)))


def test_symlinked_markdown_file_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors contentless section detection ds106: verifies a symlinked target file is skipped.

    Scenario:
        Given a symlink pointing at a Markdown file with an empty trailing section
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
    target.write_text("# Title\n\nIntro.\n\n## Empty\n", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    with pytest.raises(ValueError, match="Symlinked files are not inventoried"):
        scan(link, config=Config(profile="fast", select=("DS106",)))


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors contentless section detection ds106: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When detect runs over every finding scenario (whose bodies contain comments, anchors and code)
        Then all expected findings are still produced, proving DS106 opens no socket, makes no
        connection and never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS106 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS106 ever constructs a socket."""
        raise AssertionError("DS106 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS106 ever opens an outbound connection."""
        raise AssertionError("DS106 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS106 ever launches a subprocess."""
        raise AssertionError("DS106 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case, (expected_lines, _evidence) in FINDING_EXPECTATIONS.items():
        loaded = asset_case("ds106", case)
        findings = sections.detect(loaded.root, loaded.documents("README.md"))
        assert tuple(finding.line for finding in findings) == expected_lines


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors contentless section detection ds106: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS106 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported,
        proving the fast DS106 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS106's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether sections or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.detectors import sections\n"
        "assert sections.check_text('# Title\\n\\n## Empty\\n', 'README.md')\n"
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


def _consecutive_empty_headings(scale: int, terminator: str = "\n") -> str:
    """Return ``scale`` consecutive empty H2 leaves under one H1, joined by ``terminator``."""
    parts = ["# Root"] + [f"## S{index}" for index in range(scale)]
    return terminator.join(parts) + terminator


def _huge_body_single_heading(scale: int) -> str:
    """Return one huge content section followed by a single trailing empty section."""
    parts = ["# Root", "", "## Body", ""] + ["Prose line that fills the body."] * scale + ["", "## Tail"]
    return "\n".join(parts) + "\n"


#: A representative subset of adversarial shapes mapped to a builder and the exact finding
#: count formula. This integration suite only proves detect() routes real files through to
#: check_text with exact counts and no super-linear blow-up over the file path; the full
#: algorithmic shape coverage lives in tests/unit/test_detectors_sections_adversarial.py, so
#: shapes already proven there (alternating levels, comment-only sections, interleaved
#: paragraphs) are not duplicated here. CRLF is kept because terminator routing is a detect()
#: concern. Every count is a deterministic function of scale so a broken detector returning
#: nothing or exploding cannot pass vacuously.
ADVERSARIAL_SHAPES: dict[str, tuple[Callable[[int], str], Callable[[int], int]]] = {
    "consecutive_empty_headings": (_consecutive_empty_headings, lambda scale: scale),
    "huge_body_single_heading": (_huge_body_single_heading, lambda _scale: 1),
    "crlf_empty_headings": (lambda scale: _consecutive_empty_headings(scale, "\r\n"), lambda scale: scale),
}


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL_SHAPES))
def test_adversarial_input_stays_bounded(shape: str, tmp_path: Path):
    """
    [Integration] detectors contentless section detection ds106: verifies linear-time adversarial handling.

    Scenario:
        Given large, non-fenced, multi-line Markdown documents of one representative shape - many
        consecutive empty headings, one heading with a huge body, or a CRLF empty-heading flood
        When detect routes a doubling input series through the shared scaling helper (small sizes:
        the algorithmic shape coverage lives in tests/unit/test_detectors_sections_adversarial.py)
        Then every scale produces the exact deterministic finding count (so the pass is never vacuous)
        and the scaling stays under the shared linear bound.

    Boundaries:
        - Focus: detect() routing of real files through check_text with bounded time (contract F)
        - Non-goal: fence boundaries - this input is deliberately non-fenced heading/comment markup
        - Fixtures/params: parametrized over the representative adversarial shapes; tmp_path

    On failure, first check:
        - Any accidentally quadratic scan of the heading list or per-section span masking
        - That the exact finding count for this shape still holds at every scale
        - CRLF line splitting in the shared scanner
    """
    build, expected_count = ADVERSARIAL_SHAPES[shape]

    def _build(scale: int) -> tuple[models.Document, ...]:
        """Write the shape's document at ``scale`` and return its Document (untimed)."""
        path = tmp_path / f"{shape}_{scale}.md"
        path.write_text(build(scale), encoding="utf-8", newline="")
        return (models.Document(path.name, path.stat().st_size),)

    assert_scales_linearly(
        _build,
        lambda documents: sections.detect(tmp_path, documents),
        (500, 1_000, 2_000, 4_000),
        expected_count=expected_count,
        label=f"ds106-{shape}",
    )
