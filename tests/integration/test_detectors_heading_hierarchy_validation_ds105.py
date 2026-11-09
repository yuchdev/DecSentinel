"""Integration tests for DS105 over committed Markdown assets in ``tests/assets/ds105``.

This is Story 03.0 Task 03. Every one of the 14 committed scenarios is loaded in
isolation through the ``asset_case`` fixture and asserted against an explicit,
checked-in expectation table (never against whatever the analyzer currently
emits). Coverage spans the pure ``detect`` entry point, the shared ``scan``
engine, ``select``/``ignore``, baseline suppression, the text/json/github
reports, the CLI exit-code mapping for a warning rule, cross-rule isolation from
DS101-DS103/DS109, config propagation through both ``docsentinel.toml`` and
``[tool.doc_sentinel]``, and the linear-time requirement on adversarial
(non-fenced) heading input.

Two scenarios are deliberately *not* default-setup and the shared Milestone 0005
catalog only exercises default scenarios, so this file owns them: it builds the
exact :class:`Config` each requires (``multiple_h1_policy='warn'`` for
``optional_multiple_h1_warning``; ``first_heading_level=2`` for
``optional_nonroot_start``) and proves the complementary default-config outcome
the Task 02 spec promises.

The supported dialect is the ``gfm-subset`` documented in
``docs/dev/markdown_dialect.md``; these tests exercise its heading boundaries
(ATX + setext tokens, fenced/commented/frontmatter exclusion, blockquote and
inline hashes being non-headings, CRLF line fidelity) rather than full
CommonMark/GFM conformance.
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
from docsentinel.config import Config
from docsentinel.detectors import headings
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.timing_helpers import assert_scales_linearly

#: Default-setup scenarios whose committed Markdown has no DS105 defect under the
#: shipped ``Config()`` defaults. Each must leave the rule registered and executed
#: yet report zero findings of its own.
DEFAULT_CLEAN_CASES: tuple[str, ...] = (
    "sequential_heading_levels",
    "single_root_heading",
    "setext_then_atx",
    "heading_inside_code_fence",
    "heading_inside_html_comment",
    "heading_after_frontmatter",
    "blockquote_heading_ignored",
    "heading_symbols_in_prose",
)

#: Default-setup scenarios that each yield exactly one DS105 ``warning`` finding,
#: mapped to the expected one-based source line and a message-evidence substring.
#: These values are fixed by the committed fixtures and the Task 02 spec, not
#: derived from the analyzer.
DEFAULT_FINDING_EXPECTATIONS: dict[str, tuple[int, str]] = {
    "first_heading_level_three": (1, "first heading is level 3"),
    "skipped_intermediate_level": (5, "skips a level"),
    "multiple_levels_skipped": (3, "skips a level"),
    "crlf_line_accuracy": (5, "skips a level"),
}

#: All default-setup scenarios in a stable order for parametrization.
ALL_DEFAULT_CASES: tuple[str, ...] = DEFAULT_CLEAN_CASES + tuple(DEFAULT_FINDING_EXPECTATIONS)

#: The two non-default-setup scenarios owned by this file (see module docstring).
NON_DEFAULT_CASES: tuple[str, ...] = ("optional_multiple_h1_warning", "optional_nonroot_start")

#: All 14 promised scenarios, used for the catalog-count guard.
ALL_CASES: tuple[str, ...] = ALL_DEFAULT_CASES + NON_DEFAULT_CASES

#: The full fast-profile rule set, in registry order, run alongside DS105.
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

#: The only legitimate non-DS105 findings a full fast scan may add on these
#: fixtures: the heading_inside_html_comment case carries a real multi-line HTML
#: comment that its rightful owner DS102 reports. Every other case must leave the
#: sibling rules silent, proving a heading problem never cascades across rules.
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {
    "heading_inside_html_comment": (("DS102", 3),),
}


def _ds105(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS105 findings from a mixed finding tuple, preserving order."""
    return tuple(finding for finding in findings if finding.rule == "DS105")


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors heading hierarchy validation ds105: verifies the local catalog totals.

    Scenario:
        Given the committed ds105 asset directories and this suite's expectation table
        When clean and finding scenarios are counted across default and non-default setups
        Then there are exactly 9 clean, 5 finding and 14 total scenarios, matching Task 02.

    Boundaries:
        - Focus: this file's expectation table is complete and non-overlapping
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in more than one expectation group
    """
    clean_total = len(DEFAULT_CLEAN_CASES) + 1  # optional_nonroot_start is clean only under config
    finding_total = len(DEFAULT_FINDING_EXPECTATIONS) + 1  # optional_multiple_h1_warning under warn
    assert clean_total == 9
    assert finding_total == 5
    assert len(set(ALL_CASES)) == 14
    assert set(DEFAULT_CLEAN_CASES).isdisjoint(DEFAULT_FINDING_EXPECTATIONS)
    assert set(NON_DEFAULT_CASES).isdisjoint(ALL_DEFAULT_CASES)


def test_ds105_is_registered_as_an_exact_fast_rule():
    """
    [Integration] detectors heading hierarchy validation ds105: verifies fast-profile registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS105 is present with its warning severity and title.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.headings registered DS105 on import
        - Whether DS105 drifted to another profile or severity
    """
    fast_codes = {rule.code for rule in rules_for_profile("fast")}
    assert "DS105" in fast_codes
    rule = next(rule for rule in rules_for_profile("fast") if rule.code == "DS105")
    assert rule.severity == "warning"
    assert rule.title == "Heading hierarchy and section levels"


@pytest.mark.parametrize("case", ALL_DEFAULT_CASES)
def test_detect_matches_expectation_for_each_default_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies detect per default case.

    Scenario:
        Given one committed default-setup ds105 scenario materialized into a fresh tmp_path
        When headings.detect runs over its README.md with shipped defaults
        Then clean cases yield no finding and finding cases yield exactly one DS105 warning
        at the expected one-based line carrying the expected message evidence.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes, one default case per run
        - Fixtures/params: parametrized over the 12 default scenarios; asset_case

    On failure, first check:
        - The expected line/message in DEFAULT_FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte)
    """
    loaded = asset_case("ds105", case)
    findings = headings.detect(loaded.root, loaded.documents("README.md"))

    if case in DEFAULT_CLEAN_CASES:
        assert findings == ()
        return

    expected_line, evidence = DEFAULT_FINDING_EXPECTATIONS[case]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "DS105"
    assert finding.severity == "warning"
    assert finding.path == "README.md"
    assert finding.line == expected_line
    assert evidence in finding.message


@pytest.mark.parametrize("case", ALL_DEFAULT_CASES)
def test_scan_isolates_ds105_from_other_fast_rules(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies full fast-scan isolation.

    Scenario:
        Given one committed default-setup ds105 scenario scanned under the full fast profile
        When the engine runs DS101-DS103, DS105 and DS109 together
        Then sibling rules add only the one expected finding (DS102 owns the real HTML comment in
        heading_inside_html_comment), DS105 ran (clean cases prove execution via enabled_rules with
        zero own findings) and finding cases emit exactly the expected DS105 warning.

    Boundaries:
        - Focus: cross-rule ownership - a heading-level skip is DS105's alone, no cascade or noise
        - Fixtures/params: parametrized over the 12 default scenarios; asset_case

    On failure, first check:
        - Whether DS101/DS103/DS109 regressed and now fire on heading content
        - Whether a new sibling finding appeared beyond the documented DS102 comment overlap
        - Whether DS105 dropped out of enabled_rules (a clean result must mean it ran)
    """
    result = scan(loaded_root := asset_case("ds105", case).root, config=Config(profile="fast"))

    assert result.enabled_rules == FAST_RULE_ORDER
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS105")
    assert siblings == EXPECTED_SIBLINGS.get(case, ()), result.findings
    own = _ds105(result.findings)

    if case in DEFAULT_CLEAN_CASES:
        assert own == ()
    else:
        expected_line, evidence = DEFAULT_FINDING_EXPECTATIONS[case]
        assert len(own) == 1
        assert own[0].line == expected_line
        assert evidence in own[0].message
    assert loaded_root.is_dir()


def test_optional_multiple_h1_needs_warn_policy(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies the opt-in multiple-H1 policy.

    Scenario:
        Given the optional_multiple_h1_warning fixture (two H1s) scanned twice
        When it is scanned once with multiple_h1_policy='warn' and once with shipped defaults
        Then the warn policy reports exactly one DS105 warning on the second H1 (line 5) and the
        default 'allow' policy reports nothing, proving the subsequent-H1 check is genuinely opt-in.

    Boundaries:
        - Focus: a non-default scenario the shared catalog cannot assert; opt-in gating both ways
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether multiple_h1_policy reaches _heading_findings
        - Whether the repeated-H1 check leaked into the default 'allow' path
    """
    case = asset_case("ds105", "optional_multiple_h1_warning")

    warned = scan(case.root, config=Config(profile="fast", multiple_h1_policy="warn"))
    own = _ds105(warned.findings)
    assert len(own) == 1
    assert own[0].line == 5
    assert "additional top-level (H1)" in own[0].message

    default = scan(case.root, config=Config(profile="fast"))
    assert _ds105(default.findings) == ()


def test_optional_nonroot_start_needs_first_heading_level(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies the first_heading_level override.

    Scenario:
        Given the optional_nonroot_start fixture (document opening at H2) scanned twice
        When it is scanned once with first_heading_level=2 and once with shipped defaults
        Then first_heading_level=2 accepts the H2 start with zero findings while the default
        level-1 policy reports one DS105 warning on the first heading (line 1).

    Boundaries:
        - Focus: a non-default scenario the shared catalog cannot assert; the override is load-bearing
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether first_heading_level reaches the first-heading comparison
        - Whether the default level-1 policy still flags a non-root opening heading
    """
    case = asset_case("ds105", "optional_nonroot_start")

    accepted = scan(case.root, config=Config(profile="fast", first_heading_level=2))
    assert _ds105(accepted.findings) == ()

    default = scan(case.root, config=Config(profile="fast"))
    own = _ds105(default.findings)
    assert len(own) == 1
    assert own[0].line == 1
    assert "first heading is level 2" in own[0].message


def test_select_narrows_to_ds105_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies select activates only DS105.

    Scenario:
        Given a finding scenario scanned with select pinned to DS105
        When the engine resolves the active rule set
        Then only DS105 is enabled and its single expected finding is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS105 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds105", "skipped_intermediate_level")

    result = scan(case.root, config=Config(profile="fast", select=("DS105",)))

    assert result.enabled_rules == ("DS105",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS105", 5)]


def test_prefix_select_includes_ds105(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies the DS1 prefix selects DS105.

    Scenario:
        Given a finding scenario scanned with the DS1 prefix selector
        When the active rule set is resolved
        Then DS105 is among the enabled rules and still reports its finding.

    Boundaries:
        - Focus: prefix selector matching for DS105
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS1 against DS105
        - Whether DS105 was excluded despite the prefix
    """
    case = asset_case("ds105", "multiple_levels_skipped")

    result = scan(case.root, config=Config(profile="fast", select=("DS1",)))

    assert "DS105" in result.enabled_rules
    assert _ds105(result.findings)[0].line == 3


def test_ignore_suppresses_ds105(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies ignore removes DS105.

    Scenario:
        Given a finding scenario scanned with DS105 ignored
        When the engine resolves the active rule set
        Then DS105 is absent from enabled_rules and contributes no finding.

    Boundaries:
        - Focus: ignore precedence for a fast rule, proving the detector is genuinely gated off
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules ignore precedence over the default select
        - Whether a DS105 finding survived the ignore
    """
    case = asset_case("ds105", "skipped_intermediate_level")

    result = scan(case.root, config=Config(profile="fast", ignore=("DS105",)))

    assert "DS105" not in result.enabled_rules
    assert _ds105(result.findings) == ()


def test_prefix_ignore_suppresses_ds105(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies a DS1 prefix ignore removes DS105.

    Scenario:
        Given a finding scenario scanned under the fast profile
        When it is scanned once with the genuine prefix ignore ``DS1`` and once with the
            non-matching prefix ``DS2``
        Then ``DS1`` matches every fast DS1xx rule - so effective_rules (ignore taking
            precedence) drops the entire fast set, DS105 included - while ``DS2`` matches
            no fast rule and leaves DS105 active and still reporting its line-3 finding.

    Boundaries:
        - Focus: matches_selector prefix semantics, distinct from the exact-code ignore test
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS1 against every fast DS1xx code
        - Whether a non-matching prefix (DS2) wrongly suppressed DS105
    """
    case = asset_case("ds105", "multiple_levels_skipped")

    # "DS1" is a prefix of every fast rule code (DS101-DS110), so the whole fast set drops.
    suppressed = scan(case.root, config=Config(profile="fast", ignore=("DS1",)))
    assert "DS105" not in suppressed.enabled_rules
    assert suppressed.enabled_rules == ()
    assert _ds105(suppressed.findings) == ()

    # "DS2" matches no fast rule, so DS105 stays active and keeps reporting.
    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",)))
    assert "DS105" in unaffected.enabled_rules
    assert _ds105(unaffected.findings)[0].line == 3


def test_baseline_suppresses_a_known_ds105_finding(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies baseline suppression round-trips.

    Scenario:
        Given a finding scenario whose DS105 finding is recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then the previously known DS105 finding is filtered out while the first scan still reports it.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to a DS105 finding
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS105 finding between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds105", "skipped_intermediate_level")
    first = scan(case.root, config=Config(profile="fast", select=("DS105",)))
    assert len(_ds105(first.findings)) == 1

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS105",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds105(suppressed.findings) == ()


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies text/json/github report stability.

    Scenario:
        Given a DS105 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS105 warning deterministically (schema v1 json,
        a ::warning annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS105 warning across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path and line
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds105", "skipped_intermediate_level")
    result = scan(case.root, config=Config(profile="fast", select=("DS105",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "warning: README.md:5: heading level 4 skips a level after level 2" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS105"]
    assert payload["findings"][0]["rule"] == "DS105"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] == 5

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=README.md,line=5,title=DS105::")


def test_cli_fast_json_scan_reports_ds105_warning_and_exit_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies the CLI fast json warning path.

    Scenario:
        Given a finding scenario scanned via the CLI with --profile fast --format json
        When the command runs without --strict
        Then it prints a JSON report containing the DS105 warning at line 5 and exits 0,
        because a bare warning is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the JSON report still includes the DS105 finding
    """
    case = asset_case("ds105", "skipped_intermediate_level")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds105 = [finding for finding in payload["findings"] if finding["rule"] == "DS105"]
    assert len(ds105) == 1
    finding = ds105[0]
    assert finding["path"] == "README.md"
    assert finding["severity"] == "warning"
    assert finding["line"] == 5
    assert "skips a level" in finding["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds105_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies --strict promotes the warning.

    Scenario:
        Given a finding scenario scanned via the CLI under the fast profile with --strict
        When the command runs
        Then the DS105 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The _exit_code strict branch for non-deep profiles
        - Whether DS105 still produces a finding under the strict run
    """
    case = asset_case("ds105", "multiple_levels_skipped")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario scanned via the CLI under the fast profile
        When the command runs
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: non-blocking exit code when DS105 finds nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS105 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds105", "sequential_heading_levels")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds105_under_fast(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies `docsentinel rules` lists DS105.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS105 and its title appear under the fast profile.

    Boundaries:
        - Focus: rules-command surfacing of DS105
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS105
        - The rules-command formatting for fast rules
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS105: Heading hierarchy and section levels" in captured.out


def test_standalone_toml_warn_policy_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies docsentinel.toml multiple_h1_policy.

    Scenario:
        Given the two-H1 fixture with a standalone docsentinel.toml enabling multiple_h1_policy='warn'
        When scan discovers that config (no injected Config)
        Then the loaded policy reaches DS105 and it reports the second H1 at line 5.

    Boundaries:
        - Focus: config discovery and propagation of multiple_h1_policy via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads multiple_h1_policy from docsentinel.toml
        - Whether the engine forwards the discovered Config to DS105
    """
    case = asset_case("ds105", "optional_multiple_h1_warning")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\nmultiple_h1_policy = "warn"\n', encoding="utf-8")

    result = scan(case.root)

    own = _ds105(result.findings)
    assert len(own) == 1
    assert own[0].line == 5


def test_standalone_toml_first_heading_level_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies docsentinel.toml first_heading_level.

    Scenario:
        Given the non-root-start fixture with a standalone docsentinel.toml setting first_heading_level=2
        When scan discovers that config
        Then the H2 opening is accepted and DS105 reports nothing.

    Boundaries:
        - Focus: config discovery and propagation of first_heading_level via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads first_heading_level from docsentinel.toml
        - Whether the discovered level reaches the first-heading comparison
    """
    case = asset_case("ds105", "optional_nonroot_start")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\nfirst_heading_level = 2\n', encoding="utf-8")

    result = scan(case.root)

    assert _ds105(result.findings) == ()


def test_pyproject_table_policy_off_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies [tool.doc_sentinel] heading_level_policy.

    Scenario:
        Given a skip fixture with a pyproject.toml [tool.doc_sentinel] table turning heading_level_policy off
        When scan discovers that config
        Then the level-skip check is suppressed and DS105 reports nothing, proving the table reaches the rule.

    Boundaries:
        - Focus: config discovery and propagation of heading_level_policy via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] heading_level_policy
        - Whether 'off' disables the first-heading and skip checks
    """
    case = asset_case("ds105", "skipped_intermediate_level")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nheading_level_policy = "off"\n', encoding="utf-8"
    )

    result = scan(case.root)

    assert _ds105(result.findings) == ()


def test_pyproject_table_setext_support_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies [tool.doc_sentinel] setext_heading_support.

    Scenario:
        Given the setext-then-ATX fixture with a pyproject.toml [tool.doc_sentinel] table disabling
        setext_heading_support
        When scan discovers that config
        Then the setext H1 no longer participates, so the ATX H2 becomes the first heading and DS105
        reports a level-2 opening at line 4 - which the default (setext-supported) scan does not.

    Boundaries:
        - Focus: config discovery and propagation of setext_heading_support via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] setext_heading_support
        - Whether dropping setext headings re-seats the first participating heading
    """
    case = asset_case("ds105", "setext_then_atx")
    assert _ds105(scan(case.root, config=Config(profile="fast")).findings) == ()

    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nsetext_heading_support = false\n', encoding="utf-8"
    )

    own = _ds105(scan(case.root).findings)
    assert len(own) == 1
    assert own[0].line == 4
    assert "first heading is level 2" in own[0].message


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies repeated scans are stable.

    Scenario:
        Given a finding scenario scanned twice over the same materialized root
        When the two DS105 finding tuples are compared
        Then they are equal, so the detector holds no order-dependent mutable state.

    Boundaries:
        - Focus: determinism of DS105 over a real asset tree
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Ordering stability of the shared scanner's heading list
    """
    case = asset_case("ds105", "crlf_line_accuracy")

    first = scan(case.root, config=Config(profile="fast", select=("DS105",)))
    second = scan(case.root, config=Config(profile="fast", select=("DS105",)))

    assert first.findings == second.findings
    assert [finding.line for finding in _ds105(first.findings)] == [5]


def test_legit_level_reduction_is_clean(tmp_path: Path):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies raising/reducing levels is allowed.

    Scenario:
        Given a document that descends H1>H2>H3 then returns to H2
        When detect runs over it
        Then no finding is produced, because reducing the heading level (and a legitimate H3 after H2)
        is never a skip.

    Boundaries:
        - Focus: only deeper-by-more-than-one jumps are skips; reductions are legal
        - Fixtures/params: tmp_path

    On failure, first check:
        - The previous_level comparison in _heading_findings
        - That a level reduction is not mistaken for a skip
    """
    (tmp_path / "README.md").write_text("# A\n\n## B\n\n### C\n\n## D\n", encoding="utf-8")

    assert headings.detect(tmp_path, (models.Document("README.md", 1),)) == ()


def test_inline_and_list_hashes_are_not_headings(tmp_path: Path):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies inline/list hashes are not headings.

    Scenario:
        Given a valid H1 followed by list items whose text contains mid-line '#' hashes
        When detect runs over the document
        Then only the H1 is a heading token, so no skip or first-heading finding is produced.

    Boundaries:
        - Focus: a heading marker must begin the line; '#' inside list/prose text is content
        - Fixtures/params: tmp_path

    On failure, first check:
        - The heading-opener anchoring in the shared scanner
        - That inline '#' runs are not mistaken for ATX headings
    """
    (tmp_path / "README.md").write_text("# Title\n\n- Item #one\n- Nested #two\n", encoding="utf-8")

    assert headings.detect(tmp_path, (models.Document("README.md", 1),)) == ()


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes under a level-skipping heading
        When a fast scan reads it
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in headings._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"# Title\n\n### \xff\xfe Deep\n")

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS105",)))


def test_symlinked_markdown_file_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies a symlinked target file is skipped.

    Scenario:
        Given a symlink pointing at a Markdown file whose heading skips a level
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
    target.write_text("# Title\n\n#### Deep\n", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    with pytest.raises(ValueError, match="Symlinked files are not inventoried"):
        scan(link, config=Config(profile="fast", select=("DS105",)))


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When detect runs over every default finding scenario (whose bodies contain heading-like text)
        Then all expected findings are still produced, proving DS105 opens no socket, makes no
        connection and never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS105 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS105 ever constructs a socket."""
        raise AssertionError("DS105 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS105 ever opens an outbound connection."""
        raise AssertionError("DS105 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS105 ever launches a subprocess."""
        raise AssertionError("DS105 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case, (expected_line, _evidence) in DEFAULT_FINDING_EXPECTATIONS.items():
        loaded = asset_case("ds105", case)
        findings = headings.detect(loaded.root, loaded.documents("README.md"))
        assert [finding.line for finding in findings] == [expected_line]


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors heading hierarchy validation ds105: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS105 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported,
        proving the fast DS105 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS105's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether headings or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.detectors import headings\n"
        "assert headings.check_text('# A\\n### B\\n', 'README.md')\n"
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


def test_adversarial_heading_prose_stays_bounded(tmp_path: Path):
    """
    [Integration] detectors heading hierarchy validation ds105: verifies linear-time adversarial handling.

    Scenario:
        Given large, non-fenced Markdown documents built from a deep alternation of valid heading
        levels and one pathologically long heading line
        When detect routes a doubling input series through the shared scaling helper (small sizes:
        the algorithmic proof over the scanner lives in tests/unit/test_markdown_blocks_adversarial.py)
        Then every size is clean (balanced alternation never skips, so the count is pinned at 0) and
        the scaling stays under the shared linear bound.

    Boundaries:
        - Focus: bounded findings plus bounded time routed through detect() (contract F)
        - Non-goal: fence boundaries - this input is deliberately non-fenced prose/headings
        - Fixtures/params: tmp_path

    On failure, first check:
        - Any accidentally quadratic scan of the heading list or exclusion set
        - That balanced H1/H2 alternation is never reported as a skip
    """

    def _build(block_count: int) -> tuple[models.Document, ...]:
        """Write a long alternation of valid heading levels and return its Document (untimed)."""
        long_title = "x" * 20_000
        blocks = ["# Root\n", f"## {long_title}\n"]
        blocks.extend("# A\n\n## B\n\n" for _ in range(block_count))
        path = tmp_path / f"case_{block_count}.md"
        path.write_text("\n".join(blocks), encoding="utf-8")
        return (models.Document(path.name, path.stat().st_size),)

    assert_scales_linearly(
        _build,
        lambda documents: headings.detect(tmp_path, documents),
        (500, 1_000, 2_000, 4_000),
        expected_count=0,
        label="ds105-adversarial",
    )
