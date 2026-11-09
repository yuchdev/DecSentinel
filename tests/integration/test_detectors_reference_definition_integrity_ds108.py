"""Integration tests for DS108 over committed Markdown assets in ``tests/assets/ds108``.

This is Story 05.0 Task 03. Every one of the 14 committed scenarios is loaded in
isolation through the ``asset_case`` fixture and asserted against an explicit,
checked-in expectation table (:data:`CLEAN_CASES`, :data:`FINDING_EXPECTATIONS`
and :data:`UNUSED_ENABLED_CASE`) that is transcribed from the Task 02 manifest and
the detector's stable message contract, never derived from whatever the analyzer
currently emits. The 13 ``setup=default`` scenarios are asserted through both the
pure ``references.detect`` entry point and the shared ``scan`` engine; the lone
non-default scenario (``unused_definition_enabled``) is asserted separately with an
exact ``unused_reference_definitions=true`` config so the default-off policy is
never forced on the repo-wide self-scan.

DS108 is an always-active ``fast`` rule at ``warning`` severity. It is a pure
reference-*identity* check: it reasons about labels and definitions and never
resolves a target on disk, so no committed finding fixture produces a sibling from
any other fast rule. That isolation (an undefined label is DS108's alone, never a
DS101 dangling link) is asserted directly: DS101's matcher only sees inline
``[text](target)`` links, so a reference-style ``[text][missing]`` yields only
DS108.

Coverage follows the task: all 14 fixtures; the ``duplicate_reference_definitions``
off/warn/error severity ladder; the ``unused_reference_definitions`` opt-in through
an injected Config and a discovered ``docsentinel.toml``; select/ignore (exact and
prefix); baseline round-trips; text/json/github report stability; the CLI fast-json
and strict exit paths; ``docsentinel rules``/``doctor`` surfacing; the edge
dimensions (CRLF line fidelity, invalid UTF-8 surfacing, an unreadable file, a
symlinked Markdown file not inventoried, an out-of-root symlink target DS108 never
follows); determinism across repeated scans; the fast stdlib-only import with no
network or content execution; and the linear-time requirement on adversarial
non-fenced bracket floods (single-line and multi-line, with strictly non-repeating
labels so dedup never collapses the count) routed through ``detect`` end to end.

The exhaustive algorithmic shape coverage for ``_scan_uses`` belongs to the unit
layer; this integration suite proves only that real files route through
``check_text`` with exact deterministic counts and no super-linear blow-up over the
file path.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from docsentinel import baseline, cli, models
from docsentinel.config import Config, ConfigError
from docsentinel.detectors import references
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.timing_helpers import assert_scales_linearly

#: The eight committed CLEAN scenarios, each default-setup. A resolved full/collapsed
#: /case-folded reference, an unused definition left silent under the default off
#: policy, a broken reference buried in a fence, escaped bracket prose, a footnote
#: marker and a definition pointing at an existing local guide must all leave DS108
#: registered and executed yet report zero findings of their own.
CLEAN_CASES: tuple[str, ...] = (
    "resolved_reference_definition",
    "collapsed_reference_label",
    "case_folded_reference_labels",
    "unused_definition_disabled",
    "reference_inside_fence",
    "escaped_bracket_not_reference",
    "footnote_reference_ignored",
    "reference_definition_with_url",
)

#: The five default-setup FINDING scenarios, mapped to the exact one-based line(s) of
#: the offending construct and the full DS108 message for each line, in ascending
#: source order. These values are fixed by the committed fixtures and the detector's
#: message contract (``undefined reference label: <echo>`` /
#: ``duplicate reference definition: <echo>``), not read back from the analyzer.
#: ``multiple_missing_references`` deliberately yields two findings, one per distinct
#: undefined label. ``duplicate_whitespace_labels`` echoes the raw second label with
#: its two literal spaces preserved. The duplicate cases rely on the shipped default
#: ``duplicate_reference_definitions="warn"``.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[int, ...], tuple[str, ...]]] = {
    "missing_explicit_reference": ((3,), ("undefined reference label: missing",)),
    "duplicate_reference_labels": ((6,), ("duplicate reference definition: guide",)),
    "undefined_image_reference": ((3,), ("undefined reference label: diagram",)),
    "duplicate_whitespace_labels": ((6,), ("duplicate reference definition: project  name",)),
    "multiple_missing_references": (
        (3, 5),
        ("undefined reference label: alpha", "undefined reference label: beta"),
    ),
}

#: The single non-default FINDING scenario: an unused definition that only warns when
#: ``unused_reference_definitions`` is explicitly enabled. Asserted separately in
#: :func:`test_unused_reference_definitions_option_gates_the_finding` so the default
#: off policy is never forced onto any other scan.
UNUSED_ENABLED_CASE = "unused_definition_enabled"

#: The 13 ``setup=default`` scenarios exercised through both detect() and scan().
DEFAULT_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: All 14 committed scenarios in a stable order.
ALL_CASES: tuple[str, ...] = DEFAULT_CASES + (UNUSED_ENABLED_CASE,)

#: The full fast-profile rule set, in registry order, run alongside DS108.
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


def _ds108(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS108 findings from a mixed finding tuple, preserving order.

    :param findings: Findings from a detector or scan.
    :returns: The DS108 subset in the original order.
    """
    return tuple(finding for finding in findings if finding.rule == "DS108")


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors reference definition integrity ds108: verifies the local catalog totals.

    Scenario:
        Given the committed ds108 asset directories and this suite's expectation table
        When clean, finding and the non-default unused scenario are counted
        Then there are exactly 8 clean, 6 finding, 0 error and 14 total scenarios matching Task 02,
        and the clean and finding sets are disjoint.

    Boundaries:
        - Focus: this file's expectation table is complete and non-overlapping
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in both CLEAN_CASES and the finding sets
    """
    finding_cases = set(FINDING_EXPECTATIONS) | {UNUSED_ENABLED_CASE}
    assert len(CLEAN_CASES) == 8
    assert len(finding_cases) == 6
    assert len(set(ALL_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(finding_cases)


def test_ds108_is_registered_as_an_exact_fast_rule():
    """
    [Integration] detectors reference definition integrity ds108: verifies always-active fast registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS108 is present with warning severity, its title and an empty opt_in_option, proving it is
        an ordinary always-active rule rather than an opt-in policy rule like DS110.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.references registered DS108 on import
        - Whether DS108 drifted profile/severity or grew an opt_in_option
    """
    fast = {rule.code: rule for rule in rules_for_profile("fast")}
    assert "DS108" in fast
    rule = fast["DS108"]
    assert rule.severity == "warning"
    assert rule.title == "Reference-style link definition integrity"
    assert rule.opt_in_option == ""


@pytest.mark.parametrize("case", DEFAULT_CASES)
def test_detect_matches_expectation_for_each_default_case(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies detect per committed case.

    Scenario:
        Given one default-setup ds108 scenario materialized into a fresh tmp_path
        When references.detect runs over its README.md with shipped defaults
        Then clean cases yield no finding and finding cases yield exactly the expected DS108 warnings at
        the expected one-based line(s), path and full message, in ascending source order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes, one case per run
        - Fixtures/params: parametrized over the 13 default-setup scenarios; asset_case

    On failure, first check:
        - The expected (lines, messages) in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte)
    """
    loaded = asset_case("ds108", case)
    findings = _ds108(references.detect(loaded.root, loaded.documents("README.md")))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    expected_lines, expected_messages = FINDING_EXPECTATIONS[case]
    assert tuple(finding.line for finding in findings) == expected_lines
    assert tuple(finding.message for finding in findings) == expected_messages
    for finding in findings:
        assert finding.rule == "DS108"
        assert finding.severity == "warning"
        assert finding.path == "README.md"


@pytest.mark.parametrize("case", DEFAULT_CASES)
def test_scan_matches_expectation_and_isolates_ds108(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies full fast-scan isolation.

    Scenario:
        Given one default-setup ds108 scenario scanned under the full fast profile
        When DS101-DS117 run together
        Then DS108 ran (enabled_rules carries it, no rule pending), finding cases emit exactly the
        expected DS108 warnings at the expected lines, and no non-DS108 finding appears - DS108 is a
        pure identity check that resolves no target, so no sibling rule fires on any committed fixture.

    Boundaries:
        - Focus: cross-rule ownership - a reference-label problem is DS108's alone
        - Fixtures/params: parametrized over the 13 default-setup scenarios; asset_case

    On failure, first check:
        - Whether another fast rule began firing on reference syntax or a definition target
        - Whether DS108 dropped out of enabled_rules (a clean result must mean it ran)
    """
    loaded = asset_case("ds108", case)
    result = scan(loaded.root, config=Config(profile="fast"))

    assert result.enabled_rules == FAST_RULE_ORDER
    assert result.pending == ()
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS108")
    assert siblings == (), result.findings

    own = _ds108(result.findings)
    if case in CLEAN_CASES:
        assert own == ()
    else:
        expected_lines, expected_messages = FINDING_EXPECTATIONS[case]
        assert tuple(finding.line for finding in own) == expected_lines
        assert tuple(finding.message for finding in own) == expected_messages


def test_undefined_reference_is_ds108_only_never_ds101(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies the DS101/DS108 boundary.

    Scenario:
        Given the missing_explicit_reference fixture whose only defect is a full reference
            ``[the text][missing]`` to an undefined label, scanned under the full fast profile
        When DS101 (dangling links) and DS108 both run
        Then DS108 reports the undefined label at line 3 while DS101 stays silent, because DS101's
            matcher only sees inline ``[text](target)`` links and never a reference identifier, so the
            two rules do not double-report the same construct.

    Boundaries:
        - Focus: the documented DS101 vs DS108 ownership split for an undefined reference label
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether DS101 began matching reference-style ``[text][label]`` syntax
        - Whether DS108 stopped owning the undefined-label finding
    """
    case = asset_case("ds108", "missing_explicit_reference")

    result = scan(case.root, config=Config(profile="fast"))

    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS108", 3)]
    assert all(finding.rule != "DS101" for finding in result.findings)


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("off", []),
        ("warn", [(6, "warning")]),
        ("error", [(6, "error")]),
    ],
)
def test_duplicate_reference_definitions_policy_ladder(
    policy: str,
    expected: list[tuple[int, str]],
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors reference definition integrity ds108: verifies the duplicate-policy severity ladder.

    Scenario:
        Given the duplicate_reference_labels fixture (two ``[guide]`` definitions, the second on line 6)
        When it is scanned with duplicate_reference_definitions set to off, warn and error
        Then ``off`` suppresses the duplicate entirely, ``warn`` reports it at warning severity and
            ``error`` reports it at error severity - all pinned to the second definition's line 6.

    Boundaries:
        - Focus: the three-way duplicate-definition policy mapped to suppression/warning/error
        - Fixtures/params: parametrized over the three policy values; asset_case

    On failure, first check:
        - The duplicate_policy branch and severity selection in check_text
        - Whether the first definition was wrongly flagged instead of the second
    """
    case = asset_case("ds108", "duplicate_reference_labels")

    result = scan(
        case.root,
        config=Config(profile="fast", select=("DS108",), duplicate_reference_definitions=policy),
    )
    own = _ds108(result.findings)

    assert [(finding.line, finding.severity) for finding in own] == expected
    for finding in own:
        assert finding.message == "duplicate reference definition: guide"


def test_unused_reference_definitions_option_gates_the_finding(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies the unused opt-in via injected Config.

    Scenario:
        Given the unused_definition_enabled fixture (one never-referenced ``[orphan]`` definition on
            line 5) and the unused_definition_disabled fixture (one never-referenced ``[unlinked]``)
        When each is scanned with unused_reference_definitions off (default) and then on
        Then both are clean under the default off policy, while under the explicit on policy each reports
            exactly one unused-definition warning at line 5 - so the non-default finding fixture only
            fires when its policy is enabled and the backward-compatible default stays silent.

    Boundaries:
        - Focus: the unused_reference_definitions opt-in through an injected Config, both directions
        - Fixtures/params: asset_case

    On failure, first check:
        - The ``if settings.unused_reference_definitions`` branch in check_text
        - Whether the default off policy stopped suppressing unused definitions
    """
    enabled = asset_case("ds108", "unused_definition_enabled")
    assert _ds108(scan(enabled.root, config=Config(profile="fast", select=("DS108",))).findings) == ()
    on = _ds108(
        scan(
            enabled.root,
            config=Config(profile="fast", select=("DS108",), unused_reference_definitions=True),
        ).findings
    )
    assert [(finding.line, finding.message) for finding in on] == [(5, "unused reference definition: orphan")]

    disabled = asset_case("ds108", "unused_definition_disabled")
    assert _ds108(scan(disabled.root, config=Config(profile="fast", select=("DS108",))).findings) == ()
    on_disabled = _ds108(
        scan(
            disabled.root,
            config=Config(profile="fast", select=("DS108",), unused_reference_definitions=True),
        ).findings
    )
    assert [(finding.line, finding.message) for finding in on_disabled] == [
        (5, "unused reference definition: unlinked")
    ]


def test_unused_option_propagates_from_standalone_toml(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies docsentinel.toml unused opt-in.

    Scenario:
        Given the unused_definition_enabled fixture with a standalone docsentinel.toml setting
            unused_reference_definitions=true
        When scan discovers that config (no injected Config)
        Then the loaded policy reaches DS108 and it reports the unused definition at line 5, proving the
            opt-in is honoured through real config discovery and never forced on by default.

    Boundaries:
        - Focus: config discovery and propagation of unused_reference_definitions via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads unused_reference_definitions from docsentinel.toml
        - Whether the engine forwards the discovered Config to DS108
    """
    case = asset_case("ds108", "unused_definition_enabled")
    (case.root / "docsentinel.toml").write_text(
        'profile = "fast"\nunused_reference_definitions = true\n', encoding="utf-8"
    )

    assert [finding.line for finding in _ds108(scan(case.root).findings)] == [5]


def test_duplicate_policy_propagates_from_pyproject_table(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies [tool.doc_sentinel] duplicate policy.

    Scenario:
        Given the duplicate_reference_labels fixture with a pyproject.toml [tool.doc_sentinel] table
            setting duplicate_reference_definitions='error'
        When scan discovers that config
        Then the discovered policy reaches DS108 and the duplicate at line 6 is reported at error
            severity, proving the table-sourced value gates the rule's severity.

    Boundaries:
        - Focus: config discovery and propagation of duplicate_reference_definitions via the table form
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] duplicate_reference_definitions
        - Whether the value reaches the severity selection in check_text
    """
    case = asset_case("ds108", "duplicate_reference_labels")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nduplicate_reference_definitions = "error"\n', encoding="utf-8"
    )

    own = _ds108(scan(case.root).findings)
    assert [(finding.line, finding.severity) for finding in own] == [(6, "error")]


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("duplicate_reference_definitions", '"sometimes"'),
        ("unused_reference_definitions", '"yes"'),
        ("reference_label_normalization", '"gfm"'),
    ],
)
def test_invalid_ds108_option_raises_config_error(option: str, value: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml that sets one DS108 option to an invalid value (an unknown enum member
            or a non-boolean)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects invalid values for every DS108 option (standalone file)
        - Fixtures/params: parametrized over the three options; asset_case

    On failure, first check:
        - The enum/bool validation for the named option in config.py
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds108", "missing_explicit_reference")
    (case.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(case.root)


def test_select_narrows_to_ds108_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies select activates only DS108.

    Scenario:
        Given a finding scenario scanned with select pinned to the exact code DS108
        When the engine resolves the active rule set
        Then only DS108 is enabled and its single expected finding is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS108 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds108", "missing_explicit_reference")

    result = scan(case.root, config=Config(profile="fast", select=("DS108",)))

    assert result.enabled_rules == ("DS108",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS108", 3)]


def test_prefix_select_includes_ds108(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies the DS1 prefix selects DS108.

    Scenario:
        Given a two-finding scenario scanned with the DS1 prefix selector
        When the active rule set is resolved
        Then the whole fast set is active, DS108 is among the enabled rules and it still reports both
            undefined references at lines 3 and 5.

    Boundaries:
        - Focus: prefix selector matching for DS108
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS1 against DS108
        - Whether DS108 was excluded despite the prefix
    """
    case = asset_case("ds108", "multiple_missing_references")

    result = scan(case.root, config=Config(profile="fast", select=("DS1",)))

    assert result.enabled_rules == FAST_RULE_ORDER
    assert "DS108" in result.enabled_rules
    assert [finding.line for finding in _ds108(result.findings)] == [3, 5]


def test_ignore_suppresses_ds108(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies ignore removes DS108.

    Scenario:
        Given a finding scenario scanned with DS108 ignored by its exact code and, separately, by the
            non-matching prefix DS2
        When the engine resolves the active rule set each time
        Then the exact ignore drops DS108 and its finding while the non-matching DS2 prefix leaves DS108
            active and still reporting line 3.

    Boundaries:
        - Focus: ignore precedence for a fast rule, proving the detector is genuinely gated off
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules ignore precedence over the default select
        - Whether a DS108 finding survived the ignore
    """
    case = asset_case("ds108", "missing_explicit_reference")

    exact = scan(case.root, config=Config(profile="fast", ignore=("DS108",)))
    assert "DS108" not in exact.enabled_rules
    assert _ds108(exact.findings) == ()

    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",)))
    assert "DS108" in unaffected.enabled_rules
    assert [finding.line for finding in _ds108(unaffected.findings)] == [3]


def test_baseline_suppresses_known_ds108_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies baseline suppression round-trips.

    Scenario:
        Given a two-finding scenario whose DS108 findings are recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then both previously known DS108 findings are filtered out while the first scan still reported
            them, so the fingerprints are stable across the two scans.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS108 findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS108 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds108", "multiple_missing_references")
    first = scan(case.root, config=Config(profile="fast", select=("DS108",)))
    assert len(_ds108(first.findings)) == 2

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS108",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds108(suppressed.findings) == ()


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies repeated scans are stable.

    Scenario:
        Given a two-finding scenario scanned twice over the same materialized root
        When the two DS108 finding tuples are compared
        Then they are equal and report lines 3 and 5, so the detector holds no order-dependent state.

    Boundaries:
        - Focus: determinism of DS108 over a real asset tree, with asserted line counts
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Ordering stability of the shared scanner's masked-line view
    """
    case = asset_case("ds108", "multiple_missing_references")

    first = scan(case.root, config=Config(profile="fast", select=("DS108",)))
    second = scan(case.root, config=Config(profile="fast", select=("DS108",)))

    assert first.findings == second.findings
    assert [finding.line for finding in _ds108(first.findings)] == [3, 5]


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors reference definition integrity ds108: verifies text/json/github report stability.

    Scenario:
        Given a DS108 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS108 warning deterministically (schema v1 json, a ``::warning``
            annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS108 warning across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path, line and message
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds108", "missing_explicit_reference")
    result = scan(case.root, config=Config(profile="fast", select=("DS108",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "warning: README.md:3: undefined reference label: missing" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS108"]
    assert payload["findings"][0]["rule"] == "DS108"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] == 3

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=README.md,line=3,title=DS108::")


def test_cli_fast_json_scan_reports_ds108_warning_and_exit_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors reference definition integrity ds108: verifies the CLI fast json warning path.

    Scenario:
        Given a finding scenario scanned via the CLI with --profile fast --format json
        When the command runs without --strict
        Then it prints a JSON report containing the DS108 warning at line 3 and exits 0, because a bare
            warning is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the JSON report still includes the DS108 finding
    """
    case = asset_case("ds108", "missing_explicit_reference")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds108 = [finding for finding in payload["findings"] if finding["rule"] == "DS108"]
    assert len(ds108) == 1
    assert ds108[0]["path"] == "README.md"
    assert ds108[0]["severity"] == "warning"
    assert ds108[0]["line"] == 3
    assert "undefined reference label: missing" in ds108[0]["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds108_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors reference definition integrity ds108: verifies --strict promotes the warning.

    Scenario:
        Given a finding scenario scanned via the CLI under the fast profile with --strict
        When the command runs
        Then the DS108 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The exit-code strict branch for non-deep profiles
        - Whether DS108 still produces a finding under the strict run
    """
    case = asset_case("ds108", "missing_explicit_reference")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors reference definition integrity ds108: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario with no finding from any fast rule scanned via the CLI
        When the command runs under the fast profile
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: non-blocking exit code when DS108 and its siblings find nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS108 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds108", "resolved_reference_definition")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds108_under_fast(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors reference definition integrity ds108: verifies `docsentinel rules` lists DS108.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS108 and its title appear under the fast profile with no ``[opt-in: ...]`` marker, because
            DS108 is an ordinary always-active rule.

    Boundaries:
        - Focus: rules-command surfacing of DS108 as a non-opt-in rule
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS108
        - Whether DS108 grew an opt_in_option that added a marker
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    ds108_lines = [line for line in captured.out.splitlines() if "DS108:" in line]
    assert ds108_lines == ["  DS108: Reference-style link definition integrity"]
    assert "opt-in" not in ds108_lines[0]


def test_cli_doctor_counts_ds108_among_the_fast_rules(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors reference definition integrity ds108: verifies `docsentinel doctor` counts DS108.

    Scenario:
        Given the installed rule registry
        When the doctor command reports environment readiness
        Then the fast-rule tally reads exactly
            "16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)",
            so DS108 is one of the twelve registered always-active fast rules and is not an opt-in rule.

    Boundaries:
        - Focus: doctor's accounting of DS108 as an ordinary registered fast rule
        - Fixtures/params: capsys

    On failure, first check:
        - Whether the registered fast-rule count changed when a rule was added
        - Whether DS108 was miscounted as opt-in
    """
    exit_code = cli.main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS108" in {rule.code for rule in rules_for_profile("fast")}
    assert "fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)" in captured.out


def test_crlf_line_numbers_point_at_the_offending_reference(tmp_path: Path):
    """
    [Integration] detectors reference definition integrity ds108: verifies CRLF line fidelity.

    Scenario:
        Given a CRLF-terminated document whose undefined full reference sits on line 5
        When detect runs over it
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input for the offending reference
        - Fixtures/params: tmp_path

    On failure, first check:
        - CRLF handling in the shared scanner's line splitting
        - That the reported line is the reference's line, not its body
    """
    (tmp_path / "README.md").write_bytes(b"# Title\r\n\r\nIntro prose.\r\n\r\n[text][missing]\r\n")

    findings = _ds108(references.detect(tmp_path, (models.Document("README.md", 1),)))

    assert len(findings) == 1
    assert findings[0].line == 5
    assert findings[0].message == "undefined reference label: missing"


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors reference definition integrity ds108: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes beneath an undefined reference
        When a fast scan reads it with DS108 selected
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in references._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"# Title\n\n[text][missing]\n\xff\xfe\n")

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS108",)))


def test_unreadable_file_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors reference definition integrity ds108: verifies an unreadable file is not a silent clean.

    Scenario:
        Given a Markdown document whose read permission is removed
        When a fast scan tries to read it with DS108 selected
        Then a PermissionError propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: a filesystem read error surfaces instead of masquerading as clean
        - Fixtures/params: tmp_path (skipped when running as root, which bypasses the mode)

    On failure, first check:
        - Whether the engine swallowed the read error into a clean scan
        - Whether the test runs as root, where chmod 000 does not block reads
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("running as root bypasses the unreadable-file permission check")
    target = tmp_path / "README.md"
    target.write_text("# Title\n\n[text][missing]\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            scan(tmp_path, config=Config(profile="fast", select=("DS108",)))
    finally:
        target.chmod(0o644)


def test_symlinked_markdown_file_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors reference definition integrity ds108: verifies a symlinked target file is skipped.

    Scenario:
        Given a symlink pointing at a Markdown file carrying an undefined reference
        When that symlink is scanned directly with DS108 selected
        Then the engine refuses to inventory the symlinked file rather than following it.

    Boundaries:
        - Focus: the engine's symlink safety for a directly selected file path
        - Fixtures/params: tmp_path

    On failure, first check:
        - The symlink guard in engine.scan for selected files
        - Whether symlinks are silently followed into the scan
    """
    target = tmp_path / "real.md"
    target.write_text("# Title\n\n[text][missing]\n", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    with pytest.raises(ValueError, match="Symlinked files are not inventoried"):
        scan(link, config=Config(profile="fast", select=("DS108",)))


def test_out_of_root_symlink_target_is_never_followed(tmp_path: Path):
    """
    [Integration] detectors reference definition integrity ds108: verifies DS108 never resolves a reference target.

    Scenario:
        Given a scan root whose document defines ``[o]: ../../outside/secret.md`` and uses it as
            ``[see][o]``, with an in-root ``escape`` symlink pointing at the out-of-root tree holding a
            real secret
        When DS108 alone scans the root with socket, connection and subprocess launches wired to fail
        Then DS108 reports nothing - the label is defined and used, so the use resolves at the identity
            level - and the scan completes without opening a socket, making a connection, launching a
            subprocess, or raising, proving DS108 performs no target resolution and never follows the
            escaping symlink (that containment is DS116's job, not DS108's).

    Boundaries:
        - Focus: DS108 is a pure label-identity check that resolves no path, so an out-of-root symlink
          target is irrelevant to it and is never followed
        - Fixtures/params: tmp_path, monkeypatch-free socket/subprocess guards via MonkeyPatch.context

    On failure, first check:
        - Whether DS108 started resolving or stat-ing a reference-definition target
        - Whether a stray network or subprocess call entered the DS108 path
    """
    root = tmp_path / "scanroot"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "README.md").write_text(
        "# D\n\nSee [see][o] for details.\n\n[o]: ../../outside/secret.md\n", encoding="utf-8"
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.md").write_text("# out of root secret\n", encoding="utf-8")
    try:
        (root / "escape").symlink_to("../outside")
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    def _fail(*_args: object, **_kwargs: object):
        """Fail if DS108 ever opens a socket, connection or subprocess."""
        raise AssertionError("DS108 must not touch the network or execute content")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket, "socket", _fail)
        patch.setattr(socket, "create_connection", _fail)
        patch.setattr(subprocess, "Popen", _fail)
        result = scan(root, config=Config(profile="fast", select=("DS108",)))

    assert _ds108(result.findings) == ()


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors reference definition integrity ds108: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS108 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported, proving
            the fast DS108 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS108's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether references or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.detectors import references\n"
        "assert references.check_text('[text][missing]\\n', 'README.md')\n"
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


def _single_line_flood(scale: int) -> str:
    """Return one non-fenced line of ``scale`` distinct undefined full references.

    Each ``[t{i}][missing{i}]`` is a full reference to a non-repeating undefined label, so every
    unit yields exactly one finding and dedup never collapses the count.

    :param scale: Number of undefined full references to pack onto the single line.
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + " ".join(f"[t{index}][missing{index}]" for index in range(scale)) + "\n"


def _multi_line_flood(scale: int) -> str:
    """Return ``scale`` lines, each one distinct undefined full reference.

    :param scale: Number of lines (one undefined full reference each).
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + "".join(f"[t{index}][missing{index}]\n" for index in range(scale))


#: Representative adversarial routing shapes mapped to a builder and an exact
#: finding-count formula. Each shape is deliberately non-fenced prose with strictly
#: non-repeating labels so no unit is masked and no dedup collapse hides a count.
#: This integration suite proves only that detect() routes real files through
#: check_text with exact counts and no super-linear blow-up; the exhaustive
#: algorithmic shape coverage lives in the unit layer and is not duplicated here.
ADVERSARIAL_SHAPES: dict[str, tuple[Callable[[int], str], Callable[[int], int]]] = {
    "single_line_flood": (_single_line_flood, lambda scale: scale),
    "multi_line_flood": (_multi_line_flood, lambda scale: scale),
}


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL_SHAPES))
def test_adversarial_input_stays_bounded(shape: str, tmp_path: Path):
    """
    [Integration] detectors reference definition integrity ds108: verifies linear-time adversarial handling.

    Scenario:
        Given large, non-fenced Markdown of one representative shape - one giant line of distinct
            undefined references or many single-reference lines, both with strictly non-repeating labels
        When detect routes a doubling input series through the shared scaling helper
        Then every scale produces the exact deterministic finding count (so the pass is never vacuous)
            and the scaling stays under the shared linear bound, proving the single forward-pass use scan
            never rescans a line tail from each bracket.

    Boundaries:
        - Focus: detect() routing of real files through check_text with bounded time (contract F)
        - Non-goal: fence boundaries - this input is deliberately non-fenced bracket prose
        - Fixtures/params: parametrized over the representative adversarial shapes; tmp_path

    On failure, first check:
        - Any accidentally quadratic rescan of the line tail from each ``[``
        - That the exact finding count for this shape still holds at every scale
    """
    build, expected_count = ADVERSARIAL_SHAPES[shape]

    def _build(scale: int) -> tuple[models.Document, ...]:
        """Write the shape's document at ``scale`` and return its Document (untimed).

        :param scale: The flood size to materialize.
        :returns: The single-document tuple for detect().
        """
        path = tmp_path / f"{shape}_{scale}.md"
        path.write_text(build(scale), encoding="utf-8", newline="")
        return (models.Document(path.name, path.stat().st_size),)

    assert_scales_linearly(
        _build,
        lambda documents: references.detect(tmp_path, documents),
        (500, 1_000, 2_000, 4_000),
        expected_count=expected_count,
        label=f"ds108-{shape}",
    )
