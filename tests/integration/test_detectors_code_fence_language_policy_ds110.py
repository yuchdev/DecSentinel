"""Integration tests for DS110 over committed Markdown assets in ``tests/assets/ds110``.

This is Story 07.0 Task 03. Every one of the 14 committed scenarios is loaded in
isolation through the ``asset_case`` fixture and asserted against an explicit,
checked-in expectation table (never against whatever the analyzer currently
emits). DS110 is an *opt-in* policy, so each scenario is exercised with the
EXACT ``Config`` named in its ``fixture-matrix.csv`` ``setup`` column (recorded
once in :data:`SETUP`); the generic Milestone 0005 catalog only asserts the lone
``setup=default`` scenario, so this file owns the proof for the twelve-plus
non-default rows.

Because the policy is off by default, every FINDING scenario is additionally
re-run under the shipped ``Config()`` default and asserted to yield **zero**
findings (:func:`test_default_config_turns_the_policy_off_for_every_finding`).
That proves the rule is genuinely gated off rather than masquerading as an
evaluated clean result. DS110 carries ``opt_in_option="require_fence_languages"``,
so under the default config the engine excludes it from the evaluated-rule count
and names it in ``ScanResult.notice`` as an opt-in rule that is not enabled
(``enabled_rules`` still lists it, by the ratified contract, because selection is
orthogonal to whether an opt-in policy fires). Enabling ``require_fence_languages``
removes the note and restores DS110 to the evaluated count.

Coverage spans the pure ``detect``/``check_text`` entry points, the shared
``scan`` engine, ``select``/``ignore`` (exact plus a genuine ``DS11`` prefix that
contains DS110, the ``DS1`` whole-fast-set prefix, and the negative ``DS2``),
baseline suppression, the text/json/github reports, the CLI exit-code mapping for
a warning rule, cross-rule isolation from DS101-DS106/DS109, config propagation
through both ``docsentinel.toml`` and ``[tool.doc_sentinel]`` for all three DS110
options (including a multi-entry allowlist, label case sensitivity, and invalid
values raising :class:`ConfigError`), a hostile-info-string output-injection
regression, and the linear-time requirement on both single-line and multi-line
adversarial fence floods.

Cross-rule overlaps are proven explicitly rather than hidden. ``DS110`` owns only
fence *metadata*: the unclosed fence in ``malformed_fence_not_repeated`` belongs
to ``DS109`` alone (asserted in :func:`test_ds109_and_ds110_ownership_split`), and
the empty demonstration fences in ``empty_fence_exemption`` /
``empty_fence_strict_policy`` leave their enclosing H1 section visibly empty, which
``DS106`` rightly reports at line 1. Those legitimate siblings are modelled in
:data:`EXPECTED_SIBLINGS` and asserted, never suppressed. See
``docs/dev/markdown_dialect.md`` for the supported ``gfm-subset`` dialect.
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
from docsentinel.detectors import fence_languages
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.timing_helpers import assert_scales_linearly

#: The exact ``Config`` override each committed scenario requires, transcribed
#: from the ``setup`` column of ``fixture-matrix.csv`` (Task 02). Only
#: ``unlabelled_when_disabled`` runs under the shipped defaults; every other case
#: opts the policy in, and three further refine it (strict empty fences, or an
#: explicit allowlist). These values drive this suite's assertions and are never
#: derived from the analyzer.
SETUP: dict[str, dict[str, object]] = {
    "python_fence_label": {"require_fence_languages": True},
    "text_fence_label": {"require_fence_languages": True},
    "unlabelled_when_disabled": {},
    "empty_fence_exemption": {"require_fence_languages": True},
    "custom_language_allowed": {"require_fence_languages": True, "allowed_fence_languages": ("mermaid",)},
    "shell_session_label": {"require_fence_languages": True},
    "malformed_fence_not_repeated": {"require_fence_languages": True},
    "language_with_attributes": {"require_fence_languages": True},
    "unlabelled_python_example": {"require_fence_languages": True},
    "blank_info_string_only": {"require_fence_languages": True},
    "unlabelled_tilde_example": {"require_fence_languages": True},
    "empty_fence_strict_policy": {"require_fence_languages": True, "allow_unlabelled_empty_fences": False},
    "unknown_language_optin": {"require_fence_languages": True, "allowed_fence_languages": ("python",)},
    "multiple_unlabelled_blocks": {"require_fence_languages": True},
}

#: Scenarios whose committed Markdown produces no DS110 finding under their exact
#: matrix ``setup`` config. Each must leave DS110 registered and executed yet
#: report zero findings of its own (``unlabelled_when_disabled`` proves the
#: off-by-default behaviour; the rest are labelled, exempt, allow-listed, or owned
#: by DS109).
CLEAN_CASES: tuple[str, ...] = (
    "python_fence_label",
    "text_fence_label",
    "unlabelled_when_disabled",
    "empty_fence_exemption",
    "custom_language_allowed",
    "shell_session_label",
    "malformed_fence_not_repeated",
    "language_with_attributes",
)

#: Scenarios that each yield one or more DS110 ``warning`` findings under their
#: exact matrix ``setup`` config, mapped to the one-based opener line(s) of the
#: offending fence(s) and a message-evidence substring. These values are fixed by
#: the committed fixtures and the Task 02 spec, not derived from the analyzer.
#: ``multiple_unlabelled_blocks`` deliberately yields exactly two findings, one per
#: unlabelled block, at lines 3 and 7 in ascending source order.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[int, ...], str]] = {
    "unlabelled_python_example": ((3,), "fenced code block has no language label"),
    "blank_info_string_only": ((3,), "fenced code block has no language label"),
    "unlabelled_tilde_example": ((3,), "fenced code block has no language label"),
    "empty_fence_strict_policy": ((3,), "fenced code block has no language label"),
    "unknown_language_optin": ((3,), "is not in the configured allowlist"),
    "multiple_unlabelled_blocks": ((3, 7), "fenced code block has no language label"),
}

#: All 14 promised scenarios in a stable order for parametrization.
ALL_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: The full fast-profile rule set, in registry order, run alongside DS110.
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

#: The legitimate non-DS110 findings a full fast scan adds on these fixtures, each
#: owned by its rightful rule. The empty demonstration fence in both empty-fence
#: cases leaves the H1 section with no visible content, which DS106 reports at
#: line 1. The unclosed fence in ``malformed_fence_not_repeated`` is a delimiter
#: problem owned by DS109 at line 3. Every other case leaves the sibling rules
#: silent, proving a fence-metadata problem never cascades across rules.
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {
    "empty_fence_exemption": (("DS106", 1),),
    "empty_fence_strict_policy": (("DS106", 1),),
    "malformed_fence_not_repeated": (("DS109", 3),),
}


def _config(case: str, **overrides: object) -> Config:
    """Return the fast-profile ``Config`` for ``case`` using its exact matrix setup."""
    return Config(profile="fast", **{**SETUP[case], **overrides})  # type: ignore[arg-type]


def _ds110(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS110 findings from a mixed finding tuple, preserving order."""
    return tuple(finding for finding in findings if finding.rule == "DS110")


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors code fence language policy ds110: verifies the local catalog totals.

    Scenario:
        Given the committed ds110 asset directories and this suite's expectation table
        When clean and finding scenarios are counted
        Then there are exactly 8 clean, 6 finding and 14 total scenarios, matching Task 02, and
        every scenario carries an exact matrix setup entry.

    Boundaries:
        - Focus: this file's expectation table is complete, non-overlapping and setup-complete
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in both CLEAN_CASES and FINDING_EXPECTATIONS, or is missing from SETUP
    """
    assert len(CLEAN_CASES) == 8
    assert len(FINDING_EXPECTATIONS) == 6
    assert len(set(ALL_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)
    assert set(SETUP) == set(ALL_CASES)


def test_ds110_is_registered_as_an_exact_fast_rule():
    """
    [Integration] detectors code fence language policy ds110: verifies fast-profile registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS110 is present with its warning severity and title.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.fence_languages registered DS110 on import
        - Whether DS110 drifted to another profile or severity
    """
    fast_codes = {rule.code for rule in rules_for_profile("fast")}
    assert "DS110" in fast_codes
    rule = next(rule for rule in rules_for_profile("fast") if rule.code == "DS110")
    assert rule.severity == "warning"
    assert rule.title == "Missing language labels on code fences"


@pytest.mark.parametrize("case", ALL_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies detect per committed case.

    Scenario:
        Given one committed ds110 scenario materialized into a fresh tmp_path
        When fence_languages.detect runs over its README.md with the exact matrix setup config
        Then clean cases yield no finding and finding cases yield exactly the expected DS110
        warnings at the expected one-based opener line(s) carrying the expected message evidence,
        in stable ascending source order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes under the exact per-case config
        - Fixtures/params: parametrized over all 14 scenarios; asset_case

    On failure, first check:
        - The expected line(s)/message in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte)
        - Whether SETUP still carries this case's exact matrix overrides
    """
    loaded = asset_case("ds110", case)
    findings = fence_languages.detect(loaded.root, loaded.documents("README.md"), _config(case))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    expected_lines, evidence = FINDING_EXPECTATIONS[case]
    assert len(findings) == len(expected_lines)
    assert tuple(finding.line for finding in findings) == expected_lines
    for finding in findings:
        assert finding.rule == "DS110"
        assert finding.severity == "warning"
        assert finding.path == "README.md"
        assert evidence in finding.message


def test_default_config_turns_the_policy_off_for_every_finding(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies the opt-in gate is genuinely off.

    Scenario:
        Given every FINDING fixture (each of which fires only under its opt-in matrix setup)
        When detect runs with the shipped Config() default and the tree is also scanned under the
        default fast profile
        Then detect yields zero findings for all of them, proving the rule is off by default rather
        than masquerading as an evaluated clean result; and the engine notice excludes DS110 from the
        evaluated count and names it as an opt-in rule that is not enabled (while enabled_rules still
        lists it, by the ratified contract). Enabling require_fence_languages removes that note,
        restores DS110 to the evaluated count and flips the rule on.

    Boundaries:
        - Focus: the off-by-default opt-in gate surfaced honestly in ScanResult.notice
        - Fixtures/params: asset_case

    On failure, first check:
        - The ``require_fence_languages`` short-circuit at the top of check_text
        - rules.opt_in_satisfied and the engine notice's opt-in-rule accounting
    """
    for case in FINDING_EXPECTATIONS:
        loaded = asset_case("ds110", case)
        assert fence_languages.detect(loaded.root, loaded.documents("README.md"), Config()) == ()

    sample = asset_case("ds110", "unlabelled_python_example")
    off = scan(sample.root, config=Config(profile="fast"))
    assert "DS110" in off.enabled_rules  # selection is orthogonal to the opt-in gate (ratified contract)
    assert off.pending == ()
    assert _ds110(off.findings) == ()  # the policy is off, so DS110 evaluates nothing
    # ... and the notice says so honestly: DS110 is excluded from the count and named as not enabled.
    assert (
        off.notice
        == "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
    )

    on = scan(sample.root, config=Config(profile="fast", require_fence_languages=True))
    # DS110's opt-in note disappears and it is counted; DS112, DS115 and DS118 (the other fast
    # opt-in rules) stay off because navigation_indexes, deprecated_references_file and
    # documentation_naming are unset, so they remain named and uncounted.
    assert (
        on.notice
        == "13 fast rule(s) evaluated; opt-in rule(s) not enabled: DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
    )
    assert [finding.line for finding in _ds110(on.findings)] == [3]


@pytest.mark.parametrize("case", ALL_CASES)
def test_scan_isolates_ds110_from_other_fast_rules(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies full fast-scan isolation.

    Scenario:
        Given one committed ds110 scenario scanned under the full fast profile with its exact setup
        When the engine runs DS101-DS106, DS109 and DS110 together
        Then sibling rules add only the documented expected finding(s) (DS106 owns the visibly empty
        section around the empty demonstration fences; DS109 owns the unclosed fence), DS110 ran
        (clean cases prove execution via enabled_rules with zero own findings) and finding cases emit
        exactly the expected DS110 warnings.

    Boundaries:
        - Focus: cross-rule ownership - fence metadata is DS110's alone, documented overlaps aside
        - Fixtures/params: parametrized over all 14 scenarios; asset_case

    On failure, first check:
        - Whether DS101-DS106/DS109 regressed and now fire on fence metadata
        - Whether a new sibling finding appeared beyond the documented EXPECTED_SIBLINGS overlaps
        - Whether DS110 dropped out of enabled_rules (a clean result must mean it ran)
    """
    loaded = asset_case("ds110", case)
    result = scan(loaded.root, config=_config(case))

    assert result.enabled_rules == FAST_RULE_ORDER
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS110")
    assert siblings == EXPECTED_SIBLINGS.get(case, ()), result.findings
    own = _ds110(result.findings)

    if case in CLEAN_CASES:
        assert own == ()
    else:
        expected_lines, evidence = FINDING_EXPECTATIONS[case]
        assert tuple(finding.line for finding in own) == expected_lines
        assert all(evidence in finding.message for finding in own)
    assert loaded.root.is_dir()


def test_ds109_and_ds110_ownership_split(asset_case: Callable[[str, str], AssetCase], tmp_path: Path):
    """
    [Integration] detectors code fence language policy ds110: verifies the DS109/DS110 boundary.

    Scenario:
        Given the committed malformed_fence_not_repeated fixture (an unlabelled fence that is never
        closed) and a synthetic document pairing an unclosed unlabelled fence with a closed one
        When the full fast profile scans them with the policy enabled
        Then DS109 reports only the unclosed fence and DS110 reports nothing for it - one malformed
        fence never cascades into a second finding - while DS110 still flags the separate closed
        unlabelled fence that DS109 leaves alone.

    Boundaries:
        - Focus: the documented DS109 (delimiter validity) vs DS110 (fence metadata) ownership split
        - Fixtures/params: asset_case, tmp_path

    On failure, first check:
        - The ``_is_ds109_owned`` guard skipping fences that never closed
        - Whether DS110 began double-reporting a malformed fence DS109 already owns
    """
    fixture = asset_case("ds110", "malformed_fence_not_repeated")
    result = scan(fixture.root, config=Config(profile="fast", require_fence_languages=True))
    ds109 = [(finding.line, finding.rule) for finding in result.findings if finding.rule == "DS109"]
    assert ds109 == [(3, "DS109")]
    assert _ds110(result.findings) == ()

    (tmp_path / "README.md").write_text("# T\n\n```\nclosed body\n```\n\n```\nnever closed\n", encoding="utf-8")
    mixed = scan(tmp_path, config=Config(profile="fast", require_fence_languages=True))
    ds109_lines = [finding.line for finding in mixed.findings if finding.rule == "DS109"]
    ds110_lines = [finding.line for finding in _ds110(mixed.findings)]
    assert ds109_lines == [7]  # DS109 owns only the unclosed opener
    assert ds110_lines == [3]  # DS110 owns only the closed unlabelled fence


def test_select_narrows_to_ds110_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies select activates only DS110.

    Scenario:
        Given a finding scenario scanned with select pinned to DS110 and the policy enabled
        When the engine resolves the active rule set
        Then only DS110 is enabled and its single expected finding is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS110 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds110", "unlabelled_python_example")

    result = scan(case.root, config=Config(profile="fast", select=("DS110",), require_fence_languages=True))

    assert result.enabled_rules == ("DS110",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS110", 3)]


def test_prefix_select_semantics_for_ds110(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies DS11/DS1/DS2 prefix select semantics.

    Scenario:
        Given a two-finding scenario scanned under the fast profile with the policy enabled
        When it is selected by the genuine prefix ``DS11`` (which contains DS110, DS112, DS113, DS114,
            DS115, DS116 and DS117 but not DS10x), by the whole-fast-set prefix ``DS1``, and by the
            non-matching prefix ``DS2``
        Then ``DS11`` activates the DS11x rules (DS110, DS112, DS113, DS114, DS115, DS116 and DS117)
            and DS110 reports both lines,
            ``DS1`` activates the entire fast set with DS110 among it still reporting both lines, and
            ``DS2`` matches no fast rule so the active set is empty.

    Boundaries:
        - Focus: prefix selector matching - DS110 does NOT start with DS10, so DS11 is the genuine
          including prefix (matching the DS11x rules) while DS1 is the whole-set prefix
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the DS11x rules
        - Whether a non-matching prefix (DS2) wrongly activated any rule
    """
    case = asset_case("ds110", "multiple_unlabelled_blocks")

    ds11x = scan(case.root, config=Config(profile="fast", select=("DS11",), require_fence_languages=True))
    assert ds11x.enabled_rules == ("DS110", "DS112", "DS113", "DS114", "DS115", "DS116", "DS117", "DS118")
    assert [finding.line for finding in _ds110(ds11x.findings)] == [3, 7]

    whole_fast = scan(case.root, config=Config(profile="fast", select=("DS1",), require_fence_languages=True))
    assert "DS110" in whole_fast.enabled_rules
    assert whole_fast.enabled_rules == FAST_RULE_ORDER
    assert [finding.line for finding in _ds110(whole_fast.findings)] == [3, 7]

    none = scan(case.root, config=Config(profile="fast", select=("DS2",), require_fence_languages=True))
    assert none.enabled_rules == ()
    assert _ds110(none.findings) == ()


def test_ignore_suppresses_ds110(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies ignore removes DS110.

    Scenario:
        Given a finding scenario scanned with DS110 ignored and the policy enabled
        When the engine resolves the active rule set
        Then DS110 is absent from enabled_rules and contributes no finding.

    Boundaries:
        - Focus: ignore precedence for a fast rule, proving the detector is genuinely gated off
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules ignore precedence over the default select
        - Whether a DS110 finding survived the ignore
    """
    case = asset_case("ds110", "unlabelled_python_example")

    result = scan(case.root, config=Config(profile="fast", ignore=("DS110",), require_fence_languages=True))

    assert "DS110" not in result.enabled_rules
    assert _ds110(result.findings) == ()


def test_prefix_ignore_semantics_for_ds110(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies DS11/DS1/DS2 prefix ignore semantics.

    Scenario:
        Given a two-finding scenario scanned under the fast profile with the policy enabled
        When it is ignored by the genuine prefix ``DS11``, by the whole-set prefix ``DS1``, and by the
            non-matching prefix ``DS2``
        Then ``DS11`` drops the DS11x rules (leaving the DS10x rules active), ``DS1``
            drops the entire fast set, and ``DS2`` matches no fast rule so DS110 stays active and
            keeps reporting both lines.

    Boundaries:
        - Focus: matches_selector prefix semantics, distinct from the exact-code ignore test
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast rule codes
        - Whether a non-matching prefix (DS2) wrongly suppressed DS110
    """
    case = asset_case("ds110", "multiple_unlabelled_blocks")

    # "DS11" is a prefix of every DS11x rule, so every DS11x rule drops. Assert the remaining
    # set is the full fast set minus the DS11x rules.
    only_dropped = scan(case.root, config=Config(profile="fast", ignore=("DS11",), require_fence_languages=True))
    assert "DS110" not in only_dropped.enabled_rules
    assert only_dropped.enabled_rules == tuple(code for code in FAST_RULE_ORDER if not code.startswith("DS11"))
    assert _ds110(only_dropped.findings) == ()

    # "DS1" is a prefix of every fast rule code, so the whole fast set drops.
    whole_dropped = scan(case.root, config=Config(profile="fast", ignore=("DS1",), require_fence_languages=True))
    assert whole_dropped.enabled_rules == ()
    assert _ds110(whole_dropped.findings) == ()

    # "DS2" matches no fast rule, so DS110 stays active and keeps reporting.
    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",), require_fence_languages=True))
    assert "DS110" in unaffected.enabled_rules
    assert [finding.line for finding in _ds110(unaffected.findings)] == [3, 7]


def test_baseline_suppresses_known_ds110_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies baseline suppression round-trips.

    Scenario:
        Given a finding scenario whose two DS110 findings are recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then both previously known DS110 findings are filtered out while the first scan still reports them.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS110 findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS110 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds110", "multiple_unlabelled_blocks")
    first = scan(case.root, config=Config(profile="fast", select=("DS110",), require_fence_languages=True))
    assert len(_ds110(first.findings)) == 2

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(
            profile="fast",
            select=("DS110",),
            require_fence_languages=True,
            baseline=".docsentinel-baseline.json",
        ),
    )
    assert _ds110(suppressed.findings) == ()


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies text/json/github report stability.

    Scenario:
        Given a DS110 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS110 warning deterministically (schema v1 json,
        a ::warning annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS110 warning across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path and line
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds110", "unlabelled_python_example")
    result = scan(case.root, config=Config(profile="fast", select=("DS110",), require_fence_languages=True))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "warning: README.md: fenced code block has no language label" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS110"]
    assert payload["findings"][0]["rule"] == "DS110"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] == 3

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=README.md,line=3,title=DS110::")


def test_cli_fast_json_scan_reports_ds110_warning_and_exit_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors code fence language policy ds110: verifies the CLI fast json warning path.

    Scenario:
        Given a finding scenario carrying a docsentinel.toml that enables the policy, scanned via
        the CLI with --profile fast --format json
        When the command runs without --strict
        Then it prints a JSON report containing the DS110 warning at line 3 and exits 0,
        because a bare warning is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the discovered docsentinel.toml enabled require_fence_languages
    """
    case = asset_case("ds110", "unlabelled_python_example")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\nrequire_fence_languages = true\n', encoding="utf-8")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds110 = [finding for finding in payload["findings"] if finding["rule"] == "DS110"]
    assert len(ds110) == 1
    finding = ds110[0]
    assert finding["path"] == "README.md"
    assert finding["severity"] == "warning"
    assert finding["line"] == 3
    assert "has no language label" in finding["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds110_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors code fence language policy ds110: verifies --strict promotes the warning.

    Scenario:
        Given a finding scenario with a [tool.doc_sentinel] table enabling the policy, scanned via
        the CLI under the fast profile with --strict
        When the command runs
        Then the DS110 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The _exit_code strict branch for non-deep profiles
        - Whether DS110 still produces a finding under the strict run
    """
    case = asset_case("ds110", "multiple_unlabelled_blocks")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nrequire_fence_languages = true\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors code fence language policy ds110: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario with the policy enabled via docsentinel.toml scanned via the CLI
        When the command runs under the fast profile
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: non-blocking exit code when DS110 and its siblings find nothing even with policy on
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a labelled clean fixture accidentally triggers DS110 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds110", "python_fence_label")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\nrequire_fence_languages = true\n', encoding="utf-8")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds110_under_fast(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors code fence language policy ds110: verifies `docsentinel rules` lists DS110.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS110 and its title appear under the fast profile.

    Boundaries:
        - Focus: rules-command surfacing of DS110
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS110
        - The rules-command formatting for fast rules
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS110: Missing language labels on code fences" in captured.out


def test_standalone_toml_require_fence_languages_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies docsentinel.toml require_fence_languages.

    Scenario:
        Given the unlabelled_python_example fixture scanned first with no config and then with a
        standalone docsentinel.toml setting require_fence_languages=true
        When scan discovers that config (no injected Config)
        Then the default scan reports nothing (policy off) while the opt-in config reaches DS110 and
        it flags the unlabelled fence at line 3.

    Boundaries:
        - Focus: config discovery and propagation of require_fence_languages via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads require_fence_languages from docsentinel.toml
        - Whether the engine forwards the discovered Config to DS110
    """
    case = asset_case("ds110", "unlabelled_python_example")
    assert _ds110(scan(case.root).findings) == ()

    (case.root / "docsentinel.toml").write_text('profile = "fast"\nrequire_fence_languages = true\n', encoding="utf-8")

    assert [finding.line for finding in _ds110(scan(case.root).findings)] == [3]


def test_pyproject_table_require_fence_languages_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies [tool.doc_sentinel] require_fence_languages.

    Scenario:
        Given the unlabelled_tilde_example fixture with a pyproject.toml [tool.doc_sentinel] table
        setting require_fence_languages=true
        When scan discovers that config
        Then DS110 reports the unlabelled tilde fence at line 3, proving the table-sourced flag reaches
        the rule.

    Boundaries:
        - Focus: config discovery and propagation of require_fence_languages via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] require_fence_languages
        - Whether the engine forwards the discovered Config to DS110
    """
    case = asset_case("ds110", "unlabelled_tilde_example")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nrequire_fence_languages = true\n', encoding="utf-8"
    )

    assert [finding.line for finding in _ds110(scan(case.root).findings)] == [3]


def test_standalone_toml_allow_unlabelled_empty_fences_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies docsentinel.toml empty-fence exemption.

    Scenario:
        Given the empty_fence_exemption fixture (a closed empty fence) with a standalone
        docsentinel.toml enabling the policy and then turning the empty-fence exemption off
        When scan discovers each config
        Then the default exemption leaves the empty fence clean, while allow_unlabelled_empty_fences
        =false reclassifies it as an unlabelled fence and DS110 reports it at line 3.

    Boundaries:
        - Focus: config discovery and propagation of allow_unlabelled_empty_fences via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads allow_unlabelled_empty_fences from docsentinel.toml
        - Whether the value reaches the empty-fence branch of _fence_finding
    """
    case = asset_case("ds110", "empty_fence_exemption")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\nrequire_fence_languages = true\n', encoding="utf-8")
    assert _ds110(scan(case.root).findings) == ()

    (case.root / "docsentinel.toml").write_text(
        'profile = "fast"\nrequire_fence_languages = true\nallow_unlabelled_empty_fences = false\n',
        encoding="utf-8",
    )
    assert [finding.line for finding in _ds110(scan(case.root).findings)] == [3]


def test_pyproject_table_allow_unlabelled_empty_fences_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies [tool.doc_sentinel] empty-fence exemption.

    Scenario:
        Given the empty_fence_strict_policy fixture with a pyproject.toml [tool.doc_sentinel] table
        enabling the policy and disabling the empty-fence exemption
        When scan discovers that config
        Then DS110 reports the empty fence at line 3, proving the table-sourced boolean reaches the rule.

    Boundaries:
        - Focus: config discovery and propagation of allow_unlabelled_empty_fences via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] allow_unlabelled_empty_fences
        - Whether the value reaches the empty-fence branch of _fence_finding
    """
    case = asset_case("ds110", "empty_fence_strict_policy")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nrequire_fence_languages = true\n'
        "allow_unlabelled_empty_fences = false\n",
        encoding="utf-8",
    )

    assert [finding.line for finding in _ds110(scan(case.root).findings)] == [3]


def test_standalone_toml_allowed_fence_languages_allowlist_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies docsentinel.toml multi-entry allowlist.

    Scenario:
        Given the custom_language_allowed fixture (a `mermaid` fence) and the unknown_language_optin
        fixture (a `ruby` fence), each with a standalone docsentinel.toml declaring a multi-entry
        allowlist that lists mermaid but not ruby
        When scan discovers each config
        Then the mermaid fence passes the allowlist (clean) and the ruby fence is flagged at line 3,
        proving a several-entry allowlist is loaded and applied.

    Boundaries:
        - Focus: config discovery and propagation of a multi-entry allowed_fence_languages list
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config parses allowed_fence_languages as a string list from docsentinel.toml
        - Whether allowlist membership reaches _fence_finding
    """
    allowed = (
        'profile = "fast"\nrequire_fence_languages = true\nallowed_fence_languages = ["mermaid", "python", "text"]\n'
    )

    permitted = asset_case("ds110", "custom_language_allowed")
    (permitted.root / "docsentinel.toml").write_text(allowed, encoding="utf-8")
    assert _ds110(scan(permitted.root).findings) == ()

    rejected = asset_case("ds110", "unknown_language_optin")
    (rejected.root / "docsentinel.toml").write_text(allowed, encoding="utf-8")
    flagged = _ds110(scan(rejected.root).findings)
    assert [finding.line for finding in flagged] == [3]
    assert "'ruby'" in flagged[0].message


def test_pyproject_table_allowed_fence_languages_allowlist_propagates(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies [tool.doc_sentinel] multi-entry allowlist.

    Scenario:
        Given the unknown_language_optin fixture (a `ruby` fence) with a pyproject.toml
        [tool.doc_sentinel] table declaring a several-entry allowlist that omits ruby
        When scan discovers that config
        Then DS110 flags the fence at line 3 and the message echoes the rejected `ruby` token.

    Boundaries:
        - Focus: config discovery and propagation of a multi-entry allowed_fence_languages list via the table
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] allowed_fence_languages as a string list
        - Whether allowlist membership reaches _fence_finding
    """
    case = asset_case("ds110", "unknown_language_optin")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nrequire_fence_languages = true\n'
        'allowed_fence_languages = ["python", "bash", "console"]\n',
        encoding="utf-8",
    )

    flagged = _ds110(scan(case.root).findings)
    assert [finding.line for finding in flagged] == [3]
    assert "'ruby'" in flagged[0].message


def test_allowlist_membership_is_case_sensitive(tmp_path: Path):
    """
    [Integration] detectors code fence language policy ds110: verifies label case sensitivity as implemented.

    Scenario:
        Given two documents whose fences carry the labels `Python` and `python` and an allowlist
        containing only the lowercase `python`
        When detect runs with the allowlist
        Then the lowercase label passes and the capitalized `Python` is flagged - the allowlist
        comparison is case-sensitive exactly as the detector performs it, and the message echoes the
        rejected `Python` token.

    Boundaries:
        - Focus: pinning the detector's actual (case-sensitive) allowlist comparison, not an idealized one
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether _fence_finding started case-folding the language before the allowlist check
        - Whether the allowlist reached the detector unchanged
    """
    config = Config(require_fence_languages=True, allowed_fence_languages=("python",))

    lowercase = fence_languages.check_text("```python\nx\n```\n", "README.md", config)
    assert lowercase == ()

    capitalized = fence_languages.check_text("```Python\nx\n```\n", "README.md", config)
    assert [finding.line for finding in capitalized] == [1]
    assert "'Python'" in capitalized[0].message


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("require_fence_languages", '"yes"'),
        ("allow_unlabelled_empty_fences", "1"),
        ("allowed_fence_languages", '"python"'),
    ],
)
def test_invalid_ds110_option_raises_config_error(option: str, value: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml that sets one DS110 option to an invalid value (a non-boolean for
        the two flags or a bare string where an allowlist list is required)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects invalid values for every DS110 option (standalone file)
        - Fixtures/params: parametrized over the three options; asset_case

    On failure, first check:
        - The bool/string-list validation for the named option in config.py
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds110", "unlabelled_python_example")
    (case.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(case.root)


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_allowlist_entry_with_whitespace_is_rejected_through_config_files(
    config_file: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors code fence language policy ds110: verifies whitespace allowlist entries are rejected.

    Scenario:
        Given a committed fixture whose config (a standalone docsentinel.toml or a
        [tool.doc_sentinel] table) declares an allowed_fence_languages entry containing a space
        When scan loads that config
        Then a ConfigError about single-token entries is raised through both config-file forms,
        because a fence language is the first whitespace-delimited token and could never match such
        an entry.

    Boundaries:
        - Focus: the single-token allowlist guard reaches DS110 config through both file forms
        - Fixtures/params: parametrized over the two config-file forms; asset_case

    On failure, first check:
        - The _require_fence_language_list whitespace guard in config.py
        - Whether the table/standalone loaders route allowed_fence_languages through that validator
    """
    case = asset_case("ds110", "unlabelled_python_example")
    if config_file == "docsentinel.toml":
        body = 'profile = "fast"\nrequire_fence_languages = true\nallowed_fence_languages = ["python bash"]\n'
    else:
        body = (
            "[tool.doc_sentinel]\n"
            'profile = "fast"\n'
            "require_fence_languages = true\n"
            'allowed_fence_languages = ["python bash"]\n'
        )
    (case.root / config_file).write_text(body, encoding="utf-8")

    with pytest.raises(ConfigError, match="allowed_fence_languages entries must be single tokens"):
        scan(case.root)


def test_notice_wording_unchanged_when_no_opt_in_rule_is_active(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies the notice keeps its plain wording.

    Scenario:
        Given a clean fixture scanned with select pinned to the ordinary rule DS101 (no opt-in rule active)
        When the engine builds the scan notice
        Then it reads exactly "1 fast rule(s) evaluated." with no opt-in note, proving the opt-in
        accounting only appends a note when an active opt-in rule's policy is off.

    Boundaries:
        - Focus: the no-opt-in-rule branch of the engine notice stays byte-identical to the old wording
        - Fixtures/params: asset_case

    On failure, first check:
        - The ``if off_rules`` branch in engine.scan's notice construction
        - Whether an ordinary rule was wrongly treated as opt-in
    """
    case = asset_case("ds110", "python_fence_label")

    result = scan(case.root, config=Config(profile="fast", select=("DS101",)))

    assert result.enabled_rules == ("DS101",)
    assert result.notice == "1 fast rule(s) evaluated."


def test_notice_when_only_an_off_opt_in_rule_is_selected(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies the notice when only DS110 is selected and off.

    Scenario:
        Given a fixture scanned with select pinned to DS110 while require_fence_languages stays off
        When the engine builds the scan notice
        Then DS110 is the sole active rule yet evaluates nothing, so the notice reads exactly
        "0 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages)."
        - zero evaluated and the one active-but-off opt-in rule named.

    Boundaries:
        - Focus: the opt-in accounting when every active rule is an off opt-in rule
        - Fixtures/params: asset_case

    On failure, first check:
        - The evaluated_count/off_rules computation in engine.scan for a single off opt-in rule
        - Whether the notice still names DS110 and its enabling option
    """
    case = asset_case("ds110", "python_fence_label")

    result = scan(case.root, config=Config(profile="fast", select=("DS110",)))

    assert result.enabled_rules == ("DS110",)
    assert _ds110(result.findings) == ()
    assert result.notice == "0 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages)."


def test_notice_does_not_name_an_ignored_off_opt_in_rule(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies an ignored DS110 is not named as unmet.

    Scenario:
        Given a fixture scanned with DS110 ignored while require_fence_languages stays off
        When the engine builds the scan notice
        Then DS110 is absent from the active set, so it is neither evaluated nor named as "not
        enabled" - the user excluded it. DS112, DS115 and DS118 (the other fast opt-in rules) are
        still active and off, so the notice names only those and reads exactly
        "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS112 (set navigation_indexes),
        DS115 (set deprecated_references_file), DS118 (set documentation_naming)."

    Boundaries:
        - Focus: only active-and-unmet opt-in rules are named; an ignored rule is never mentioned
        - Fixtures/params: asset_case

    On failure, first check:
        - That off_rules is computed over active_codes only, not the whole profile
        - Whether an ignored opt-in rule leaked into the opt-in note
    """
    case = asset_case("ds110", "python_fence_label")

    result = scan(case.root, config=Config(profile="fast", ignore=("DS110",)))

    assert "DS110" not in result.enabled_rules
    assert (
        result.notice
        == "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
    )
    assert "DS110" not in result.notice


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors code fence language policy ds110: verifies repeated scans are stable.

    Scenario:
        Given a two-finding scenario scanned twice over the same materialized root
        When the two DS110 finding tuples are compared
        Then they are equal and report lines 3 and 7, so the detector holds no order-dependent state.

    Boundaries:
        - Focus: determinism of DS110 over a real asset tree, with asserted line counts
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Ordering stability of the shared scanner's fence list
    """
    case = asset_case("ds110", "multiple_unlabelled_blocks")

    first = scan(case.root, config=Config(profile="fast", select=("DS110",), require_fence_languages=True))
    second = scan(case.root, config=Config(profile="fast", select=("DS110",), require_fence_languages=True))

    assert first.findings == second.findings
    assert [finding.line for finding in _ds110(first.findings)] == [3, 7]


def test_crlf_line_numbers_point_at_the_fence_opener(tmp_path: Path):
    """
    [Integration] detectors code fence language policy ds110: verifies CRLF line fidelity.

    Scenario:
        Given a CRLF-terminated document whose unlabelled fence opener sits on line 5
        When detect runs over it with the policy enabled
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input for the fence opener
        - Fixtures/params: tmp_path

    On failure, first check:
        - CRLF handling in the shared scanner's line splitting
        - That the reported line is the fence opener, not its body
    """
    (tmp_path / "README.md").write_bytes(b"# Title\r\n\r\nIntro prose.\r\n\r\n```\r\ncode\r\n```\r\n")

    findings = fence_languages.detect(
        tmp_path, (models.Document("README.md", 1),), Config(require_fence_languages=True)
    )

    assert len(findings) == 1
    assert findings[0].line == 5
    assert "has no language label" in findings[0].message


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors code fence language policy ds110: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes inside an unlabelled fence
        When a fast scan reads it with the policy enabled
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in fence_languages._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"# Title\n\n```\n\xff\xfe\n```\n")

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS110",), require_fence_languages=True))


def test_symlinked_markdown_file_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors code fence language policy ds110: verifies a symlinked target file is skipped.

    Scenario:
        Given a symlink pointing at a Markdown file with an unlabelled fence
        When that symlink is scanned directly with the policy enabled
        Then the engine refuses to inventory the symlinked file rather than following it.

    Boundaries:
        - Focus: the engine's symlink safety for a directly selected file path
        - Fixtures/params: tmp_path

    On failure, first check:
        - The symlink guard in engine.scan for selected files
        - Whether symlinks are silently followed into the scan
    """
    target = tmp_path / "real.md"
    target.write_text("# Title\n\n```\ncode\n```\n", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    with pytest.raises(ValueError, match="Symlinked files are not inventoried"):
        scan(link, config=Config(profile="fast", select=("DS110",), require_fence_languages=True))


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors code fence language policy ds110: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When detect runs over every finding scenario (whose bodies contain code and shell commands)
        Then all expected findings are still produced, proving DS110 opens no socket, makes no
        connection and never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS110 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS110 ever constructs a socket."""
        raise AssertionError("DS110 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS110 ever opens an outbound connection."""
        raise AssertionError("DS110 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS110 ever launches a subprocess."""
        raise AssertionError("DS110 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case, (expected_lines, _evidence) in FINDING_EXPECTATIONS.items():
        loaded = asset_case("ds110", case)
        findings = fence_languages.detect(loaded.root, loaded.documents("README.md"), _config(case))
        assert tuple(finding.line for finding in findings) == expected_lines


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors code fence language policy ds110: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS110 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported,
        proving the fast DS110 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS110's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether fence_languages or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.config import Config\n"
        "from docsentinel.detectors import fence_languages\n"
        "assert fence_languages.check_text('```\\ncode\\n```\\n', 'README.md', "
        "Config(require_fence_languages=True))\n"
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


def test_hostile_info_string_cannot_inject_into_text_or_github_output(tmp_path: Path):
    """
    [Integration] detectors code fence language policy ds110: verifies hostile info strings cannot inject output.

    Scenario:
        Given a fence whose language token carries an ESC byte, a workflow-command payload and a
        literal '%0A', with an allowlist that excludes it so DS110 fires once
        When the scan result is rendered as text and as GitHub workflow commands
        Then the ``!r`` message escapes the ESC (no raw control byte and no injected newline in text),
        the github output is exactly one ``::warning`` line with the ESC still escaped and the literal
        ``%0A`` further escaped to ``%250A`` - so no second workflow command can be smuggled in - and
        the echoed token is bounded to the detector's truncation limit.

    Boundaries:
        - Focus: output-injection safety of DS110 messages across the text and github renderers
        - Fixtures/params: tmp_path

    On failure, first check:
        - That the DS110 allowlist message keeps ``{language!r}`` so control bytes render as escapes
        - reporting._escape_data percent/newline handling for the github format, and _echo truncation
    """
    hostile = "evil\x1b[31m::error%0Afile=x::ypwned"
    (tmp_path / "README.md").write_text(f"# Title\n\n```{hostile}\ncode\n```\n", encoding="utf-8")

    result = scan(
        tmp_path,
        config=Config(
            profile="fast", select=("DS110",), require_fence_languages=True, allowed_fence_languages=("python",)
        ),
    )
    own = _ds110(result.findings)
    assert len(own) == 1  # a single excluded fence -> exactly one finding
    assert "is not in the configured allowlist" in own[0].message

    text = render(result, "text")
    assert "\x1b" not in text  # the ESC byte is repr-escaped, never emitted raw
    assert "\\x1b" in text  # ... and appears as the literal escape sequence
    finding_lines = [line for line in text.splitlines() if "allowlist" in line]
    assert len(finding_lines) == 1  # the literal %0A did not break the message onto a new line
    assert "%0A" in finding_lines[0]

    github = render(result, "github")
    github_lines = github.split("\n")
    assert len(github_lines) == 1  # exactly one ::warning line for the one finding
    assert github_lines[0].startswith("::warning file=README.md,line=3,title=DS110::")
    assert "\x1b" not in github  # no raw control byte survives into the annotation
    assert "%250A" in github  # the literal %0A had its % escaped, so it cannot be a command break


def test_large_allowlist_is_correct_and_bounded(tmp_path: Path):
    """
    [Integration] detectors code fence language policy ds110: verifies a 10k-entry allowlist stays correct and cheap.

    Scenario:
        Given a growing allowlist that omits the fences' language
        When detect runs over one labelled fence that the list excludes and one it includes
        Then the excluded label yields exactly one finding and the included label yields none at every
        allowlist size (so the pass is never vacuous), and growing the allowlist keeps a single lookup
        under the shared linear bound - membership is a set lookup, not a scan of the list.

    Boundaries:
        - Focus: allowlist correctness and bounded membership cost on a pathologically large allowlist
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether allowed_fence_languages is materialized into a frozenset before the membership test
        - Whether the excluded/included counts still hold at scale
    """
    (tmp_path / "README.md").write_text("# T\n\n```ruby\nx\n```\n", encoding="utf-8")
    excluded_doc = (models.Document("README.md", 1),)
    (tmp_path / "included.md").write_text("# T\n\n```lang5\nx\n```\n", encoding="utf-8")
    included_doc = (models.Document("included.md", 1),)

    def _build(size: int) -> Config:
        """Build the enabled Config carrying a ``size``-entry allowlist and assert the included fence stays clean."""
        config = Config(require_fence_languages=True, allowed_fence_languages=tuple(f"lang{i}" for i in range(size)))
        assert fence_languages.detect(tmp_path, included_doc, config) == ()  # lang5 is allow-listed
        return config

    # Scaling is over the ALLOWLIST size, not the document: a per-fence list scan would grow with it
    # while a frozenset lookup stays flat. The excluded count (one ``ruby`` finding) pins non-vacuity.
    assert_scales_linearly(
        _build,
        lambda config: fence_languages.detect(tmp_path, excluded_doc, config),
        (5_000, 10_000, 20_000, 40_000),
        expected_count=1,
        label="ds110-large-allowlist",
    )


def _unlabelled_blocks(scale: int) -> str:
    """Return ``scale`` closed unlabelled backtick fences (one finding each)."""
    return "# Flood\n\n" + "".join("```\ncode\n```\n\n" for _ in range(scale))


def _labelled_blocks(scale: int) -> str:
    """Return ``scale`` closed python-labelled fences (clean, zero findings)."""
    return "# Flood\n\n" + "".join("```python\ncode\n```\n\n" for _ in range(scale))


def _excluded_long_label_blocks(scale: int) -> str:
    """Return ``scale`` fences carrying a long single-token label the allowlist omits (one finding each)."""
    label = "z" * 120  # longer than the 80-char echo bound, so each message exercises truncation
    return "# Flood\n\n" + "".join(f"```{label}\ncode\n```\n\n" for _ in range(scale))


#: A representative subset of adversarial fence shapes mapped to a builder, an exact
#: finding-count formula and the extra ``Config`` overrides each needs. This integration
#: suite only proves detect() routes real files (and config overrides) through to
#: check_text with exact counts and no super-linear blow-up over the file path; the full
#: algorithmic shape coverage -- alternating markers, unclosed openers, the strict
#: empty-fence path, enormous single lines and the large allowlist -- lives in
#: tests/unit/test_detectors_fence_languages_adversarial.py and is not duplicated here.
#: The clean labelled shape sits beside the two non-zero shapes so a zero can never be a
#: dead detector, and the excluded-long-label shape pins config propagation plus truncation.
ADVERSARIAL_SHAPES: dict[str, tuple[Callable[[int], str], Callable[[int], int], dict[str, object]]] = {
    "unlabelled_blocks": (_unlabelled_blocks, lambda scale: scale, {}),
    "labelled_blocks": (_labelled_blocks, lambda _scale: 0, {}),
    "excluded_long_label_blocks": (
        _excluded_long_label_blocks,
        lambda scale: scale,
        {"allowed_fence_languages": ("python",)},
    ),
}


@pytest.mark.parametrize("shape", sorted(ADVERSARIAL_SHAPES))
def test_adversarial_input_stays_bounded(shape: str, tmp_path: Path):
    """
    [Integration] detectors code fence language policy ds110: verifies linear-time adversarial handling.

    Scenario:
        Given large adversarial fence documents of one representative shape with the policy on - many
        unlabelled blocks, many clean labelled blocks, or many long-labelled allowlist-excluded fences
        When detect routes a doubling input series (and the shape's config overrides) through the
        shared scaling helper (small sizes: the algorithmic shape coverage lives in
        tests/unit/test_detectors_fence_languages_adversarial.py)
        Then every scale produces the exact deterministic finding count (so the pass is never vacuous)
        and the scaling stays under the shared linear bound.

    Boundaries:
        - Focus: detect() routing of real files and config overrides through check_text (contract F)
        - Fixtures/params: parametrized over the representative adversarial shapes; tmp_path

    On failure, first check:
        - Any accidentally quadratic scan of the fence list or per-fence span masking
        - That the exact finding count for this shape still holds at every scale
        - Whether the shape's Config override reaches detect()
    """
    build, expected_count, overrides = ADVERSARIAL_SHAPES[shape]
    config = Config(require_fence_languages=True, **overrides)  # type: ignore[arg-type]

    def _build(scale: int) -> tuple[models.Document, ...]:
        """Write the shape's document at ``scale`` and return its Document (untimed)."""
        path = tmp_path / f"{shape}_{scale}.md"
        path.write_text(build(scale), encoding="utf-8", newline="")
        return (models.Document(path.name, path.stat().st_size),)

    assert_scales_linearly(
        _build,
        lambda documents: fence_languages.detect(tmp_path, documents, config),
        (500, 1_000, 2_000, 4_000),
        expected_count=expected_count,
        label=f"ds110-{shape}",
    )
