"""Integration tests for DS104 over committed Markdown assets in ``tests/assets/ds104``.

This is Story 02.0 Task 03. Every one of the 14 committed scenarios is loaded in
isolation through the ``asset_case`` fixture and asserted against an explicit,
checked-in expectation table (never against whatever the analyzer currently
emits). Coverage spans the pure ``detect`` entry point, the shared ``scan``
engine, ``select``/``ignore`` (exact and prefix), baseline suppression, the
text/json/github reports, the CLI exit-code mapping for a warning rule,
cross-rule isolation from DS101-DS103/DS105/DS109, config propagation through
both ``docsentinel.toml`` and ``[tool.doc_sentinel]`` (the ``anchor_collision_policy``
and ``anchor_renderer`` options, policy ``off`` disabling the rule, and invalid
values raising :class:`ConfigError`), and the linear-time requirement on
adversarial (non-fenced) anchor and heading input.

Two cross-rule ownership facts are proven explicitly rather than hidden. The
``anchor_inside_html_comment`` fixture carries a real multi-line HTML comment
that its rightful owner DS102 reports, so that one sibling finding is modelled in
:data:`EXPECTED_SIBLINGS` instead of being suppressed. And the DS101/DS104 split
is asserted directly: DS104 never reports a dangling link, DS101 never reports a
duplicate explicit id.

The supported dialect is the ``gfm-subset`` documented in
``docs/dev/markdown_dialect.md``; these tests exercise its explicit-anchor
identity boundaries (``<a id=...>`` / ``<a name=...>`` tokens, GitHub-style slug
collisions with duplicate-suffixed headings, case sensitivity, fenced/commented/
inline-code exclusion, cross-document scoping, CRLF line fidelity) rather than
full CommonMark/GFM conformance.
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
from docsentinel.detectors import anchors
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.timing_helpers import assert_scales_linearly

#: Scenarios whose committed Markdown has no DS104 collision under the shipped
#: ``Config()`` defaults (policy ``explicit``, renderer ``github``). Each must
#: leave the rule registered and executed yet report zero findings of its own.
CLEAN_CASES: tuple[str, ...] = (
    "duplicate_headings_suffixed",
    "distinct_explicit_anchors",
    "same_anchor_other_files",
    "explicit_different_cases",
    "anchor_inside_code_fence",
    "anchor_inside_html_comment",
    "inline_literal_anchor_text",
    "unicode_heading_normalization",
)

#: Scenarios that each yield one or more DS104 ``warning`` findings, mapped to the
#: exact one-based source line(s) of the offending later anchor(s) and a
#: message-evidence substring. These values are fixed by the committed fixtures
#: and the Task 02 spec, not derived from the analyzer. ``three_anchor_occurrences``
#: deliberately yields exactly two findings (one per later occurrence), proving no
#: pairwise explosion.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[int, ...], str]] = {
    "duplicate_explicit_ids": ((7,), "defined more than once"),
    "duplicate_named_anchors": ((7,), "defined more than once"),
    "explicit_shadow_heading": ((7,), "collides with the generated anchor"),
    "three_anchor_occurrences": ((5, 7), "defined more than once"),
    "indented_html_anchor": ((7,), "defined more than once"),
    "generated_suffix_collision": ((11,), "collides with the generated anchor"),
}

#: All 14 promised scenarios in a stable order for parametrization.
ALL_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: The full fast-profile rule set, in registry order, run alongside DS104.
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

#: The Markdown document(s) each case owns. Every case uses README.md except the
#: two-document cross-scoping case.
CASE_DOCUMENTS: dict[str, tuple[str, ...]] = {"same_anchor_other_files": ("a.md", "b.md")}

#: The legitimate non-DS104 findings a full fast scan may add on these fixtures.
#: anchor_inside_html_comment holds a real multi-line HTML comment that its rightful
#: owner DS102 reports at line 3. duplicate_explicit_ids and three_anchor_occurrences
#: place a heading section whose only body is explicit HTML anchor tags, which render
#: nothing visible, so DS106 rightfully reports those sections as contentless. Every
#: other case must leave the sibling rules silent, proving an anchor-identity problem
#: never cascades across rules (and that DS101 never usurps DS104's duplicate-id
#: territory).
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {
    "anchor_inside_html_comment": (("DS102", 3),),
    "duplicate_explicit_ids": (("DS106", 5), ("DS106", 9)),
    "three_anchor_occurrences": (("DS106", 1),),
}


def _ds104(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS104 findings from a mixed finding tuple, preserving order."""
    return tuple(finding for finding in findings if finding.rule == "DS104")


def _documents(case: str) -> tuple[str, ...]:
    """Return the Markdown document names a case owns, defaulting to README.md."""
    return CASE_DOCUMENTS.get(case, ("README.md",))


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors anchor identity and collisions ds104: verifies the local catalog totals.

    Scenario:
        Given the committed ds104 asset directories and this suite's expectation table
        When clean and finding scenarios are counted
        Then there are exactly 8 clean, 6 finding and 14 total scenarios, matching Task 02.

    Boundaries:
        - Focus: this file's expectation table is complete and non-overlapping
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in both CLEAN_CASES and FINDING_EXPECTATIONS
    """
    assert len(CLEAN_CASES) == 8
    assert len(FINDING_EXPECTATIONS) == 6
    assert len(set(ALL_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)


def test_ds104_is_registered_as_an_exact_fast_rule():
    """
    [Integration] detectors anchor identity and collisions ds104: verifies fast-profile registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS104 is present with its warning severity and title.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.anchors registered DS104 on import
        - Whether DS104 drifted to another profile or severity
    """
    fast_codes = {rule.code for rule in rules_for_profile("fast")}
    assert "DS104" in fast_codes
    rule = next(rule for rule in rules_for_profile("fast") if rule.code == "DS104")
    assert rule.severity == "warning"
    assert rule.title == "Conflicting heading and explicit anchors"


@pytest.mark.parametrize("case", ALL_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies detect per committed case.

    Scenario:
        Given one committed ds104 scenario materialized into a fresh tmp_path
        When anchors.detect runs over its Markdown document(s) with shipped defaults
        Then clean cases yield no finding and finding cases yield exactly the expected DS104
        warnings at the expected one-based line(s) carrying the expected message evidence,
        in stable source order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes, one case per run
        - Fixtures/params: parametrized over all 14 scenarios; asset_case

    On failure, first check:
        - The expected line(s)/message in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte)
    """
    loaded = asset_case("ds104", case)
    findings = anchors.detect(loaded.root, loaded.documents(*_documents(case)))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    expected_lines, evidence = FINDING_EXPECTATIONS[case]
    assert len(findings) == len(expected_lines)
    assert tuple(finding.line for finding in findings) == expected_lines
    for finding in findings:
        assert finding.rule == "DS104"
        assert finding.severity == "warning"
        assert finding.path == "README.md"
        assert evidence in finding.message


@pytest.mark.parametrize("case", ALL_CASES)
def test_scan_isolates_ds104_from_other_fast_rules(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies full fast-scan isolation.

    Scenario:
        Given one committed ds104 scenario scanned under the full fast profile
        When the engine runs DS101-DS103, DS104, DS105 and DS109 together
        Then sibling rules add only the one expected finding (DS102 owns the real HTML comment in
        anchor_inside_html_comment), DS104 ran (clean cases prove execution via enabled_rules with
        zero own findings) and finding cases emit exactly the expected DS104 warnings.

    Boundaries:
        - Focus: cross-rule ownership - an anchor collision is DS104's alone, no cascade or noise
        - Fixtures/params: parametrized over all 14 scenarios; asset_case

    On failure, first check:
        - Whether DS101/DS103/DS105/DS109 regressed and now fire on anchor content
        - Whether a new sibling finding appeared beyond the documented DS102 comment overlap
        - Whether DS104 dropped out of enabled_rules (a clean result must mean it ran)
    """
    result = scan(loaded_root := asset_case("ds104", case).root, config=Config(profile="fast"))

    assert result.enabled_rules == FAST_RULE_ORDER
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS104")
    assert siblings == EXPECTED_SIBLINGS.get(case, ()), result.findings
    own = _ds104(result.findings)

    if case in CLEAN_CASES:
        assert own == ()
    else:
        expected_lines, evidence = FINDING_EXPECTATIONS[case]
        assert tuple(finding.line for finding in own) == expected_lines
        assert all(evidence in finding.message for finding in own)
    assert loaded_root.is_dir()


def test_same_anchor_in_other_files_is_not_a_collision(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies cross-document scoping.

    Scenario:
        Given a.md and b.md that each independently declare the identifier 'details'
        When the two-document tree is scanned and then one duplicate anchor is appended to a.md
        Then the independent cross-document declaration yields zero DS104 findings, while the
        in-file duplicate added to a.md does fire - proving collisions are scoped per document.

    Boundaries:
        - Focus: identity collisions are per-document; two files sharing a name never collide
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether the detector pools anchors across documents instead of scanning each alone
        - Whether the in-file duplicate check still fires once a single file repeats an id
    """
    case = asset_case("ds104", "same_anchor_other_files")

    cross = scan(case.root, config=Config(profile="fast", select=("DS104",)))
    assert _ds104(cross.findings) == ()

    a_path = case.root / "a.md"
    original = a_path.read_text(encoding="utf-8")
    expected_line = len(original.splitlines()) + 1  # original ends with a newline
    a_path.write_text(original + '<a id="details"></a>\n', encoding="utf-8")

    in_file = _ds104(scan(case.root, config=Config(profile="fast", select=("DS104",))).findings)
    assert len(in_file) == 1
    assert in_file[0].path == "a.md"
    assert in_file[0].line == expected_line
    assert "defined more than once" in in_file[0].message


def test_ds101_and_ds104_ownership_split(tmp_path: Path):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies the DS101/DS104 boundary.

    Scenario:
        Given a document with both a dangling anchor link and a duplicate explicit id
        When the full fast profile scans it
        Then DS101 reports only the dangling link and DS104 reports only the duplicate id:
        DS104 never claims the dangling link and DS101 never claims the duplicate id.

    Boundaries:
        - Focus: the documented DS101 (link resolution) vs DS104 (anchor identity) ownership split
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether DS104 began reporting unresolved fragments (DS101's job)
        - Whether DS101 began reporting repeated anchor ids (DS104's job)
    """
    (tmp_path / "README.md").write_text(
        '# Guide\n\n[broken](#does-not-exist)\n\n<a id="dup"></a>\n\n<a id="dup"></a>\n',
        encoding="utf-8",
    )

    result = scan(tmp_path, config=Config(profile="fast"))

    ds101 = [(finding.line, finding.message) for finding in result.findings if finding.rule == "DS101"]
    ds104 = [(finding.line, finding.message) for finding in result.findings if finding.rule == "DS104"]
    assert len(ds101) == 1
    assert ds101[0][0] == 3
    assert "does-not-exist" in ds101[0][1]
    assert all("does-not-exist" not in message for _line, message in ds104)
    assert len(ds104) == 1
    assert ds104[0][0] == 7
    assert "defined more than once" in ds104[0][1]
    assert all("dup" not in message for _line, message in ds101)


def test_select_narrows_to_ds104_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies select activates only DS104.

    Scenario:
        Given a finding scenario scanned with select pinned to DS104
        When the engine resolves the active rule set
        Then only DS104 is enabled and its single expected finding is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS104 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds104", "duplicate_explicit_ids")

    result = scan(case.root, config=Config(profile="fast", select=("DS104",)))

    assert result.enabled_rules == ("DS104",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS104", 7)]


def test_prefix_select_includes_ds104(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies the DS1 prefix selects DS104.

    Scenario:
        Given a finding scenario scanned with the DS1 prefix selector
        When the active rule set is resolved
        Then DS104 is among the enabled rules and still reports its finding.

    Boundaries:
        - Focus: prefix selector matching for DS104
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS1 against DS104
        - Whether DS104 was excluded despite the prefix
    """
    case = asset_case("ds104", "explicit_shadow_heading")

    result = scan(case.root, config=Config(profile="fast", select=("DS1",)))

    assert "DS104" in result.enabled_rules
    assert _ds104(result.findings)[0].line == 7


def test_ignore_suppresses_ds104(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies ignore removes DS104.

    Scenario:
        Given a finding scenario scanned with DS104 ignored
        When the engine resolves the active rule set
        Then DS104 is absent from enabled_rules and contributes no finding.

    Boundaries:
        - Focus: ignore precedence for a fast rule, proving the detector is genuinely gated off
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules ignore precedence over the default select
        - Whether a DS104 finding survived the ignore
    """
    case = asset_case("ds104", "duplicate_explicit_ids")

    result = scan(case.root, config=Config(profile="fast", ignore=("DS104",)))

    assert "DS104" not in result.enabled_rules
    assert _ds104(result.findings) == ()


def test_prefix_ignore_semantics_for_ds104(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies DS1/DS2 prefix ignore semantics.

    Scenario:
        Given a finding scenario scanned under the fast profile
        When it is scanned once with the genuine prefix ignore ``DS1`` and once with the
            non-matching prefix ``DS2``
        Then ``DS1`` matches every fast DS1xx rule - so effective_rules (ignore taking precedence)
            drops the entire fast set, DS104 included - while ``DS2`` matches no fast rule and leaves
            DS104 active and still reporting both expected lines.

    Boundaries:
        - Focus: matches_selector prefix semantics, distinct from the exact-code ignore test
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS1 against every fast DS1xx code
        - Whether a non-matching prefix (DS2) wrongly suppressed DS104
    """
    case = asset_case("ds104", "three_anchor_occurrences")

    # "DS1" is a prefix of every fast rule code (DS101-DS110), so the whole fast set drops.
    suppressed = scan(case.root, config=Config(profile="fast", ignore=("DS1",)))
    assert suppressed.enabled_rules == ()
    assert _ds104(suppressed.findings) == ()

    # "DS2" matches no fast rule, so DS104 stays active and keeps reporting.
    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",)))
    assert "DS104" in unaffected.enabled_rules
    assert [finding.line for finding in _ds104(unaffected.findings)] == [5, 7]


def test_baseline_suppresses_known_ds104_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies baseline suppression round-trips.

    Scenario:
        Given a finding scenario whose two DS104 findings are recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then both previously known DS104 findings are filtered out while the first scan still reports them.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS104 findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS104 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds104", "three_anchor_occurrences")
    first = scan(case.root, config=Config(profile="fast", select=("DS104",)))
    assert len(_ds104(first.findings)) == 2

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS104",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds104(suppressed.findings) == ()


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies text/json/github report stability.

    Scenario:
        Given a DS104 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS104 warning deterministically (schema v1 json,
        a ::warning annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS104 warning across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path and line
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds104", "duplicate_explicit_ids")
    result = scan(case.root, config=Config(profile="fast", select=("DS104",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "warning: README.md: explicit anchor 'setup' is defined more than once" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS104"]
    assert payload["findings"][0]["rule"] == "DS104"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] == 7

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=README.md,line=7,title=DS104::")


def test_cli_fast_json_scan_reports_ds104_warning_and_exit_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies the CLI fast json warning path.

    Scenario:
        Given a finding scenario scanned via the CLI with --profile fast --format json
        When the command runs without --strict
        Then it prints a JSON report containing the DS104 warning at line 7 and exits 0,
        because a bare warning is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the JSON report still includes the DS104 finding
    """
    case = asset_case("ds104", "duplicate_named_anchors")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds104 = [finding for finding in payload["findings"] if finding["rule"] == "DS104"]
    assert len(ds104) == 1
    finding = ds104[0]
    assert finding["path"] == "README.md"
    assert finding["severity"] == "warning"
    assert finding["line"] == 7
    assert "defined more than once" in finding["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds104_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies --strict promotes the warning.

    Scenario:
        Given a finding scenario scanned via the CLI under the fast profile with --strict
        When the command runs
        Then the DS104 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The _exit_code strict branch for non-deep profiles
        - Whether DS104 still produces a finding under the strict run
    """
    case = asset_case("ds104", "explicit_shadow_heading")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario scanned via the CLI under the fast profile
        When the command runs
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: non-blocking exit code when DS104 finds nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS104 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds104", "distinct_explicit_anchors")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds104_under_fast(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies `docsentinel rules` lists DS104.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS104 and its title appear under the fast profile.

    Boundaries:
        - Focus: rules-command surfacing of DS104
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS104
        - The rules-command formatting for fast rules
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS104: Conflicting heading and explicit anchors" in captured.out


def test_standalone_toml_policy_off_disables_ds104(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies docsentinel.toml anchor_collision_policy.

    Scenario:
        Given a finding fixture with a standalone docsentinel.toml setting anchor_collision_policy='off'
        When scan discovers that config (no injected Config)
        Then the loaded policy reaches DS104 and it reports nothing, proving the file-sourced option
        gates the rule off.

    Boundaries:
        - Focus: config discovery and propagation of anchor_collision_policy via the standalone file
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config reads anchor_collision_policy from docsentinel.toml
        - Whether policy 'off' short-circuits DS104 before scanning
    """
    case = asset_case("ds104", "duplicate_explicit_ids")
    (case.root / "docsentinel.toml").write_text(
        'profile = "fast"\nanchor_collision_policy = "off"\n', encoding="utf-8"
    )

    result = scan(case.root)

    assert "DS104" in result.enabled_rules
    assert _ds104(result.findings) == ()


def test_pyproject_table_policy_and_renderer_propagate(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies [tool.doc_sentinel] anchor options.

    Scenario:
        Given a finding fixture with a pyproject.toml [tool.doc_sentinel] table setting
        anchor_collision_policy='explicit' and anchor_renderer='github'
        When scan discovers that config
        Then both options reach DS104 and it still reports its line-7 finding, proving the table is
        read and forwarded for the active (non-default-file) configuration.

    Boundaries:
        - Focus: config discovery and propagation of both anchor options via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] anchor_collision_policy/anchor_renderer
        - Whether the engine forwards the discovered Config to DS104
    """
    case = asset_case("ds104", "duplicate_explicit_ids")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nanchor_collision_policy = "explicit"\nanchor_renderer = "github"\n',
        encoding="utf-8",
    )

    own = _ds104(scan(case.root).findings)
    assert len(own) == 1
    assert own[0].line == 7


def test_pyproject_table_policy_off_disables_ds104(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies [tool.doc_sentinel] policy off.

    Scenario:
        Given a finding fixture with a pyproject.toml [tool.doc_sentinel] table turning
        anchor_collision_policy off
        When scan discovers that config
        Then DS104 reports nothing, proving the table-sourced 'off' value gates the rule.

    Boundaries:
        - Focus: config discovery and propagation of anchor_collision_policy via [tool.doc_sentinel]
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether load_config unwraps [tool.doc_sentinel] anchor_collision_policy
        - Whether 'off' disables the collision scan
    """
    case = asset_case("ds104", "three_anchor_occurrences")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nanchor_collision_policy = "off"\n', encoding="utf-8"
    )

    assert _ds104(scan(case.root).findings) == ()


def test_unsupported_renderer_config_yields_no_confident_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies an unmodelled renderer is honored.

    Scenario:
        Given a finding fixture and an injected Config naming a renderer DS104 does not model
        When detect runs with that config
        Then DS104 emits no confident diagnostics, proving anchor_renderer actually reaches the rule
        and gates its slug-based reasoning (the loader's allowlist is exercised separately).

    Boundaries:
        - Focus: the renderer setting is load-bearing inside the rule, not merely validated at load
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether check_text short-circuits for a non-'github' renderer
        - Whether an injected Config field reaches detect
    """
    case = asset_case("ds104", "duplicate_explicit_ids")

    findings = anchors.detect(
        case.root,
        case.documents("README.md"),
        config=Config(profile="fast", anchor_renderer="mkdocs"),
    )

    assert findings == ()


def test_invalid_anchor_collision_policy_raises_config_error(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies an invalid policy is rejected.

    Scenario:
        Given a docsentinel.toml that sets anchor_collision_policy to an unrecognized value
        When scan loads that config
        Then a ConfigError is raised rather than silently falling back to a default.

    Boundaries:
        - Focus: the config allowlist rejects invalid anchor_collision_policy values (standalone file)
        - Fixtures/params: asset_case

    On failure, first check:
        - The _require_enum allowlist for anchor_collision_policy
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds104", "duplicate_explicit_ids")
    (case.root / "docsentinel.toml").write_text(
        'profile = "fast"\nanchor_collision_policy = "aggressive"\n', encoding="utf-8"
    )

    with pytest.raises(ConfigError, match="anchor_collision_policy"):
        scan(case.root)


def test_invalid_anchor_renderer_raises_config_error(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies an invalid renderer is rejected.

    Scenario:
        Given a pyproject.toml [tool.doc_sentinel] table naming an unsupported anchor_renderer
        When scan loads that config
        Then a ConfigError is raised rather than silently accepting an unmodelled renderer.

    Boundaries:
        - Focus: the config allowlist rejects invalid anchor_renderer values ([tool.doc_sentinel])
        - Fixtures/params: asset_case

    On failure, first check:
        - The _require_enum allowlist for anchor_renderer
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds104", "duplicate_explicit_ids")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nanchor_renderer = "kramdown"\n', encoding="utf-8"
    )

    with pytest.raises(ConfigError, match="anchor_renderer"):
        scan(case.root)


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies repeated scans are stable.

    Scenario:
        Given a finding scenario scanned twice over the same materialized root
        When the two DS104 finding tuples are compared
        Then they are equal, so the detector holds no order-dependent mutable state.

    Boundaries:
        - Focus: determinism of DS104 over a real asset tree, with asserted line counts
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Ordering stability of the shared scanner's anchor list
    """
    case = asset_case("ds104", "three_anchor_occurrences")

    first = scan(case.root, config=Config(profile="fast", select=("DS104",)))
    second = scan(case.root, config=Config(profile="fast", select=("DS104",)))

    assert first.findings == second.findings
    assert [finding.line for finding in _ds104(first.findings)] == [5, 7]


def test_crlf_line_numbers_point_at_the_later_anchor(tmp_path: Path):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies CRLF line fidelity.

    Scenario:
        Given a CRLF-terminated document whose second identical explicit id sits on line 5
        When detect runs over it
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input for the offending later anchor
        - Fixtures/params: tmp_path

    On failure, first check:
        - CRLF handling in the shared scanner's line splitting
        - That the reported line is the later (not the first) occurrence
    """
    (tmp_path / "README.md").write_bytes(b'# Title\r\n\r\n<a id="x"></a>\r\n\r\n<a id="x"></a>\r\n')

    findings = anchors.detect(tmp_path, (models.Document("README.md", 1),))

    assert len(findings) == 1
    assert findings[0].line == 5
    assert "defined more than once" in findings[0].message


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes among duplicate anchors
        When a fast scan reads it
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in anchors._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b'# T\n\n<a id="\xff\xfe"></a>\n<a id="\xff\xfe"></a>\n')

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS104",)))


def test_symlinked_markdown_file_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies a symlinked target file is skipped.

    Scenario:
        Given a symlink pointing at a Markdown file with a duplicate explicit anchor
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
    target.write_text('# T\n\n<a id="x"></a>\n<a id="x"></a>\n', encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    with pytest.raises(ValueError, match="Symlinked files are not inventoried"):
        scan(link, config=Config(profile="fast", select=("DS104",)))


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When detect runs over every finding scenario (whose bodies contain anchor-like markup)
        Then all expected findings are still produced, proving DS104 opens no socket, makes no
        connection and never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS104 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS104 ever constructs a socket."""
        raise AssertionError("DS104 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS104 ever opens an outbound connection."""
        raise AssertionError("DS104 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS104 ever launches a subprocess."""
        raise AssertionError("DS104 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case, (expected_lines, _evidence) in FINDING_EXPECTATIONS.items():
        loaded = asset_case("ds104", case)
        findings = anchors.detect(loaded.root, loaded.documents(*_documents(case)))
        assert tuple(finding.line for finding in findings) == expected_lines


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors anchor identity and collisions ds104: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS104 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported,
        proving the fast DS104 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS104's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether anchors or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.detectors import anchors\n"
        "assert anchors.check_text('<a id=\"x\"></a>\\n<a id=\"x\"></a>\\n', 'README.md')\n"
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


def test_adversarial_anchor_input_stays_bounded(tmp_path: Path):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies linear-time adversarial handling.

    Scenario:
        Given large, non-fenced Markdown documents built from one pathologically long heading line,
        many duplicate headings, many identical explicit anchors, and an unterminated `<a id="` flood
        packed onto a single line
        When detect routes a doubling input series through the shared scaling helper (small sizes:
        the algorithmic proof over the scanner lives in tests/unit/test_markdown_blocks_adversarial.py)
        Then the finding count equals the exact deterministic formula at every size (duplicate headings
        never fire because of GitHub -N suffixes; the identical ids and the flood each report one fewer
        than their occurrence count) and the scaling stays under the shared linear bound.

    Boundaries:
        - Focus: bounded findings plus bounded time routed through detect() (contract F)
        - Non-goal: fence boundaries - this input is deliberately non-fenced heading/anchor markup
        - Fixtures/params: tmp_path

    On failure, first check:
        - Any accidentally quadratic scan of the anchor or heading list
        - That duplicate headings slugged -N never register as collisions
        - That the single-line flood is parsed in time proportional to its length
    """

    def _build(scale: int) -> tuple[models.Document, ...]:
        """Write the combined adversarial document at ``scale`` and return its Document (untimed)."""
        long_title = "x" * scale
        parts = ["# Root", f"## {long_title}"]
        parts += ["## Section"] * scale  # duplicate headings -> GitHub -N suffixes, no finding
        parts += ['<a id="dup"></a>'] * scale  # identical explicit ids -> scale - 1 findings
        parts.append('<a id="' * scale)  # unterminated flood on one line -> scale // 2 - 1 findings
        path = tmp_path / f"case_{scale}.md"
        path.write_text("\n".join(parts) + "\n", encoding="utf-8")
        return (models.Document(path.name, path.stat().st_size),)

    assert_scales_linearly(
        _build,
        lambda documents: anchors.detect(tmp_path, documents),
        (500, 1_000, 2_000, 4_000),
        expected_count=lambda scale: (scale - 1) + (scale // 2 - 1),
        label="ds104-adversarial",
    )


def test_hostile_anchor_id_cannot_inject_into_text_or_github_output(tmp_path: Path):
    """
    [Integration] detectors anchor identity and collisions ds104: verifies hostile ids cannot inject output.

    Scenario:
        Given an explicit id carrying an ESC byte, a workflow-command payload and a literal
        '%0A', declared twice so DS104 fires once
        When the scan result is rendered as text and as GitHub workflow commands
        Then the ``!r`` message escapes the ESC (no raw control byte and no injected newline in
        text), the GitHub output is exactly one ``::warning`` line per finding with the ESC still
        escaped and the literal ``%0A`` further escaped to ``%250A`` - so no second workflow command
        can be smuggled in.

    Boundaries:
        - Focus: output-injection safety of DS104 messages across the text and github renderers
        - Fixtures/params: tmp_path

    On failure, first check:
        - That the DS104 message keeps ``{value!r}`` so control bytes render as escapes
        - reporting._escape_data percent/newline handling for the github format
    """
    hostile = "evil\x1b[31m::error file=/etc/passwd::pwned%0Amore"
    (tmp_path / "README.md").write_text(
        f'# Title\n\n<a id="{hostile}"></a>\n\n<a id="{hostile}"></a>\n', encoding="utf-8"
    )

    result = scan(tmp_path, config=Config(profile="fast", select=("DS104",)))
    own = _ds104(result.findings)
    assert len(own) == 1  # defined twice -> exactly one duplicate finding
    assert "defined more than once" in own[0].message

    text = render(result, "text")
    assert "\x1b" not in text  # the ESC byte is repr-escaped, never emitted raw
    assert "\\x1b" in text  # ... and appears as the literal escape sequence
    finding_lines = [line for line in text.splitlines() if "defined more than once" in line]
    assert len(finding_lines) == 1  # the literal %0A did not break the message onto a new line
    assert "%0A" in finding_lines[0]

    github = render(result, "github")
    github_lines = github.split("\n")
    assert len(github_lines) == 1  # exactly one ::warning line for the one finding
    assert github_lines[0].startswith("::warning file=README.md,line=5,title=DS104::")
    assert "\x1b" not in github  # no raw control byte survives into the annotation
    assert "%250A" in github  # the literal %0A had its % escaped, so it cannot be a command break
