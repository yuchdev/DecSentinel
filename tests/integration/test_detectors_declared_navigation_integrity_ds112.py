"""Integration tests for DS112 over committed Markdown assets in ``tests/assets/ds112``.

This is Story 09.0 Task 03, the security-sensitive, opt-in configured-navigation
rule. Every one of the 14 committed scenarios is loaded in isolation through the
``asset_case`` fixture and asserted against an explicit, checked-in expectation
table (:data:`SETUP`, :data:`CLEAN_CASES`, :data:`FINDING_EXPECTATIONS`,
:data:`ERROR_CASE`, :data:`EXPECTED_SIBLINGS`) transcribed from the Task 02 manifest,
the ``fixture-matrix`` DS112 rows and the detector's stable message contract, never
derived from whatever the analyzer currently emits. The generic Milestone 0005
fixture catalog executes **none** of the 14 DS112 scenarios -- all carry a non-default
``setup`` -- so this file is the only place their outcomes are proven. For every
scenario the exact ``Config`` is built from its matrix ``setup`` string and the
outcome is asserted through both ``navigation.detect`` and the shared ``scan`` engine:
one-based line, offending path, ``warning`` severity and message meaning for the five
FINDING cases, zero findings for the eight CLEAN cases, and a fail-closed
:class:`ConfigError` (CLI exit 2, no report, no absolute path) for the lone ERROR case.

DS112 is a ``fast``-profile **opt-in** policy rule at ``warning`` severity, gated on
``navigation_indexes`` exactly as DS110 is gated on ``require_fence_languages``. With
no index configured it is registered and selectable yet evaluates nothing, and the
engine notice names it ``DS112 (set navigation_indexes)`` and excludes it from the
evaluated count; once an index is configured it is counted. Coverage follows the
standing threat model
(``docs/security/threat-model-ds112-navigation-integrity-2026-10-23.md``): the
config-injection surface is exercised with injected hostile indexes (absolute, ``..``,
an in-root symlink out, a directory, a glob, a non-Markdown file, a nonexistent path,
a runtime FIFO and a huge file) under the filesystem recorder from
``tests/mock/test_detectors_navigation_oracle.py``, proving each raises a
:class:`ConfigError` (or is bounded-read) without hanging, opening or reading outside
the root; the escaping nav target is DS112's lexical finding and DS116's ``error``
finding with no double stat; a missing nav destination is the documented DS101 + DS112
overlap; a prose link outside any list and a nav-looking link inside a fence are not
navigation; reference-style items are joined to their definitions; and the echoed
target/index path is bounded and ``repr``-escaped so no control byte or resolved
absolute path reaches a report sink.

The file also exercises ``select``/``ignore`` (exact and the ``DS11``/``DS1``/``DS2``
prefixes); baseline round-trips; text/json/github report stability; the CLI warning
exit paths; ``docsentinel rules``/``doctor`` surfacing of the opt-in marker; the four
navigation options through both ``docsentinel.toml`` and ``[tool.doc_sentinel]``
including invalid values; CRLF line fidelity; invalid UTF-8 and an unreadable index
surfacing rather than a false clean; determinism across repeated scans; the fast
stdlib-only import with no network or content execution; and the linear-time
requirement on adversarial navigation floods (single-line, multi-line and a large
``navigation_required`` set) routed through ``detect`` end to end. The exhaustive
algorithmic shape coverage lives in ``tests/unit/test_detectors_navigation.py`` and the
syscall-level containment proofs in ``tests/mock/test_detectors_navigation_oracle.py``;
this suite proves the committed scenarios and the cross-module behaviour. See
``docs/dev/markdown_dialect.md`` for the inherited shared-scanner and list-membership
gaps (indented/block-quoted list items and shortcut references are known false
negatives).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Optional

import pytest

from docsentinel import baseline, cli, models
from docsentinel.config import Config, ConfigError
from docsentinel.detectors import navigation
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.mock.test_detectors_navigation_oracle import (
    _install_recorder,
    _is_under,
    _Recorder,
    _symlink_or_skip,
)
from tests.timing_helpers import assert_scales_linearly

#: The exact navigation ``Config`` override each committed scenario requires,
#: transcribed from the ``setup`` column of ``fixture-matrix`` (Task 02). Only
#: ``navigation_indexes`` (and, for two cases, ``navigation_required``) are set; the
#: ``navigation_unique_targets``/``navigation_check_missing`` sub-checks keep their
#: shipped defaults (both on). These values drive this suite's assertions and are never
#: derived from the analyzer.
SETUP: dict[str, dict[str, object]] = {
    "required_pages_all_listed": {
        "navigation_indexes": ("README.md",),
        "navigation_required": ("docs/guide.md", "docs/api.md"),
    },
    "valid_nested_navigation": {"navigation_indexes": ("README.md", "docs/index.md")},
    "external_navigation_links": {"navigation_indexes": ("README.md",)},
    "missing_required_nav_item": {
        "navigation_indexes": ("README.md",),
        "navigation_required": ("docs/guide.md",),
    },
    "duplicate_navigation_target": {"navigation_indexes": ("README.md",)},
    "missing_navigation_destination": {"navigation_indexes": ("README.md",)},
    "prose_link_outside_list": {"navigation_indexes": ("README.md",)},
    "fragment_navigation_is_local": {"navigation_indexes": ("README.md",)},
    "reference_style_navigation_item": {"navigation_indexes": ("README.md",)},
    "duplicate_with_fragments": {"navigation_indexes": ("README.md",)},
    "missing_index_is_error": {"navigation_indexes": ("docs/missing.md",)},
    "nested_relative_nav_path": {"navigation_indexes": ("docs/index.md",)},
    "fake_nav_in_fence": {"navigation_indexes": ("README.md",)},
    "unsafe_parent_navigation": {"navigation_indexes": ("docs/index.md",)},
}

#: The eight committed CLEAN scenarios: all required targets listed, a nested index,
#: external links, a prose link outside any list, a same-document fragment, a resolved
#: reference-style item, an index-relative nested path, and a nav-looking link buried in
#: a fence must all leave DS112 registered and executed yet report zero findings.
CLEAN_CASES: tuple[str, ...] = (
    "required_pages_all_listed",
    "valid_nested_navigation",
    "external_navigation_links",
    "prose_link_outside_list",
    "fragment_navigation_is_local",
    "reference_style_navigation_item",
    "nested_relative_nav_path",
    "fake_nav_in_fence",
)

#: The five FINDING scenarios, mapped to the ordered ``(line, path, message)`` tuple of
#: each expected DS112 ``warning``. An unlisted required target carries ``line=None`` and
#: is anchored at the first configured index; a duplicate is reported at the later link;
#: a duplicate across fragments echoes the author's raw (still fragmented) second target;
#: an escaping target is a lexical escape finding. Fixed by the committed fixtures and the
#: message contract, not derived from the analyzer.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[Optional[int], str, str], ...]] = {
    "missing_required_nav_item": (
        (None, "README.md", "required navigation target is not listed in the configured navigation: docs/guide.md"),
    ),
    "duplicate_navigation_target": ((6, "README.md", "navigation target is linked more than once: docs/guide.md"),),
    "missing_navigation_destination": ((5, "README.md", "navigation target does not exist: docs/missing.md"),),
    "duplicate_with_fragments": ((6, "README.md", "navigation target is linked more than once: docs/guide.md#setup"),),
    "unsafe_parent_navigation": (
        (5, "docs/index.md", "navigation target escapes the documentation root: ../../secret.md"),
    ),
}

#: The lone ERROR scenario and its exact fail-closed ``ConfigError`` message. The
#: configured index ``docs/missing.md`` is absent, so it is not among the discovered
#: documents and the readiness contract (R3) raises rather than scanning clean.
ERROR_CASE = "missing_index_is_error"
ERROR_MESSAGE = "configured navigation index is not a scanned document: docs/missing.md"

#: The 13 CLEAN + FINDING scenarios asserted through detect() and scan() for an outcome.
OUTCOME_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: All 14 committed scenarios in a stable order.
ALL_CASES: tuple[str, ...] = OUTCOME_CASES + (ERROR_CASE,)

#: The full fast-profile rule set, in registry order, run alongside DS112.
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

#: Legitimate non-DS112 findings a full fast scan adds on the FINDING scenarios, each
#: owned by its rightful rule and transcribed from the fixture content. A missing nav
#: destination is DS101's dangling link *and* DS112's missing target (documented
#: overlap, R6); an escaping nav target is DS116's root-escape error *and* DS112's lexical
#: escape warning (documented overlap, R4/contract E); a broken prose link outside any
#: list is DS101's alone -- DS112 never counts it. Every other case leaves the siblings
#: silent, proving a navigation problem never cascades across rules.
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {
    "missing_navigation_destination": (("DS101", 5),),
    "prose_link_outside_list": (("DS101", 3),),
    "unsafe_parent_navigation": (("DS116", 5),),
}


def _config(case: str, **overrides: object) -> Config:
    """Return the fast-profile ``Config`` for ``case`` using its exact matrix setup.

    :param case: The committed scenario slug.
    :param overrides: Extra ``Config`` keyword overrides merged over the matrix setup.
    :returns: The ``Config`` with ``profile="fast"`` and the scenario's navigation setup.
    """
    return Config(profile="fast", **{**SETUP[case], **overrides})  # type: ignore[arg-type]


def _ds112(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS112 findings from a mixed finding tuple, preserving order.

    :param findings: Findings from a detector or scan.
    :returns: The DS112 subset in the original order.
    """
    return tuple(finding for finding in findings if finding.rule == "DS112")


def _triples(findings: tuple[models.Finding, ...]) -> list[tuple[Optional[int], str, str]]:
    """Return ordered ``(line, path, message)`` triples for a finding tuple.

    :param findings: Findings to describe.
    :returns: The ordered ``(line, path, message)`` triples.
    """
    return [(finding.line, finding.path, finding.message) for finding in findings]


def _injected_config(**navigation_overrides: object) -> Config:
    """Return a ``Config`` built without ``load_config`` validation (library-caller path).

    An injected ``Config`` bypasses the lexical path validation ``load_config`` applies,
    which is exactly the config-injection trust boundary DS112 must defend against (R2).
    Only the four navigation fields the detector reads are populated.

    :param navigation_overrides: Overrides for the ``navigation_*`` fields; unset fields
        take their shipped defaults.
    :returns: The injected ``Config`` instance.
    """
    config = Config.__new__(Config)
    object.__setattr__(config, "navigation_indexes", navigation_overrides.get("navigation_indexes", ()))
    object.__setattr__(config, "navigation_required", navigation_overrides.get("navigation_required", ()))
    object.__setattr__(config, "navigation_unique_targets", navigation_overrides.get("navigation_unique_targets", True))
    object.__setattr__(config, "navigation_check_missing", navigation_overrides.get("navigation_check_missing", True))
    return config


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors declared navigation integrity ds112: verifies the local catalog totals.

    Scenario:
        Given the committed ds112 asset directories and this suite's expectation table
        When the clean, finding and error scenarios are counted
        Then there are exactly 8 clean, 5 finding, 1 error and 14 total scenarios matching Task 02, the
        clean and finding sets are disjoint and error-free, and every scenario carries an exact matrix setup.

    Boundaries:
        - Focus: the expectation table is complete, non-overlapping and matches the 8/5/1 split
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in two outcome sets or is missing from SETUP
    """
    assert len(CLEAN_CASES) == 8
    assert len(FINDING_EXPECTATIONS) == 5
    assert len(set(ALL_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)
    assert ERROR_CASE not in CLEAN_CASES and ERROR_CASE not in FINDING_EXPECTATIONS
    assert set(SETUP) == set(ALL_CASES)


def test_ds112_is_registered_as_an_opt_in_fast_rule():
    """
    [Integration] detectors declared navigation integrity ds112: verifies opt-in fast registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS112 is present with warning severity, its title and opt_in_option="navigation_indexes",
        proving it is an opt-in policy rule like DS110 rather than an always-active rule.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.navigation registered DS112 on import
        - Whether DS112 drifted profile/severity or lost its opt_in_option
    """
    fast = {rule.code: rule for rule in rules_for_profile("fast")}
    assert "DS112" in fast
    rule = fast["DS112"]
    assert rule.severity == "warning"
    assert rule.title == "Declared documentation navigation integrity"
    assert rule.opt_in_option == "navigation_indexes"


@pytest.mark.parametrize("case", OUTCOME_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies detect per committed case.

    Scenario:
        Given one CLEAN or FINDING ds112 scenario materialized into a fresh tmp_path
        When navigation.detect runs over all its documents with the exact matrix setup config
        Then clean cases yield no finding and finding cases yield exactly the expected DS112 warnings at
        the expected one-based line (or None for an unlisted required target), offending path and full
        message, in the detector's deterministic order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes under the exact per-case config
        - Fixtures/params: parametrized over the 13 outcome scenarios; asset_case

    On failure, first check:
        - The expected (line, path, message) in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown or a companion file was altered (both must stay byte-for-byte)
        - Whether SETUP still carries this case's exact matrix overrides
    """
    loaded = asset_case("ds112", case)
    findings = _ds112(navigation.detect(loaded.root, loaded.documents(), _config(case)))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    assert _triples(findings) == list(FINDING_EXPECTATIONS[case])
    for finding in findings:
        assert finding.rule == "DS112"
        assert finding.severity == "warning"


@pytest.mark.parametrize("case", OUTCOME_CASES)
def test_scan_isolated_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the engine reproduces each outcome.

    Scenario:
        Given one CLEAN or FINDING ds112 scenario scanned through the shared engine with select pinned
            to DS112 and the exact matrix setup config
        When scan resolves and runs only DS112
        Then DS112 is the sole enabled rule with nothing pending, and its findings match the exact
            expectation table (zero for clean cases, the expected warnings for finding cases), proving the
            engine path yields the same outcome as the pure detector.

    Boundaries:
        - Focus: the shared scan engine reproduces the detector outcome through config dispatch
        - Fixtures/params: parametrized over the 13 outcome scenarios; asset_case

    On failure, first check:
        - Whether the engine still forwards the effective Config to DS112 (keyword dispatch)
        - Whether select=("DS112",) narrowed the active set to DS112 alone
    """
    loaded = asset_case("ds112", case)
    result = scan(loaded.root, config=_config(case, select=("DS112",)))

    assert result.enabled_rules == ("DS112",)
    assert result.pending == ()
    own = _ds112(result.findings)
    if case in CLEAN_CASES:
        assert own == ()
    else:
        assert _triples(own) == list(FINDING_EXPECTATIONS[case])


def test_detect_raises_readiness_error_for_the_missing_index(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the missing-index readiness error.

    Scenario:
        Given the missing_index_is_error scenario whose configured index docs/missing.md is absent
        When navigation.detect runs with that matrix setup
        Then it raises a ConfigError naming the configured path (never a clean empty-findings result), and
            the message echoes only the bounded configured path, never the resolved absolute root.

    Boundaries:
        - Focus: R3 fail-closed readiness error from the pure detector, not a silent clean
        - Fixtures/params: asset_case

    On failure, first check:
        - The document-membership gate in _require_readable_index (absent index is not a document)
        - That the message carries no resolved absolute path
    """
    loaded = asset_case("ds112", ERROR_CASE)

    with pytest.raises(ConfigError) as excinfo:
        navigation.detect(loaded.root, loaded.documents(), _config(ERROR_CASE))

    message = str(excinfo.value)
    assert message == ERROR_MESSAGE
    assert str(Path(os.path.realpath(loaded.root))) not in message


def test_scan_raises_readiness_error_and_produces_no_clean_result(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the engine propagates the readiness error.

    Scenario:
        Given the missing_index_is_error scenario scanned with DS112 selected and then under the full fast
            profile
        When scan runs DS112 with the absent configured index
        Then both runs raise the readiness ConfigError out of scan (the engine does not catch analyzer
            exceptions and never builds a clean ScanResult), so a dropped detector can never masquerade as a
            clean scan.

    Boundaries:
        - Focus: R3 propagation through the engine for both the isolated and full-profile paths
        - Fixtures/params: asset_case

    On failure, first check:
        - That engine._run_analyzer does not wrap analyzers in try/except
        - Whether a clean ScanResult with empty findings was produced instead of raising
    """
    loaded = asset_case("ds112", ERROR_CASE)

    with pytest.raises(ConfigError, match="docs/missing.md"):
        scan(loaded.root, config=_config(ERROR_CASE, select=("DS112",)))
    with pytest.raises(ConfigError, match="docs/missing.md"):
        scan(loaded.root, config=_config(ERROR_CASE))


def test_cli_readiness_error_exits_two_without_report_or_absolute_path(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the CLI maps the readiness error to exit 2.

    Scenario:
        Given the missing_index_is_error scenario carrying a docsentinel.toml that configures the absent
            navigation index, scanned via the CLI with --profile fast --format json
        When the command runs
        Then it returns exit code 2, prints a "Scan failed" line to stderr with the bounded configured path
            and no resolved absolute root, and emits no JSON report on stdout (no clean result is rendered).

    Boundaries:
        - Focus: R3 end-to-end mapping to the existing config/scan-failure exit code, no report leaked
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI's ``except (ConfigError, ValueError, OSError)`` -> exit 2 path
        - Whether a JSON report was printed before the exception, or an absolute path leaked into stderr
    """
    case = asset_case("ds112", ERROR_CASE)
    (case.root / "docsentinel.toml").write_text(
        'profile = "fast"\nnavigation_indexes = ["docs/missing.md"]\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Scan failed" in captured.err
    assert "docs/missing.md" in captured.err
    assert str(Path(os.path.realpath(case.root))) not in captured.err


def test_opt_in_gate_off_by_default_is_honest_in_the_notice(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the opt-in gate is honestly reported.

    Scenario:
        Given the required_pages_all_listed fixture scanned under the default fast profile (no
            navigation_indexes configured) and then with the index configured
        When the engine builds the scan notice
        Then with no index DS112 stays in enabled_rules (selection is orthogonal to the gate), evaluates
            zero findings, is excluded from the evaluated count and named "DS112 (set navigation_indexes)" in
            the notice; configuring the index counts DS112 (the notice no longer names it) while DS110,
            DS115 and DS118, the other off opt-in rules, stay named.

    Boundaries:
        - Focus: R8 opt-in accounting - a disabled policy never masquerades as an evaluated clean result
        - Fixtures/params: asset_case

    On failure, first check:
        - The navigation_indexes guard at the top of detect and rules.opt_in_satisfied for a tuple option
        - The engine notice's opt-in-rule accounting (off_rules excluded from evaluated_count)
    """
    case = asset_case("ds112", "required_pages_all_listed")

    off = scan(case.root, config=Config(profile="fast"))
    assert "DS112" in off.enabled_rules
    assert off.pending == ()
    assert _ds112(off.findings) == ()
    assert off.notice == (
        "12 fast rule(s) evaluated; opt-in rule(s) not enabled: "
        "DS110 (set require_fence_languages), DS112 (set navigation_indexes), "
        "DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
    )

    on = scan(
        case.root,
        config=Config(
            profile="fast",
            navigation_indexes=("README.md",),
            navigation_required=("docs/guide.md", "docs/api.md"),
        ),
    )
    assert "DS112" not in on.notice
    assert (
        on.notice
        == "13 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
    )
    assert _ds112(on.findings) == ()


def test_cli_rules_tags_ds112_as_opt_in(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies `docsentinel rules` tags the opt-in.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS112 appears under the fast profile tagged "[opt-in: set navigation_indexes]", exactly as
            DS110 is tagged for its own enabling option.

    Boundaries:
        - Focus: rules-command surfacing of DS112 as an opt-in policy rule
        - Fixtures/params: capsys

    On failure, first check:
        - Whether DS112 kept opt_in_option="navigation_indexes"
        - The rules-command opt-in tag formatting
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    ds112_lines = [line for line in captured.out.splitlines() if "DS112:" in line]
    assert ds112_lines == ["  DS112: Declared documentation navigation integrity [opt-in: set navigation_indexes]"]


def test_cli_doctor_counts_ds112_among_the_two_opt_in_rules(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies `docsentinel doctor` counts DS112.

    Scenario:
        Given the installed rule registry
        When the doctor command reports environment readiness
        Then the fast-rule tally reads exactly
            "16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)", so DS112 is
            inside the registered count and is one of the four opt-in rules alongside DS110, DS115 and DS118.

    Boundaries:
        - Focus: doctor's separate accounting of opt-in versus always-active fast rules
        - Fixtures/params: capsys

    On failure, first check:
        - Whether the registered fast-rule count changed when a rule was added
        - Whether DS112 was miscounted as always-active rather than opt-in
    """
    exit_code = cli.main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS112" in {rule.code for rule in rules_for_profile("fast")}
    assert "fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)" in captured.out


def test_cli_fast_json_scan_reports_ds112_warning_and_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the CLI fast json warning path.

    Scenario:
        Given the duplicate_with_fragments fixture (a DS112-only defect with no error sibling) carrying a
            docsentinel.toml that configures the index, scanned via the CLI with --profile fast --format json
            and no --strict
        When the command runs
        Then it prints a JSON report containing the DS112 warning at line 6 and exits 0, because a bare
            warning is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the discovered docsentinel.toml configured navigation_indexes
    """
    case = asset_case("ds112", "duplicate_with_fragments")
    (case.root / "docsentinel.toml").write_text(
        'profile = "fast"\nnavigation_indexes = ["README.md"]\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds112 = [finding for finding in payload["findings"] if finding["rule"] == "DS112"]
    assert len(ds112) == 1
    assert ds112[0]["path"] == "README.md"
    assert ds112[0]["severity"] == "warning"
    assert ds112[0]["line"] == 6
    assert "navigation target is linked more than once" in ds112[0]["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds112_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies --strict promotes the warning.

    Scenario:
        Given the duplicate_navigation_target fixture with a [tool.doc_sentinel] table configuring the
            index, scanned via the CLI under the fast profile with --strict
        When the command runs
        Then the DS112 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The _exit_code strict branch for non-deep profiles
        - Whether DS112 still produces a finding under the strict run
    """
    case = asset_case("ds112", "duplicate_navigation_target")
    (case.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nnavigation_indexes = ["README.md"]\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_select_narrows_to_ds112_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies select activates only DS112.

    Scenario:
        Given the missing_navigation_destination scenario scanned with select pinned to DS112 and the
            index configured
        When the engine resolves the active rule set
        Then only DS112 is enabled and its single expected warning at line 5 is produced, with the DS101
            sibling that a full scan would add dropped.

    Boundaries:
        - Focus: exact-code select resolution for a fast opt-in rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS112 selector
        - Whether DS101 leaked into enabled_rules despite the select
    """
    case = asset_case("ds112", "missing_navigation_destination")

    result = scan(case.root, config=_config("missing_navigation_destination", select=("DS112",)))

    assert result.enabled_rules == ("DS112",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS112", 5)]


def test_prefix_select_and_ignore_semantics_for_ds112(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies DS11/DS1/DS2 select and ignore.

    Scenario:
        Given the missing_navigation_destination scenario (a DS112 warning plus a DS101 sibling) scanned
            under the fast profile with the index configured
        When it is selected by the genuine ``DS11`` prefix (today DS110/DS112/DS113/DS114/DS115/DS116/DS117), the
            whole-set ``DS1`` prefix and the non-matching ``DS2`` prefix, then ignored by the exact code, by
            ``DS11`` and by ``DS2``
        Then ``DS11`` and ``DS1`` keep DS112 active and still reporting line 5, ``DS2`` activates no fast
            rule, the exact and ``DS11`` ignores drop DS112 and its finding, and ``DS2`` leaves it active -
            all expectations derived from FAST_RULE_ORDER, not hard-coded.

    Boundaries:
        - Focus: prefix select and ignore precedence for DS112 against the live fast rule set
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast rule codes
        - Whether a non-matching prefix (DS2) wrongly activated or suppressed DS112
    """
    case = asset_case("ds112", "missing_navigation_destination")
    ds11_prefixed = tuple(code for code in FAST_RULE_ORDER if code.startswith("DS11"))

    ds11x = scan(case.root, config=_config("missing_navigation_destination", select=("DS11",)))
    assert ds11x.enabled_rules == ds11_prefixed
    assert [finding.line for finding in _ds112(ds11x.findings)] == [5]

    whole_fast = scan(case.root, config=_config("missing_navigation_destination", select=("DS1",)))
    assert whole_fast.enabled_rules == FAST_RULE_ORDER
    assert [finding.line for finding in _ds112(whole_fast.findings)] == [5]

    none = scan(case.root, config=_config("missing_navigation_destination", select=("DS2",)))
    assert none.enabled_rules == ()
    assert _ds112(none.findings) == ()

    exact = scan(case.root, config=_config("missing_navigation_destination", ignore=("DS112",)))
    assert "DS112" not in exact.enabled_rules
    assert _ds112(exact.findings) == ()

    by_prefix = scan(case.root, config=_config("missing_navigation_destination", ignore=("DS11",)))
    assert by_prefix.enabled_rules == tuple(code for code in FAST_RULE_ORDER if not code.startswith("DS11"))
    assert _ds112(by_prefix.findings) == ()

    unaffected = scan(case.root, config=_config("missing_navigation_destination", ignore=("DS2",)))
    assert "DS112" in unaffected.enabled_rules
    assert [finding.line for finding in _ds112(unaffected.findings)] == [5]


@pytest.mark.parametrize("case", sorted(EXPECTED_SIBLINGS))
def test_ownership_split_vs_ds101_and_ds116_without_double_reporting(
    case: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the documented cross-rule overlaps.

    Scenario:
        Given a FINDING scenario with a documented sibling (missing_navigation_destination -> DS101 dangling
            link; prose_link_outside_list -> DS101 only; unsafe_parent_navigation -> DS116 root escape) scanned
            under the full fast profile with the index configured
        When DS101-DS117 run together
        Then the only non-DS112 findings are the documented EXPECTED_SIBLINGS at their exact lines - a missing
            nav destination is DS101 + DS112, an escaping nav target is DS116 + DS112, a prose link outside any
            list is DS101 alone with DS112 silent - and no third rule double-reports the same construct.

    Boundaries:
        - Focus: cross-rule ownership (R4/R6/contract E) and the prose-outside-list exclusion
        - Fixtures/params: parametrized over the three overlap scenarios; asset_case

    On failure, first check:
        - Whether a new sibling finding appeared beyond the documented EXPECTED_SIBLINGS overlap
        - Whether DS112 began counting a prose link outside any list
    """
    loaded = asset_case("ds112", case)
    result = scan(loaded.root, config=_config(case))

    assert result.enabled_rules == FAST_RULE_ORDER
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS112")
    assert siblings == EXPECTED_SIBLINGS[case]

    own = _ds112(result.findings)
    if case in FINDING_EXPECTATIONS:
        assert _triples(own) == list(FINDING_EXPECTATIONS[case])
    else:
        assert own == ()


def test_ds116_owned_escape_target_is_never_statted(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the escape finding needs no filesystem I/O.

    Scenario:
        Given the unsafe_parent_navigation index copied into a scan root, a filesystem recorder over every
            reachable stat/open entry point, and a real out-of-root secret.md the ../../secret.md target would
            resolve to
        When a full fast scan runs under the recorder
        Then DS112 emits its lexical escape warning at line 5 and DS116 its escape error at line 5, yet no
            recorded path reaches the out-of-root secret and the secret is never opened - the escaping target is
            reported purely lexically with zero filesystem access (R4).

    Boundaries:
        - Focus: R4 - a DS116-owned escaping nav target is reported lexically, never stat-ed or opened
        - Fixtures/params: asset_case (committed index), tmp_path, monkeypatch, the FS recorder

    On failure, first check:
        - Whether the is_ds116_owned / OUTSIDE_ROOT short-circuit ``continue``s before any resolve/stat
        - Whether the walk began stat-ing the escaped target instead of echoing it lexically
    """
    index_text = asset_case("ds112", "unsafe_parent_navigation").read_text("docs/index.md")
    root = tmp_path / "scanroot"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "index.md").write_text(index_text, encoding="utf-8")
    secret = tmp_path / "secret.md"
    secret.write_text("out-of-root secret", encoding="utf-8")

    config = Config(profile="fast", navigation_indexes=("docs/index.md",))
    canonical = Path(os.path.realpath(root))
    secret_real = os.path.normpath(os.path.realpath(secret))

    scan(root, config=config)  # warm up lazy imports before recording

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)
    result = scan(root, config=config)

    ds112 = _ds112(result.findings)
    assert [(finding.line, finding.message) for finding in ds112] == [
        (5, "navigation target escapes the documentation root: ../../secret.md")
    ]
    ds116 = [(finding.line, finding.rule) for finding in result.findings if finding.rule == "DS116"]
    assert (5, "DS116") in ds116

    assert recorder.paths, "recorder captured no filesystem access; the scan did not run"
    assert secret_real not in recorder.paths, "stat-ed the out-of-root secret"
    assert secret_real not in recorder.opened, "opened the out-of-root secret"
    tmp_real = os.path.normpath(str(tmp_path))
    for recorded in recorder.paths:
        if recorded == tmp_real or _is_under(tmp_real, recorded):
            continue  # a realpath ancestor walk above the root is allowed
        assert _is_under(recorded, str(canonical)), f"touched a path outside the scan root: {recorded}"


def test_fake_nav_in_fence_is_ignored_but_a_plain_list_link_fires(tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies masked-region scoping (R1).

    Scenario:
        Given the fake_nav_in_fence fixture (a nav-looking broken link inside a fenced block) and a second
            document carrying the identical broken link as a plain list item outside any fence
        When navigation.detect runs over each with the index configured
        Then the fenced link is never navigation (zero findings) while the plain list link is flagged as a
            missing destination, proving navigation is scoped over the scanner's masked text and not a regex
            over raw source.

    Boundaries:
        - Focus: R1 scanner-evasion parity - mask only what CommonMark hides
        - Fixtures/params: tmp_path (both an asset-equivalent fenced doc and a plain-list doc)

    On failure, first check:
        - That _masked_lines / _masked_offset_ranges blank fenced spans before the marker test
        - Whether the scoping was replaced by a raw-source scan that sees the fenced link
    """
    config = Config(navigation_indexes=("README.md",))
    fenced = "# Project\n\n```markdown\n- [Fake](docs/does_not_exist.md)\n```\n"
    assert navigation.check_text(fenced, "README.md", Path(os.path.realpath(tmp_path)), config) == ()

    plain = "# Project\n\n- [Fake](docs/does_not_exist.md)\n"
    findings = navigation.check_text(plain, "README.md", Path(os.path.realpath(tmp_path)), config)
    assert [(finding.line, finding.message) for finding in findings] == [
        (3, "navigation target does not exist: docs/does_not_exist.md")
    ]


@pytest.mark.parametrize(
    "masked",
    [
        "# Project\n\n- here is `[x](nope.md)` inline\n",
        "# Project\n\n- item <!-- [x](nope.md) --> end\n",
    ],
)
def test_list_link_inside_inline_code_or_comment_is_not_navigation(masked: str, tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies inline-code/comment masking (R1).

    Scenario:
        Given a navigation list item whose only link sits inside an inline-code span or an HTML comment
            (regions the shared scanner still emits tokens for but a CommonMark renderer hides), contrasted
            with the same list item carrying the link as live text
        When navigation.detect runs with the index configured
        Then the masked link is never navigation (zero findings) while the live link is flagged as a missing
            destination, proving DS112 scopes navigation over the scanner's masked text rather than the raw
            source - the control that a raw-text regex would break.

    Boundaries:
        - Focus: R1 token-level masking via _offset_masked over inline-code and comment spans
        - Fixtures/params: parametrized over the inline-code and comment masks; tmp_path

    On failure, first check:
        - Whether _navigation_links still drops tokens whose offset falls inside a masked span
        - Whether the masked-text scoping was replaced by a raw-source scan
    """
    root = Path(os.path.realpath(tmp_path))
    config = Config(navigation_indexes=("README.md",))

    assert navigation.check_text(masked, "README.md", root, config) == ()

    live = "# Project\n\n- here is [x](nope.md) link\n"
    findings = navigation.check_text(live, "README.md", root, config)
    assert [(finding.line, finding.message) for finding in findings] == [
        (3, "navigation target does not exist: nope.md")
    ]


def test_reference_style_navigation_item_joins_definitions(tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies reference-style nav items resolve (R7).

    Scenario:
        Given a nav list item written as a full reference [Guide][guide] with a [guide] definition, once
            pointing at an existing in-root doc and once at an absent doc
        When navigation.detect runs with missing checking on
        Then the item resolving to the existing doc is clean and the one resolving to the absent doc is a
            missing-destination finding, proving reference uses are joined to their definitions by label.

    Boundaries:
        - Focus: R7 full/collapsed reference-use join to definitions by normalized label
        - Fixtures/params: tmp_path (real files)

    On failure, first check:
        - The reference_uses -> reference_definitions label join in _navigation_links
        - Whether the join stopped resolving the definition target relative to the index
    """
    root = Path(os.path.realpath(tmp_path))
    config = Config(navigation_indexes=("README.md",))

    (root / "docs").mkdir()
    (root / "docs" / "guide.md").write_text("# guide\n", encoding="utf-8")
    present = "# Nav\n\n- [Guide][guide]\n\n[guide]: docs/guide.md\n"
    assert navigation.check_text(present, "README.md", root, config) == ()

    absent = "# Nav\n\n- [Guide][guide]\n\n[guide]: docs/gone.md\n"
    findings = navigation.check_text(absent, "README.md", root, config)
    assert [(finding.line, finding.message) for finding in findings] == [
        (3, "navigation target does not exist: docs/gone.md")
    ]


def test_nested_list_items_are_navigation(tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies indented nested list links are navigation.

    Scenario:
        Given a navigation index whose list nests a second-level item two spaces deep, both linking to
            absent in-root docs
        When navigation.detect runs with the index configured
        Then both the top-level and the two-space-indented nested item are navigation list items (0-3 space
            indent) and each yields a missing-destination finding at its own line.

    Boundaries:
        - Focus: R1 list-marker membership across 0-3 spaces of indentation for nested items
        - Fixtures/params: tmp_path

    On failure, first check:
        - The _LIST_MARKER_RE 0-3 space indent bound in _navigation_list_lines
        - Whether a deeper (>3 space) indent was expected; that is a documented false negative
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "README.md").write_text("# Nav\n\n- [a](x.md)\n  - [b](y.md)\n", encoding="utf-8")

    findings = navigation.detect(root, (models.Document("README.md", 0),), Config(navigation_indexes=("README.md",)))

    assert [(finding.line, finding.message) for finding in findings] == [
        (3, "navigation target does not exist: x.md"),
        (4, "navigation target does not exist: y.md"),
    ]


def test_crlf_line_numbers_point_at_the_navigation_link(tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies CRLF line fidelity.

    Scenario:
        Given a CRLF-terminated index whose only navigation list item sits on line 5 and links to an absent
            doc
        When navigation.detect runs with the index configured
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input for the navigation link
        - Fixtures/params: tmp_path

    On failure, first check:
        - CRLF handling in the shared scanner's line splitting
        - That the reported line is the list-item line, not its surroundings
    """
    (tmp_path / "README.md").write_bytes(b"# Title\r\n\r\nIntro prose.\r\n\r\n- [Gone](docs/gone.md)\r\n")

    findings = navigation.detect(
        tmp_path, (models.Document("README.md", 1),), Config(navigation_indexes=("README.md",))
    )

    assert len(findings) == 1
    assert findings[0].line == 5
    assert findings[0].message == "navigation target does not exist: docs/gone.md"


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a configured navigation index holding invalid UTF-8 bytes
        When a fast scan reads it with DS112 selected and the index configured
        Then the documented readiness ConfigError (R3) is raised instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in navigation._read_index
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"# Title\n\n- [x](docs/g.md)\n\xff\xfe\n")

    with pytest.raises(ConfigError, match="could not be read"):
        scan(tmp_path, config=Config(profile="fast", select=("DS112",), navigation_indexes=("README.md",)))


def test_unreadable_index_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies an unreadable index is not a silent clean.

    Scenario:
        Given a configured navigation index whose read permission is removed
        When a fast scan tries to read it with DS112 selected and the index configured
        Then the documented readiness ConfigError (R3) is raised instead of a misleading zero-finding result,
            so a readiness problem fails closed rather than scanning clean.

    Boundaries:
        - Focus: a filesystem read error surfaces instead of masquerading as clean
        - Fixtures/params: tmp_path (skipped when running as root, which bypasses the mode)

    On failure, first check:
        - Whether navigation._read_index swallowed the read error into a clean scan
        - Whether the test runs as root, where chmod 000 does not block reads
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("running as root bypasses the unreadable-file permission check")
    target = tmp_path / "README.md"
    target.write_text("# Title\n\n- [x](docs/g.md)\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        with pytest.raises(ConfigError, match="could not be read"):
            scan(tmp_path, config=Config(profile="fast", select=("DS112",), navigation_indexes=("README.md",)))
    finally:
        target.chmod(0o644)


def test_baseline_suppresses_known_ds112_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies baseline suppression round-trips.

    Scenario:
        Given the required_pages_all_listed tree extended at runtime with a second index that links two
            distinct missing docs, whose two DS112 findings are recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then both previously known DS112 findings are filtered out while the first scan still reported them,
            so the fingerprints are stable across the two scans.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS112 findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS112 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds112", "required_pages_all_listed")
    (case.root / "nav.md").write_text("# Nav\n\n- [a](docs/gone1.md)\n- [b](docs/gone2.md)\n", encoding="utf-8")
    config = Config(profile="fast", select=("DS112",), navigation_indexes=("nav.md",))

    first = scan(case.root, config=config)
    assert len(_ds112(first.findings)) == 2

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(
            profile="fast",
            select=("DS112",),
            navigation_indexes=("nav.md",),
            baseline=".docsentinel-baseline.json",
        ),
    )
    assert _ds112(suppressed.findings) == ()


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies repeated scans are stable.

    Scenario:
        Given the duplicate_with_fragments scenario scanned twice over the same materialized root
        When the two DS112 finding tuples are compared
        Then they are equal and report the single duplicate at line 6, so the detector holds no
            order-dependent state and the per-scan stat memo does not leak between runs.

    Boundaries:
        - Focus: determinism of DS112 over a real asset tree, with asserted line counts
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Whether the per-scan stat_cache leaked across runs
    """
    case = asset_case("ds112", "duplicate_with_fragments")
    config = _config("duplicate_with_fragments", select=("DS112",))

    first = _ds112(scan(case.root, config=config).findings)
    second = _ds112(scan(case.root, config=config).findings)

    assert first == second
    assert [finding.line for finding in first] == [6]


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors declared navigation integrity ds112: verifies text/json/github report stability.

    Scenario:
        Given a DS112 missing-destination finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS112 warning deterministically (schema v1 json, a ``::warning``
            annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS112 warning across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path, line and message
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds112", "missing_navigation_destination")
    result = scan(case.root, config=_config("missing_navigation_destination", select=("DS112",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "warning: README.md: navigation target does not exist: docs/missing.md" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS112"]
    assert payload["findings"][0]["rule"] == "DS112"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] == 5

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=README.md,line=5,title=DS112::")


def test_hostile_targets_and_index_are_bounded_and_repr_escaped(tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies hostile strings cannot inject output.

    Scenario:
        Given a navigation index whose list item links to a 10,000-character in-root target carrying NUL and
            ESC control bytes (missing on disk), and a separately injected configured index path carrying the
            same control bytes and length (absent)
        When the finding scan is rendered as text and the readiness ConfigError is raised
        Then the finding message and the ConfigError both stay bounded to the echo limit, repr-escape every
            control byte, carry only the author's raw target/path (never the resolved absolute root) and leave
            no raw control byte in the text report.

    Boundaries:
        - Focus: output-injection and information-disclosure safety of DS112 messages and the readiness error
        - Fixtures/params: tmp_path

    On failure, first check:
        - navigation._echo's unicode_escape bound and whether a message leaked a resolved absolute path
        - Whether the readiness ConfigError echoed the raw configured path unbounded
    """
    root = Path(os.path.realpath(tmp_path))
    hostile_target = "docs/\x00\x1b" + ("a" * 10_000) + ".md"
    (root / "README.md").write_text(f"# Nav\n\n- [x]({hostile_target})\n", encoding="utf-8")

    result = scan(root, config=Config(profile="fast", select=("DS112",), navigation_indexes=("README.md",)))
    own = _ds112(result.findings)
    assert len(own) == 1
    message = own[0].message
    assert len(message) < 200
    assert not any(ord(character) < 0x20 or ord(character) == 0x7F for character in message)
    assert str(root) not in message
    assert message.endswith("...")

    text = render(result, "text")
    assert "\x00" not in text and "\x1b" not in text
    assert str(root) not in text

    hostile_index = "docs/\x1b]0;pwned\x07" + ("b" * 10_000) + ".md"
    with pytest.raises(ConfigError) as excinfo:
        navigation.detect(
            root, (models.Document("README.md", 0),), _injected_config(navigation_indexes=(hostile_index,))
        )
    error_message = str(excinfo.value)
    assert len(error_message) < 200
    assert not any(ord(character) < 0x20 or ord(character) == 0x7F for character in error_message)
    assert str(root) not in error_message
    assert error_message.endswith("...")


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_navigation_options_propagate_from_both_config_files(
    config_file: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the four options load from both files.

    Scenario:
        Given the duplicate_navigation_target fixture carrying either a standalone docsentinel.toml or a
            [tool.doc_sentinel] table that sets navigation_indexes and then, in a second run, also turns
            navigation_unique_targets off
        When scan discovers each config (no injected Config)
        Then the index-only config flags the duplicate at line 6, and disabling navigation_unique_targets
            silences it - proving navigation_indexes and navigation_unique_targets both load and reach DS112
            through each config-file form.

    Boundaries:
        - Focus: config discovery and propagation of navigation_indexes/navigation_unique_targets via both forms
        - Fixtures/params: parametrized over the two config-file forms; asset_case

    On failure, first check:
        - Whether load_config reads navigation_indexes/navigation_unique_targets from the given file form
        - Whether the engine forwards the discovered Config to DS112
    """
    case = asset_case("ds112", "duplicate_navigation_target")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (case.root / config_file).write_text(
        f'{prefix}profile = "fast"\nnavigation_indexes = ["README.md"]\n', encoding="utf-8"
    )
    flagged = _ds112(scan(case.root).findings)
    assert [(finding.line, finding.message) for finding in flagged] == [
        (6, "navigation target is linked more than once: docs/guide.md")
    ]

    (case.root / config_file).write_text(
        f'{prefix}profile = "fast"\nnavigation_indexes = ["README.md"]\nnavigation_unique_targets = false\n',
        encoding="utf-8",
    )
    assert _ds112(scan(case.root).findings) == ()


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_navigation_required_and_check_missing_propagate_from_both_config_files(
    config_file: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the remaining two options load from both files.

    Scenario:
        Given the missing_navigation_destination fixture carrying either a standalone docsentinel.toml or a
            [tool.doc_sentinel] table that sets navigation_indexes plus navigation_required for an unlisted doc,
            and then, in a second run, also turns navigation_check_missing off
        When scan discovers each config
        Then the first config reports both the required-not-listed finding and the missing-destination finding,
            while navigation_check_missing=false drops the missing-destination finding yet keeps the required one -
            proving navigation_required and navigation_check_missing both load and reach DS112 through each form.

    Boundaries:
        - Focus: config discovery and propagation of navigation_required/navigation_check_missing via both forms
        - Fixtures/params: parametrized over the two config-file forms; asset_case

    On failure, first check:
        - Whether load_config reads navigation_required/navigation_check_missing from the given file form
        - Whether the navigation_check_missing guard still gates the os.stat probe
    """
    case = asset_case("ds112", "missing_navigation_destination")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (case.root / config_file).write_text(
        f'{prefix}profile = "fast"\nnavigation_indexes = ["README.md"]\nnavigation_required = ["docs/extra.md"]\n',
        encoding="utf-8",
    )
    both = _ds112(scan(case.root).findings)
    messages = {finding.message for finding in both}
    assert "navigation target does not exist: docs/missing.md" in messages
    assert "required navigation target is not listed in the configured navigation: docs/extra.md" in messages

    (case.root / config_file).write_text(
        f'{prefix}profile = "fast"\nnavigation_indexes = ["README.md"]\n'
        'navigation_required = ["docs/extra.md"]\nnavigation_check_missing = false\n',
        encoding="utf-8",
    )
    required_only = _ds112(scan(case.root).findings)
    assert [finding.message for finding in required_only] == [
        "required navigation target is not listed in the configured navigation: docs/extra.md"
    ]


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("navigation_indexes", '"README.md"'),
        ("navigation_required", '"docs/guide.md"'),
        ("navigation_unique_targets", '"yes"'),
        ("navigation_check_missing", '"yes"'),
    ],
)
def test_invalid_navigation_option_raises_config_error(
    option: str,
    value: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml that sets one navigation option to an invalid value (a bare string where a
            path list is required, or a non-boolean for a flag)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects invalid values for every DS112 option (standalone file)
        - Fixtures/params: parametrized over the four options; asset_case

    On failure, first check:
        - The list/bool validation for the named option in config.py
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds112", "required_pages_all_listed")
    (case.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(case.root)


@pytest.mark.parametrize("variant", ["absolute", "parent_traversal", "glob", "non_markdown", "nonexistent"])
def test_injected_hostile_index_raises_without_outside_io(
    variant: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies injected hostile index paths fail closed.

    Scenario:
        Given an injected Config (bypassing load_config validation) whose navigation_indexes names a hostile
            path - an absolute path, a ../ traversal, a glob, an excluded non-Markdown file, or a nonexistent
            doc - scanned under a filesystem recorder over every reachable entry point
        When navigation.detect runs
        Then each raises a ConfigError (never a clean result), and the recorder shows DS112 opened nothing
            under the recorder and touched no path outside the scan root, so a config-injection PR cannot make
            DS112 open or probe an out-of-root or special path.

    Boundaries:
        - Focus: R2/R3 config-injection containment for the non-blocking hostile index shapes
        - Fixtures/params: parametrized over five hostile index shapes; tmp_path, monkeypatch, the FS recorder

    On failure, first check:
        - The is_ds116_owned / resolver / membership gates in _require_readable_index
        - Whether any path outside the root was opened or stat-ed before the ConfigError
    """
    root = Path(os.path.realpath(tmp_path))
    outside = root.parent / "outside"
    outside.mkdir(exist_ok=True)
    (outside / "secret.md").write_text("secret", encoding="utf-8")
    (root / "notes.txt").write_text("not markdown", encoding="utf-8")
    hostile = {
        "absolute": str(outside / "secret.md"),
        "parent_traversal": "../outside/secret.md",
        "glob": "docs/*.md",
        "non_markdown": "notes.txt",
        "nonexistent": "docs/nope.md",
    }[variant]
    # No document matches the hostile index (notes.txt is committed but excluded from the
    # discovered set), so each hostile path fails the membership/containment gate.
    config = _injected_config(navigation_indexes=(hostile,))

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)

    with pytest.raises(ConfigError):
        navigation.detect(root, (), config)

    secret_real = os.path.normpath(str(outside / "secret.md"))
    assert secret_real not in recorder.opened, "opened the out-of-root secret"
    assert secret_real not in recorder.paths, "stat-ed the out-of-root secret"
    outside_real = os.path.normpath(str(outside))
    assert not any(_is_under(opened, outside_real) for opened in recorder.opened), "opened a path outside the root"


def test_injected_symlink_out_index_raises_without_following(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors declared navigation integrity ds112: verifies an in-root symlink-out index is refused.

    Scenario:
        Given an in-root symlink committed at an index path pointing at a real out-of-root secret, listed by
            identity in an injected Config's documents, scanned under a filesystem recorder
        When navigation.detect runs
        Then it raises a ConfigError (the escapes_via_symlink defence) and the out-of-root secret is never
            opened, so a symlink index cannot read outside the root.

    Boundaries:
        - Focus: R2 - escapes_via_symlink refuses an in-root symlink that resolves outside, with no open
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder; skipped when symlinks are unavailable

    On failure, first check:
        - The escapes_via_symlink branch of _require_readable_index running before _read_index
        - Whether the symlink was followed and the secret opened
    """
    root = Path(os.path.realpath(tmp_path)) / "scanroot"
    root.mkdir()
    outside = Path(os.path.realpath(tmp_path)) / "outside"
    outside.mkdir()
    secret = outside / "secret.md"
    secret.write_text("secret", encoding="utf-8")
    _symlink_or_skip(root / "index.md", "../outside/secret.md")

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)

    with pytest.raises(ConfigError):
        navigation.detect(root, (models.Document("index.md", 0),), _injected_config(navigation_indexes=("index.md",)))

    secret_real = os.path.normpath(os.path.realpath(secret))
    assert secret_real not in recorder.opened, "opened the out-of-root secret through the symlink"


def test_injected_directory_index_raises_without_opening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors declared navigation integrity ds112: verifies a directory index is refused without opening.

    Scenario:
        Given a directory committed where a configured index path should be a file, listed by identity in an
            injected Config's documents, scanned under a filesystem recorder
        When navigation.detect runs
        Then it raises a ConfigError (the os.stat + S_ISREG defence) and never opens the directory path.

    Boundaries:
        - Focus: R2 os.stat + S_ISREG check before any open; never open a non-regular path
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder

    On failure, first check:
        - The stat.S_ISREG branch of _require_readable_index
        - Whether the directory path was opened before the ConfigError
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "docs").mkdir()

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)

    with pytest.raises(ConfigError):
        navigation.detect(root, (models.Document("docs", 0),), _injected_config(navigation_indexes=("docs",)))

    assert os.path.normpath(str(root / "docs")) not in recorder.opened, "opened the directory configured as an index"


def test_fifo_configured_as_index_never_opens_or_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors declared navigation integrity ds112: verifies a FIFO index never blocks or opens.

    Scenario:
        Given a runtime FIFO committed at a configured index path and listed by identity, scanned under a
            filesystem recorder
        When navigation.detect runs inside a worker thread guarded by a hard join timeout
        Then the detector completes promptly (the thread is not alive after the join), raises the non-regular
            readiness ConfigError, and never opens the FIFO path - so a crafted FIFO index can neither wedge the
            scan nor trigger an unbounded read.

    Boundaries:
        - Focus: the HIGH config-injection control (os.stat + S_ISREG before any open on a blocking special file)
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder; skipped where os.mkfifo is unavailable

    On failure, first check:
        - Whether _require_readable_index ran os.stat + stat.S_ISREG before _read_index
        - Whether the regular-file check followed a read that blocks on a FIFO
    """
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo unavailable on this platform")
    root = Path(os.path.realpath(tmp_path))
    fifo = root / "index.md"
    try:
        os.mkfifo(fifo)
    except OSError as error:
        pytest.skip(f"mkfifo failed: {error}")
    fifo_real = os.path.normpath(str(fifo))

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)

    box: dict[str, Exception] = {}

    def _run():
        """Run DS112 over the FIFO index, capturing the raised exception for the main thread."""
        try:
            navigation.detect(
                root, (models.Document("index.md", 0),), _injected_config(navigation_indexes=("index.md",))
            )
        except (ConfigError, OSError) as error:
            # Captured, not muted: re-asserted as a ConfigError on the main thread below. OSError
            # is caught too so a regression that opens the FIFO and fails is reported, not swallowed.
            box["error"] = error

    # A daemon worker so a regression that opens (and blocks on) the FIFO fails this
    # assertion after the join timeout instead of wedging interpreter shutdown.
    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout=15)

    assert not worker.is_alive(), "detect blocked on the FIFO index; the regular-file check opened it"
    assert isinstance(box.get("error"), ConfigError), f"expected a ConfigError, got {box.get('error')!r}"
    assert fifo_real not in recorder.opened, "opened a FIFO configured as an index"


def test_huge_index_read_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the index read is bounded.

    Scenario:
        Given a configured index whose byte length exceeds the read cap, with a navigation list item placed
            only beyond the cap, and the read cap temporarily lowered
        When navigation.detect runs with the full cap and then under the lowered cap
        Then the full-cap run sees the trailing list item and reports its missing destination, while the
            lowered-cap run never reads that far and reports nothing - proving a huge in-root file configured as
            an index is read bounded rather than whole, so it cannot exhaust memory.

    Boundaries:
        - Focus: the bounded index read (_MAX_INDEX_BYTES) against a memory-exhaustion index
        - Fixtures/params: tmp_path, monkeypatch (lowers the cap)

    On failure, first check:
        - Whether _read_index still passes _MAX_INDEX_BYTES to stream.read
        - Whether the cap was read from the module global at call time
    """
    root = Path(os.path.realpath(tmp_path))
    padding = "x" * 400
    body = f"# Nav\n\n{padding}\n\n- [Gone](docs/gone.md)\n"
    (root / "README.md").write_text(body, encoding="utf-8")
    documents = (models.Document("README.md", len(body)),)
    config = Config(navigation_indexes=("README.md",))

    full = navigation.detect(root, documents, config)
    assert [(finding.line, finding.message) for finding in full] == [
        (5, "navigation target does not exist: docs/gone.md")
    ]

    monkeypatch.setattr(navigation, "_MAX_INDEX_BYTES", 50)
    assert navigation.detect(root, documents, config) == ()


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors declared navigation integrity ds112: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS112 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported, proving the
            fast DS112 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS112's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether navigation or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from pathlib import Path\n"
        "from docsentinel.config import Config\n"
        "from docsentinel.detectors import navigation\n"
        "navigation.check_text('- [x](y.md)\\n', 'README.md', Path('/scanroot'), "
        "Config(navigation_indexes=('README.md',)))\n"
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


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors declared navigation integrity ds112: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When navigation.detect runs over every FINDING scenario (whose indexes carry links and reference
            definitions)
        Then all expected findings are still produced, proving DS112 opens no socket, makes no connection and
            never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS112 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS112 ever constructs a socket."""
        raise AssertionError("DS112 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS112 ever opens an outbound connection."""
        raise AssertionError("DS112 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS112 ever launches a subprocess."""
        raise AssertionError("DS112 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case in FINDING_EXPECTATIONS:
        loaded = asset_case("ds112", case)
        findings = _ds112(navigation.detect(loaded.root, loaded.documents(), _config(case)))
        assert _triples(findings) == list(FINDING_EXPECTATIONS[case])


def _single_line_nav_flood(scale: int) -> str:
    """Return one navigation list line linking ``scale`` distinct missing in-root docs.

    Every ``[t{i}](m{i}.md)`` targets a non-repeating missing file, so the shape yields exactly one
    missing-destination finding per link and the ``(line, message)`` dedup never collapses the count.

    :param scale: Number of distinct missing links to pack onto the single list line.
    :returns: The Markdown source text.
    """
    return "# Flood\n\n- " + "".join(f"[t{index}](m{index}.md)" for index in range(scale)) + "\n"


def _multi_line_nav_flood(scale: int) -> str:
    """Return ``scale`` navigation list lines, each linking one distinct missing in-root doc.

    :param scale: Number of list lines (one missing link each).
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + "".join(f"- [t{index}](m{index}.md)\n" for index in range(scale))


#: Representative adversarial navigation-flood shapes mapped to a builder and an exact
#: finding-count formula. Each is deliberately a genuine list with strictly non-repeating
#: missing targets so every unit yields one finding and the dedup never collapses the count.
#: This suite proves only that detect() routes real files through check_text with exact
#: counts and no super-linear blow-up; the exhaustive algorithmic shapes live in
#: tests/unit/test_detectors_navigation.py and are not duplicated here.
FLOOD_SHAPES: dict[str, Callable[[int], str]] = {
    "single_line_nav_flood": _single_line_nav_flood,
    "multi_line_nav_flood": _multi_line_nav_flood,
}


@pytest.mark.parametrize("shape", sorted(FLOOD_SHAPES))
def test_adversarial_navigation_floods_stay_linear(shape: str, tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies linear-time adversarial handling.

    Scenario:
        Given large navigation indexes of one representative shape - one giant list line of distinct missing
            links, or many single-link list lines
        When navigation.detect routes a doubling input series through the shared scaling helper with the index
            configured
        Then every scale produces the exact deterministic finding count (so the pass is never vacuous) and the
            scaling stays under the shared linear bound, proving the masked-text list scan and the memoised stat
            are linear over the file path.

    Boundaries:
        - Focus: detect() routing of real files through check_text with bounded time (threat model MEDIUM DoS)
        - Non-goal: the exhaustive algorithmic shapes, which live in the navigation unit tests
        - Fixtures/params: parametrized over the representative flood shapes; tmp_path

    On failure, first check:
        - Any accidentally quadratic rescan or a stat that is no longer memoised per distinct path
        - That the exact finding count for this shape still holds at every scale
    """
    build = FLOOD_SHAPES[shape]
    config = Config(navigation_indexes=("README.md",))

    def _build(scale: int) -> tuple[models.Document, ...]:
        """Write the shape's index at ``scale`` and return its Document tuple (untimed).

        :param scale: The flood size to materialize.
        :returns: The single-document tuple for detect().
        """
        path = tmp_path / "README.md"
        path.write_text(build(scale), encoding="utf-8", newline="")
        return (models.Document("README.md", path.stat().st_size),)

    assert_scales_linearly(
        _build,
        lambda documents: navigation.detect(tmp_path, documents, config),
        (500, 1_000, 2_000, 4_000),
        expected_count=lambda scale: scale,
        label=f"ds112-{shape}",
    )


def test_navigation_required_check_stays_linear(tmp_path: Path):
    """
    [Integration] detectors declared navigation integrity ds112: verifies the required check is not quadratic.

    Scenario:
        Given an index listing the even-numbered docs and a navigation_required set demanding all n docs, with
            missing checking off and a fresh index written per size through a doubling series
        When navigation.detect runs end to end over each materialized root
        Then exactly n/2 unlisted-required findings are produced at every size and the scaling stays under the
            shared linear bound, proving the required check is O(links + required) set membership rather than
            O(required x links).

    Boundaries:
        - Focus: no quadratic required x links; set-based membership over the resolved navigation targets
        - Fixtures/params: tmp_path (a new scan root and index per size)

    On failure, first check:
        - Whether the required loop does a linear scan of the identities per entry
        - Whether identities is a set, not a list
    """

    def _build(size: int) -> tuple[Path, tuple[models.Document, ...], Config]:
        """Create a per-size scan root with an index listing the even docs.

        :param size: Number of navigation_required entries (even).
        :returns: The ``(root, documents, config)`` triple for one detect run.
        """
        root = tmp_path / f"root{size}"
        root.mkdir()
        listed = "".join(f"- [d{index}](docs/d{index}.md)\n" for index in range(0, size, 2))
        (root / "index.md").write_text(listed, encoding="utf-8")
        documents = (models.Document("index.md", 0),)
        config = Config(
            navigation_indexes=("index.md",),
            navigation_required=tuple(f"docs/d{index}.md" for index in range(size)),
            navigation_check_missing=False,
        )
        return root, documents, config

    def _run(payload: tuple[Path, tuple[models.Document, ...], Config]) -> tuple[models.Finding, ...]:
        """Run detect for one pre-built payload.

        :param payload: The ``(root, documents, config)`` triple from ``_build``.
        :returns: The DS112 findings.
        """
        root, documents, config = payload
        return navigation.detect(root, documents, config)

    assert_scales_linearly(
        _build,
        _run,
        (200, 400, 800, 1_600),
        expected_count=lambda size: size // 2,
        label="ds112-required-not-quadratic",
    )
