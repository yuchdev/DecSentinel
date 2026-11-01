"""Integration tests for DS115 over committed Markdown assets in ``tests/assets/ds115``.

This is Story 13.0 Task 03, the security-sensitive, opt-in deprecated-references
rule. Every one of the 14 committed scenarios is loaded in isolation through the
``asset_case`` fixture and asserted against an explicit, checked-in expectation table
(:data:`SETUP`, :data:`CLEAN_CASES`, :data:`FINDING_EXPECTATIONS`, :data:`ERROR_CASES`,
:data:`EXPECTED_SIBLINGS`) transcribed from the Task 02 manifest, the ``fixture-matrix``
DS115 rows and the detector's stable message contract -- never derived from whatever the
analyzer currently emits. The generic Milestone 0005 fixture catalog executes **only**
``unconfigured_mapping_is_inert`` (the lone ``default``-setup scenario); the other 13
outcomes carry a non-default ``setup`` and are proven only by this file. For every
scenario the exact ``Config`` is built from its matrix ``setup`` string and the outcome is
asserted through both ``deprecated_refs.detect`` and the shared ``scan`` engine: one-based
line, offending path, ``warning`` severity and message meaning (old token, suggested new,
and provenance = the configured mapping relative path plus the integer entry index), counts
and ordering for the six FINDING cases; zero findings for the six CLEAN cases (including
``unconfigured_mapping_is_inert``, which keeps DS115 in ``enabled_rules`` yet is named in
``ScanResult.notice`` as not enabled and excluded from the evaluated count); and a
fail-closed :class:`ConfigError` (CLI exit 2, no report, no absolute path, no raw
``tomllib`` text) for the two ERROR cases.

DS115 is a ``fast``-profile **opt-in** policy rule at ``warning`` severity, gated on
``deprecated_references_file`` exactly as DS110 is gated on ``require_fence_languages`` and
DS112 on ``navigation_indexes``. With no mapping configured it is registered and selectable
yet evaluates nothing and performs zero filesystem access, and the engine notice names it
``DS115 (set deprecated_references_file)`` and excludes it from the evaluated count; once a
mapping is configured it is counted. Coverage follows the standing threat model
(``docs/security/threat-model-ds115-deprecated-references-2026-10-23.md``): the
config-injection surface (R1/R3) is exercised with injected hostile mapping paths (absolute,
``..``, an in-root symlink out, a directory, a glob, a nonexistent path, a runtime FIFO and
an oversized file) under the filesystem recorder from
``tests/mock/test_detectors_deprecated_oracle.py``, proving each raises a bounded
:class:`ConfigError` without hanging, opening or reading outside the root; hostile mapping
content (bad version, unknown keys, wrong types, bad kind, duplicate/conflicting olds, parse
failure, control bytes, over-cap entry counts) propagates the readiness error end to end
through ``scan``; a deprecated link to an existing and to a missing in-root file is flagged
identically with zero target probe (R9); DS115's "explicitly mapped deprecated name" overlaps
DS101's dangling-link job precisely without a third rule double-reporting (contract E); and
the echoed provenance / configured path is bounded and ``repr``-escaped so no control byte or
resolved absolute path reaches a report sink (R6).

The file also exercises ``select``/``ignore`` (exact and the ``DS11``/``DS1``/``DS2``
prefixes); baseline round-trips; text/json/github report stability; the CLI warning and
readiness exit paths; ``docsentinel rules``/``doctor`` surfacing of the opt-in marker; the
four deprecated options through both ``docsentinel.toml`` and ``[tool.doc_sentinel]``
including invalid values; token boundaries, inline-code/comment masking, multi-word
adjacency, NFC equivalence, regex-metacharacter literalness and the archive ``scope``
exemption through the engine; CRLF line fidelity; an invalid-UTF-8 and an unreadable
**document** surfacing rather than a false clean; determinism across repeated scans; the
fast stdlib-only import with no network or content execution; and the linear-time
requirement on adversarial deprecated floods routed through ``detect`` end to end. The
exhaustive algorithmic shape coverage lives in ``tests/unit/test_detectors_deprecated.py``
and the syscall-level containment proofs in ``tests/mock/test_detectors_deprecated_oracle.py``;
this suite proves the committed scenarios and the cross-module behaviour. See
``docs/dev/markdown_dialect.md`` for the inherited shared-scanner false negatives and the
documented normalization/case policy.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Optional

import pytest

from docsentinel import baseline, cli, models
from docsentinel.config import Config, ConfigError
from docsentinel.detectors import deprecated_refs as dep
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.mock.test_detectors_deprecated_oracle import (
    _install_recorder,
    _is_under,
    _Recorder,
    _symlink_or_skip,
)
from tests.timing_helpers import assert_scales_linearly

#: The exact ``Config`` override each committed scenario requires, transcribed from the
#: ``setup`` column of ``fixture-matrix`` (Task 02). Every configured case names the
#: committed ``mapping.toml`` companion; ``deprecated_casefolded_optin`` additionally turns
#: ``deprecated_case_sensitive`` off; ``unconfigured_mapping_is_inert`` configures nothing
#: (the ``default`` setup); ``mapping_path_outside_root`` supplies an escaping path string
#: whose companion mapping is deliberately not committed (the escape is rejected before any
#: read). These values drive this suite's assertions and are never derived from the analyzer.
SETUP: dict[str, dict[str, object]] = {
    "only_current_module_name": {"deprecated_references_file": "mapping.toml"},
    "historical_archive_exempt": {"deprecated_references_file": "mapping.toml"},
    "substring_of_longer_name": {"deprecated_references_file": "mapping.toml"},
    "deprecated_module_in_prose": {"deprecated_references_file": "mapping.toml"},
    "deprecated_local_link_path": {"deprecated_references_file": "mapping.toml"},
    "deprecated_identifier_code_span": {"deprecated_references_file": "mapping.toml"},
    "deprecated_case_sensitive": {"deprecated_references_file": "mapping.toml"},
    "deprecated_casefolded_optin": {
        "deprecated_references_file": "mapping.toml",
        "deprecated_case_sensitive": False,
    },
    "deprecated_in_fenced_example": {"deprecated_references_file": "mapping.toml"},
    "multiple_occurrences_same_line": {"deprecated_references_file": "mapping.toml"},
    "obsolete_name_with_punctuation": {"deprecated_references_file": "mapping.toml"},
    "unconfigured_mapping_is_inert": {},
    "invalid_mapping_duplicate_key": {"deprecated_references_file": "mapping.toml"},
    "mapping_path_outside_root": {"deprecated_references_file": "../escape.toml"},
}

#: The six committed CLEAN scenarios: prose naming only the current symbol, a bang-excluded
#: historical archive path, the ``APIv1``-not-inside-``APIv10`` substring guard, a
#: case-sensitive non-match, a fenced migration sample exempt by the scanner mask, and the
#: unconfigured-inert case must all leave DS115 registered and executed yet report zero DS115
#: findings.
CLEAN_CASES: tuple[str, ...] = (
    "only_current_module_name",
    "historical_archive_exempt",
    "substring_of_longer_name",
    "deprecated_case_sensitive",
    "deprecated_in_fenced_example",
    "unconfigured_mapping_is_inert",
)

#: The six FINDING scenarios, mapped to the ordered ``(line, path, message)`` tuple of each
#: expected DS115 ``warning``. Every message is the detector's stable contract -- the kind,
#: the bounded old token, the suggested new, and the provenance (configured ``mapping.toml``
#: plus the integer ``[[replacement]]`` index). ``multiple_occurrences_same_line`` is the
#: one-finding-per-occurrence (R10) case, so it carries two identical triples on one line.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[Optional[int], str, str], ...]] = {
    "deprecated_module_in_prose": (
        (3, "README.md", "deprecated prose 'oldmod' should be replaced with 'newmod' (mapping mapping.toml entry 0)"),
    ),
    "deprecated_local_link_path": (
        (
            3,
            "README.md",
            "deprecated link 'docs/old-guide.md' should be replaced with "
            "'docs/new-guide.md' (mapping mapping.toml entry 0)",
        ),
    ),
    "deprecated_identifier_code_span": (
        (
            3,
            "README.md",
            "deprecated identifier 'OldWidget' should be replaced with 'NewWidget' (mapping mapping.toml entry 0)",
        ),
    ),
    "deprecated_casefolded_optin": (
        (3, "README.md", "deprecated prose 'OldName' should be replaced with 'NewName' (mapping mapping.toml entry 0)"),
    ),
    "multiple_occurrences_same_line": (
        (3, "README.md", "deprecated prose 'obso' should be replaced with 'fresh' (mapping mapping.toml entry 0)"),
        (3, "README.md", "deprecated prose 'obso' should be replaced with 'fresh' (mapping mapping.toml entry 0)"),
    ),
    "obsolete_name_with_punctuation": (
        (
            3,
            "README.md",
            "deprecated prose 'OldClass' should be replaced with 'NewClass' (mapping mapping.toml entry 0)",
        ),
    ),
}

#: The two ERROR scenarios and the fail-closed ``ConfigError`` substring each must carry.
#: ``invalid_mapping_duplicate_key`` has two ``[[replacement]]`` entries sharing the same
#: ``old`` (a semantic conflict ``tomllib`` accepts but the DS115 schema validator rejects);
#: ``mapping_path_outside_root`` names a path that escapes the scan root, rejected before any
#: read. Neither is a ``Finding`` and neither yields a clean empty-findings scan (R3).
ERROR_CASES: dict[str, str] = {
    "invalid_mapping_duplicate_key": "conflicts with an earlier entry",
    "mapping_path_outside_root": "escapes the documentation root",
}

#: The 12 CLEAN + FINDING scenarios asserted through detect() and scan() for an outcome.
OUTCOME_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: All 14 committed scenarios in a stable order.
ALL_CASES: tuple[str, ...] = OUTCOME_CASES + tuple(ERROR_CASES)

#: The full fast-profile rule set, in registry order, run alongside DS115.
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

#: Legitimate non-DS115 findings a full fast scan adds on a FINDING scenario, each owned by
#: its rightful rule and transcribed from the fixture content. ``deprecated_local_link_path``
#: links an in-root path that does not exist, so DS101 flags it as a dangling link at the
#: same line DS115 flags the deprecated name -- the documented overlap (R9/contract E):
#: DS115 owns "explicitly mapped deprecated name", DS101 owns existence, and no third rule
#: double-reports the construct.
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {
    "deprecated_local_link_path": (("DS101", 3),),
}


def _config(case: str, **overrides: object) -> Config:
    """Return the fast-profile ``Config`` for ``case`` using its exact matrix setup.

    :param case: The committed scenario slug.
    :param overrides: Extra ``Config`` keyword overrides merged over the matrix setup.
    :returns: The ``Config`` with ``profile="fast"`` and the scenario's deprecated setup.
    """
    return Config(profile="fast", **{**SETUP[case], **overrides})  # type: ignore[arg-type]


def _ds115(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS115 findings from a mixed finding tuple, preserving order.

    :param findings: Findings from a detector or scan.
    :returns: The DS115 subset in the original order.
    """
    return tuple(finding for finding in findings if finding.rule == "DS115")


def _triples(findings: tuple[models.Finding, ...]) -> list[tuple[Optional[int], str, str]]:
    """Return ordered ``(line, path, message)`` triples for a finding tuple.

    :param findings: Findings to describe.
    :returns: The ordered ``(line, path, message)`` triples.
    """
    return [(finding.line, finding.path, finding.message) for finding in findings]


def _injected_config(**overrides: object) -> Config:
    """Return a ``Config`` built without ``load_config`` validation (library-caller path).

    An injected ``Config`` bypasses the lexical path validation ``load_config`` applies,
    which is exactly the config-injection trust boundary DS115 must defend against (R1).
    Only the four deprecated fields the detector reads are populated.

    :param overrides: Overrides for the ``deprecated_*`` fields; unset fields take their
        shipped defaults.
    :returns: The injected ``Config`` instance.
    """
    config = Config.__new__(Config)
    object.__setattr__(config, "deprecated_references_file", overrides.get("deprecated_references_file", ""))
    object.__setattr__(config, "deprecated_check_prose", overrides.get("deprecated_check_prose", True))
    object.__setattr__(config, "deprecated_check_links", overrides.get("deprecated_check_links", True))
    object.__setattr__(config, "deprecated_case_sensitive", overrides.get("deprecated_case_sensitive", True))
    return config


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors deprecated references ds115: verifies the local catalog totals.

    Scenario:
        Given the committed ds115 asset directories and this suite's expectation table
        When the clean, finding and error scenarios are counted
        Then there are exactly 6 clean, 6 finding, 2 error and 14 total scenarios matching Task 02, the
        clean and finding sets are disjoint and error-free, and every scenario carries an exact matrix setup.

    Boundaries:
        - Focus: the expectation table is complete, non-overlapping and matches the 6/6/2 split
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in two outcome sets or is missing from SETUP
    """
    assert len(CLEAN_CASES) == 6
    assert len(FINDING_EXPECTATIONS) == 6
    assert len(ERROR_CASES) == 2
    assert len(set(ALL_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)
    assert set(ERROR_CASES).isdisjoint(set(CLEAN_CASES) | set(FINDING_EXPECTATIONS))
    assert set(SETUP) == set(ALL_CASES)


def test_ds115_is_registered_as_an_opt_in_fast_rule():
    """
    [Integration] detectors deprecated references ds115: verifies opt-in fast registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS115 is present with warning severity, its title and opt_in_option="deprecated_references_file",
        proving it is an opt-in policy rule like DS110/DS112 rather than an always-active rule.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.deprecated_refs registered DS115 on import
        - Whether DS115 drifted profile/severity or lost its opt_in_option
    """
    fast = {rule.code: rule for rule in rules_for_profile("fast")}
    assert "DS115" in fast
    rule = fast["DS115"]
    assert rule.severity == "warning"
    assert rule.title == "Deprecated names and migrated references"
    assert rule.opt_in_option == "deprecated_references_file"


@pytest.mark.parametrize("case", OUTCOME_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies detect per committed case.

    Scenario:
        Given one CLEAN or FINDING ds115 scenario materialized into a fresh tmp_path
        When deprecated_refs.detect runs over all its documents with the exact matrix setup config
        Then clean cases yield no finding and finding cases yield exactly the expected DS115 warnings at
        the expected one-based line, offending path and full message, in the detector's deterministic order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes under the exact per-case config
        - Fixtures/params: parametrized over the 12 outcome scenarios; asset_case

    On failure, first check:
        - The expected (line, path, message) in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown or its mapping.toml companion was altered (both must stay byte-for-byte)
        - Whether SETUP still carries this case's exact matrix overrides
    """
    loaded = asset_case("ds115", case)
    findings = _ds115(dep.detect(loaded.root, loaded.documents(), _config(case)))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    assert _triples(findings) == list(FINDING_EXPECTATIONS[case])
    for finding in findings:
        assert finding.rule == "DS115"
        assert finding.severity == "warning"


@pytest.mark.parametrize("case", OUTCOME_CASES)
def test_scan_isolated_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies the engine reproduces each outcome.

    Scenario:
        Given one CLEAN or FINDING ds115 scenario scanned through the shared engine with select pinned to
            DS115 and the exact matrix setup config
        When scan resolves and runs only DS115
        Then DS115 is the sole enabled rule with nothing pending, and its findings match the exact
            expectation table (zero for clean cases, the expected warnings for finding cases), proving the
            engine path yields the same outcome as the pure detector.

    Boundaries:
        - Focus: the shared scan engine reproduces the detector outcome through config dispatch
        - Fixtures/params: parametrized over the 12 outcome scenarios; asset_case

    On failure, first check:
        - Whether the engine still forwards the effective Config to DS115 (keyword dispatch)
        - Whether select=("DS115",) narrowed the active set to DS115 alone
    """
    loaded = asset_case("ds115", case)
    result = scan(loaded.root, config=_config(case, select=("DS115",)))

    assert result.enabled_rules == ("DS115",)
    assert result.pending == ()
    own = _ds115(result.findings)
    if case in CLEAN_CASES:
        assert own == ()
    else:
        assert _triples(own) == list(FINDING_EXPECTATIONS[case])


@pytest.mark.parametrize("case", sorted(ERROR_CASES))
def test_detect_and_scan_raise_readiness_error_for_each_error_case(
    case: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors deprecated references ds115: verifies both ERROR cases fail closed.

    Scenario:
        Given an ERROR ds115 scenario (a conflicting-duplicate mapping, or an escaping mapping path)
            materialized into a fresh tmp_path
        When deprecated_refs.detect runs, and then the shared engine scans with DS115 selected and under the
            full fast profile
        Then every path raises the documented readiness ConfigError (never a clean empty-findings result), the
            message carries the expected bounded phrase, and it never contains the resolved absolute root.

    Boundaries:
        - Focus: R3 fail-closed readiness error from both detect and the engine, not a silent clean
        - Fixtures/params: parametrized over the two ERROR scenarios; asset_case

    On failure, first check:
        - Whether load_mapping raised before reading (escape) or parse_mapping rejected the conflict
        - Whether the engine swallowed the analyzer exception into a clean ScanResult
    """
    loaded = asset_case("ds115", case)
    phrase = ERROR_CASES[case]
    canonical_root = str(Path(os.path.realpath(loaded.root)))

    with pytest.raises(ConfigError, match=phrase) as detect_info:
        dep.detect(loaded.root, loaded.documents(), _config(case))
    assert canonical_root not in str(detect_info.value)

    with pytest.raises(ConfigError, match=phrase):
        scan(loaded.root, config=_config(case, select=("DS115",)))
    with pytest.raises(ConfigError, match=phrase):
        scan(loaded.root, config=_config(case))


@pytest.mark.parametrize("case", sorted(ERROR_CASES))
def test_cli_readiness_error_exits_two_without_report_or_absolute_path(
    case: str,
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors deprecated references ds115: verifies the CLI maps each ERROR to exit 2.

    Scenario:
        Given an ERROR ds115 scenario carrying a docsentinel.toml that configures the offending mapping,
            scanned via the CLI with --profile fast --format json
        When the command runs
        Then it returns exit code 2, prints a "Scan failed" line to stderr with no resolved absolute root and
            no raw tomllib text, and emits no JSON report on stdout (no clean result is rendered).

    Boundaries:
        - Focus: R3 end-to-end mapping to the config/scan-failure exit code, no report leaked
        - Fixtures/params: parametrized over the two ERROR scenarios; asset_case, capsys

    On failure, first check:
        - The CLI's ``except (ConfigError, ValueError, OSError)`` -> exit 2 path
        - Whether a JSON report was printed before the exception, or an absolute path leaked into stderr
    """
    loaded = asset_case("ds115", case)
    mapping_value = SETUP[case]["deprecated_references_file"]
    (loaded.root / "docsentinel.toml").write_text(
        f'profile = "fast"\ndeprecated_references_file = "{mapping_value}"\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(loaded.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Scan failed" in captured.err
    assert str(Path(os.path.realpath(loaded.root))) not in captured.err


def test_unconfigured_mapping_is_named_not_counted_in_the_notice(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies the off opt-in gate is honest (R8).

    Scenario:
        Given the unconfigured_mapping_is_inert fixture (an old-looking token but no mapping) scanned under
            the default fast profile
        When the engine builds the scan notice
        Then DS115 stays in enabled_rules (selection is orthogonal to the gate), evaluates zero findings, is
            excluded from the evaluated count and named "DS115 (set deprecated_references_file)" alongside the
            other three off opt-in rules, so an unconfigured repo never flags an old-looking term and the disabled
            policy never masquerades as an evaluated clean result.

    Boundaries:
        - Focus: R8 opt-in accounting for the unconfigured gate
        - Fixtures/params: asset_case

    On failure, first check:
        - The deprecated_references_file guard at the top of detect and rules.opt_in_satisfied
        - The engine notice's opt-in-rule accounting (off rules excluded from the evaluated count)
    """
    loaded = asset_case("ds115", "unconfigured_mapping_is_inert")

    result = scan(loaded.root, config=Config(profile="fast"))
    assert "DS115" in result.enabled_rules
    assert result.pending == ()
    assert _ds115(result.findings) == ()
    assert result.notice == (
        "12 fast rule(s) evaluated; opt-in rule(s) not enabled: "
        "DS110 (set require_fence_languages), DS112 (set navigation_indexes), "
        "DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
    )


def test_configured_mapping_is_counted_in_the_notice(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies a configured mapping is counted (R8).

    Scenario:
        Given the deprecated_module_in_prose fixture scanned under the full fast profile with its mapping
            configured
        When the engine builds the scan notice
        Then DS115 is counted among the evaluated rules and no longer named in the notice, while DS110,
            DS112 and DS118 (the still-off opt-in rules) stay named, proving a configured mapping makes DS115
            genuinely evaluated even though the gate is a single option.

    Boundaries:
        - Focus: R8 - a configured opt-in rule is counted and dropped from the not-enabled list
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether opt_in_satisfied read the non-empty deprecated_references_file as on
        - The engine notice's evaluated-count accounting when one opt-in rule is enabled
    """
    loaded = asset_case("ds115", "deprecated_module_in_prose")

    result = scan(loaded.root, config=_config("deprecated_module_in_prose"))
    assert "DS115" not in result.notice
    assert result.notice == (
        "13 fast rule(s) evaluated; opt-in rule(s) not enabled: "
        "DS110 (set require_fence_languages), DS112 (set navigation_indexes), "
        "DS118 (set documentation_naming)."
    )
    assert _triples(_ds115(result.findings)) == list(FINDING_EXPECTATIONS["deprecated_module_in_prose"])


def test_cli_rules_tags_ds115_as_opt_in(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors deprecated references ds115: verifies `docsentinel rules` tags the opt-in.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS115 appears under the fast profile tagged "[opt-in: set deprecated_references_file]", exactly as
            DS110 and DS112 are tagged for their own enabling options.

    Boundaries:
        - Focus: rules-command surfacing of DS115 as an opt-in policy rule
        - Fixtures/params: capsys

    On failure, first check:
        - Whether DS115 kept opt_in_option="deprecated_references_file"
        - The rules-command opt-in tag formatting
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    ds115_lines = [line for line in captured.out.splitlines() if "DS115:" in line]
    assert ds115_lines == ["  DS115: Deprecated names and migrated references [opt-in: set deprecated_references_file]"]


def test_cli_doctor_counts_ds115_among_the_three_opt_in_rules(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors deprecated references ds115: verifies `docsentinel doctor` counts DS115.

    Scenario:
        Given the installed rule registry
        When the doctor command reports environment readiness
        Then the fast-rule tally reads exactly
            "16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)", so DS115 is inside
            the registered count and is one of the four opt-in rules alongside DS110, DS112 and DS118.

    Boundaries:
        - Focus: doctor's separate accounting of opt-in versus always-active fast rules
        - Fixtures/params: capsys

    On failure, first check:
        - Whether the registered fast-rule count changed when a rule was added
        - Whether DS115 was miscounted as always-active rather than opt-in
    """
    exit_code = cli.main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS115" in {rule.code for rule in rules_for_profile("fast")}
    assert "fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)" in captured.out


def test_cli_fast_json_scan_reports_ds115_warning_and_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors deprecated references ds115: verifies the CLI fast json warning path.

    Scenario:
        Given the deprecated_module_in_prose fixture carrying a docsentinel.toml that configures the mapping,
            scanned via the CLI with --profile fast --format json and no --strict
        When the command runs
        Then it prints a JSON report containing the DS115 warning at line 3 and exits 0, because a bare warning
            is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the discovered docsentinel.toml configured deprecated_references_file
    """
    loaded = asset_case("ds115", "deprecated_module_in_prose")
    (loaded.root / "docsentinel.toml").write_text(
        'profile = "fast"\ndeprecated_references_file = "mapping.toml"\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(loaded.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds115 = [finding for finding in payload["findings"] if finding["rule"] == "DS115"]
    assert len(ds115) == 1
    assert ds115[0]["path"] == "README.md"
    assert ds115[0]["severity"] == "warning"
    assert ds115[0]["line"] == 3
    assert "deprecated prose 'oldmod'" in ds115[0]["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds115_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors deprecated references ds115: verifies --strict promotes the warning.

    Scenario:
        Given the deprecated_identifier_code_span fixture with a [tool.doc_sentinel] table configuring the
            mapping, scanned via the CLI under the fast profile with --strict
        When the command runs
        Then the DS115 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The _exit_code strict branch for non-deep profiles
        - Whether DS115 still produces a finding under the strict run
    """
    loaded = asset_case("ds115", "deprecated_identifier_code_span")
    (loaded.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\ndeprecated_references_file = "mapping.toml"\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(loaded.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_select_narrows_to_ds115_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies select activates only DS115.

    Scenario:
        Given the deprecated_local_link_path scenario (a DS115 warning plus a DS101 dangling-link sibling)
            scanned with select pinned to DS115 and the mapping configured
        When the engine resolves the active rule set
        Then only DS115 is enabled and its single expected warning at line 3 is produced, with the DS101
            sibling a full scan would add dropped.

    Boundaries:
        - Focus: exact-code select resolution for a fast opt-in rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS115 selector
        - Whether DS101 leaked into enabled_rules despite the select
    """
    loaded = asset_case("ds115", "deprecated_local_link_path")

    result = scan(loaded.root, config=_config("deprecated_local_link_path", select=("DS115",)))

    assert result.enabled_rules == ("DS115",)
    assert _triples(result.findings) == list(FINDING_EXPECTATIONS["deprecated_local_link_path"])


def test_prefix_select_and_ignore_semantics_for_ds115(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies DS11/DS1/DS2 select and ignore.

    Scenario:
        Given the deprecated_module_in_prose scenario (a DS115-only warning) scanned under the fast profile
            with the mapping configured
        When it is selected by the genuine ``DS11`` prefix, the whole-set ``DS1`` prefix and the non-matching
            ``DS2`` prefix, then ignored by the exact code, by ``DS11`` and by ``DS2``
        Then ``DS11`` and ``DS1`` keep DS115 active and still reporting line 3, ``DS2`` activates no fast rule,
            the exact and ``DS11`` ignores drop DS115 and its finding, and ``DS2`` leaves it active - all
            expectations derived from FAST_RULE_ORDER, not hard-coded.

    Boundaries:
        - Focus: prefix select and ignore precedence for DS115 against the live fast rule set
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast rule codes
        - Whether a non-matching prefix (DS2) wrongly activated or suppressed DS115
    """
    loaded = asset_case("ds115", "deprecated_module_in_prose")
    ds11_prefixed = tuple(code for code in FAST_RULE_ORDER if code.startswith("DS11"))

    ds11x = scan(loaded.root, config=_config("deprecated_module_in_prose", select=("DS11",)))
    assert ds11x.enabled_rules == ds11_prefixed
    assert [finding.line for finding in _ds115(ds11x.findings)] == [3]

    whole_fast = scan(loaded.root, config=_config("deprecated_module_in_prose", select=("DS1",)))
    assert whole_fast.enabled_rules == FAST_RULE_ORDER
    assert [finding.line for finding in _ds115(whole_fast.findings)] == [3]

    none = scan(loaded.root, config=_config("deprecated_module_in_prose", select=("DS2",)))
    assert none.enabled_rules == ()
    assert _ds115(none.findings) == ()

    exact = scan(loaded.root, config=_config("deprecated_module_in_prose", ignore=("DS115",)))
    assert "DS115" not in exact.enabled_rules
    assert _ds115(exact.findings) == ()

    by_prefix = scan(loaded.root, config=_config("deprecated_module_in_prose", ignore=("DS11",)))
    assert by_prefix.enabled_rules == tuple(code for code in FAST_RULE_ORDER if not code.startswith("DS11"))
    assert _ds115(by_prefix.findings) == ()

    unaffected = scan(loaded.root, config=_config("deprecated_module_in_prose", ignore=("DS2",)))
    assert "DS115" in unaffected.enabled_rules
    assert [finding.line for finding in _ds115(unaffected.findings)] == [3]


def test_ownership_split_vs_ds101_without_double_reporting(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies the documented DS101 overlap (R9).

    Scenario:
        Given the deprecated_local_link_path fixture (a deprecated link whose in-root target does not exist)
            scanned under the full fast profile with the mapping configured
        When DS101-DS117 run together
        Then the only non-DS115 finding is DS101's dangling link at line 3 - the documented overlap where
            DS115 owns "explicitly mapped deprecated name" and DS101 owns existence - and no third rule
            double-reports the same construct.

    Boundaries:
        - Focus: cross-rule ownership (R9/contract E) with no accidental triple reporting
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether a new sibling finding appeared beyond the documented DS101 overlap
        - Whether DS115 began probing the link target instead of matching it lexically
    """
    loaded = asset_case("ds115", "deprecated_local_link_path")
    result = scan(loaded.root, config=_config("deprecated_local_link_path"))

    assert result.enabled_rules == FAST_RULE_ORDER
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS115")
    assert siblings == EXPECTED_SIBLINGS["deprecated_local_link_path"]
    assert _triples(_ds115(result.findings)) == list(FINDING_EXPECTATIONS["deprecated_local_link_path"])


def test_deprecated_link_to_existing_and_missing_is_flagged_identically_without_target_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors deprecated references ds115: verifies links are matched lexically only (R9).

    Scenario:
        Given one document linking a deprecated path that exists in-root and another linking a deprecated path
            that is missing, both mapped as kind="link", scanned under a filesystem recorder over every entry
            point
        When deprecated_refs.detect runs
        Then both links are flagged identically with the same message, proving DS115 matches the deprecated
            target lexically whether or not it exists, and neither target is ever stat-ed or opened.

    Boundaries:
        - Focus: R9 - existence is DS101's concern; DS115 never probes the deprecated target
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder

    On failure, first check:
        - Whether the link matcher resolved or stat-ed the target instead of matching lexically
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "present.md").write_text("# present\n", encoding="utf-8")
    (root / "mapping.toml").write_text(
        'version = 1\n[[replacement]]\nold = "present.md"\nnew = "fresh.md"\nkind = "link"\n'
        '[[replacement]]\nold = "missing.md"\nnew = "fresh.md"\nkind = "link"\n',
        encoding="utf-8",
    )
    (root / "exists.md").write_text("See [p](present.md).\n", encoding="utf-8")
    (root / "gone.md").write_text("See [m](missing.md).\n", encoding="utf-8")
    documents = (models.Document("exists.md", 0), models.Document("gone.md", 0))
    config = Config(deprecated_references_file="mapping.toml")

    dep.detect(root, documents, config)  # warm up lazy imports before recording

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)
    findings = dep.detect(root, documents, config)

    by_path = {finding.path: finding.message for finding in findings}
    assert by_path == {
        "exists.md": "deprecated link 'present.md' should be replaced with 'fresh.md' (mapping mapping.toml entry 0)",
        "gone.md": "deprecated link 'missing.md' should be replaced with 'fresh.md' (mapping mapping.toml entry 1)",
    }
    probed = {os.path.normpath(os.fspath(root / name)) for name in ("present.md", "missing.md", "fresh.md")}
    assert recorder.paths.isdisjoint(probed), f"DS115 probed a deprecated link target: {recorder.paths & probed}"


@pytest.mark.parametrize("variant", ["absolute", "parent_traversal", "glob", "nonexistent", "directory"])
def test_injected_hostile_mapping_path_raises_without_outside_io(
    variant: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors deprecated references ds115: verifies injected hostile mapping paths fail closed (R1).

    Scenario:
        Given an injected Config (bypassing load_config validation) whose deprecated_references_file names a
            hostile path - an absolute path, a ../ traversal, a glob, a nonexistent file, or an in-root
            directory - scanned under a filesystem recorder over every reachable entry point
        When deprecated_refs.detect runs
        Then each raises a ConfigError (never a clean result), and the recorder shows DS115 opened nothing
            under the recorder and touched no path outside the scan root, so a config-injection PR cannot make
            DS115 open or probe an out-of-root or special path.

    Boundaries:
        - Focus: R1 config-injection containment for the non-blocking hostile mapping-path shapes
        - Fixtures/params: parametrized over five hostile path shapes; tmp_path, monkeypatch, the FS recorder

    On failure, first check:
        - The is_ds116_owned / resolver / S_ISREG gates in load_mapping
        - Whether any path outside the root was opened or stat-ed before the ConfigError
    """
    root = Path(os.path.realpath(tmp_path))
    outside = root.parent / "outside"
    outside.mkdir(exist_ok=True)
    (outside / "secret.toml").write_text("version = 1\n", encoding="utf-8")
    (root / "docs").mkdir()
    hostile = {
        "absolute": str(outside / "secret.toml"),
        "parent_traversal": "../outside/secret.toml",
        "glob": "docs/*.toml",
        "nonexistent": "docs/nope.toml",
        "directory": "docs",
    }[variant]
    config = _injected_config(deprecated_references_file=hostile)

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)

    with pytest.raises(ConfigError):
        dep.detect(root, (models.Document("README.md", 0),), config)

    secret_real = os.path.normpath(str(outside / "secret.toml"))
    outside_real = os.path.normpath(str(outside))
    assert secret_real not in recorder.opened, "opened the out-of-root secret"
    assert secret_real not in recorder.paths, "stat-ed the out-of-root secret"
    assert not any(_is_under(opened, outside_real) for opened in recorder.opened), "opened a path outside the root"


def test_injected_symlink_out_mapping_raises_without_following(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors deprecated references ds115: verifies an in-root symlink-out mapping is refused (R1).

    Scenario:
        Given an in-root symlink committed at the configured mapping path pointing at a real out-of-root
            secret, scanned under a filesystem recorder
        When deprecated_refs.detect runs
        Then it raises a ConfigError (the escapes_via_symlink defence) and the out-of-root secret is never
            opened, so a symlink mapping cannot read outside the root.

    Boundaries:
        - Focus: R1 - escapes_via_symlink refuses an in-root symlink that resolves outside, with no open
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder; skipped when symlinks are unavailable

    On failure, first check:
        - The escapes_via_symlink branch of load_mapping running before the bounded read
        - Whether the symlink was followed and the secret opened
    """
    root = Path(os.path.realpath(tmp_path)) / "scanroot"
    root.mkdir()
    outside = Path(os.path.realpath(tmp_path)) / "outside"
    outside.mkdir()
    secret = outside / "secret.toml"
    secret.write_text("version = 1\n", encoding="utf-8")
    _symlink_or_skip(root / "mapping.toml", "../outside/secret.toml")

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)

    with pytest.raises(ConfigError):
        dep.detect(
            root, (models.Document("README.md", 0),), _injected_config(deprecated_references_file="mapping.toml")
        )

    secret_real = os.path.normpath(os.path.realpath(secret))
    assert secret_real not in recorder.opened, "opened the out-of-root secret through the symlink"


def test_fifo_configured_as_mapping_never_opens_or_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors deprecated references ds115: verifies a FIFO mapping never blocks or opens (R1).

    Scenario:
        Given a runtime FIFO committed at the configured mapping path, scanned under a filesystem recorder
        When deprecated_refs.detect runs inside a worker thread guarded by a hard join timeout
        Then the detector completes promptly (the thread is not alive after the join), raises the non-regular
            readiness ConfigError, and never opens the FIFO path - so a crafted FIFO mapping can neither wedge
            the scan nor trigger an unbounded read.

    Boundaries:
        - Focus: the HIGH config-injection control (os.stat + S_ISREG before any open on a blocking special file)
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder; skipped where os.mkfifo is unavailable

    On failure, first check:
        - Whether load_mapping ran os.stat + stat.S_ISREG before the bounded read
        - Whether the regular-file check followed a read that blocks on a FIFO
    """
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo unavailable on this platform")
    root = Path(os.path.realpath(tmp_path))
    fifo = root / "mapping.toml"
    try:
        os.mkfifo(fifo)
    except OSError as error:
        pytest.skip(f"mkfifo failed: {error}")
    fifo_real = os.path.normpath(str(fifo))

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)

    box: dict[str, Exception] = {}

    def _run():
        """Run DS115 over the FIFO mapping, capturing the raised exception for the main thread."""
        try:
            dep.detect(
                root, (models.Document("README.md", 0),), _injected_config(deprecated_references_file="mapping.toml")
            )
        except (ConfigError, OSError) as error:
            # Captured, not muted: re-asserted as a ConfigError on the main thread below. OSError is
            # caught too so a regression that opens the FIFO and fails is reported, not swallowed.
            box["error"] = error

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout=15)

    assert not worker.is_alive(), "detect blocked on the FIFO mapping; the regular-file check opened it"
    assert isinstance(box.get("error"), ConfigError), f"expected a ConfigError, got {box.get('error')!r}"
    assert fifo_real not in recorder.opened, "opened a FIFO configured as the mapping"


def test_oversized_mapping_raises_before_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors deprecated references ds115: verifies the mapping size cap fails closed (R1).

    Scenario:
        Given a regular in-root mapping whose byte length exceeds the (test-lowered) cap, with a document that
            would otherwise match, scanned through detect
        When the cap is lowered below the file size
        Then detect raises the oversized readiness ConfigError on the st_size check before reading or parsing,
            so a huge in-root mapping can neither exhaust memory nor reach an unbounded parse.

    Boundaries:
        - Focus: R1 st_size cap enforced before the bounded read, routed through detect end to end
        - Fixtures/params: tmp_path, monkeypatch (lowers the cap)

    On failure, first check:
        - Whether load_mapping checked st_size against _MAX_MAPPING_BYTES before open
        - Whether the cap was read from the module global at call time
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "mapping.toml").write_text(
        'version = 1\n[[replacement]]\nold = "oldmod"\nnew = "newmod"\nkind = "prose"\n' + "# pad\n" * 40,
        encoding="utf-8",
    )
    (root / "README.md").write_text("the oldmod helper\n", encoding="utf-8")
    documents = (models.Document("README.md", 0),)
    config = Config(deprecated_references_file="mapping.toml")

    assert len(dep.detect(root, documents, config)) == 1

    monkeypatch.setattr(dep, "_MAX_MAPPING_BYTES", 8)
    with pytest.raises(ConfigError, match="larger than"):
        dep.detect(root, documents, config)


@pytest.mark.parametrize(
    "body",
    [
        "version = 2\n",
        "bogus = 1\nversion = 1\n",
        'version = 1\n[[replacement]]\nnew = "b"\nkind = "prose"\n',
        'version = 1\n[[replacement]]\nold = 7\nnew = "b"\nkind = "prose"\n',
        'version = 1\n[[replacement]]\nold = "a"\nnew = "b"\nkind = "unknown"\n',
        'version = 1\n[[replacement]]\nold = ""\nnew = "b"\nkind = "prose"\n',
        'version = 1\n[[replacement]]\nold = "a\\u0000"\nnew = "b"\nkind = "prose"\n',
        'version = 1\n[[replacement]]\nold = "a"\nnew = "b"\nkind = "prose"\nextra = 1\n',
        'version = 1\n[[replacement]]\nold = "a"\nnew = "b"\nkind = "prose"\n'
        '[[replacement]]\nold = "a"\nnew = "c"\nkind = "prose"\n',
        "this is not = valid = toml ===\n",
    ],
)
def test_hostile_mapping_content_fails_closed_through_scan(body: str, tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies hostile mapping content propagates (R2/R3).

    Scenario:
        Given a committed in-root mapping whose content violates the schema (wrong version, unknown top key,
            missing/mistyped key, bad kind, empty or control-laden old, unknown entry key, a cross-entry
            duplicate old, or unparseable TOML) and a document, scanned through the shared engine with DS115
            selected
        When scan runs DS115
        Then the readiness ConfigError propagates out of scan (never a clean empty-findings result), proving
            the schema validator's rejection reaches the engine end to end rather than only the pure validator.

    Boundaries:
        - Focus: R2/R3 fail-closed schema validation routed through scan, not just parse_mapping
        - Fixtures/params: parametrized over ten hostile mapping bodies; tmp_path

    On failure, first check:
        - Which schema branch failed to reject its hostile input
        - Whether the engine swallowed the analyzer exception into a clean scan
    """
    (tmp_path / "mapping.toml").write_text(body, encoding="utf-8")
    (tmp_path / "README.md").write_text("# doc\n\nThe a token here.\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        scan(tmp_path, config=Config(profile="fast", select=("DS115",), deprecated_references_file="mapping.toml"))


def test_over_cap_entry_count_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors deprecated references ds115: verifies the entry-count cap fails closed (R2).

    Scenario:
        Given a mapping with more entries than the (test-lowered) _MAX_ENTRIES cap, scanned through detect
        When the cap is lowered below the entry count
        Then detect raises the over-cap readiness ConfigError, so no mapping can drive an unbounded
            per-document compare.

    Boundaries:
        - Focus: R2 entry-count bound enforced at schema load, routed through detect
        - Fixtures/params: tmp_path, monkeypatch (lowers the cap)

    On failure, first check:
        - Whether parse_mapping checked len(raw_entries) against _MAX_ENTRIES
    """
    root = Path(os.path.realpath(tmp_path))
    body = "version = 1\n" + "".join(
        f'[[replacement]]\nold = "old{index}"\nnew = "new{index}"\nkind = "prose"\n' for index in range(3)
    )
    (root / "mapping.toml").write_text(body, encoding="utf-8")
    (root / "README.md").write_text("# doc\n", encoding="utf-8")
    monkeypatch.setattr(dep, "_MAX_ENTRIES", 2)

    with pytest.raises(ConfigError, match="exceeds"):
        dep.detect(root, (models.Document("README.md", 0),), Config(deprecated_references_file="mapping.toml"))


def test_chain_and_cycle_are_inert_through_detect(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies chains and cycles never loop (R7).

    Scenario:
        Given a committed mapping with a cycle a->b and b->a and a document containing both a and b once,
            scanned through detect
        When detect runs
        Then each literal occurrence is reported exactly once and the run terminates, proving DS115 reports
            occurrences and never follows new back into another match.

    Boundaries:
        - Focus: R7 literal-occurrence reporting with inert chains/cycles, routed through detect
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether the matcher re-applied a replacement by following new
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "mapping.toml").write_text(
        "version = 1\n"
        '[[replacement]]\nold = "alpha"\nnew = "beta"\nkind = "prose"\n'
        '[[replacement]]\nold = "beta"\nnew = "alpha"\nkind = "prose"\n',
        encoding="utf-8",
    )
    (root / "README.md").write_text("first alpha then beta end\n", encoding="utf-8")

    findings = dep.detect(root, (models.Document("README.md", 0),), Config(deprecated_references_file="mapping.toml"))
    assert sorted(finding.message.split("'")[1] for finding in findings) == ["alpha", "beta"]


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_deprecated_options_propagate_from_both_config_files(
    config_file: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors deprecated references ds115: verifies the four options load from both files.

    Scenario:
        Given the deprecated_casefolded_optin fixture carrying either a standalone docsentinel.toml or a
            [tool.doc_sentinel] table that sets deprecated_references_file plus deprecated_case_sensitive=false,
            and then, in a second run, also turns deprecated_check_prose off
        When scan discovers each config (no injected Config)
        Then the case-folded config flags the differently cased token at line 3, and disabling the prose
            sub-check silences it - proving deprecated_references_file, deprecated_case_sensitive and
            deprecated_check_prose all load and reach DS115 through each config-file form.

    Boundaries:
        - Focus: config discovery and propagation of the DS115 options via both forms
        - Fixtures/params: parametrized over the two config-file forms; asset_case

    On failure, first check:
        - Whether load_config reads the deprecated_* options from the given file form
        - Whether the engine forwards the discovered Config to DS115
    """
    loaded = asset_case("ds115", "deprecated_casefolded_optin")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (loaded.root / config_file).write_text(
        f'{prefix}profile = "fast"\ndeprecated_references_file = "mapping.toml"\ndeprecated_case_sensitive = false\n',
        encoding="utf-8",
    )
    flagged = _ds115(scan(loaded.root).findings)
    assert [(finding.line, finding.message) for finding in flagged] == [
        (3, "deprecated prose 'OldName' should be replaced with 'NewName' (mapping mapping.toml entry 0)")
    ]

    (loaded.root / config_file).write_text(
        f'{prefix}profile = "fast"\ndeprecated_references_file = "mapping.toml"\n'
        "deprecated_case_sensitive = false\ndeprecated_check_prose = false\n",
        encoding="utf-8",
    )
    assert _ds115(scan(loaded.root).findings) == ()


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("deprecated_references_file", "7"),
        ("deprecated_references_file", '"../escape.toml"'),
        ("deprecated_check_prose", '"yes"'),
        ("deprecated_check_links", '"yes"'),
        ("deprecated_case_sensitive", '"yes"'),
    ],
)
def test_invalid_deprecated_option_raises_config_error(
    option: str,
    value: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors deprecated references ds115: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml that sets one deprecated option to an invalid value (a non-string or an
            escaping path for the file, or a non-boolean for a sub-check flag)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects invalid values for every DS115 option (standalone file)
        - Fixtures/params: parametrized over the file-path and three bool options; asset_case

    On failure, first check:
        - The str/within-root and bool validation for the named option in config.py
        - Whether an invalid value was coerced instead of raising
    """
    loaded = asset_case("ds115", "deprecated_module_in_prose")
    (loaded.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match="deprecated"):
        scan(loaded.root)


def test_token_boundary_and_fence_and_inline_mask_through_detect(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies token boundaries and mask exemptions (R4/R5).

    Scenario:
        Given a committed prose mapping for "oldmod" and a document that writes oldmod once in live prose,
            once inside a longer token oldmodule, once in a fenced block, once in an inline-code span and once
            in an HTML comment, scanned through detect
        When detect runs
        Then exactly one finding fires at the live-prose line, proving whole-token matching (oldmodule is not a
            match) and the scanner-mask exemption of fenced code, inline code and HTML comments.

    Boundaries:
        - Focus: R4 token boundary and R5 scanner-mask parity routed through detect over real bytes
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether substring matching crept back in, or a masked span was scanned as prose
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "mapping.toml").write_text(
        'version = 1\n[[replacement]]\nold = "oldmod"\nnew = "newmod"\nkind = "prose"\n', encoding="utf-8"
    )
    (root / "README.md").write_text(
        "# Doc\n\n"
        "The oldmod helper is retired.\n"
        "But oldmodule is a distinct token.\n\n"
        "```\noldmod sample\n```\n\n"
        "An inline `oldmod` span.\n"
        "A comment <!-- oldmod --> here.\n",
        encoding="utf-8",
    )

    findings = dep.detect(root, (models.Document("README.md", 0),), Config(deprecated_references_file="mapping.toml"))
    assert [finding.line for finding in findings] == [3]


def test_multi_word_old_requires_whitespace_adjacency_through_detect(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies multi-word olds need whitespace adjacency (R4).

    Scenario:
        Given a committed prose mapping whose old is the two-word phrase "old module" and a document that
            places the two tokens whitespace-adjacent on one line, comma-separated, and split across two lines,
            scanned through detect
        When detect runs
        Then only the whitespace-adjacent occurrence on one physical line is flagged.

    Boundaries:
        - Focus: R4 bounded whitespace-adjacent tail compare for multi-word olds, routed through detect
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether the gap check accepted non-whitespace between tokens, or folded across physical lines
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "mapping.toml").write_text(
        'version = 1\n[[replacement]]\nold = "old module"\nnew = "new module"\nkind = "prose"\n', encoding="utf-8"
    )
    (root / "README.md").write_text(
        "the old module is retired\nthe old, module split by comma\nold\nmodule across lines\n", encoding="utf-8"
    )

    findings = dep.detect(root, (models.Document("README.md", 0),), Config(deprecated_references_file="mapping.toml"))
    assert [finding.line for finding in findings] == [1]


def test_nfc_equivalence_and_regex_metacharacter_old_through_detect(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies NFC matching and literal metacharacters (R4/R7).

    Scenario:
        Given a committed mapping whose first old is an accented name written NFD and whose second old is the
            catastrophic-looking literal "(a+)+", and a document that writes the accented name NFC plus the
            literal metacharacter string and a benign "aaaa" run, scanned through detect
        When detect runs
        Then the NFC-equivalent name matches once and the metacharacter old matches its literal occurrence once
            with no spurious match on "aaaa" and no stall, proving NFC normalization and literal (never regex)
            matching.

    Boundaries:
        - Focus: R7 NFC normalization and R4 literal matching of regex metacharacters, routed through detect
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether normalization skipped NFC on one side, or an old was handed to re.compile
    """
    root = Path(os.path.realpath(tmp_path))
    old_nfd = unicodedata.normalize("NFD", "Café")
    (root / "mapping.toml").write_text(
        "version = 1\n"
        f'[[replacement]]\nold = "{old_nfd}"\nnew = "Bistro"\nkind = "prose"\n'
        '[[replacement]]\nold = "(a+)+"\nnew = "SAFE"\nkind = "prose"\n',
        encoding="utf-8",
    )
    doc_nfc = unicodedata.normalize("NFC", "the Café bar and aaaa and (a+)+ token\n")
    (root / "README.md").write_text(doc_nfc, encoding="utf-8")

    findings = dep.detect(root, (models.Document("README.md", 0),), Config(deprecated_references_file="mapping.toml"))
    # The NFC-equivalent name matches (proving NFC on both sides) and the metacharacter old matches its
    # single literal occurrence; each echoed old is the raw mapping value bounded through _echo, so the NFD
    # old renders as its unicode_escape form rather than NFC.
    assert sorted(finding.message.split("'")[1] for finding in findings) == sorted([dep._echo(old_nfd), "(a+)+"])
    assert len(findings) == 2


def test_crlf_line_numbers_point_at_the_occurrence(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies CRLF line fidelity.

    Scenario:
        Given a CRLF-terminated document whose only deprecated occurrence sits on line 5, with a committed
            mapping, scanned through detect
        When detect runs
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input for the deprecated occurrence
        - Fixtures/params: tmp_path

    On failure, first check:
        - CRLF handling in the shared scanner's line splitting and the line-start offsets
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "mapping.toml").write_text(
        'version = 1\n[[replacement]]\nold = "oldmod"\nnew = "newmod"\nkind = "prose"\n', encoding="utf-8"
    )
    (root / "README.md").write_bytes(b"# Title\r\n\r\nIntro prose.\r\n\r\nThe oldmod helper here.\r\n")

    findings = dep.detect(root, (models.Document("README.md", 1),), Config(deprecated_references_file="mapping.toml"))
    assert len(findings) == 1
    assert findings[0].line == 5


def test_invalid_utf8_document_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies an invalid-UTF-8 document is not a silent clean.

    Scenario:
        Given a committed mapping and a discovered document holding invalid UTF-8 bytes
        When a fast scan reads it with DS115 selected and the mapping configured
        Then an error is raised instead of a misleading zero-finding result, so an unreadable document fails
            closed rather than scanning clean.

    Boundaries:
        - Focus: an undecodable document surfaces rather than masquerading as clean
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in deprecated_refs._read_document
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "mapping.toml").write_text(
        'version = 1\n[[replacement]]\nold = "oldmod"\nnew = "newmod"\nkind = "prose"\n', encoding="utf-8"
    )
    (tmp_path / "README.md").write_bytes(b"# Title\n\nThe oldmod helper.\n\xff\xfe\n")

    with pytest.raises((UnicodeDecodeError, ConfigError, OSError)):
        scan(tmp_path, config=Config(profile="fast", select=("DS115",), deprecated_references_file="mapping.toml"))


def test_unreadable_document_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies an unreadable document is not a silent clean.

    Scenario:
        Given a committed mapping and a discovered document whose read permission is removed
        When a fast scan tries to read it with DS115 selected and the mapping configured
        Then an OSError surfaces instead of a misleading zero-finding result, so a readiness problem fails
            closed rather than scanning clean.

    Boundaries:
        - Focus: a filesystem read error surfaces instead of masquerading as clean
        - Fixtures/params: tmp_path (skipped when running as root, which bypasses the mode)

    On failure, first check:
        - Whether deprecated_refs._read_document swallowed the read error into a clean scan
        - Whether the test runs as root, where chmod 000 does not block reads
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("running as root bypasses the unreadable-file permission check")
    (tmp_path / "mapping.toml").write_text(
        'version = 1\n[[replacement]]\nold = "oldmod"\nnew = "newmod"\nkind = "prose"\n', encoding="utf-8"
    )
    target = tmp_path / "README.md"
    target.write_text("# Title\n\nThe oldmod helper.\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        with pytest.raises(OSError):
            scan(tmp_path, config=Config(profile="fast", select=("DS115",), deprecated_references_file="mapping.toml"))
    finally:
        target.chmod(0o644)


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies repeated scans are stable (R10).

    Scenario:
        Given the multiple_occurrences_same_line scenario scanned twice over the same materialized root
        When the two DS115 finding tuples are compared
        Then they are equal and report the two occurrences at line 3 in a stable order, so the detector holds
            no order-dependent state across runs.

    Boundaries:
        - Focus: determinism of DS115 over a real asset tree, with asserted line counts (R10)
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches, or a set/dict iteration order leaking into the output ordering
    """
    loaded = asset_case("ds115", "multiple_occurrences_same_line")
    config = _config("multiple_occurrences_same_line", select=("DS115",))

    first = _ds115(scan(loaded.root, config=config).findings)
    second = _ds115(scan(loaded.root, config=config).findings)

    assert _triples(first) == _triples(second)
    assert [finding.line for finding in first] == [3, 3]


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies text/json/github report stability (R6).

    Scenario:
        Given a DS115 prose finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS115 warning deterministically (schema v1 json, a ``::warning``
            annotation with file and line), repeated renders are byte-identical, and no raw control byte or
            resolved absolute path appears.

    Boundaries:
        - Focus: report serialization of a DS115 warning across the three formats, no control/abs leakage (R6)
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path, line and message
        - Whether repeated renders diverge (nondeterminism)
    """
    loaded = asset_case("ds115", "deprecated_module_in_prose")
    result = scan(loaded.root, config=_config("deprecated_module_in_prose", select=("DS115",)))
    expected = FINDING_EXPECTATIONS["deprecated_module_in_prose"][0][2]

    text = render(result, "text")
    assert render(result, "text") == text
    assert f"warning: README.md: {expected}" in text
    assert "\x00" not in text and "\x1b" not in text
    assert str(Path(os.path.realpath(loaded.root))) not in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS115"]
    assert payload["findings"][0]["rule"] == "DS115"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] == 3

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=README.md,line=3,title=DS115::")


def test_hostile_configured_path_yields_bounded_repr_escaped_error(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies a hostile configured path cannot inject output (R6).

    Scenario:
        Given an injected Config whose deprecated_references_file carries ESC, a newline, a "::error" token and
            10,000 characters (absent on disk)
        When deprecated_refs.detect runs and raises the readiness ConfigError
        Then the message stays bounded to the echo limit, repr-escapes every control byte, carries no resolved
            absolute root and leaves no raw newline, so a report sink cannot be driven to inject a second
            github command.

    Boundaries:
        - Focus: R6 bounded repr-escaped echo of the configured path in the readiness error
        - Fixtures/params: tmp_path

    On failure, first check:
        - deprecated_refs._echo's unicode_escape bound and whether the raw configured path reached the message
    """
    root = Path(os.path.realpath(tmp_path))
    hostile_path = "docs/\x1b]0;pwned\x07::error\n" + ("b" * 10_000) + ".toml"

    with pytest.raises(ConfigError) as excinfo:
        dep.detect(root, (models.Document("README.md", 0),), _injected_config(deprecated_references_file=hostile_path))

    message = str(excinfo.value)
    assert len(message) < 200
    assert not any(ord(character) < 0x20 or ord(character) == 0x7F for character in message)
    assert str(root) not in message
    assert message.endswith("...")


def test_baseline_suppresses_known_ds115_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors deprecated references ds115: verifies baseline suppression round-trips.

    Scenario:
        Given the multiple_occurrences_same_line scenario whose two DS115 findings are recorded into a baseline
            file
        When the same tree is rescanned with that baseline configured
        Then both previously known DS115 findings are filtered out while the first scan still reported them, so
            the fingerprints are stable across the two scans.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS115 findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS115 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    loaded = asset_case("ds115", "multiple_occurrences_same_line")
    config = _config("multiple_occurrences_same_line", select=("DS115",))

    first = scan(loaded.root, config=config)
    assert len(_ds115(first.findings)) == 2

    baseline_path = loaded.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        loaded.root,
        config=_config("multiple_occurrences_same_line", select=("DS115",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds115(suppressed.findings) == ()


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors deprecated references ds115: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS115 detector and runs its pure core
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported, proving the fast
            DS115 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS115's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether deprecated_refs or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from pathlib import Path\n"
        "from docsentinel.config import Config\n"
        "from docsentinel.detectors import deprecated_refs as dep\n"
        'm = dep.parse_mapping(\'version = 1\\n[[replacement]]\\nold = "x"\\nnew = "y"\\nkind = "prose"\\n\', \'m.toml\')\n'
        "dep.check_text('the x here\\n', 'README.md', Path('/scanroot'), m, Config())\n"
        "heavy = sorted(mod for mod in ('sklearn', 'textstat', 'docsig', 'spacy', 'textacy') if mod in sys.modules)\n"
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
    [Integration] detectors deprecated references ds115: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When deprecated_refs.detect runs over every FINDING scenario
        Then all expected findings are still produced, proving DS115 opens no socket, makes no connection and
            never executes embedded documentation or mapping content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS115 path
    """

    def _no_socket(*args: object, **kwargs: object) -> object:
        """Fail the test if DS115 ever constructs a socket."""
        raise AssertionError("DS115 must not create a socket")

    def _no_connect(*args: object, **kwargs: object) -> object:
        """Fail the test if DS115 ever opens an outbound connection."""
        raise AssertionError("DS115 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object) -> object:
        """Fail the test if DS115 ever launches a subprocess."""
        raise AssertionError("DS115 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case in FINDING_EXPECTATIONS:
        loaded = asset_case("ds115", case)
        findings = _ds115(dep.detect(loaded.root, loaded.documents(), _config(case)))
        assert _triples(findings) == list(FINDING_EXPECTATIONS[case])


def _single_line_flood(scale: int) -> str:
    """Return one line holding ``scale`` distinct deprecated occurrences.

    Each ``obso{i}`` token is a distinct non-repeating occurrence so the shape yields exactly ``scale``
    findings and the ``(line, offset, entry)`` dedup never collapses the count.

    :param scale: Number of distinct deprecated occurrences on the single line.
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + " ".join(f"obso{index}" for index in range(scale)) + "\n"


def _multi_line_flood(scale: int) -> str:
    """Return ``scale`` lines, each holding one distinct deprecated occurrence.

    :param scale: Number of lines (one occurrence each).
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + "".join(f"line {index} has obso{index} here\n" for index in range(scale))


#: Representative adversarial deprecated-flood shapes mapped to a builder. Each uses strictly
#: non-repeating tokens so every unit yields one finding and the dedup never collapses the count.
#: This suite proves only that detect() routes real files through check_text with exact counts and
#: no super-linear blow-up; the exhaustive algorithmic shapes live in the DS115 unit tests.
FLOOD_SHAPES: dict[str, Callable[[int], str]] = {
    "single_line_flood": _single_line_flood,
    "multi_line_flood": _multi_line_flood,
}


@pytest.mark.parametrize("shape", sorted(FLOOD_SHAPES))
def test_adversarial_deprecated_floods_stay_linear(shape: str, tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies linear-time adversarial handling (R4).

    Scenario:
        Given a mapping of ``scale`` distinct prose entries (one per distinct token) and a document of one
            representative flood shape - one giant line of distinct occurrences, or many single-occurrence lines
        When deprecated_refs.detect routes a doubling input series through the shared scaling helper with the
            mapping configured
        Then every scale produces the exact deterministic finding count (so the pass is never vacuous) and the
            scaling stays under the shared linear bound, proving the masked-text tokenize-and-dict-lookup matcher
            is O(document tokens + entries) through detect end to end.

    Boundaries:
        - Focus: detect() routing of real files through check_text with bounded time (threat model HIGH DoS)
        - Non-goal: the exhaustive algorithmic shapes, which live in the DS115 unit tests
        - Fixtures/params: parametrized over the representative flood shapes; tmp_path

    On failure, first check:
        - Any accidentally quadratic per-entry document rescan or per-token glob
        - That the exact finding count for this shape still holds at every scale
    """
    build_text = FLOOD_SHAPES[shape]
    root = tmp_path
    config = Config(deprecated_references_file="mapping.toml")

    def _build(scale: int) -> tuple[models.Document, ...]:
        """Write the mapping and the shape's document at ``scale`` and return the Document tuple (untimed).

        :param scale: The flood size to materialize.
        :returns: The single-document tuple for detect().
        """
        body = "version = 1\n" + "".join(
            f'[[replacement]]\nold = "obso{index}"\nnew = "fresh{index}"\nkind = "prose"\n' for index in range(scale)
        )
        (root / "mapping.toml").write_text(body, encoding="utf-8")
        path = root / "README.md"
        path.write_text(build_text(scale), encoding="utf-8", newline="")
        return (models.Document("README.md", path.stat().st_size),)

    def _run(documents: tuple[models.Document, ...]) -> tuple[models.Finding, ...]:
        """Run detect over the pre-built document tuple.

        :param documents: The single-document tuple from ``_build``.
        :returns: The DS115 findings.
        """
        return dep.detect(root, documents, config)

    assert_scales_linearly(
        _build,
        _run,
        (500, 1_000, 2_000, 4_000),
        expected_count=lambda scale: scale,
        label=f"ds115-{shape}",
    )


def _shared_first_token_mapping(scale: int) -> str:
    """Return a mapping of ``scale`` multi-word olds that all share the first token ``aaaa``.

    All ``scale`` entries collapse into the one ``aaaa`` first-token bucket -- the shared-prefix
    shape a first-token-only index fanned a single document ``aaaa`` token out across, one tail
    compare per entry (the O(entries x document tokens) HIGH DoS). The committed R4 flood shapes
    use strictly distinct tokens, so each of their first-token buckets held one entry and they
    never exercised this amplification.

    :param scale: Number of entries sharing the first token.
    :returns: The TOML mapping body.
    """
    return "version = 1\n" + "".join(
        f'[[replacement]]\nold = "aaaa z{index}"\nnew = "r{index}"\nkind = "prose"\n' for index in range(scale)
    )


@pytest.mark.parametrize("shape", ["single_line", "multi_line"])
def test_shared_first_token_flood_stays_linear_through_detect(shape: str, tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: verifies the shared-first-token DoS stays linear (R4).

    Scenario:
        Given a mapping of ``scale`` multi-word olds that all share the first token ``aaaa`` and a document
            that saturates one physical line - or ``scale`` separate lines - with the shared ``aaaa`` token
            plus one real ``aaaa z0`` occurrence, scanned through detect over a doubling series that grows the
            entry count and the document together
        When detect routes the files through check_text
        Then exactly one finding is produced at every scale and the scaling stays under the shared linear
            bound, proving the token trie keys its second step on the second token so a single document token
            cannot fan out to one tail compare per entry - the HIGH matcher DoS the committed distinct-token
            flood tests passed vacuously against.

    Boundaries:
        - Focus: the shared-first-token bucket fan-out (R4 HIGH DoS), routed through detect end to end
        - Fixtures/params: parametrized over the single-line and multi-line shapes; tmp_path

    On failure, first check:
        - Whether the matcher reverted to a first-token-only bucket with a per-entry tail compare
        - That the exact finding count (1) still holds at every scale
    """
    root = tmp_path
    config = Config(deprecated_references_file="mapping.toml")

    def _build(scale: int) -> tuple[models.Document, ...]:
        """Write the shared-first-token mapping and the shape's document at ``scale`` (untimed).

        :param scale: The flood size to materialize.
        :returns: The single-document tuple for detect().
        """
        (root / "mapping.toml").write_text(_shared_first_token_mapping(scale), encoding="utf-8")
        if shape == "single_line":
            body = ("aaaa " * scale) + "aaaa z0\n"
        else:
            body = "".join("aaaa\n" for _ in range(scale)) + "aaaa z0\n"
        path = root / "README.md"
        path.write_text(body, encoding="utf-8", newline="")
        return (models.Document("README.md", path.stat().st_size),)

    def _run(documents: tuple[models.Document, ...]) -> tuple[models.Finding, ...]:
        """Run detect over the pre-built shared-first-token document.

        :param documents: The single-document tuple from ``_build``.
        :returns: The DS115 findings.
        """
        return dep.detect(root, documents, config)

    assert_scales_linearly(_build, _run, (500, 1_000, 2_000, 4_000), expected_count=1, label=f"ds115-shared-{shape}")


def test_cli_unknown_key_readiness_error_is_bounded_and_escaped(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors deprecated references ds115: verifies a hostile TOML key cannot inject the log (R6).

    Scenario:
        Given a committed mapping carrying an unknown top-level TOML key whose unicode escapes decode to raw
            ESC/BEL/CR/LF/NUL bytes and 10,000 characters, configured via docsentinel.toml and scanned via the
            CLI under the fast profile with --format github
        When the command runs
        Then it returns exit 2, prints a single bounded "Scan failed" line to stderr with no raw control byte
            and no forged second line, and emits no report on stdout - so the attacker key can neither inject a
            terminal escape, forge a github annotation, nor flood the log (BLOCK #5 / R6).

    Boundaries:
        - Focus: R6 bounded repr-escaped echo of an attacker TOML key through the CLI stderr / github sink
        - Fixtures/params: tmp_path, capsys

    On failure, first check:
        - Whether the unknown-key ConfigError routed each key through _echo_keys before the CLI printed it
    """
    root = Path(os.path.realpath(tmp_path))
    hostile_key = r'"\u001b]0;PWNED\u0007\r\n::error::forged\u0000 ' + ("A" * 10_000) + r'" = true'
    (root / "mapping.toml").write_text(f"version = 1\n{hostile_key}\n", encoding="utf-8")
    (root / "README.md").write_text("# doc\n", encoding="utf-8")
    (root / "docsentinel.toml").write_text(
        'profile = "fast"\ndeprecated_references_file = "mapping.toml"\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(root), "--profile", "fast", "--format", "github"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Scan failed" in captured.err
    err = captured.err
    assert "\x1b" not in err and "\x07" not in err and "\x00" not in err and "\r" not in err
    assert err.rstrip("\n").count("\n") == 0
    assert len(err) < 300


def test_deeply_nested_toml_mapping_fails_closed_through_scan_and_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors deprecated references ds115: verifies deeply nested TOML fails closed to exit 2 (R3).

    Scenario:
        Given a committed mapping well under the byte cap whose single value is a deeply nested array that
            drives tomllib's recursive-descent parser into a RecursionError, scanned through the engine and the
            CLI under the fast profile
        When scan runs DS115 and, separately, the CLI runs
        Then scan raises the bounded readiness ConfigError (never a RecursionError traceback) and the CLI
            returns exit 2 with a "Scan failed" line and no report on stdout - the R3 fail-closed surface.

    Boundaries:
        - Focus: R3 catching the RecursionError parser crash and surfacing a bounded ConfigError to exit 2
        - Fixtures/params: tmp_path, capsys

    On failure, first check:
        - Whether parse_mapping's except clause caught RecursionError, and cli mapped ConfigError to exit 2
    """
    root = Path(os.path.realpath(tmp_path))
    depth = 50_000
    (root / "mapping.toml").write_text("version = 1\nx = " + ("[" * depth) + ("]" * depth) + "\n", encoding="utf-8")
    (root / "README.md").write_text("# doc\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="could not be parsed"):
        scan(root, config=Config(profile="fast", select=("DS115",), deprecated_references_file="mapping.toml"))

    (root / "docsentinel.toml").write_text(
        'profile = "fast"\ndeprecated_references_file = "mapping.toml"\n', encoding="utf-8"
    )
    exit_code = cli.main(["scan", str(root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Scan failed" in captured.err


def test_prose_in_indented_code_and_html_block_is_a_documented_false_positive(tmp_path: Path):
    """
    [Integration] detectors deprecated references ds115: pins the indented-code / HTML-block prose-mask gap (R5).

    Scenario:
        Given a committed prose mapping and a document that writes the old token in live prose, in a 4-space
            indented code block, in an HTML block, and (as controls) in a fenced block and an inline-code span,
            scanned through detect
        When detect runs
        Then the fenced and inline-code occurrences are exempt (the scanner masks them) while the live-prose,
            indented-code and HTML-block occurrences are reported - the one documented false-positive direction
            (markdown_dialect.md), pinned so a future mask extension is a deliberate, tested change.

    Boundaries:
        - Focus: the documented indented-code / HTML-block prose-mask false positive (R5)
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether the shared scanner began exposing indented-code / HTML-block spans (then extend _masked_text)
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "mapping.toml").write_text(
        'version = 1\n[[replacement]]\nold = "oldname"\nnew = "newname"\nkind = "prose"\n', encoding="utf-8"
    )
    (root / "README.md").write_text(
        "# Doc\n\n"
        "The oldname helper is retired.\n\n"  # live prose, line 3 -> reported
        "```\noldname fenced\n```\n\n"  # fenced -> masked
        "An inline `oldname` span.\n\n"  # inline code -> masked
        "    oldname indented\n\n"  # indented code block -> reported (documented FP)
        "<div>\noldname in html\n</div>\n",  # HTML block -> reported (documented FP)
        encoding="utf-8",
    )

    findings = dep.detect(root, (models.Document("README.md", 0),), Config(deprecated_references_file="mapping.toml"))
    lines = sorted(finding.line for finding in findings)
    assert lines == [3, 11, 14]
