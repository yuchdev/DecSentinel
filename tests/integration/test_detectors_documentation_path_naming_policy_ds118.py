"""Integration tests for DS118 over committed Markdown assets in ``tests/assets/ds118``.

This is Story 14.0 Task 03, the opt-in documentation file and directory naming-policy
rule. Every one of the 14 committed scenarios is loaded in isolation through the
``asset_case`` fixture and asserted against an explicit, checked-in expectation table
(:data:`SETUP`, :data:`CLEAN_CASES`, :data:`FINDING_EXPECTATIONS`) transcribed from the
Task 02 manifest, the ``fixture-matrix`` DS118 rows and the detector's stable message
contract -- never derived from whatever the analyzer currently emits. The generic
Milestone 0005 fixture catalog executes **only** ``naming_disabled_is_inert`` (the lone
``default``-setup scenario); the other 13 outcomes carry a non-default ``setup`` and are
proven only by this file. For every scenario the exact ``Config`` is built from its matrix
``setup`` string (``documentation_naming=kebab``/``snake``, ``exclude=["vendor"]`` for the
excluded tree, and the ``????-*`` ADR prefix pattern for ``adr-prefix-allow``) and the
outcome is asserted through both ``naming.detect`` and the shared ``scan`` engine:
``line=None`` (the policy is over the path string, not the body), the offending path,
``warning`` severity and message meaning (the offending component, the suggested rename),
counts and ordering, one finding per offending component per document as implemented, for
the six CLEAN and eight FINDING scenarios the matrix fixes (0 ERROR scenarios -- DS118 has
no readiness error surface: it never touches the filesystem).

DS118 is a ``fast``-profile **opt-in** policy rule at ``warning`` severity, gated on
``documentation_naming`` exactly as DS110 is gated on ``require_fence_languages``, DS112
on ``navigation_indexes`` and DS115 on ``deprecated_references_file``. With the style
``off`` (the default) it is registered and selectable yet evaluates nothing, and the
engine notice names it ``DS118 (set documentation_naming)`` and excludes it from the
evaluated count; selecting a style counts it (the inert ``naming_disabled_is_inert``
scenario flips to a counted finding the moment a style is configured). Unlike every other
rule in ``markdown_dialect.md`` DS118 performs **zero filesystem access** of any kind: it
is a pure policy over ``Document.path``. That contract is proven two ways here -- the
syscall-armed proof lives in ``tests/mock/test_detectors_documentation_naming_oracle.py``,
and this suite additionally proves through the shared engine that a ``select=("DS118",)``
scan touches exactly the paths a no-rule scan touches (DS118 adds none) using the
path-recording recorder from ``tests/mock/test_detectors_document_ids_oracle.py``.

The file also exercises ``select``/``ignore`` (exact and the ``DS11``/``DS1``/``DS2``
prefixes); baseline round-trips; text/json/github report stability; the CLI warning and
strict exit paths; ``docsentinel rules``/``doctor`` surfacing of the opt-in marker; the
four naming options through both ``docsentinel.toml`` and ``[tool.doc_sentinel]``
including invalid values; the injected-``Config`` fail-closed defences (invalid style,
pattern count/length bounds); the exemptions (README.md/index.md, allow exact and
full-path, the ``?``/``*`` glob subset with regex metacharacters matched literally); the
``documentation_naming_directories`` scope toggle; suggested-rename determinism and safety
(ASCII, ``café`` -> ``cafe``, camelCase split, the ``document`` fallback); hostile names
(ESC/newline/``::error``/RTL/NUL/very long components) bounded and ``repr``-escaped in
every report format; the documented NFC-vs-NFD path behaviour; determinism across repeated
scans and fresh roots; the fast stdlib-only import with no network or content execution;
and the linear-time requirement on adversarial naming floods (many documents, long
components, deep nesting and a shared offending prefix) routed through ``detect`` end to
end, with a naive list-membership reference proving the shared workload would be quadratic.
The exhaustive algorithmic shape coverage lives in
``tests/unit/test_detectors_documentation_naming.py``; this suite proves the committed
scenarios and the cross-module behaviour. See ``docs/dev/markdown_dialect.md`` (the DS118
section) for the documented case-insensitive-filesystem and NFC policy.

CRLF, invalid UTF-8, unreadable files and very long *lines* are **not applicable** to
DS118: it never reads document content, so content encoding and line structure cannot
affect a path-only policy. :func:`test_content_is_irrelevant_so_crlf_and_utf8_are_not_applicable`
pins that explicitly rather than leaving the N/A dimensions unexercised.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Optional

import pytest

from docsentinel import baseline, cli, models
from docsentinel.config import Config, ConfigError
from docsentinel.detectors import naming
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase, load_asset_case
from tests.mock.test_detectors_document_ids_oracle import _install_recorder, _is_under, _Recorder
from tests.timing_helpers import assert_scales_linearly, measure_scaling

#: The exact ``Config`` override each committed scenario requires, transcribed from the
#: ``setup`` column of ``fixture-matrix`` (Task 02). Most cases only select a style;
#: ``allowed_numeric_adr_prefix`` adds the ``????-*`` ADR prefix pattern the ``adr-prefix-allow``
#: setup names; ``excluded_vendor_directory`` adds ``exclude=["vendor"]`` so discovery drops
#: the imported tree; ``naming_disabled_is_inert`` configures nothing (the ``default`` setup,
#: so the style stays ``off``). These values drive this suite's assertions and are never
#: derived from the analyzer.
SETUP: dict[str, dict[str, object]] = {
    "lower_kebab_docs_paths": {"documentation_naming": "kebab"},
    "readme_index_exemptions": {"documentation_naming": "kebab"},
    "allowed_numeric_adr_prefix": {
        "documentation_naming": "kebab",
        "documentation_naming_prefix_patterns": ("????-*",),
    },
    "deep_nested_clean_paths": {"documentation_naming": "kebab"},
    "excluded_vendor_directory": {"documentation_naming": "kebab", "exclude": ("vendor",)},
    "naming_disabled_is_inert": {},
    "uppercase_filename_violation": {"documentation_naming": "kebab"},
    "spaces_in_filename_violation": {"documentation_naming": "kebab"},
    "underscore_kebab_violation": {"documentation_naming": "kebab"},
    "hyphen_snake_violation": {"documentation_naming": "snake"},
    "uppercase_directory_violation": {"documentation_naming": "kebab"},
    "unicode_filename_policy": {"documentation_naming": "kebab"},
    "multiple_bad_components": {"documentation_naming": "kebab"},
    "camelcase_path_diagnostic": {"documentation_naming": "kebab"},
}

#: The six committed CLEAN scenarios: conformant kebab paths, the canonical README/index
#: exemptions, a numeric ADR prefix accepted under the explicit pattern, a deep nest of
#: kebab components, an excluded vendor tree (clean because discovery drops it), and the
#: inert default-off scenario -- all must report zero DS118 findings.
CLEAN_CASES: tuple[str, ...] = (
    "lower_kebab_docs_paths",
    "readme_index_exemptions",
    "allowed_numeric_adr_prefix",
    "deep_nested_clean_paths",
    "excluded_vendor_directory",
    "naming_disabled_is_inert",
)

#: The eight FINDING scenarios, mapped to the ordered ``(line, path, message)`` tuple of
#: each expected DS118 ``warning``. Every ``line`` is ``None`` (the policy is over the path
#: string, not the body) and every message is the detector's stable contract: the component
#: kind, the bounded offending component (``unicode_filename_policy`` renders its accented
#: byte as ``\xe9`` through the bounded ``unicode_escape`` echo), the active style, and the
#: deterministic suggested rename. ``multiple_bad_components`` is the two-findings case
#: (directory outermost-first, then file). Fixed by the committed fixtures and the message
#: contract, never derived from the analyzer.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[Optional[int], str, str], ...]] = {
    "uppercase_filename_violation": (
        (
            None,
            "docs/GettingStarted.md",
            'file name "GettingStarted.md" does not match the kebab naming policy; suggested rename "getting-started.md"',
        ),
    ),
    "spaces_in_filename_violation": (
        (
            None,
            "docs/Quick Start.md",
            'file name "Quick Start.md" does not match the kebab naming policy; suggested rename "quick-start.md"',
        ),
    ),
    "underscore_kebab_violation": (
        (
            None,
            "docs/quick_start.md",
            'file name "quick_start.md" does not match the kebab naming policy; suggested rename "quick-start.md"',
        ),
    ),
    "hyphen_snake_violation": (
        (
            None,
            "docs/quick-start.md",
            'file name "quick-start.md" does not match the snake naming policy; suggested rename "quick_start.md"',
        ),
    ),
    "uppercase_directory_violation": (
        (
            None,
            "Docs/README.md",
            'directory name "Docs" does not match the kebab naming policy; suggested rename "docs"',
        ),
    ),
    "unicode_filename_policy": (
        (
            None,
            "docs/café-guide.md",
            r'file name "caf\xe9-guide.md" does not match the kebab naming policy; suggested rename "cafe-guide.md"',
        ),
    ),
    "multiple_bad_components": (
        (
            None,
            "BadDocs/Quick_Start.md",
            'directory name "BadDocs" does not match the kebab naming policy; suggested rename "bad-docs"',
        ),
        (
            None,
            "BadDocs/Quick_Start.md",
            'file name "Quick_Start.md" does not match the kebab naming policy; suggested rename "quick-start.md"',
        ),
    ),
    "camelcase_path_diagnostic": (
        (
            None,
            "docs/apiClient.md",
            'file name "apiClient.md" does not match the kebab naming policy; suggested rename "api-client.md"',
        ),
    ),
}

#: All 14 committed scenarios asserted through scan() for an outcome.
OUTCOME_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: The outcome scenarios whose outcome is a property of DS118's per-path policy and so can
#: also be asserted through the pure ``detect`` entry point. ``excluded_vendor_directory`` is
#: excluded here: its clean outcome is a *discovery* property (the engine drops the vendor
#: tree), not a detector property -- ``test_excluded_vendor_directory_is_clean_via_discovery``
#: proves that distinction on its own.
DETECT_CASES: tuple[str, ...] = tuple(case for case in OUTCOME_CASES if case != "excluded_vendor_directory")

#: The full fast-profile rule set, in registry order, run alongside DS118.
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

#: The engine notice when every opt-in fast rule is off (the default): DS118 is named, not
#: counted, alongside the other three off opt-in rules.
NOTICE_ALL_OPT_IN_OFF = (
    "12 fast rule(s) evaluated; opt-in rule(s) not enabled: "
    "DS110 (set require_fence_languages), DS112 (set navigation_indexes), "
    "DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
)

#: The engine notice when only DS118 is configured: DS118 drops out of the not-enabled list
#: and the evaluated count rises by one, while the other three opt-in rules stay named.
NOTICE_DS118_ON = (
    "13 fast rule(s) evaluated; opt-in rule(s) not enabled: "
    "DS110 (set require_fence_languages), DS112 (set navigation_indexes), "
    "DS115 (set deprecated_references_file)."
)


def _config(case: str, **overrides: object) -> Config:
    """Return the fast-profile ``Config`` for ``case`` using its exact matrix setup.

    :param case: The committed scenario slug.
    :param overrides: Extra ``Config`` keyword overrides merged over the matrix setup.
    :returns: The ``Config`` with ``profile="fast"`` and the scenario's naming setup.
    """
    return Config(profile="fast", **{**SETUP[case], **overrides})  # type: ignore[arg-type]


def _ds118(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS118 findings from a mixed finding tuple, preserving order.

    :param findings: Findings from a detector or scan.
    :returns: The DS118 subset in the original order.
    """
    return tuple(finding for finding in findings if finding.rule == "DS118")


def _triples(findings: tuple[models.Finding, ...]) -> list[tuple[Optional[int], str, str]]:
    """Return ordered ``(line, path, message)`` triples for a finding tuple.

    :param findings: Findings to describe.
    :returns: The ordered ``(line, path, message)`` triples.
    """
    return [(finding.line, finding.path, finding.message) for finding in findings]


def _docs(*paths: str) -> tuple[models.Document, ...]:
    """Return fabricated zero-byte Documents for the given relative paths.

    DS118 reads only ``Document.path``, so a fabricated Document with a hostile or
    arbitrary path is a faithful input: no file need exist on disk.

    :param paths: The relative POSIX document paths.
    :returns: The fabricated Documents in the given order.
    """
    return tuple(models.Document(path, 0) for path in paths)


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors documentation path naming ds118: verifies the local catalog totals.

    Scenario:
        Given the committed ds118 asset directories and this suite's expectation table
        When the clean and finding scenarios are counted
        Then there are exactly 6 clean, 8 finding, 0 error and 14 total scenarios matching Task 02, the
        clean and finding sets are disjoint, and every scenario carries an exact matrix setup.

    Boundaries:
        - Focus: the expectation table is complete, non-overlapping and matches the 6/8/0 split
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in two outcome sets or is missing from SETUP
    """
    assert len(CLEAN_CASES) == 6
    assert len(FINDING_EXPECTATIONS) == 8
    assert len(set(OUTCOME_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)
    assert set(SETUP) == set(OUTCOME_CASES)


def test_ds118_is_registered_as_an_opt_in_fast_rule():
    """
    [Integration] detectors documentation path naming ds118: verifies opt-in fast registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS118 is present with warning severity, its title and opt_in_option="documentation_naming",
        proving it is an opt-in policy rule like DS110/DS112/DS115 rather than an always-active rule.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.naming registered DS118 on import
        - Whether DS118 drifted profile/severity or lost its opt_in_option
    """
    fast = {rule.code: rule for rule in rules_for_profile("fast")}
    assert "DS118" in fast
    rule = fast["DS118"]
    assert rule.severity == "warning"
    assert rule.title == "Documentation file and directory naming policy"
    assert rule.opt_in_option == "documentation_naming"


@pytest.mark.parametrize("case", DETECT_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies detect per committed case.

    Scenario:
        Given one CLEAN or FINDING ds118 scenario (except the discovery-only excluded tree) materialized
            into a fresh tmp_path
        When naming.detect runs over all its documents with the exact matrix setup config
        Then clean cases yield no finding and finding cases yield exactly the expected DS118 warnings at
        line None, the offending path and full message, in the detector's deterministic order (directory
        components outermost-first, then the file component).

    Boundaries:
        - Focus: the pure detect entry point over real asset paths under the exact per-case config
        - Fixtures/params: parametrized over the 13 detector-provable outcome scenarios; asset_case

    On failure, first check:
        - The expected (line, path, message) in FINDING_EXPECTATIONS for this case
        - Whether the fixture file name was altered (it must stay byte-for-byte, including the accented one)
        - Whether SETUP still carries this case's exact matrix overrides
    """
    loaded = asset_case("ds118", case)
    findings = _ds118(naming.detect(loaded.root, loaded.documents(), _config(case)))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    assert _triples(findings) == list(FINDING_EXPECTATIONS[case])
    for finding in findings:
        assert finding.rule == "DS118"
        assert finding.severity == "warning"
        assert finding.line is None


@pytest.mark.parametrize("case", OUTCOME_CASES)
def test_scan_isolated_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies the engine reproduces each outcome.

    Scenario:
        Given one CLEAN or FINDING ds118 scenario scanned through the shared engine with select pinned to
            DS118 and the exact matrix setup config
        When scan resolves and runs only DS118 (applying discovery, so the excluded vendor tree is dropped)
        Then DS118 is the sole enabled rule with nothing pending, and its findings match the exact
            expectation table (zero for clean cases, the expected warnings for finding cases), proving the
            engine path yields the same outcome as the pure detector and that discovery exclusion holds.

    Boundaries:
        - Focus: the shared scan engine reproduces the detector outcome through config dispatch and discovery
        - Fixtures/params: parametrized over all 14 outcome scenarios; asset_case

    On failure, first check:
        - Whether the engine still forwards the effective Config to DS118 (keyword dispatch)
        - Whether select=("DS118",) narrowed the active set to DS118 alone
        - Whether discovery honoured exclude=["vendor"] for the excluded scenario
    """
    loaded = asset_case("ds118", case)
    result = scan(loaded.root, config=_config(case, select=("DS118",)))

    assert result.enabled_rules == ("DS118",)
    assert result.pending == ()
    own = _ds118(result.findings)
    if case in CLEAN_CASES:
        assert own == ()
    else:
        assert _triples(own) == list(FINDING_EXPECTATIONS[case])


def test_excluded_vendor_directory_is_clean_via_discovery(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies exclusion, not a detector exemption.

    Scenario:
        Given the excluded_vendor_directory fixture (vendor/SomeDoc.md, an uppercase-stem file) scanned
            under the fast profile with documentation_naming=kebab and exclude=["vendor"]
        When the engine discovers documents and then, separately, DS118 detect runs over the vendor document
            directly
        Then the scan is clean because discovery drops the vendor tree, yet DS118 itself flags SomeDoc.md
            when handed the vendor document -- proving the clean outcome is a discovery exclusion and that
            DS118 has no built-in vendor exemption of its own.

    Boundaries:
        - Focus: the matrix "excluded imported docs must not be checked" outcome is a discovery property
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether discovery still removes the excluded directory before the engine calls DS118
        - Whether DS118 wrongly grew a vendor exemption (detect over the vendor doc should still flag it)
    """
    loaded = asset_case("ds118", "excluded_vendor_directory")

    result = scan(loaded.root, config=_config("excluded_vendor_directory", select=("DS118",)))
    assert _ds118(result.findings) == ()

    direct = _ds118(naming.detect(loaded.root, _docs("vendor/SomeDoc.md"), Config(documentation_naming="kebab")))
    assert [finding.message for finding in direct] == [
        'file name "SomeDoc.md" does not match the kebab naming policy; suggested rename "some-doc.md"'
    ]


def test_inert_default_is_named_not_counted_and_flips_when_configured(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies the opt-in gate is honest (R8).

    Scenario:
        Given the naming_disabled_is_inert fixture (docs/Getting Started.md, a space-bearing file name)
            scanned under the default fast profile and then with documentation_naming=kebab configured
        When the engine builds the scan notice
        Then with the style off DS118 stays in enabled_rules (selection is orthogonal to the gate), evaluates
            zero findings, is excluded from the evaluated count and named "DS118 (set documentation_naming)";
            selecting kebab flips the same fixture to a counted finding and drops DS118 from the not-enabled
            list, so the disabled policy never masquerades as an evaluated clean result.

    Boundaries:
        - Focus: R8 opt-in accounting for the inert default and the flip to counted
        - Fixtures/params: asset_case

    On failure, first check:
        - The documentation_naming off short-circuit in check_paths and rules.opt_in_satisfied
        - The engine notice's opt-in-rule accounting (off rules excluded from the evaluated count)
    """
    loaded = asset_case("ds118", "naming_disabled_is_inert")

    off = scan(loaded.root, config=Config(profile="fast"))
    assert "DS118" in off.enabled_rules
    assert off.pending == ()
    assert _ds118(off.findings) == ()
    assert off.notice == NOTICE_ALL_OPT_IN_OFF

    on = scan(loaded.root, config=Config(profile="fast", documentation_naming="kebab"))
    assert "DS118" not in on.notice
    assert on.notice == NOTICE_DS118_ON
    assert [finding.message for finding in _ds118(on.findings)] == [
        'file name "Getting Started.md" does not match the kebab naming policy; suggested rename "getting-started.md"'
    ]


def test_cli_rules_tags_ds118_as_opt_in(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors documentation path naming ds118: verifies `docsentinel rules` tags the opt-in.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS118 appears under the fast profile tagged "[opt-in: set documentation_naming]", exactly as
            DS110, DS112 and DS115 are tagged for their own enabling options.

    Boundaries:
        - Focus: rules-command surfacing of DS118 as an opt-in policy rule
        - Fixtures/params: capsys

    On failure, first check:
        - Whether DS118 kept opt_in_option="documentation_naming"
        - The rules-command opt-in tag formatting
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    ds118_lines = [line for line in captured.out.splitlines() if "DS118:" in line]
    assert ds118_lines == ["  DS118: Documentation file and directory naming policy [opt-in: set documentation_naming]"]


def test_cli_doctor_counts_ds118_among_the_four_opt_in_rules(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors documentation path naming ds118: verifies `docsentinel doctor` counts DS118.

    Scenario:
        Given the installed rule registry
        When the doctor command reports environment readiness
        Then the fast-rule tally reads exactly
            "16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)", so DS118 is inside
            the registered count and is one of the four opt-in rules alongside DS110, DS112 and DS115.

    Boundaries:
        - Focus: doctor's separate accounting of opt-in versus always-active fast rules
        - Fixtures/params: capsys

    On failure, first check:
        - Whether the registered fast-rule count changed when a rule was added
        - Whether DS118 was miscounted as always-active rather than opt-in
    """
    exit_code = cli.main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS118" in {rule.code for rule in rules_for_profile("fast")}
    assert "fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)" in captured.out


def test_cli_fast_json_scan_reports_ds118_warning_and_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors documentation path naming ds118: verifies the CLI fast json warning path.

    Scenario:
        Given the camelcase_path_diagnostic fixture carrying a docsentinel.toml that selects the kebab style,
            scanned via the CLI with --profile fast --format json and no --strict
        When the command runs
        Then it prints a JSON report containing the DS118 warning with line null and the api-client.md
            suggestion and exits 0, because a bare warning is non-blocking.

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the non-blocking warning exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for warning-severity findings
        - Whether the discovered docsentinel.toml configured documentation_naming
    """
    loaded = asset_case("ds118", "camelcase_path_diagnostic")
    (loaded.root / "docsentinel.toml").write_text(
        'profile = "fast"\ndocumentation_naming = "kebab"\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(loaded.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds118 = [finding for finding in payload["findings"] if finding["rule"] == "DS118"]
    assert len(ds118) == 1
    assert ds118[0]["path"] == "docs/apiClient.md"
    assert ds118[0]["severity"] == "warning"
    assert ds118[0]["line"] is None
    assert 'suggested rename "api-client.md"' in ds118[0]["message"]
    assert exit_code == 0


def test_cli_strict_scan_blocks_on_ds118_warning(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors documentation path naming ds118: verifies --strict promotes the warning.

    Scenario:
        Given the uppercase_filename_violation fixture with a [tool.doc_sentinel] table selecting the kebab
            style, scanned via the CLI under the fast profile with --strict
        When the command runs
        Then the DS118 warning becomes blocking and the process exits 1.

    Boundaries:
        - Focus: the strict exit-code promotion for a warning-only rule
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The _exit_code strict branch for non-deep profiles
        - Whether DS118 still produces a finding under the strict run
    """
    loaded = asset_case("ds118", "uppercase_filename_violation")
    (loaded.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\ndocumentation_naming = "kebab"\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(loaded.root), "--profile", "fast", "--strict"])

    capsys.readouterr()
    assert exit_code == 1


def test_cli_clean_case_without_strict_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors documentation path naming ds118: verifies a clean kebab tree exits 0.

    Scenario:
        Given the lower_kebab_docs_paths fixture carrying a docsentinel.toml selecting the kebab style,
            scanned via the CLI under the fast profile without --strict
        When the command runs
        Then it exits 0 with no DS118 finding, proving a conformant tree is not flagged under an active style.

    Boundaries:
        - Focus: the no-blocking-findings exit code for a genuinely clean configured scan
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether DS118 wrongly flagged a conformant kebab path
        - The CLI exit-code mapping when no findings are produced
    """
    loaded = asset_case("ds118", "lower_kebab_docs_paths")
    (loaded.root / "docsentinel.toml").write_text(
        'profile = "fast"\ndocumentation_naming = "kebab"\n', encoding="utf-8"
    )

    exit_code = cli.main(["scan", str(loaded.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert [finding for finding in payload["findings"] if finding["rule"] == "DS118"] == []
    assert exit_code == 0


def test_select_narrows_to_ds118_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies select activates only DS118.

    Scenario:
        Given the multiple_bad_components scenario scanned with select pinned to DS118 and the kebab style
        When the engine resolves the active rule set
        Then only DS118 is enabled and its two expected warnings (directory then file) are produced, with any
            sibling a full scan would add dropped.

    Boundaries:
        - Focus: exact-code select resolution for a fast opt-in rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS118 selector
        - Whether another rule leaked into enabled_rules despite the select
    """
    loaded = asset_case("ds118", "multiple_bad_components")

    result = scan(loaded.root, config=_config("multiple_bad_components", select=("DS118",)))

    assert result.enabled_rules == ("DS118",)
    assert _triples(result.findings) == list(FINDING_EXPECTATIONS["multiple_bad_components"])


def test_prefix_select_and_ignore_semantics_for_ds118(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies DS11/DS1/DS2 select and ignore.

    Scenario:
        Given the camelcase_path_diagnostic scenario (a DS118-only warning) scanned under the fast profile
            with the kebab style configured
        When it is selected by the genuine ``DS11`` prefix, the whole-set ``DS1`` prefix and the non-matching
            ``DS2`` prefix, then ignored by the exact code, by ``DS11`` and by ``DS2``
        Then ``DS11`` and ``DS1`` keep DS118 active and still reporting its single finding, ``DS2`` activates
            no fast rule, the exact and ``DS11`` ignores drop DS118 and its finding, and ``DS2`` leaves it
            active - all expectations derived from FAST_RULE_ORDER, not hard-coded.

    Boundaries:
        - Focus: prefix select and ignore precedence for DS118 against the live fast rule set
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast rule codes
        - Whether a non-matching prefix (DS2) wrongly activated or suppressed DS118
    """
    loaded = asset_case("ds118", "camelcase_path_diagnostic")
    ds11_prefixed = tuple(code for code in FAST_RULE_ORDER if code.startswith("DS11"))

    ds11x = scan(loaded.root, config=_config("camelcase_path_diagnostic", select=("DS11",)))
    assert ds11x.enabled_rules == ds11_prefixed
    assert [finding.path for finding in _ds118(ds11x.findings)] == ["docs/apiClient.md"]

    whole_fast = scan(loaded.root, config=_config("camelcase_path_diagnostic", select=("DS1",)))
    assert whole_fast.enabled_rules == FAST_RULE_ORDER
    assert [finding.path for finding in _ds118(whole_fast.findings)] == ["docs/apiClient.md"]

    none = scan(loaded.root, config=_config("camelcase_path_diagnostic", select=("DS2",)))
    assert none.enabled_rules == ()
    assert _ds118(none.findings) == ()

    exact = scan(loaded.root, config=_config("camelcase_path_diagnostic", ignore=("DS118",)))
    assert "DS118" not in exact.enabled_rules
    assert _ds118(exact.findings) == ()

    by_prefix = scan(loaded.root, config=_config("camelcase_path_diagnostic", ignore=("DS11",)))
    assert by_prefix.enabled_rules == tuple(code for code in FAST_RULE_ORDER if not code.startswith("DS11"))
    assert _ds118(by_prefix.findings) == ()

    unaffected = scan(loaded.root, config=_config("camelcase_path_diagnostic", ignore=("DS2",)))
    assert "DS118" in unaffected.enabled_rules
    assert [finding.path for finding in _ds118(unaffected.findings)] == ["docs/apiClient.md"]


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_style_and_directories_options_propagate_from_both_config_files(
    config_file: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors documentation path naming ds118: verifies style and directories load from both files.

    Scenario:
        Given the uppercase_directory_violation fixture carrying either a standalone docsentinel.toml or a
            [tool.doc_sentinel] table that selects the kebab style, and then, in a second run, also turns
            documentation_naming_directories off
        When scan discovers each config (no injected Config)
        Then the style-only config flags the Docs directory, and disabling directory checking silences it -
            proving documentation_naming and documentation_naming_directories both load and reach DS118
            through each config-file form.

    Boundaries:
        - Focus: config discovery and propagation of documentation_naming/documentation_naming_directories
        - Fixtures/params: parametrized over the two config-file forms; asset_case

    On failure, first check:
        - Whether load_config reads the two options from the given file form
        - Whether the engine forwards the discovered Config to DS118
    """
    loaded = asset_case("ds118", "uppercase_directory_violation")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (loaded.root / config_file).write_text(
        f'{prefix}profile = "fast"\ndocumentation_naming = "kebab"\n', encoding="utf-8"
    )
    flagged = _ds118(scan(loaded.root).findings)
    assert [finding.message for finding in flagged] == [
        'directory name "Docs" does not match the kebab naming policy; suggested rename "docs"'
    ]

    (loaded.root / config_file).write_text(
        f'{prefix}profile = "fast"\ndocumentation_naming = "kebab"\ndocumentation_naming_directories = false\n',
        encoding="utf-8",
    )
    assert _ds118(scan(loaded.root).findings) == ()


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_allow_and_prefix_options_propagate_from_both_config_files(
    config_file: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors documentation path naming ds118: verifies allow and prefix patterns load from both files.

    Scenario:
        Given the uppercase_filename_violation fixture carrying either a standalone docsentinel.toml or a
            [tool.doc_sentinel] table selecting the kebab style, then adding documentation_naming_allow with
            the exact file name, then instead adding documentation_naming_prefix_patterns with a matching glob
        When scan discovers each config (no injected Config)
        Then the style-only config flags GettingStarted.md, the allow entry silences it, and the prefix pattern
            silences it too - proving documentation_naming_allow and documentation_naming_prefix_patterns both
            load and reach DS118 through each config-file form.

    Boundaries:
        - Focus: config discovery and propagation of documentation_naming_allow/prefix_patterns via both forms
        - Fixtures/params: parametrized over the two config-file forms; asset_case

    On failure, first check:
        - Whether load_config reads the allow/prefix list options from the given file form
        - Whether the allowlist and prefix patterns reach the DS118 policy
    """
    loaded = asset_case("ds118", "uppercase_filename_violation")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (loaded.root / config_file).write_text(
        f'{prefix}profile = "fast"\ndocumentation_naming = "kebab"\n', encoding="utf-8"
    )
    assert len(_ds118(scan(loaded.root).findings)) == 1

    (loaded.root / config_file).write_text(
        f'{prefix}profile = "fast"\ndocumentation_naming = "kebab"\n'
        'documentation_naming_allow = ["README.md", "index.md", "GettingStarted.md"]\n',
        encoding="utf-8",
    )
    assert _ds118(scan(loaded.root).findings) == ()

    (loaded.root / config_file).write_text(
        f'{prefix}profile = "fast"\ndocumentation_naming = "kebab"\n'
        'documentation_naming_prefix_patterns = ["Getting*"]\n',
        encoding="utf-8",
    )
    assert _ds118(scan(loaded.root).findings) == ()


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("documentation_naming", '"camel"'),
        ("documentation_naming_allow", '"README.md"'),
        ("documentation_naming_prefix_patterns", '"RFC*"'),
        ("documentation_naming_directories", '"yes"'),
    ],
)
def test_invalid_naming_option_raises_config_error(
    option: str,
    value: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors documentation path naming ds118: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml that sets one naming option to an invalid value (a style outside
            off|kebab|snake, a bare string where a list is required for allow or prefix patterns, or a
            non-boolean for the directories flag)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects invalid values for every DS118 option (standalone file)
        - Fixtures/params: parametrized over the four options; asset_case

    On failure, first check:
        - The enum/list/bool validation for the named option in config.py
        - Whether an invalid value was coerced instead of raising
    """
    loaded = asset_case("ds118", "lower_kebab_docs_paths")
    (loaded.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(loaded.root)


def test_injected_invalid_style_fails_closed_through_detect_and_scan(tmp_path: Path):
    """
    [Integration] detectors documentation path naming ds118: verifies an injected invalid style fails closed.

    Scenario:
        Given a library-caller Config carrying documentation_naming="camel" (an unrecognised style that
            bypasses load_config's enum gate) over a real tree with one offending file
        When naming.detect runs and, separately, the shared engine scans with DS118 selected
        Then both raise a ConfigError (never a clean empty-findings result), so a config-injection PR cannot
            make DS118 silently degrade to no-op on an unknown style.

    Boundaries:
        - Focus: the _VALID_STYLES fail-closed defence against a Config injection, through both entry points
        - Fixtures/params: tmp_path

    On failure, first check:
        - The _VALID_STYLES guard in _Policy.__init__ and that scan does not swallow the ConfigError
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "docs").mkdir()
    (root / "docs" / "Bad.md").write_text("# bad\n", encoding="utf-8")
    config = Config(profile="fast", select=("DS118",), documentation_naming="camel")

    with pytest.raises(ConfigError, match="documentation_naming must be one of"):
        naming.detect(root, _docs("docs/Bad.md"), config)
    with pytest.raises(ConfigError, match="documentation_naming must be one of"):
        scan(root, config=config)


def test_injected_out_of_bound_prefix_patterns_fail_closed_through_detect_and_scan(tmp_path: Path):
    """
    [Integration] detectors documentation path naming ds118: verifies oversized prefix patterns fail closed.

    Scenario:
        Given a library-caller Config whose documentation_naming_prefix_patterns exceeds the count cap, and a
            second whose single pattern exceeds the length cap (both bypassing load_config), over a real tree
        When naming.detect runs and the shared engine scans with DS118 selected
        Then every path raises a ConfigError rather than allowing an unbounded per-component glob compare, so
            a config-injection PR cannot drive a pattern-flood or a giant pattern.

    Boundaries:
        - Focus: the _validated_patterns count/length bounds fail-closed through both entry points
        - Fixtures/params: tmp_path

    On failure, first check:
        - The _MAX_PREFIX_PATTERNS / _MAX_PATTERN_LENGTH checks in _validated_patterns
        - Whether scan swallowed the ConfigError into a clean result
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "docs").mkdir()
    (root / "docs" / "Bad.md").write_text("# bad\n", encoding="utf-8")

    too_many = tuple(f"p{index}" for index in range(naming._MAX_PREFIX_PATTERNS + 1))
    too_long = ("x" * (naming._MAX_PATTERN_LENGTH + 1),)
    for patterns in (too_many, too_long):
        config = Config(
            profile="fast",
            select=("DS118",),
            documentation_naming="kebab",
            documentation_naming_prefix_patterns=patterns,
        )
        with pytest.raises(ConfigError):
            naming.detect(root, _docs("docs/Bad.md"), config)
        with pytest.raises(ConfigError):
            scan(root, config=config)


def test_canonical_and_allow_exemptions_through_detect():
    """
    [Integration] detectors documentation path naming ds118: verifies the allowlist exemptions.

    Scenario:
        Given the default README.md/index.md allowlist and a custom allowlist holding one exact file name and
            one full relative path
        When the kebab policy runs over nested canonical names, the exact-name file anywhere, the full-path
            entry and an unlisted sibling
        Then the canonical names are exempt at any depth, the exact-name entry exempts that file name anywhere,
            the full-path entry exempts only that path, and the unlisted sibling is still flagged.

    Boundaries:
        - Focus: README/index default exemption plus exact-filename and full-relative-path allowlist matching
        - Fixtures/params: none

    On failure, first check:
        - The allow frozenset filename-and-full-path membership in _Policy.check_path/evaluate_filename
    """
    canonical = naming.detect(object(), _docs("a/b/index.md", "c/README.md"), Config(documentation_naming="kebab"))
    assert _ds118(canonical) == ()

    allow = ("README.md", "index.md", "CHANGELOG.md", "docs/NOTES.md")
    config = Config(documentation_naming="kebab", documentation_naming_allow=allow)
    findings = _ds118(naming.detect(object(), _docs("deep/CHANGELOG.md", "docs/NOTES.md", "other/NOTES.md"), config))
    assert [finding.path for finding in findings] == ["other/NOTES.md"]


def test_prefix_glob_subset_is_literal_for_regex_metacharacters_through_detect():
    """
    [Integration] detectors documentation path naming ds118: verifies the glob subset is literal, not regex.

    Scenario:
        Given a prefix pattern "RC.1*" whose "." is a literal dot (not a regex any-character), the pattern
            "????-*" for ADR-style numeric prefixes, and a pattern "[ab]*" whose brackets are literal
        When the kebab policy runs over components the glob exempts, a look-alike a regex would wrongly exempt,
            and a bracket-literal component
        Then "RC.1-Draft.md" and "0001-Fast.md" and "[ab]Thing.md" are exempt while "RCX1Bad.md" is still
            flagged - proving "." never matched "X" as a regex any-character and brackets are literal.

    Boundaries:
        - Focus: the restricted ?/* glob subset, with regex metacharacters and brackets matched literally
        - Fixtures/params: none

    On failure, first check:
        - Whether a user pattern was handed to re.compile or fnmatch instead of the two-pointer _glob_matches
    """
    config = Config(documentation_naming="kebab", documentation_naming_prefix_patterns=("RC.1*", "????-*", "[ab]*"))
    findings = _ds118(
        naming.detect(
            object(),
            _docs("RC.1-Draft.md", "0001-Fast.md", "[ab]Thing.md", "RCX1Bad.md"),
            config,
        )
    )
    assert [finding.path for finding in findings] == ["RCX1Bad.md"]


def test_directories_flag_scope_through_scan(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies the directories scope toggle via scan.

    Scenario:
        Given the multiple_bad_components fixture (a bad directory and a bad file) scanned with DS118 selected
            and the kebab style, once with documentation_naming_directories true (the default) and once false
        When the engine runs DS118
        Then directories true reports both the directory and the file component while directories false reports
            only the file component, proving the scope toggle gates directory checking without affecting the
            file check.

    Boundaries:
        - Focus: documentation_naming_directories exactly as implemented (file always checked; dirs gated)
        - Fixtures/params: asset_case

    On failure, first check:
        - The check_directories guard in _Policy.check_path
    """
    loaded = asset_case("ds118", "multiple_bad_components")

    both = _ds118(scan(loaded.root, config=_config("multiple_bad_components", select=("DS118",))).findings)
    assert [finding.message for finding in both] == [
        message for _, _, message in FINDING_EXPECTATIONS["multiple_bad_components"]
    ]

    file_only = _ds118(
        scan(
            loaded.root,
            config=_config("multiple_bad_components", select=("DS118",), documentation_naming_directories=False),
        ).findings
    )
    assert [finding.message for finding in file_only] == [
        'file name "Quick_Start.md" does not match the kebab naming policy; suggested rename "quick-start.md"'
    ]


@pytest.mark.parametrize(
    ("path", "style", "suggestion"),
    [
        ("docs/GettingStarted.md", "kebab", "getting-started.md"),
        ("docs/apiClient.md", "kebab", "api-client.md"),
        ("docs/café-guide.md", "kebab", "cafe-guide.md"),
        ("docs/quick-start.md", "snake", "quick_start.md"),
        ("docs/Привет.md", "kebab", "document.md"),
    ],
)
def test_suggested_rename_is_deterministic_and_safe(path: str, style: str, suggestion: str):
    """
    [Integration] detectors documentation path naming ds118: verifies deterministic, ASCII-safe suggestions.

    Scenario:
        Given offending file names covering ASCII PascalCase, camelCase, an accented Latin letter, a
            wrong-separator snake case and an all-non-Latin name
        When the active style's policy runs over each
        Then each suggestion is exactly the deterministic conformant rename (camelCase split, café->cafe,
            the document fallback for a name with no ASCII word), is ASCII and uses the active separator.

    Boundaries:
        - Focus: _suggest_component/_suggest_filename determinism and the ASCII/document-fallback safety rules
        - Fixtures/params: parametrized (path, style, suggestion) triples

    On failure, first check:
        - NFKD folding, camelCase splitting and the _EMPTY_SUGGESTION fallback in _suggest_component
    """
    findings = _ds118(naming.detect(object(), _docs(path), Config(documentation_naming=style)))
    assert len(findings) == 1
    message = findings[0].message
    assert f'suggested rename "{suggestion}"' in message
    assert all(ord(character) < 0x80 for character in suggestion)


def test_hostile_component_names_are_bounded_and_repr_escaped_in_every_format(tmp_path: Path):
    """
    [Integration] detectors documentation path naming ds118: verifies hostile names cannot inject output.

    Scenario:
        Given a fabricated Document whose file name carries ESC, a newline, a NUL, an RTL override, a
            "::error" token and a 10,000-character run (constructed through detect because a NUL/newline name
            cannot exist on a POSIX filesystem and a real component is bounded by NAME_MAX), plus - where the
            filesystem allows it - a real file whose short name carries ESC/RTL/::error scanned end to end
        When detect runs and the real-file scan is rendered as text, json and github
        Then the fabricated message carries no raw control byte, renders every control/RTL byte as its escaped
            form, bounds the echoed *original* with a trailing ellipsis and keeps the suggestion pure ASCII;
            and the real on-disk finding renders in every format with no raw control byte, no resolved root and
            a message bounded by the real name - so a hostile path can never inject a terminal escape, forge a
            github annotation, or leak the scan root.

    Boundaries:
        - Focus: output-injection and information-disclosure safety of DS118 messages across all report sinks
        - Non-goal: bounding the ASCII suggestion for a 10 KB *injected* component - a real on-disk component
          is bounded by NAME_MAX, so the realistic sink is the real-file leg, which is fully bounded
        - Fixtures/params: tmp_path (the real-file leg is skipped when the filesystem rejects the name)

    On failure, first check:
        - naming._echo's unicode_escape bound and whether a message leaked a resolved absolute path
    """
    hostile_fabricated = "A\x1b\n\x00‮B::error" + ("z" * 10_000) + ".md"
    findings = _ds118(
        naming.detect(object(), _docs(f"docs/{hostile_fabricated}"), Config(documentation_naming="kebab"))
    )
    assert len(findings) == 1
    message = findings[0].message
    assert not any(ord(character) < 0x20 or ord(character) == 0x7F for character in message)
    assert "\\x1b" in message and "\\x00" in message and "\\n" in message and "\\u202e" in message
    assert message.split(" does not match")[0].endswith('..."')
    _, _, suggestion = message.partition('suggested rename "')
    assert all(ord(character) < 0x80 for character in suggestion)

    root = Path(os.path.realpath(tmp_path))
    (root / "docs").mkdir()
    hostile_real = "A\x1b‮B::error-" + ("y" * 40) + ".md"
    try:
        (root / "docs" / hostile_real).write_text("# hostile\n", encoding="utf-8")
    except OSError:
        pytest.skip("filesystem rejected the hostile file name; the fabricated-Document leg still proves the echo")

    result = scan(root, config=Config(profile="fast", select=("DS118",), documentation_naming="kebab"))
    own = _ds118(result.findings)
    assert len(own) == 1
    # DS118's message (its own output) is bounded, repr-escapes the ESC/RTL bytes and carries a pure-ASCII
    # suggestion. The raw path in Finding.path (and the reporter's document inventory / github file= field) is
    # a tool-wide reporting behaviour -- every rule that reports a hostile-named file echoes that path raw --
    # and is outside DS118's own contract, so the message is what this suite pins across the three formats.
    message = own[0].message
    assert len(message) < 300
    assert not any(ord(character) < 0x20 or ord(character) == 0x7F for character in message)
    assert "\\x1b" in message and "\\u202e" in message
    suggestion_fragment = "a-b-error-" + ("y" * 40)
    for form in ("text", "json", "github"):
        rendered = render(result, form)
        assert render(result, form) == rendered
        assert message in rendered or suggestion_fragment in rendered
        assert str(root) not in rendered


def test_nfc_and_nfd_paths_are_both_flagged_with_the_same_suggestion():
    """
    [Integration] detectors documentation path naming ds118: documents the NFC-vs-NFD path behaviour.

    Scenario:
        Given one document whose accented file name is NFC-encoded and one whose identical name is NFD-encoded,
            both handed to detect exactly as a discovery step would supply them
        When the kebab policy runs over each
        Then both are flagged (the accented letter is outside portable ASCII either way) and both suggest the
            same transliterated cafe-guide.md, while the echoed original differs by encoding - DS118 reports on
            the path bytes as supplied and never normalizes the path itself; the repository relies on git's
            precomposeunicode to deliver committed names in NFC.

    Boundaries:
        - Focus: the documented policy that DS118 operates on Document.path as discovery supplies it
        - Fixtures/params: none

    On failure, first check:
        - Whether _suggest_component's NFKD folding still collapses both encodings to the same ASCII stem
    """
    nfc = unicodedata.normalize("NFC", "café-guide.md")
    nfd = unicodedata.normalize("NFD", "café-guide.md")
    assert nfc != nfd

    nfc_finding = _ds118(naming.detect(object(), _docs(f"docs/{nfc}"), Config(documentation_naming="kebab")))[0]
    nfd_finding = _ds118(naming.detect(object(), _docs(f"docs/{nfd}"), Config(documentation_naming="kebab")))[0]

    assert 'suggested rename "cafe-guide.md"' in nfc_finding.message
    assert 'suggested rename "cafe-guide.md"' in nfd_finding.message
    assert nfc_finding.message != nfd_finding.message


def test_content_is_irrelevant_so_crlf_and_utf8_are_not_applicable(tmp_path: Path):
    """
    [Integration] detectors documentation path naming ds118: documents why CRLF/UTF-8 cases are N/A.

    Scenario:
        Given a real document with a policy-violating name whose *content* is CRLF-terminated and ends in
            invalid UTF-8 bytes, scanned with DS118 selected under the kebab style
        When the engine runs DS118
        Then the single path-only finding is produced without any decode and without crashing - proving CRLF,
            invalid UTF-8, unreadable content and very long *lines* are not applicable to DS118, which reads
            only Document.path and never opens the file body.

    Boundaries:
        - Focus: the one-sentence N/A justification for the content-dependent edge dimensions
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether DS118 (or the engine, for a DS118-only select) began reading document content
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "docs").mkdir()
    (root / "docs" / "Bad Name.md").write_bytes(b"# Title\r\n\r\nbody\r\n\xff\xfe\n")

    result = scan(root, config=Config(profile="fast", select=("DS118",), documentation_naming="kebab"))
    assert [finding.message for finding in _ds118(result.findings)] == [
        'file name "Bad Name.md" does not match the kebab naming policy; suggested rename "bad-name.md"'
    ]


def test_ds118_scan_adds_no_filesystem_access_over_a_no_rule_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors documentation path naming ds118: verifies DS118 adds zero filesystem access.

    Scenario:
        Given a real tree with one offending document, scanned under the path-recording recorder once with
            select=("DS118",) and once with a select that enables no rule at all
        When each scan runs (lazy imports warmed first so the recorded window holds only scan's own calls)
        Then DS118 still produces its finding, yet the set of filesystem paths the DS118-only scan touches is
            exactly the set a no-rule scan touches, DS118 opens no document, and every recorded path stays
            within the canonical root - proving DS118 adds nothing beyond what discovery and the engine touch.

    Boundaries:
        - Focus: the zero-filesystem contract proven at the engine boundary by differencing against a no-rule scan
        - Fixtures/params: tmp_path, monkeypatch, the shared path recorder

    On failure, first check:
        - Whether DS118 began stat-ing or opening a document (the recorder set would grow over the baseline)
        - Whether a path outside the canonical root was touched
    """
    root = Path(os.path.realpath(tmp_path))
    (root / "docs").mkdir()
    (root / "docs" / "BadName.md").write_text("# bad\n", encoding="utf-8")

    ds118_config = Config(profile="fast", select=("DS118",), documentation_naming="kebab")
    none_config = Config(profile="fast", select=("DS000",), documentation_naming="kebab")
    scan(root, config=ds118_config)  # warm up lazy imports before recording

    def _record(config: Config) -> _Recorder:
        """Run one scan under a fresh recorder and return it.

        :param config: The scan configuration to record.
        :returns: The recorder populated with the scan's filesystem access.
        """
        recorder = _Recorder()
        with monkeypatch.context() as patch:
            _install_recorder(patch, recorder)
            scan(root, config=config)
        return recorder

    ds118_recorder = _record(ds118_config)
    baseline_recorder = _record(none_config)

    result = scan(root, config=ds118_config)
    assert [finding.path for finding in _ds118(result.findings)] == ["docs/BadName.md"]

    assert ds118_recorder.paths == baseline_recorder.paths
    assert not any(opened.endswith("BadName.md") for opened in ds118_recorder.opened)
    root_str = str(root)
    for recorded in ds118_recorder.paths:
        assert _is_under(recorded, root_str) or _is_under(root_str, recorded), f"touched outside the root: {recorded}"


def test_baseline_suppresses_known_ds118_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies baseline suppression round-trips.

    Scenario:
        Given the multiple_bad_components scenario whose two DS118 findings are recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then both previously known DS118 findings are filtered out while the first scan still reported them, so
            the line=None path-only fingerprints are stable across the two scans.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS118 findings (line=None)
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS118 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    loaded = asset_case("ds118", "multiple_bad_components")
    config = _config("multiple_bad_components", select=("DS118",))

    first = scan(loaded.root, config=config)
    assert len(_ds118(first.findings)) == 2

    baseline_path = loaded.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        loaded.root,
        config=_config("multiple_bad_components", select=("DS118",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds118(suppressed.findings) == ()


def test_repeated_scans_and_fresh_roots_are_deterministic(tmp_path: Path):
    """
    [Integration] detectors documentation path naming ds118: verifies repeated scans and fresh roots are stable.

    Scenario:
        Given the multiple_bad_components scenario scanned twice over the same materialized root and once over
            a second freshly materialized root
        When the DS118 finding tuples are compared
        Then all three are equal (directory then file, both at line None), so the detector holds no
            order-dependent state and the per-component memo does not leak between runs or roots.

    Boundaries:
        - Focus: determinism of DS118 across repeated scans and independent fresh roots
        - Fixtures/params: tmp_path (two independently materialized roots)

    On failure, first check:
        - Module-level mutable caches, or a per-scan _Policy cache leaking across runs
    """
    config = _config("multiple_bad_components", select=("DS118",))
    root_a = load_asset_case("ds118", "multiple_bad_components", tmp_path / "a").root
    root_b = load_asset_case("ds118", "multiple_bad_components", tmp_path / "b").root

    first = _triples(_ds118(scan(root_a, config=config).findings))
    second = _triples(_ds118(scan(root_a, config=config).findings))
    fresh = _triples(_ds118(scan(root_b, config=config).findings))

    assert first == second == fresh
    assert first == list(FINDING_EXPECTATIONS["multiple_bad_components"])


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors documentation path naming ds118: verifies text/json/github report stability.

    Scenario:
        Given a DS118 uppercase-filename finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS118 warning deterministically (schema v1 json with a null line, a
            ``::warning`` annotation with the file) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a line=None DS118 warning across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path, null line and message
        - Whether repeated renders diverge (nondeterminism)
    """
    loaded = asset_case("ds118", "uppercase_filename_violation")
    result = scan(loaded.root, config=_config("uppercase_filename_violation", select=("DS118",)))
    expected = FINDING_EXPECTATIONS["uppercase_filename_violation"][0][2]

    text = render(result, "text")
    assert render(result, "text") == text
    assert f"warning: docs/GettingStarted.md: {expected}" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS118"]
    assert payload["findings"][0]["rule"] == "DS118"
    assert payload["findings"][0]["severity"] == "warning"
    assert payload["findings"][0]["line"] is None

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::warning file=docs/GettingStarted.md,title=DS118::")


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors documentation path naming ds118: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS118 detector and runs its pure core
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported, proving the
            fast DS118 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS118's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether naming gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.config import Config\n"
        "from docsentinel.detectors import naming\n"
        "naming.check_paths(('docs/Bad Name.md',), Config(documentation_naming='kebab'))\n"
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
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors documentation path naming ds118: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When naming.detect runs over every FINDING scenario
        Then all expected findings are still produced, proving DS118 opens no socket, makes no connection and
            never executes embedded documentation content (which it never even reads).

    Boundaries:
        - Focus: the security invariant that the policy is pure, offline and non-executing
        - Fixtures/params: monkeypatch; tmp_path (each case materialized into its own isolated subdirectory)

    On failure, first check:
        - Any accidental network client or subprocess call on the DS118 path
    """

    def _no_socket(*args: object, **kwargs: object) -> object:
        """Fail the test if DS118 ever constructs a socket.

        :returns: Never returns; always raises.
        """
        raise AssertionError("DS118 must not create a socket")

    def _no_connect(*args: object, **kwargs: object) -> object:
        """Fail the test if DS118 ever opens an outbound connection.

        :returns: Never returns; always raises.
        """
        raise AssertionError("DS118 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object) -> object:
        """Fail the test if DS118 ever launches a subprocess.

        :returns: Never returns; always raises.
        """
        raise AssertionError("DS118 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case in FINDING_EXPECTATIONS:
        loaded = load_asset_case("ds118", case, tmp_path / case)
        findings = _ds118(naming.detect(loaded.root, loaded.documents(), _config(case)))
        assert _triples(findings) == list(FINDING_EXPECTATIONS[case])


def _many_documents(scale: int) -> tuple[models.Document, ...]:
    """Build ``scale`` distinct offending documents, one bad file component each.

    :param scale: The number of documents to build.
    :returns: The fabricated Documents, each with an uppercase (offending) file stem.
    """
    return _docs(*(f"docs/File{index}.md" for index in range(scale)))


def _deep_nested(scale: int) -> tuple[models.Document, ...]:
    """Build one document nested under ``scale`` distinct offending directory components.

    :param scale: The directory depth (number of distinct bad directory names).
    :returns: A one-element Document tuple holding the deeply nested path.
    """
    directories = "/".join(f"Dir{index}" for index in range(scale))
    return _docs(f"{directories}/file.md")


def _shared_prefix(scale: int) -> tuple[models.Document, ...]:
    """Build ``scale`` clean-named files under one fixed, deeply offending directory prefix.

    :param scale: The number of documents sharing the prefix.
    :returns: The fabricated Documents, all under the same offending eight-component prefix.
    """
    prefix = "/".join(f"Shared{index}" for index in range(8))
    return _docs(*(f"{prefix}/file-{index}.md" for index in range(scale)))


@pytest.mark.parametrize(
    ("shape", "builder", "expected"),
    [
        ("many-documents", _many_documents, lambda scale: scale),
        ("deep-nesting", _deep_nested, lambda scale: scale),
        ("shared-prefix", _shared_prefix, lambda scale: scale * 8),
    ],
)
def test_adversarial_naming_floods_stay_linear_through_detect(
    shape: str,
    builder: Callable[[int], tuple[models.Document, ...]],
    expected: Callable[[int], int],
):
    """
    [Integration] detectors documentation path naming ds118: verifies linear-time adversarial handling.

    Scenario:
        Given one representative adversarial corpus shape - many distinct offending documents, one deeply
            nested path of distinct offending directories, or many clean files under one shared offending
            eight-component prefix - routed through naming.detect over a doubling input series
        When detect runs with the kebab style
        Then every scale produces the exact deterministic finding count (so the pass is never vacuous) and the
            scaling stays under the shared linear bound, proving per-document, per-depth and per-shared-prefix
            cost is linear (the prefix is evaluated once then served from the per-component memo).

    Boundaries:
        - Focus: detect() routing of fabricated corpora with bounded time (threat model DoS)
        - Non-goal: the exhaustive algorithmic shapes, which live in the DS118 unit tests
        - Fixtures/params: parametrized over the three representative shapes

    On failure, first check:
        - Any accidentally quadratic per-document, per-depth or per-shared-prefix rescan
        - That the exact finding count for this shape still holds at every scale
    """
    sizes = (2_000, 4_000, 8_000, 16_000)
    config = Config(documentation_naming="kebab")
    assert_scales_linearly(
        builder,
        lambda documents: naming.detect(object(), documents, config),
        sizes,
        expected_count=expected,
        label=f"ds118-{shape}",
    )


def test_large_allowlist_crossed_with_many_documents_stays_linear():
    """
    [Integration] detectors documentation path naming ds118: verifies many allow entries x many documents is linear.

    Scenario:
        Given a doubling series where both the offending-document count and the allowlist size grow together,
            with every allow entry distinct from every document name so membership is always consulted
        When naming.detect runs with the kebab style
        Then cost stays linear because allowlist membership is a frozenset O(1) lookup, and each document still
            yields its one finding at every scale.

    Boundaries:
        - Focus: many allow entries x many documents must not be O(documents x allow)
        - Fixtures/params: assert_scales_linearly over a doubling series

    On failure, first check:
        - Whether the allowlist is stored as a frozenset (O(1)) rather than a list/tuple (O(n)) membership
    """
    holder: dict[str, tuple[str, ...]] = {}

    def build(scale: int) -> tuple[models.Document, ...]:
        """Build the offending documents and capture a never-matching allowlist of the same size.

        :param scale: The number of documents and allowlist entries.
        :returns: The fabricated offending Documents for this scale.
        """
        holder["allow"] = tuple(f"allowed-{index}.md" for index in range(scale))
        return _docs(*(f"docs/Doc{index}.md" for index in range(scale)))

    def run(documents: tuple[models.Document, ...]) -> tuple[models.Finding, ...]:
        """Run DS118 detect with the captured allowlist for this scale.

        :param documents: The offending documents for this scale.
        :returns: The DS118 findings (one per document).
        """
        config = Config(documentation_naming="kebab", documentation_naming_allow=holder["allow"])
        return naming.detect(object(), documents, config)

    assert_scales_linearly(
        build,
        run,
        (10_000, 20_000, 40_000, 80_000),
        expected_count=lambda scale: scale,
        label="ds118-allowlist",
    )


def test_naive_list_allowlist_membership_would_be_quadratic():
    """
    [Integration] detectors documentation path naming ds118: proves the shared workload breaks a naive list membership.

    Scenario:
        Given the same growing (documents, allowlist) workload used for the linear allowlist test
        When a NAIVE reference consults a Python list for membership (O(allow) per document)
        Then its measured log-log slope is clearly super-linear - confirming the shared-workload trap the real
            detector avoids by storing the allowlist as a frozenset, as the DS118 unit suite also demonstrates.

    Boundaries:
        - Focus: demonstrate that the shared workload WOULD fail a naive implementation
        - Fixtures/params: measure_scaling over a doubling series; asserts a super-linear slope

    On failure, first check:
        - Whether the smallest size is large enough to lift the quadratic above the timing floor
    """

    def build(scale: int) -> tuple[tuple[str, ...], list[str]]:
        """Build the naive payload: document filenames plus a list allowlist.

        :param scale: The number of documents and allowlist entries.
        :returns: A ``(filenames, allow_list)`` pair for the naive reference.
        """
        filenames = tuple(f"Doc{index}.md" for index in range(scale))
        allow_list = [f"allowed-{index}.md" for index in range(scale)]
        return filenames, allow_list

    def naive(payload: tuple[tuple[str, ...], list[str]]) -> list[str]:
        """Flag each filename not present in a list allowlist (O(documents x allow)).

        :param payload: The ``(filenames, allow_list)`` pair.
        :returns: The filenames that were not found in the allowlist.
        """
        filenames, allow_list = payload
        return [name for name in filenames if name not in allow_list]

    report = measure_scaling(
        build,
        naive,
        sizes=(2_000, 4_000, 8_000, 16_000),
        expected_count=lambda scale: scale,
    )
    assert report.slope > 1.5, f"naive list-membership was not super-linear: {report.describe()}"
