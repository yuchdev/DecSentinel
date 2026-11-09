"""Integration tests for DS116 over committed Markdown assets in ``tests/assets/ds116``.

This is Story 11.0 Task 03, the security-sensitive path-boundary rule. Every one
of the 15 committed scenarios is loaded in isolation through the ``asset_case``
fixture and asserted against an explicit, checked-in expectation table
(:data:`CLEAN_CASES`, :data:`FINDING_EXPECTATIONS` and :data:`EXPECTED_SIBLINGS`)
that is transcribed from the Task 02 manifest and the threat model, never derived
from whatever the analyzer currently emits. The 14 ``setup=default`` scenarios are
asserted through both the pure ``detect`` entry point and the shared ``scan``
engine; the lone ``runtime-symlink-companion`` scenario
(``symlink_escape_is_rejected``) commits only its Markdown owner, so this suite
builds the in-root symlink and the sibling out-of-root target at runtime in
``tmp_path`` and proves, with the shared filesystem recorder from
``tests/mock/test_path_boundaries_oracle.py``, that nothing outside the scan root
(including the symlink's real target) is ever stat-ed, opened or listed.

DS116 is an always-active ``fast`` rule at ``error`` severity with no opt-in
marker, so a single finding makes the CLI exit 1 even without ``--strict`` while a
clean tree exits 0; both are asserted. Coverage follows the standing threat-model
checklist: the detector owns every unsafe reference category for links, images,
reference definitions and HTML attributes, while DS101/DS103 keep their in-root
behaviour and never stat an escaping target (the ownership split is asserted
through :data:`EXPECTED_SIBLINGS`). Inline code spans report only genuine traversal
(root escape, residual single-decode encoding, in-root symlink-out); drive, UNC and
backslash code spans are documentation and stay with DS103.

The file also exercises select/ignore (exact plus the live ``DS11`` prefix that
contains DS110/DS112/DS113/DS114/DS115/DS116/DS117 today, the whole-fast-set ``DS1`` prefix and the
negative ``DS2``), baseline round-trips, text/json/github report stability, the
three CLI exit paths, ``docsentinel rules``/``doctor`` surfacing, the engine
notice, config propagation for ``root_escape_policy`` / ``decode_percent_paths`` /
``windows_path_policy`` through both ``docsentinel.toml`` and ``[tool.doc_sentinel]``
(invalid values raising :class:`ConfigError`), hostile-target output safety
(bounded, repr-escaped echo; exactly one ``::error`` line per finding), and the
edge dimensions required by the task (CRLF lines, invalid UTF-8, unreadable file,
symlinked Markdown not inventoried, very long lines, repeated/fresh roots, fast
stdlib-only import, no network or content execution, documents passed individually,
a subdirectory scan root as the boundary, and cwd never entering resolution). The
small integration-level routing and bounded symlink-chain checks confirm linear
handling; the exhaustive algorithmic floods live in
``tests/unit/test_detectors_path_boundaries_adversarial.py`` and are not duplicated.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Optional

import pytest

from docsentinel import baseline, cli, models
from docsentinel.config import Config, ConfigError
from docsentinel.detectors import path_boundaries as pb
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.git_marker_helpers import (
    GitMarkerGuard,
    install_git_marker_guard,
    is_git_marker_probe,
    is_project_marker_probe,
)
from tests.mock.test_path_boundaries_oracle import (
    _install_recorder,
    _is_under,
    _Recorder,
    _symlink_or_skip,
)
from tests.timing_helpers import assert_scales_linearly

#: Fixed diagnostic text DS116 prepends to the echoed raw target, keyed by the
#: violation category. Transcribed from the detector's stable message contract and
#: the threat model, not read back from the analyzer at runtime.
CATEGORY_MESSAGE: dict[str, str] = {
    "escape": "reference escapes the documentation root",
    "residual": "reference keeps percent-encoded path separators after one decode",
    "drive": "reference uses a Windows drive-letter path",
    "unc": "reference uses a UNC network path",
    "backslash": "reference uses backslash path separators",
    "control": "reference contains control characters",
    "symlink": "reference resolves through a symlink that escapes the documentation root",
}

#: The five committed CLEAN scenarios: legitimate ``../`` navigation inside the
#: root, a root-relative link, an external https URL, a ``../`` link that stays in
#: the docs subtree, and a ``{placeholder}`` template that is not a real path.
CLEAN_CASES: tuple[str, ...] = (
    "nested_parent_within_root",
    "root_relative_local_link",
    "external_https_url",
    "safe_parent_link_subdir",
    "template_link_literal_skipped",
)

#: The nine ``setup=default`` FINDING scenarios, each mapped to the one-based line
#: of the offending reference, its violation category and the exact DS116 finding
#: count. These are fixed by the committed fixtures and the Task 02 spec. The tenth
#: finding scenario (``symlink_escape_is_rejected``) needs a runtime symlink and is
#: asserted separately in :func:`test_symlink_escape_is_rejected_with_recorder`.
FINDING_EXPECTATIONS: dict[str, tuple[int, str, int]] = {
    "parent_escape_from_root": (3, "escape", 1),
    "percent_encoded_parent_escape": (3, "escape", 1),
    "windows_absolute_drive_path": (3, "drive", 1),
    "windows_unc_network_path": (3, "unc", 1),
    "encoded_separator_escape": (3, "escape", 1),
    "unsafe_image_target": (3, "escape", 1),
    "unsafe_code_span_target": (3, "escape", 1),
    "encoded_double_decode_attack": (3, "residual", 1),
    "absolute_rooted_backslash": (3, "backslash", 1),
}

#: The document that carries the asserted finding (or, for clean cases, the one
#: whose reference is validated). Every finding fixture keeps its reference in a
#: root-level README.md; the two nested clean fixtures place it deeper.
PRIMARY_DOCUMENT: dict[str, str] = {
    "nested_parent_within_root": "docs/README.md",
    "root_relative_local_link": "README.md",
    "external_https_url": "README.md",
    "safe_parent_link_subdir": "docs/deep/README.md",
    "template_link_literal_skipped": "README.md",
    **dict.fromkeys(FINDING_EXPECTATIONS, "README.md"),
}

#: The 14 ``setup=default`` scenarios, exercised through detect() and scan().
DEFAULT_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: The committed runtime-symlink scenario, asserted on its own.
SYMLINK_CASE = "symlink_escape_is_rejected"

#: All 15 committed scenarios in a stable order.
ALL_CASES: tuple[str, ...] = DEFAULT_CASES + (SYMLINK_CASE,)

#: The full fast-profile rule set, in registry order, run alongside DS116. The
#: DS11 prefix below is derived from this tuple so the prefix expectations never go
#: stale when another DS11x rule is added.
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

#: The DS11x rules the genuine ``DS11`` prefix matches today, derived live so the
#: test tracks the registry rather than a brittle hard-coded set.
DS11_PREFIXED: tuple[str, ...] = tuple(code for code in FAST_RULE_ORDER if code.startswith("DS11"))

#: Legitimate non-DS116 findings a full fast scan adds on the finding fixtures,
#: each owned by its rightful rule. Only ``encoded_double_decode_attack`` has one:
#: its single-decode form ``%2e%2e/x.md`` is a literal in-root directory that does
#: not exist, so DS101 rightly reports a dangling link at line 3 while DS116 owns
#: the residual-encoding finding. Every other escaping target is owned solely by
#: DS116, proving DS101/DS103 no longer stat or resolve an escaping reference.
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {
    "encoded_double_decode_attack": (("DS101", 3),),
}


def _ds116(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS116 findings from a mixed tuple, preserving order.

    :param findings: Findings from a detector or scan.
    :returns: The DS116 subset in the original order.
    """
    return tuple(finding for finding in findings if finding.rule == "DS116")


def _siblings(findings: tuple[models.Finding, ...]) -> tuple[tuple[str, int], ...]:
    """Return the non-DS116 ``(rule, line)`` pairs of a finding tuple, sorted.

    :param findings: Findings from a full fast scan.
    :returns: Sorted ``(rule, line)`` pairs for every non-DS116 finding.
    """
    return tuple(sorted((finding.rule, finding.line) for finding in findings if finding.rule != "DS116"))


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors repository root path boundaries ds116: verifies the local catalog totals.

    Scenario:
        Given the committed ds116 asset directories and this suite's expectation table
        When the clean, finding and runtime-symlink scenarios are counted
        Then there are exactly 5 clean, 10 finding, 0 error and 15 total scenarios matching Task 02,
        the clean and finding sets are disjoint, and every scenario has a primary document.

    Boundaries:
        - Focus: the expectation table is complete, non-overlapping and matches the 5/10/0 split
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in both CLEAN_CASES and FINDING_EXPECTATIONS or lacks a primary document
    """
    finding_cases = set(FINDING_EXPECTATIONS) | {SYMLINK_CASE}
    assert len(CLEAN_CASES) == 5
    assert len(finding_cases) == 10
    assert len(set(ALL_CASES)) == 15
    assert set(CLEAN_CASES).isdisjoint(finding_cases)
    assert set(PRIMARY_DOCUMENT) == set(DEFAULT_CASES)


def test_ds116_is_registered_as_an_exact_fast_rule_without_opt_in():
    """
    [Integration] detectors repository root path boundaries ds116: verifies always-active registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS116 is present with error severity, its title and an empty opt_in_option, proving it is
        an ordinary always-active rule rather than an opt-in policy rule like DS110.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether path_boundaries registered DS116 on import
        - Whether DS116 drifted profile/severity or grew an opt_in_option
    """
    fast = {rule.code: rule for rule in rules_for_profile("fast")}
    assert "DS116" in fast
    rule = fast["DS116"]
    assert rule.severity == "error"
    assert rule.title == "Path traversal outside documentation root"
    assert rule.opt_in_option == ""


@pytest.mark.parametrize("case", DEFAULT_CASES)
def test_detect_matches_expectation_for_each_default_case(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies detect per committed case.

    Scenario:
        Given one default-setup ds116 scenario materialized into a fresh tmp_path
        When path_boundaries.detect runs over all its documents with the default error policy
        Then clean cases yield no DS116 finding and finding cases yield exactly the expected count of
        DS116 error findings at the expected one-based line, path and violation-category message.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes, independent of the engine
        - Fixtures/params: parametrized over the 14 default-setup scenarios; asset_case

    On failure, first check:
        - The expected (line, category, count) in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte)
    """
    loaded = asset_case("ds116", case)
    findings = _ds116(pb.detect(loaded.root, loaded.documents()))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    line, category, count = FINDING_EXPECTATIONS[case]
    assert len(findings) == count
    finding = findings[0]
    assert finding.rule == "DS116"
    assert finding.severity == "error"
    assert finding.path == PRIMARY_DOCUMENT[case]
    assert finding.line == line
    assert finding.message.startswith(CATEGORY_MESSAGE[category] + ": ")


@pytest.mark.parametrize("case", DEFAULT_CASES)
def test_scan_matches_expectation_and_ownership_split(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies full-scan ownership split.

    Scenario:
        Given one default-setup ds116 scenario scanned under the full fast profile
        When DS101-DS117 run together
        Then DS116 ran (enabled_rules carries it), finding cases emit exactly the expected DS116 error
        at the expected line, and the only non-DS116 findings are the documented EXPECTED_SIBLINGS -
        so DS101/DS103 never report a dangling/unresolvable finding for an escaping target (DS116 owns
        them), proving the oracle fix and the ownership split hold.

    Boundaries:
        - Focus: cross-rule ownership - escaping targets belong to DS116, documented overlaps aside
        - Fixtures/params: parametrized over the 14 default-setup scenarios; asset_case

    On failure, first check:
        - Whether DS101/DS103 began resolving or stat-ing an escaping target again
        - Whether a new sibling finding appeared beyond the documented EXPECTED_SIBLINGS overlap
    """
    loaded = asset_case("ds116", case)
    result = scan(loaded.root, config=Config(profile="fast"))

    assert result.enabled_rules == FAST_RULE_ORDER
    assert result.pending == ()
    assert _siblings(result.findings) == EXPECTED_SIBLINGS.get(case, ())

    own = _ds116(result.findings)
    if case in CLEAN_CASES:
        assert own == ()
    else:
        line, category, count = FINDING_EXPECTATIONS[case]
        assert len(own) == count
        assert own[0].line == line
        assert own[0].path == PRIMARY_DOCUMENT[case]
        assert own[0].message.startswith(CATEGORY_MESSAGE[category] + ": ")


def test_symlink_escape_is_rejected_with_recorder(asset_case: Callable[[str, str], AssetCase], tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies the safe symlink containment.

    Scenario:
        Given the committed symlink_escape_is_rejected README copied into a scan root, an ``escape``
            symlink inside the root pointing at a sibling directory outside the root that holds a real
            secret, and a second document whose link lexically escapes to that same real secret, with a
            filesystem recorder wrapping every reachable stat/lstat/readlink/scandir/listdir/open call
        When a full fast scan runs under the recorder
        Then DS116 reports the in-root symlink escape at line 3 and the lexical escape, yet no recorded
            path argument reaches the out-of-root tree or the real secret file - the walk reads the link
            lexically and never stats or opens the outside target.

    Boundaries:
        - Focus: ruling G4 (lexical-first; os.lstat/os.readlink only on in-root objects) and the no
          outside-root I/O invariant, proven for the runtime-symlink fixture
        - Fixtures/params: asset_case (committed owner), tmp_path, the shared recorder helper

    On failure, first check:
        - Whether escapes_via_symlink stopped reading the link target lexically
        - Whether the detector stat-ed or opened the escaping/symlinked target instead of skipping it
    """
    loaded = asset_case("ds116", SYMLINK_CASE)
    owner_text = loaded.read_text("README.md")

    root = tmp_path / "scanroot"
    (root / "docs").mkdir(parents=True)
    (root / "README.md").write_text(owner_text, encoding="utf-8")
    (root / "docs" / "direct.md").write_text("# Direct\n\n[s](../../outside/secret.md)\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.md"
    secret.write_text("# out of root secret\n", encoding="utf-8")
    _symlink_or_skip(root / "escape", "../outside")

    canonical = Path(os.path.realpath(root))
    secret_real = Path(os.path.realpath(secret))

    # Warm up lazy imports before recording so the window holds only scan I/O.
    scan(root, config=Config(profile="fast"))

    recorder = _Recorder()
    guard = GitMarkerGuard(str(canonical))
    with pytest.MonkeyPatch.context() as patch:
        _install_recorder(patch, recorder)
        install_git_marker_guard(patch, guard)
        result = scan(root, config=Config(profile="fast"))

    own = _ds116(result.findings)
    by_path = {(finding.path, finding.line): finding for finding in own}
    assert ("README.md", 3) in by_path
    assert "symlink that escapes the documentation root" in by_path[("README.md", 3)].message
    assert ("docs/direct.md", 3) in by_path

    assert recorder.paths, "recorder captured no filesystem access; the scan did not run"
    root_str, outside_str, secret_str = str(canonical), str(outside), str(secret_real)
    for recorded in recorder.paths:
        assert recorded != secret_str, f"touched the out-of-root secret file: {recorded}"
        assert not _is_under(recorded, outside_str), f"touched a path under the out-of-root tree: {recorded}"
        if is_git_marker_probe(recorded, root_str) or is_project_marker_probe(recorded, root_str):
            continue  # link_root: an lstat existence check of <ancestor>/.git or a project marker only
        allowed = _is_under(recorded, root_str) or _is_under(root_str, recorded)
        assert allowed, f"touched a path outside the scan root: {recorded}"
    assert guard.violations == [], f"went past an existence check of a .git path: {guard.violations}"


def test_finding_line_is_the_offending_reference_not_the_first(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies the reported line is the offender's.

    Scenario:
        Given a document whose first reference is a clean in-root link on line 3 and whose escaping
            reference sits later on line 7
        When DS116 recognition runs
        Then the single finding reports line 7 - the offending reference's own line - not the first
            reference's line, so line attribution tracks the real violation.

    Boundaries:
        - Focus: per-reference one-based line fidelity across multiple references
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether check_text started reusing the first candidate's line for every finding
        - Whether candidate sorting dropped the per-reference span offset
    """
    (tmp_path / "ok.md").write_text("# ok\n", encoding="utf-8")
    body = "# Home\n\nSee [ok](ok.md) first.\n\nMore prose.\n\nNever [bad](../../secrets.md) last.\n"
    (tmp_path / "README.md").write_text(body, encoding="utf-8")

    findings = _ds116(pb.detect(tmp_path, (models.Document("README.md", 0),)))

    assert len(findings) == 1
    assert findings[0].line == 7
    assert findings[0].message.startswith("reference escapes the documentation root: ")


def test_code_span_scope_is_narrower_than_full_references(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies the inline code-span ruling.

    Scenario:
        Given one document with a Windows-drive, a UNC and a backslash path inside inline code spans,
            and a second document with a parent-escape inside a code span
        When a full fast scan runs
        Then DS116 stays silent on the drive/UNC/backslash code spans (documentation, left to DS103's
            legacy check, which does report them) but reports the genuine root-escape code span, so the
            code-span scope is narrower than the full-reference scope exactly as the Story 11.0 ruling requires.

    Boundaries:
        - Focus: the code-span ruling - only real traversal is a DS116 finding inside inline code
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether the code-span branch stopped exempting the drive/UNC/backslash categories
        - Whether DS103 stopped reporting the documentation code spans it still owns
    """
    docs = tmp_path / "windows.md"
    docs.write_text("# W\n\nUse `\\Windows\\win.ini` and `C:\\Program.ini` here.\n", encoding="utf-8")
    (tmp_path / "escape.md").write_text("# E\n\nNever `../../etc/passwd` from docs.\n", encoding="utf-8")

    result = scan(tmp_path, config=Config(profile="fast"))
    ds116 = {(finding.path, finding.line) for finding in _ds116(result.findings)}
    assert ds116 == {("escape.md", 3)}

    ds103_paths = {finding.path for finding in result.findings if finding.rule == "DS103"}
    assert "windows.md" in ds103_paths  # DS103 still owns the documentation code spans DS116 skips


def test_select_narrows_to_ds116_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies select activates only DS116.

    Scenario:
        Given a finding scenario scanned with select pinned to the exact code DS116
        When the engine resolves the active rule set
        Then only DS116 is enabled and its single expected error finding is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS116 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds116", "parent_escape_from_root")

    result = scan(case.root, config=Config(profile="fast", select=("DS116",)))

    assert result.enabled_rules == ("DS116",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS116", 3)]


def test_prefix_select_semantics_for_ds116(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies DS11/DS1/DS2 prefix select.

    Scenario:
        Given a finding scenario scanned under the fast profile
        When it is selected by the genuine prefix ``DS11`` (which today contains DS110, DS116 and
            DS117), by the whole-fast-set prefix ``DS1``, and by the non-matching prefix ``DS2``
        Then ``DS11`` activates exactly the live DS11x set and DS116 still reports line 3, ``DS1``
            activates the entire fast set with DS116 among it, and ``DS2`` matches no fast rule so the
            active set is empty - the expectations are derived from FAST_RULE_ORDER, not hard-coded.

    Boundaries:
        - Focus: prefix selector matching for DS116 against the live fast rule set
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast rule codes
        - Whether a new DS11x rule shifted DS11_PREFIXED out of sync
    """
    case = asset_case("ds116", "parent_escape_from_root")

    ds11x = scan(case.root, config=Config(profile="fast", select=("DS11",)))
    assert ds11x.enabled_rules == DS11_PREFIXED
    assert [finding.line for finding in _ds116(ds11x.findings)] == [3]

    whole_fast = scan(case.root, config=Config(profile="fast", select=("DS1",)))
    assert whole_fast.enabled_rules == FAST_RULE_ORDER
    assert [finding.line for finding in _ds116(whole_fast.findings)] == [3]

    none = scan(case.root, config=Config(profile="fast", select=("DS2",)))
    assert none.enabled_rules == ()
    assert _ds116(none.findings) == ()


def test_ignore_suppresses_ds116_exact_and_by_prefix(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies ignore removes DS116.

    Scenario:
        Given a finding scenario scanned with DS116 ignored by its exact code, by the genuine ``DS11``
            prefix, by the whole-set ``DS1`` prefix, and by the non-matching ``DS2`` prefix
        When the engine resolves the active rule set each time
        Then the exact and ``DS11``/``DS1`` ignores drop DS116 (and its finding) while ``DS2`` leaves
            DS116 active and still reporting line 3.

    Boundaries:
        - Focus: ignore precedence for a fast rule, exact and prefix, proving the detector is gated off
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules ignore precedence and matches_selector prefix logic
        - Whether a DS116 finding survived an ignore
    """
    case = asset_case("ds116", "parent_escape_from_root")

    exact = scan(case.root, config=Config(profile="fast", ignore=("DS116",)))
    assert "DS116" not in exact.enabled_rules
    assert _ds116(exact.findings) == ()

    by_prefix = scan(case.root, config=Config(profile="fast", ignore=("DS11",)))
    assert by_prefix.enabled_rules == tuple(code for code in FAST_RULE_ORDER if not code.startswith("DS11"))
    assert _ds116(by_prefix.findings) == ()

    whole = scan(case.root, config=Config(profile="fast", ignore=("DS1",)))
    assert whole.enabled_rules == ()

    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",)))
    assert "DS116" in unaffected.enabled_rules
    assert [finding.line for finding in _ds116(unaffected.findings)] == [3]


def test_baseline_suppresses_known_ds116_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies baseline suppression round-trips.

    Scenario:
        Given a finding scenario whose DS116 finding is recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then the previously known DS116 finding is filtered out while the first scan still reported it.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to a DS116 error finding
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS116 finding between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds116", "parent_escape_from_root")
    first = scan(case.root, config=Config(profile="fast", select=("DS116",)))
    assert len(_ds116(first.findings)) == 1

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS116",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds116(suppressed.findings) == ()


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies text/json/github report stability.

    Scenario:
        Given a DS116 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS116 error deterministically (schema v1 json, an ``::error``
            annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS116 error across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path and line
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds116", "parent_escape_from_root")
    result = scan(case.root, config=Config(profile="fast", select=("DS116",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "error: README.md:3: reference escapes the documentation root: ../../secrets.md" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS116"]
    assert payload["findings"][0]["rule"] == "DS116"
    assert payload["findings"][0]["severity"] == "error"
    assert payload["findings"][0]["line"] == 3

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::error file=README.md,line=3,title=DS116::")


def test_cli_fast_json_scan_reports_ds116_and_exits_one_without_strict(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors repository root path boundaries ds116: verifies an error finding blocks without strict.

    Scenario:
        Given a finding scenario scanned via the CLI with --profile fast --format json and no --strict
        When the command runs
        Then it prints a JSON report containing the DS116 error at line 3 and exits 1, because an
            error-severity finding is blocking even without --strict; a second run with --strict also exits 1.

    Boundaries:
        - Focus: the CLI exit-code mapping for an error-severity rule, strict and non-strict
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for error-severity findings
        - Whether DS116 still produced its finding through the CLI path
    """
    case = asset_case("ds116", "parent_escape_from_root")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds116 = [finding for finding in payload["findings"] if finding["rule"] == "DS116"]
    assert len(ds116) == 1
    assert ds116[0]["severity"] == "error"
    assert ds116[0]["line"] == 3
    assert exit_code == 1

    strict_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])
    capsys.readouterr()
    assert strict_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors repository root path boundaries ds116: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario scanned via the CLI under the fast profile
        When the command runs
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: the non-blocking exit code when DS116 and its siblings find nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS116 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds116", "nested_parent_within_root")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds116_without_an_opt_in_marker(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies `docsentinel rules` surfaces DS116.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS116 and its title appear with no ``[opt-in: ...]`` marker, unlike DS110, because DS116
            is an ordinary always-active rule.

    Boundaries:
        - Focus: rules-command surfacing of DS116 as a non-opt-in rule
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS116
        - Whether DS116 grew an opt_in_option that added a marker
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    ds116_lines = [line for line in captured.out.splitlines() if "DS116:" in line]
    assert ds116_lines == ["  DS116: Path traversal outside documentation root"]
    assert "opt-in" not in ds116_lines[0]


def test_cli_doctor_counts_ds116_as_an_ordinary_fast_rule(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies `docsentinel doctor` counts DS116.

    Scenario:
        Given the installed rule registry
        When the doctor command reports environment readiness
        Then the fast-rule tally reads exactly
            "16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)",
            so DS116 is inside the registered count and is not one of the opt-in rules.

    Boundaries:
        - Focus: doctor's separate accounting of opt-in versus always-active fast rules
        - Fixtures/params: capsys

    On failure, first check:
        - Whether the registered fast-rule count changed when a rule was added
        - Whether DS116 was miscounted as opt-in
    """
    exit_code = cli.main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)" in captured.out


def test_notice_names_only_the_off_opt_in_rule(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies the engine notice wording.

    Scenario:
        Given a clean fixture scanned under the full fast profile with no opt-in policy configured
        When the engine builds the scan notice
        Then it reads exactly "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set
            require_fence_languages), DS112 (set navigation_indexes), DS115 (set
            deprecated_references_file), DS118 (set documentation_naming)." - DS116 is counted among
            the twelve evaluated always-active rules and all four off opt-in rules
            (DS110, DS112, DS115, DS118) are named, derived by running rather than hard-coded in the detector.

    Boundaries:
        - Focus: DS116 counts as evaluated while the off opt-in DS110 is the only named rule
        - Fixtures/params: asset_case

    On failure, first check:
        - The engine notice's evaluated-count/off-rule accounting
        - Whether DS116 was wrongly excluded from the evaluated count
    """
    case = asset_case("ds116", "external_https_url")

    result = scan(case.root, config=Config(profile="fast"))

    assert "DS116" in result.enabled_rules
    assert (
        result.notice
        == "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set navigation_indexes), DS115 (set deprecated_references_file), DS118 (set documentation_naming)."
    )


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
@pytest.mark.parametrize(("policy", "expected_severity"), [("off", None), ("warn", "warning"), ("error", "error")])
def test_root_escape_policy_propagates_from_both_config_files(
    config_file: str,
    policy: str,
    expected_severity: Optional[str],
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors repository root path boundaries ds116: verifies root_escape_policy propagation.

    Scenario:
        Given the parent_escape_from_root fixture carrying a standalone docsentinel.toml or a
            [tool.doc_sentinel] table that sets root_escape_policy to off, warn or error
        When scan discovers that config (no injected Config)
        Then ``off`` silences DS116 entirely, ``warn`` keeps the finding but downgrades its severity to
            warning (while the rule metadata stays error), and ``error`` emits the blocking error - the
            exact behaviour each policy produces in the detector.

    Boundaries:
        - Focus: config discovery and the detector's severity/suppression branch for each policy value
        - Fixtures/params: parametrized over the two config-file forms and the three policy values; asset_case

    On failure, first check:
        - The root_escape_policy short-circuit and severity selection in check_text
        - Whether load_config reads root_escape_policy from the given file form
    """
    case = asset_case("ds116", "parent_escape_from_root")
    if config_file == "docsentinel.toml":
        body = f'profile = "fast"\nroot_escape_policy = "{policy}"\n'
    else:
        body = f'[tool.doc_sentinel]\nprofile = "fast"\nroot_escape_policy = "{policy}"\n'
    (case.root / config_file).write_text(body, encoding="utf-8")

    findings = _ds116(scan(case.root).findings)

    if expected_severity is None:
        assert findings == ()
    else:
        assert len(findings) == 1
        assert findings[0].severity == expected_severity
        assert findings[0].line == 3


def test_decode_percent_paths_false_keeps_raw_traversal_but_not_encoded(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies decode_percent_paths=false behaviour.

    Scenario:
        Given decode_percent_paths=false supplied through docsentinel.toml for a raw parent escape and
            for a percent-encoded parent escape
        When each is scanned
        Then the raw ``../../`` traversal is still reported (decoding is irrelevant to it) while the
            percent-encoded escape is left clean - with decoding suppressed the detector treats the
            encoded octets as literal in-root text and never decodes them, exactly as implemented.

    Boundaries:
        - Focus: the single-decode suppression branch of _classify under decode_percent_paths=false
        - Fixtures/params: asset_case

    On failure, first check:
        - The ``target.replace("%", "%25")`` neutralisation in _classify
        - Whether the residual-encoding check wrongly ran while decoding was off
    """
    raw = asset_case("ds116", "parent_escape_from_root")
    (raw.root / "docsentinel.toml").write_text('profile = "fast"\ndecode_percent_paths = false\n', encoding="utf-8")
    assert [finding.line for finding in _ds116(scan(raw.root).findings)] == [3]

    encoded = asset_case("ds116", "percent_encoded_parent_escape")
    (encoded.root / "docsentinel.toml").write_text(
        'profile = "fast"\ndecode_percent_paths = false\n', encoding="utf-8"
    )
    assert _ds116(scan(encoded.root).findings) == ()


def test_windows_path_policy_off_silences_but_portable_reports(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies windows_path_policy behaviour.

    Scenario:
        Given the windows_absolute_drive_path fixture scanned with windows_path_policy set to off and
            then to portable via [tool.doc_sentinel]
        When each config is discovered
        Then ``off`` silences the drive-letter finding while the default ``portable`` reports it at
            line 3, so the Windows category is gated exactly by that option.

    Boundaries:
        - Focus: the windows_path_policy gate for the drive/UNC/backslash categories in _classify
        - Fixtures/params: asset_case

    On failure, first check:
        - The ``windows_path_policy == "off"`` branch in _classify
        - Whether load_config unwraps windows_path_policy from the table
    """
    off = asset_case("ds116", "windows_absolute_drive_path")
    (off.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nwindows_path_policy = "off"\n', encoding="utf-8"
    )
    assert _ds116(scan(off.root).findings) == ()

    portable = asset_case("ds116", "windows_absolute_drive_path")
    (portable.root / "pyproject.toml").write_text(
        '[tool.doc_sentinel]\nprofile = "fast"\nwindows_path_policy = "portable"\n', encoding="utf-8"
    )
    assert [finding.line for finding in _ds116(scan(portable.root).findings)] == [3]


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("root_escape_policy", '"bogus"'),
        ("windows_path_policy", '"relaxed"'),
        ("decode_percent_paths", '"nope"'),
    ],
)
def test_invalid_ds116_option_raises_config_error(option: str, value: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml that sets one DS116 option to an invalid value (an out-of-vocabulary
            enum string or a non-boolean)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects invalid enum/bool values for every DS116 option
        - Fixtures/params: parametrized over the three options; asset_case

    On failure, first check:
        - The enum/bool validation for the named option in config.py
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds116", "parent_escape_from_root")
    (case.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(case.root)


def test_hostile_targets_are_bounded_and_repr_escaped(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies hostile targets cannot inject output.

    Scenario:
        Given link targets carrying an ESC byte, a NUL byte, a literal ``%0A``, a ``::error file=x::y``
            workflow payload, a 5000-character path, a unicode confusable and a right-to-left override,
            each crafted to trip DS116
        When the scan result is rendered as text and as GitHub workflow commands
        Then every message is bounded to the detector's echo limit, repr-escapes all control and
            non-ASCII bytes, carries only the author's raw target (no resolved/absolute path, no
            existence), the text output holds no raw ESC/NUL/newline, and the github output is exactly
            one ``::error`` line per finding with its ``%0A`` further escaped to ``%250A`` so no second
            workflow command can be smuggled in.

    Boundaries:
        - Focus: output-injection and information-disclosure safety of DS116 messages (threat model MEDIUM)
        - Fixtures/params: tmp_path

    On failure, first check:
        - _echo's unicode_escape bound and reporting._escape_data percent/newline handling
        - Whether a message leaked a resolved absolute path or an un-escaped control byte
    """
    hostile_targets = (
        "../../a\x1bb.md",
        "../../a\x00b.md",
        "../../a%0Ab.md",
        "../../x::error::y.md",
        "../../" + "a" * 5000 + ".md",
        "../../a\u202eb.md",
        "../../\uff0e\uff0e_c.md",
    )
    body = "# Home\n\n" + "".join(f"[t{index}]({target})\n" for index, target in enumerate(hostile_targets))
    (tmp_path / "README.md").write_text(body, encoding="utf-8")

    result = scan(tmp_path, config=Config(profile="fast", select=("DS116",)))
    own = _ds116(result.findings)
    assert len(own) == len(hostile_targets)

    max_message = max(len(CATEGORY_MESSAGE[category]) for category in CATEGORY_MESSAGE) + len(": ") + pb._MAX_ECHO + 3
    for finding in own:
        assert "\x1b" not in finding.message and "\x00" not in finding.message
        assert "\n" not in finding.message and "\r" not in finding.message
        assert len(finding.message) <= max_message
        assert not os.path.isabs(finding.message.partition(": ")[2])  # never a resolved absolute path

    text = render(result, "text")
    assert "\x1b" not in text and "\x00" not in text
    assert "\\x1b" in text and "\\x00" in text
    error_lines = [line for line in text.splitlines() if line.startswith("  error: README.md:")]
    assert len(error_lines) == len(hostile_targets)  # no message broke onto a second line

    github = render(result, "github")
    github_lines = github.split("\n")
    assert len(github_lines) == len(hostile_targets)
    assert all(line.startswith("::error file=README.md,line=") for line in github_lines)
    assert "\x1b" not in github and "\x00" not in github
    assert "%250A" in github  # the literal %0A had its % escaped, so it cannot break a command


def test_crlf_line_numbers_point_at_the_offending_reference(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies CRLF line fidelity.

    Scenario:
        Given a CRLF-terminated document whose escaping link sits on line 5
        When DS116 recognition runs over it
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input
        - Fixtures/params: tmp_path

    On failure, first check:
        - CRLF handling in the shared scanner's line splitting
        - That the reported line is the reference's line, not its body
    """
    (tmp_path / "README.md").write_bytes(b"# Title\r\n\r\nIntro prose.\r\n\r\n[x](../../secret.md)\r\n")

    findings = _ds116(pb.detect(tmp_path, (models.Document("README.md", 1),)))

    assert len(findings) == 1
    assert findings[0].line == 5


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes
        When a fast scan reads it with DS116 selected
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in path_boundaries._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"# Title\n\n[x](\xff\xfe/../../x.md)\n")

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS116",)))


def test_unreadable_file_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies an unreadable file is not a silent clean.

    Scenario:
        Given a Markdown document whose read permission is removed
        When a fast scan tries to read it with DS116 selected
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
    target.write_text("# Title\n\n[x](../../secret.md)\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            scan(tmp_path, config=Config(profile="fast", select=("DS116",)))
    finally:
        target.chmod(0o644)


def test_symlinked_markdown_file_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies a symlinked target file is skipped.

    Scenario:
        Given a symlink pointing at a Markdown file
        When that symlink is scanned directly with DS116 selected
        Then the engine refuses to inventory the symlinked file rather than following it.

    Boundaries:
        - Focus: the engine's symlink safety for a directly selected file path
        - Fixtures/params: tmp_path

    On failure, first check:
        - The symlink guard in engine.scan for selected files
        - Whether symlinks are silently followed into the scan
    """
    target = tmp_path / "real.md"
    target.write_text("# Title\n\n[x](../../secret.md)\n", encoding="utf-8")
    link = tmp_path / "link.md"
    _symlink_or_skip(link, str(target))

    with pytest.raises(ValueError, match="Symlinked files are not inventoried"):
        scan(link, config=Config(profile="fast", select=("DS116",)))


def test_scan_root_subdirectory_is_the_boundary(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies the boundary is the scan root.

    Scenario:
        Given a repository whose scan root is the ``docs`` subdirectory and a document under it whose
            link climbs above ``docs`` but stays inside the repository
        When DS116 scans the ``docs`` subdirectory
        Then the link is reported as an escape, because the configured scan root - not the repository -
            is the containment boundary.

    Boundaries:
        - Focus: containment is relative to the scan root even when it is a repo subdirectory
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether root canonicalisation used the repository instead of the passed scan root
        - Whether a reference above the scan root but inside the repo wrongly read as clean
    """
    docs = tmp_path / "docs"
    (docs / "inner").mkdir(parents=True)
    (tmp_path / "sibling.md").write_text("# repo sibling\n", encoding="utf-8")
    (docs / "inner" / "README.md").write_text("# H\n\n[x](../../sibling.md)\n", encoding="utf-8")

    findings = _ds116(scan(docs, config=Config(profile="fast", select=("DS116",))).findings)

    assert [(finding.path, finding.line) for finding in findings] == [("inner/README.md", 3)]


def test_cwd_never_enters_resolution(asset_case: Callable[[str, str], AssetCase], monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors repository root path boundaries ds116: verifies cwd independence.

    Scenario:
        Given a finding scenario scanned once from its own directory and once after chdir into an
            unrelated directory
        When DS116 resolves containment both times
        Then the findings are identical, proving the current working directory never enters resolution
            and only the scan root plus document path are used.

    Boundaries:
        - Focus: the standing requirement that cwd never participates in containment
        - Fixtures/params: asset_case, monkeypatch (for a restored chdir)

    On failure, first check:
        - Whether the detector joined targets against os.getcwd() instead of the canonical root
        - Whether realpath was applied to anything other than the trusted root
    """
    case = asset_case("ds116", "parent_escape_from_root")
    baseline_findings = scan(case.root, config=Config(profile="fast", select=("DS116",))).findings

    elsewhere = case.root.parent / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    relocated = scan(case.root, config=Config(profile="fast", select=("DS116",))).findings

    assert relocated == baseline_findings
    assert [finding.line for finding in _ds116(relocated)] == [3]


def test_repeated_scans_and_fresh_roots_are_stable(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors repository root path boundaries ds116: verifies repeated and fresh-root stability.

    Scenario:
        Given a finding scenario scanned twice over the same root and once more over an independently
            materialized fresh copy
        When the DS116 finding tuples are compared
        Then all three agree and report line 3, so the detector holds no order-dependent or path-cached state.

    Boundaries:
        - Focus: determinism across repeats and across a fresh materialization of the same case
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Whether a cache keyed only on basename leaked across roots
    """
    case = asset_case("ds116", "unsafe_image_target")
    first = _ds116(scan(case.root, config=Config(profile="fast", select=("DS116",))).findings)
    second = _ds116(scan(case.root, config=Config(profile="fast", select=("DS116",))).findings)
    assert first == second
    assert [finding.line for finding in first] == [3]


def test_documents_are_scanned_individually(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies documents are scanned in isolation.

    Scenario:
        Given a root holding one escaping document and one clean document
        When detect runs over each document tuple individually
        Then only the escaping document yields a finding and the clean document yields none, proving the
            detector scans exactly the documents it is handed without cross-contamination.

    Boundaries:
        - Focus: per-document isolation of detect over an explicit document tuple
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether detect iterated documents beyond the tuple it was given
        - Whether a shared index leaked findings between documents
    """
    (tmp_path / "bad.md").write_text("# Bad\n\n[x](../../secret.md)\n", encoding="utf-8")
    (tmp_path / "good.md").write_text("# Good\n\n[y](good.md)\n", encoding="utf-8")

    bad = _ds116(pb.detect(tmp_path, (models.Document("bad.md", 0),)))
    good = _ds116(pb.detect(tmp_path, (models.Document("good.md", 0),)))

    assert [(finding.path, finding.line) for finding in bad] == [("bad.md", 3)]
    assert good == ()


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors repository root path boundaries ds116: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When detect runs over every default-setup finding scenario
        Then all expected findings are still produced, proving DS116 opens no socket, makes no
            connection and never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS116 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS116 ever constructs a socket."""
        raise AssertionError("DS116 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS116 ever opens an outbound connection."""
        raise AssertionError("DS116 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS116 ever launches a subprocess."""
        raise AssertionError("DS116 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case, (line, _category, count) in FINDING_EXPECTATIONS.items():
        loaded = asset_case("ds116", case)
        findings = _ds116(pb.detect(loaded.root, loaded.documents()))
        assert len(findings) == count
        assert findings[0].line == line


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors repository root path boundaries ds116: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS116 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported,
            proving the fast DS116 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS116's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether path_boundaries or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from pathlib import Path\n"
        "from docsentinel.config import Config\n"
        "from docsentinel.detectors import path_boundaries\n"
        "assert path_boundaries.check_text('[x](../../secret.md)\\n', 'README.md', Path('/scanroot'), "
        "Config(root_escape_policy='error'))\n"
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


def _escape_flood(scale: int) -> str:
    """Return a document of ``scale`` distinct escaping links (one finding each).

    :param scale: Number of escaping links to emit.
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + "".join(f"[a{index}](../../out{index}.md)\n" for index in range(scale))


def _oscillation_flood(scale: int) -> str:
    """Return a document of ``scale`` in-root oscillation links (zero findings).

    :param scale: Number of in-root ``a/../`` links to emit.
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + "".join(f"[a{index}](a/../in{index}.md)\n" for index in range(scale))


#: Representative routing shapes mapped to a builder and an exact finding-count
#: formula. This integration suite proves only that detect() routes real files
#: through check_text with exact counts and no super-linear blow-up over the file
#: path; the exhaustive algorithmic flood coverage lives in
#: tests/unit/test_detectors_path_boundaries_adversarial.py and is not duplicated.
#: The clean oscillation shape sits beside the escaping shape so a zero can never
#: be a dead detector.
ROUTING_SHAPES: dict[str, tuple[Callable[[int], str], Callable[[int], int]]] = {
    "escape_flood": (_escape_flood, lambda scale: scale),
    "oscillation_flood": (_oscillation_flood, lambda _scale: 0),
}


@pytest.mark.parametrize("shape", sorted(ROUTING_SHAPES))
def test_detect_routing_stays_linear(shape: str, tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies linear-time file routing.

    Scenario:
        Given large documents of one representative shape - many distinct escaping links or many in-root
            oscillation links
        When detect routes a doubling series of them through the shared scaling helper
        Then every scale produces the exact deterministic finding count (so the pass is never vacuous)
            and the scaling stays under the shared linear bound.

    Boundaries:
        - Focus: detect() routing of real files through check_text with exact counts (contract F)
        - Non-goal: the algorithmic flood shapes, which live in the adversarial unit test
        - Fixtures/params: parametrized over the representative routing shapes; tmp_path

    On failure, first check:
        - Any accidentally quadratic scan of the reference list or per-reference re-decode
        - That the exact finding count for this shape still holds at every scale
    """
    build, expected_count = ROUTING_SHAPES[shape]

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
        lambda documents: pb.detect(tmp_path, documents, Config(root_escape_policy="error")),
        (500, 1_000, 2_000, 4_000),
        expected_count=expected_count,
        label=f"ds116-{shape}",
    )


def test_symlink_chain_walk_terminates_and_stays_linear(tmp_path: Path):
    """
    [Integration] detectors repository root path boundaries ds116: verifies a bounded symlink chain is linear.

    Scenario:
        Given an in-root chain of ``n`` symlinks whose final link points outside the root, referenced by
            a document, across a small capped doubling series within the hop bound
        When DS116 follows the chain with its lexical, non-following containment walk
        Then exactly one escape finding is produced at every size and the walk terminates and scales
            near-linearly - a crafted chain cannot stall the scan (threat-model MEDIUM DoS).

    Boundaries:
        - Focus: the walk is hop-bounded and linear over the collapsed in-root component count
        - Fixtures/params: tmp_path (symlink chain regenerated per size)

    On failure, first check:
        - Whether escapes_via_symlink lost its hop bound or per-component loop detection
        - Whether the walk began stat-ing the outside target instead of reading the link lexically
    """

    def build(size: int) -> tuple[Path, tuple[models.Document, ...]]:
        """Build a fresh in-root symlink chain of ``size`` links ending outside the root.

        :param size: Number of chained symlinks to create.
        :returns: The scan root and the single-document tuple.
        """
        root = tmp_path / f"root{size}"
        root.mkdir()
        outside = tmp_path / f"outside{size}.md"
        outside.write_text("secret\n", encoding="utf-8")
        for index in range(size - 1):
            _symlink_or_skip(root / f"link{index}", f"link{index + 1}")
        _symlink_or_skip(root / f"link{size - 1}", f"../outside{size}.md")
        (root / "README.md").write_text("[x](link0)\n", encoding="utf-8")
        return root, (models.Document("README.md", 0),)

    def run(payload: tuple[Path, tuple[models.Document, ...]]) -> tuple[models.Finding, ...]:
        """Run DS116 over the prebuilt symlink-chain document.

        :param payload: The scan root and document tuple from ``build``.
        :returns: The DS116 findings for the chain.
        """
        root, documents = payload
        return pb.detect(root, documents, Config(root_escape_policy="error"))

    assert_scales_linearly(build, run, (8, 16, 32), expected_count=1, label="ds116-symlink-chain")
