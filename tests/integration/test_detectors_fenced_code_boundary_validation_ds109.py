"""Integration tests for DS109 over committed Markdown assets in ``tests/assets/ds109``.

This is Story 06.0 Task 03. Every one of the 14 committed scenarios is loaded in
isolation through the ``asset_case`` fixture and asserted against an explicit,
checked-in expectation table (never against whatever the analyzer currently
emits). Coverage spans the pure ``detect`` entry point, the shared ``scan``
engine, ``select``/``ignore``, baseline suppression, the text/json/github
reports, the CLI, cross-rule isolation from DS101-DS103, and the linear-time
requirement on adversarial fenced input.

The supported dialect is the ``gfm-subset`` documented in
``docs/dev/markdown_dialect.md``; these tests exercise its known boundaries
(indent <= 3 openers, matching-marker closers, closer length >= opener length,
backtick-opener info-string rule, CRLF line fidelity) rather than full
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
from docsentinel.detectors import fences
from docsentinel.engine import scan
from docsentinel.markdown_blocks import scan_markdown
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.timing_helpers import assert_scales_linearly

#: Scenarios whose committed Markdown has no DS109 defect. Each must leave the
#: rule registered and executed yet report zero findings of its own.
CLEAN_CASES: tuple[str, ...] = (
    "valid_backtick_fence",
    "valid_longer_closer",
    "valid_tilde_fence",
    "indented_literal_ticks",
    "fence_with_info_string",
    "nested_opposite_marker",
    "fence_trailing_whitespace",
)

#: Scenarios that must each yield exactly one DS109 ``error`` finding, mapped to
#: the expected one-based source line and a message-evidence substring. These
#: values are fixed by the committed fixtures, not derived from the analyzer.
FINDING_EXPECTATIONS: dict[str, tuple[int, str]] = {
    "unterminated_fence_eof": (5, "unclosed"),
    "wrong_fence_character": (5, "unclosed"),
    "shorter_closing_run": (5, "unclosed"),
    "closing_with_extra_text": (5, "unclosed"),
    "multiple_unterminated_blocks": (6, "unclosed"),
    "crlf_fence_positions": (5, "unclosed"),
    "backtick_in_info_string": (5, "info string"),
}

#: All 14 promised scenarios in a stable order for parametrization.
ALL_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)


def _ds109(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS109 findings from a mixed finding tuple, preserving order."""
    return tuple(finding for finding in findings if finding.rule == "DS109")


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors fenced code boundary validation ds109: verifies the local catalog totals.

    Scenario:
        Given the committed ds109 asset directories and this suite's expectation table
        When clean and finding scenarios are counted
        Then there are exactly 7 clean, 7 finding and 14 total scenarios, matching Task 02.

    Boundaries:
        - Focus: this file's expectation table is complete and non-overlapping
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02
        - Whether a case appears in both CLEAN_CASES and FINDING_EXPECTATIONS
    """
    assert len(CLEAN_CASES) == 7
    assert len(FINDING_EXPECTATIONS) == 7
    assert len(set(ALL_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)


def test_ds109_is_registered_as_an_exact_fast_rule():
    """
    [Integration] detectors fenced code boundary validation ds109: verifies fast-profile registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS109 is present with its error severity and title.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.fences registered DS109 on import
        - Whether DS109 drifted to another profile or severity
    """
    fast_codes = {rule.code for rule in rules_for_profile("fast")}
    assert "DS109" in fast_codes
    rule = next(rule for rule in rules_for_profile("fast") if rule.code == "DS109")
    assert rule.severity == "error"
    assert rule.title == "Malformed or unclosed fenced code blocks"


@pytest.mark.parametrize("case", ALL_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies detect per committed case.

    Scenario:
        Given one committed ds109 scenario materialized into a fresh tmp_path
        When fences.detect runs over its README.md
        Then clean cases yield no finding and finding cases yield exactly one DS109 error
        at the expected one-based line carrying the expected message evidence.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes, one case per run
        - Fixtures/params: parametrized over all 14 scenarios; asset_case

    On failure, first check:
        - The expected line/message in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte)
    """
    loaded = asset_case("ds109", case)
    findings = fences.detect(loaded.root, loaded.documents("README.md"))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    expected_line, evidence = FINDING_EXPECTATIONS[case]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "DS109"
    assert finding.severity == "error"
    assert finding.path == "README.md"
    assert finding.line == expected_line
    assert evidence in finding.message
    if evidence == "unclosed":
        assert str(expected_line) in finding.message


@pytest.mark.parametrize("case", ALL_CASES)
def test_scan_isolates_ds109_from_other_fast_rules(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies full fast-scan isolation.

    Scenario:
        Given one committed ds109 scenario scanned under the full fast profile
        When the engine runs DS101-DS103 and DS109 together
        Then DS101-DS103 add no findings, DS109 ran (clean cases prove execution via
        enabled_rules with zero findings) and finding cases emit exactly the expected DS109 error.

    Boundaries:
        - Focus: cross-rule ownership - a malformed fence is DS109's alone, no cascade or noise
        - Fixtures/params: parametrized over all 14 scenarios; asset_case

    On failure, first check:
        - Whether DS101/DS102/DS103 regressed and now fire on fenced content
        - Whether DS109 dropped out of enabled_rules (a clean result must mean it ran)
    """
    result = scan(loaded_root := asset_case("ds109", case).root, config=Config(profile="fast"))

    assert result.enabled_rules == (
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
    assert all(finding.rule == "DS109" for finding in result.findings), result.findings
    own = _ds109(result.findings)

    if case in CLEAN_CASES:
        assert own == ()
    else:
        expected_line, evidence = FINDING_EXPECTATIONS[case]
        assert len(own) == 1
        assert own[0].line == expected_line
        assert evidence in own[0].message
    assert loaded_root.is_dir()


def test_select_narrows_to_ds109_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies select activates only DS109.

    Scenario:
        Given a finding scenario scanned with select pinned to DS109
        When the engine resolves the active rule set
        Then only DS109 is enabled and its single expected finding is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS109 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds109", "unterminated_fence_eof")

    result = scan(case.root, config=Config(profile="fast", select=("DS109",)))

    assert result.enabled_rules == ("DS109",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS109", 5)]


def test_prefix_select_includes_ds109(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies the DS1 prefix selects DS109.

    Scenario:
        Given a finding scenario scanned with the DS1 prefix selector
        When the active rule set is resolved
        Then DS109 is among the enabled rules and still reports its finding.

    Boundaries:
        - Focus: prefix selector matching for DS109
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS1 against DS109
        - Whether DS109 was excluded despite the prefix
    """
    case = asset_case("ds109", "wrong_fence_character")

    result = scan(case.root, config=Config(profile="fast", select=("DS1",)))

    assert "DS109" in result.enabled_rules
    assert _ds109(result.findings)[0].line == 5


def test_ignore_suppresses_ds109(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies ignore removes DS109.

    Scenario:
        Given a finding scenario scanned with DS109 ignored
        When the engine resolves the active rule set
        Then DS109 is absent from enabled_rules and contributes no finding.

    Boundaries:
        - Focus: ignore precedence for a fast rule, proving the detector is genuinely gated off
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules ignore precedence over the default select
        - Whether a DS109 finding survived the ignore
    """
    case = asset_case("ds109", "unterminated_fence_eof")

    result = scan(case.root, config=Config(profile="fast", ignore=("DS109",)))

    assert "DS109" not in result.enabled_rules
    assert _ds109(result.findings) == ()


def test_baseline_suppresses_a_known_ds109_finding(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies baseline suppression round-trips.

    Scenario:
        Given a finding scenario whose DS109 finding is recorded into a baseline file
        When the same tree is rescanned with that baseline configured
        Then the previously known DS109 finding is filtered out while an unbaselined scan still reports it.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to a DS109 finding
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS109 finding between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds109", "shorter_closing_run")
    first = scan(case.root, config=Config(profile="fast", select=("DS109",)))
    assert len(_ds109(first.findings)) == 1

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS109",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds109(suppressed.findings) == ()


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies text/json/github report stability.

    Scenario:
        Given a DS109 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS109 finding deterministically (schema v1 json,
        a ::error annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS109 error across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path and line
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds109", "unterminated_fence_eof")
    result = scan(case.root, config=Config(profile="fast", select=("DS109",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "error: README.md:5: unclosed" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS109"]
    assert payload["findings"][0]["rule"] == "DS109"
    assert payload["findings"][0]["line"] == 5

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::error file=README.md,line=5,title=DS109::")


def test_cli_fast_json_scan_reports_ds109_and_exit_one(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies the CLI fast json scan path.

    Scenario:
        Given a finding scenario scanned via the CLI with --profile fast --format json
        When the command runs
        Then it prints a JSON report containing the DS109 error at line 5 and exits 1 (blocking error).

    Boundaries:
        - Focus: end-to-end CLI wiring, JSON output and the error exit code
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for error-severity findings
        - Whether the JSON report still includes the DS109 finding
    """
    case = asset_case("ds109", "wrong_fence_character")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds109 = [finding for finding in payload["findings"] if finding["rule"] == "DS109"]
    assert len(ds109) == 1
    finding = ds109[0]
    assert finding["rule"] == "DS109"
    assert finding["path"] == "README.md"
    assert finding["severity"] == "error"
    assert finding["line"] == 5
    assert "unclosed" in finding["message"]
    assert exit_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario scanned via the CLI under the fast profile
        When the command runs
        Then no blocking finding is reported and the process exits 0.

    Boundaries:
        - Focus: non-blocking exit code when DS109 finds nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS109 or a sibling rule
        - The CLI exit-code mapping when no error-severity finding exists
    """
    case = asset_case("ds109", "valid_backtick_fence")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds109_under_fast(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies `docsentinel rules` lists DS109.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS109 and its title appear under the fast profile.

    Boundaries:
        - Focus: rules-command surfacing of DS109
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS109
        - The rules-command formatting for fast rules
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS109: Malformed or unclosed fenced code blocks" in captured.out


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies repeated scans are stable.

    Scenario:
        Given a finding scenario scanned twice over the same materialized root
        When the two DS109 finding tuples are compared
        Then they are equal, so the detector holds no order-dependent mutable state.

    Boundaries:
        - Focus: determinism of DS109 over a real asset tree
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Ordering stability of the shared scanner's fence list
    """
    case = asset_case("ds109", "multiple_unterminated_blocks")

    first = scan(case.root, config=Config(profile="fast", select=("DS109",)))
    second = scan(case.root, config=Config(profile="fast", select=("DS109",)))

    assert first.findings == second.findings
    assert [finding.line for finding in _ds109(first.findings)] == [6]


def test_tilde_opener_is_not_closed_by_backticks(tmp_path: Path):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies a backtick run cannot close a tilde fence.

    Scenario:
        Given a tilde opener whose only candidate closer is a backtick run
        When detect runs over the document
        Then the mismatched marker does not close the fence and one unclosed finding is reported.

    Boundaries:
        - Focus: the symmetric marker rule (the backtick/tilde direction not covered by an asset)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The is-closer marker comparison in the shared scanner
        - That a wrong-marker run never silently completes a fence
    """
    (tmp_path / "README.md").write_text("intro\n~~~\ncode\n```\n", encoding="utf-8")

    findings = fences.detect(tmp_path, (models.Document("README.md", 1),))

    assert len(findings) == 1
    assert findings[0].line == 2
    assert "unclosed" in findings[0].message


def test_triple_backticks_in_prose_are_not_a_fence(tmp_path: Path):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies mid-line backticks never open a fence.

    Scenario:
        Given prose that mentions triple backticks mid-line rather than at the line start
        When detect runs over the document
        Then no fence opener is recognized and no finding is produced.

    Boundaries:
        - Focus: an opener must begin the line (indent <= 3); mid-line runs are content
        - Fixtures/params: tmp_path

    On failure, first check:
        - The fence-opener anchoring in the shared scanner regex
        - That inline backtick runs are not mistaken for block openers
    """
    (tmp_path / "README.md").write_text("Write a fence with ``` at the line start.\n", encoding="utf-8")

    assert fences.detect(tmp_path, (models.Document("README.md", 1),)) == ()


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes
        When a fast scan reads it
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in fences._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"```\n\xff\xfe never closes\n")

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS109",)))


def test_symlinked_markdown_file_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies a symlinked target file is skipped.

    Scenario:
        Given a symlink pointing at a Markdown file with an unclosed fence
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
    target.write_text("```\nunclosed\n", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    with pytest.raises(ValueError, match="Symlinked files are not inventoried"):
        scan(link, config=Config(profile="fast", select=("DS109",)))


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When detect runs over every finding scenario (whose bodies contain code-like text)
        Then all expected findings are still produced, proving DS109 opens no socket, makes no
        connection and never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS109 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS109 ever constructs a socket."""
        raise AssertionError("DS109 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS109 ever opens an outbound connection."""
        raise AssertionError("DS109 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS109 ever launches a subprocess."""
        raise AssertionError("DS109 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case, (expected_line, _evidence) in FINDING_EXPECTATIONS.items():
        loaded = asset_case("ds109", case)
        findings = fences.detect(loaded.root, loaded.documents("README.md"))
        assert [finding.line for finding in findings] == [expected_line]


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors fenced code boundary validation ds109: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS109 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported,
        proving the fast DS109 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS109's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether fences or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.detectors import fences\n"
        "assert fences.check_text('```\\ncode\\n', 'README.md')\n"
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


def test_adversarial_nested_fences_stay_bounded(tmp_path: Path):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies linear-time adversarial handling.

    Scenario:
        Given a single long opener that swallows many nested pseudo-opener and very-long body lines
        When detect routes a doubling input series through the shared scaling helper (small sizes:
        the algorithmic proof over the scanner lives in tests/unit/test_markdown_blocks_adversarial.py)
        Then exactly one unclosed finding is produced at every size (the first opener swallows every
        nested pseudo-opener as body, so the count is pinned at 1) and the scaling stays under the
        shared linear bound.

    Boundaries:
        - Focus: bounded findings plus bounded time routed through detect() (contract F)
        - Fixtures/params: tmp_path

    On failure, first check:
        - That the first opener swallows later pseudo-openers as body (no per-line finding)
        - Any accidentally quadratic span masking in the shared scanner
    """

    def _build(line_count: int) -> tuple[models.Document, ...]:
        """Write an adversarial unclosed fence of ``line_count`` body lines and return its Document."""
        long_line = "~" * 200
        body = "".join(f"```\n{long_line}\n" for _ in range(line_count))
        path = tmp_path / f"case_{line_count}.md"
        path.write_text(f"`````\n{body}", encoding="utf-8")
        return (models.Document(path.name, path.stat().st_size),)

    assert_scales_linearly(
        _build,
        lambda documents: fences.detect(tmp_path, documents),
        (1_000, 2_000, 4_000, 8_000),
        expected_count=1,
        label="ds109-adversarial",
    )


def test_shared_fence_mask_covers_unclosed_asset_span(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors fenced code boundary validation ds109: verifies the shared mask over a real asset.

    Scenario:
        Given an unclosed-fence asset scanned through the shared Markdown block index
        When fenced_line_numbers builds the mask DS1xx rules share
        Then it covers the opener line through end of file, so sibling rules skip swallowed content.

    Boundaries:
        - Focus: the shared fence-mask offered to other DS1xx analyzers, over committed bytes
        - Fixtures/params: asset_case

    On failure, first check:
        - That an unclosed fence extends the mask to the last line
        - The inclusive start/end range used to build the mask
    """
    case = asset_case("ds109", "unterminated_fence_eof")
    text = case.read_text("README.md")

    index = scan_markdown(text, "README.md")
    mask = fences.fenced_line_numbers(index)

    total_lines = len(text.splitlines())
    assert min(mask) == 5
    assert max(mask) == total_lines
