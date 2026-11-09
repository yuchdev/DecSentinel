"""Integration tests for DS113 over committed Markdown assets in ``tests/assets/ds113``.

This is Story 10.0 Task 03, the security-sensitive missing-local-asset rule. Every
one of the 15 committed scenarios is loaded in isolation through the ``asset_case``
fixture and asserted against an explicit, checked-in expectation table
(:data:`CLEAN_CASES`, :data:`FINDING_EXPECTATIONS`, :data:`EXPECTED_SIBLINGS`, the
exact-config :data:`PDF_CASE` and the runtime :data:`SYMLINK_CASE`) transcribed from
the Task 02 manifest, the fixture matrix and the detector's stable message contract,
never derived from whatever the analyzer currently emits. The 13 ``default``-setup
scenarios (8 CLEAN + 5 FINDING) are asserted through both the pure ``assets.detect``
entry point and the shared ``scan`` engine; ``missing_pdf_attachment`` is asserted
with its explicit ``asset_extensions=["pdf"]`` config and ``asset_symlink_outside``
builds its in-root symlink to a sibling out-of-root target at runtime in ``tmp_path``.

DS113 is an always-active ``fast`` rule at ``error`` severity with no opt-in marker,
so a single finding makes the CLI exit 1 even without ``--strict`` while the
``missing_asset_policy=warn`` downgrade keeps it to exit 0 (and 1 under ``--strict``);
all three are asserted. Coverage follows the standing threat model
(``docs/security/threat-model-ds113-missing-assets-2026-10-23.md``): escaping and
in-root-symlink-out references are DS116's alone and are never ``stat``-ed by DS113
(proven with a filesystem recorder); a missing in-root Markdown image is the
documented DS101 + DS113 overlap with no triple reporting; a committed FIFO or a
directory at an asset path is reported as "not a regular file" without ever being
opened (the FIFO test runs ``detect`` in a worker thread with a hard join timeout so a
regression that opens the pipe cannot hang the suite); a ``data:`` URI ``srcset``
candidate never manufactures a filesystem probe of its base64 fragment; and the
echoed target is bounded and ``repr``-escaped so no control byte or resolved absolute
path reaches a report sink.

The file also exercises the ``missing_asset_policy`` off/warn/error ladder (``off``
performing no ``stat``, proven with the recorder) through both ``docsentinel.toml``
and ``[tool.doc_sentinel]``; the ``check_html_asset_tags``/``check_markdown_images``/
``check_srcset`` toggles; case-insensitive extension matching; select/ignore (exact
and prefix); baseline round-trips; text/json/github report stability; the CLI exit
paths; ``docsentinel rules``/``doctor`` surfacing; invalid-config rejection; the edge
dimensions required by the task (CRLF line fidelity, invalid UTF-8, an unreadable
file); determinism across repeated and fresh roots; the fast stdlib-only import with
no network or content execution; and the linear-time requirement on adversarial image
and ``srcset`` floods routed through ``detect`` end to end over non-fenced prose. The
exhaustive algorithmic shape coverage for the shared scanner belongs to the unit
layer; this suite proves only that real files route through ``check_text`` with exact
deterministic counts and no super-linear blow-up over the file path. A markdown-it-py
differential over the image/srcset/href fixtures is kept as a scratch oracle (never a
runtime dependency) and is not duplicated here.
"""

from __future__ import annotations

import builtins
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
from docsentinel.detectors import assets
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
from tests.mock.test_path_boundaries_oracle import _is_under, _symlink_or_skip
from tests.timing_helpers import assert_scales_linearly

#: The fixed diagnostic prefixes DS113 prepends to the bounded, escaped raw target,
#: keyed by the classification reason. Transcribed from the detector's stable message
#: contract, not read back from the analyzer at runtime.
MISSING_PREFIX = "missing asset: "
NOT_REGULAR_PREFIX = "asset is not a regular file: "

#: The eight committed CLEAN scenarios: an existing relative/HTML/subdir/reference
#: image, an external https+data-URI image, a path-like alt text, a template
#: placeholder and a broken image buried in a fence/inline-code span must all leave
#: DS113 registered and executed yet report zero DS113 findings of their own.
CLEAN_CASES: tuple[str, ...] = (
    "relative_image_exists",
    "html_image_exists",
    "external_image_is_skipped",
    "asset_reference_definition",
    "alt_text_not_filename",
    "asset_path_from_subdir",
    "template_asset_is_skipped",
    "bad_asset_under_code",
)

#: The five ``default``-setup FINDING scenarios, each mapped to the one-based line(s)
#: of the offending reference and the full DS113 message for each line, in ascending
#: source order. ``percent_encoded_asset_path`` echoes the author's raw (still
#: percent-encoded) target, and ``multiple_missing_images`` deliberately yields two
#: findings, one per distinct missing image. Fixed by the committed fixtures and the
#: message contract (``missing asset: <echo>``), not derived from the analyzer.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[int, ...], tuple[str, ...]]] = {
    "missing_markdown_image": ((5,), (f"{MISSING_PREFIX}diagrams/flow.svg",)),
    "missing_html_image": ((5,), (f"{MISSING_PREFIX}media/missing.png",)),
    "missing_srcset_candidate": ((5,), (f"{MISSING_PREFIX}images/big.png",)),
    "percent_encoded_asset_path": ((5,), (f"{MISSING_PREFIX}images/my%20file.png",)),
    "multiple_missing_images": ((5, 7), (f"{MISSING_PREFIX}first.png", f"{MISSING_PREFIX}second.png")),
}

#: The document that carries the asserted DS113 finding (or, for clean cases, the one
#: whose reference is validated). Every scenario keeps its reference in a root-level
#: README.md except ``asset_path_from_subdir``, which nests it under ``docs/``.
PRIMARY_DOCUMENT: dict[str, str] = {
    "relative_image_exists": "README.md",
    "html_image_exists": "README.md",
    "external_image_is_skipped": "README.md",
    "asset_reference_definition": "README.md",
    "alt_text_not_filename": "README.md",
    "asset_path_from_subdir": "docs/README.md",
    "template_asset_is_skipped": "README.md",
    "bad_asset_under_code": "README.md",
    **dict.fromkeys(FINDING_EXPECTATIONS, "README.md"),
}

#: The non-default FINDING scenario gated by an explicit ``asset_extensions=["pdf"]``
#: config (its HTML ``<a href>`` to ``docs/manual.pdf`` is a link-shaped reference
#: that the extension gate must admit). Asserted on its own so the default self-scan
#: is never forced to a wider extension set.
PDF_CASE = "missing_pdf_attachment"

#: The runtime-symlink FINDING scenario. The committed fixture carries only the
#: Markdown owner; this suite builds the in-root ``evil.png`` symlink and the sibling
#: out-of-root target at runtime and proves the escape is DS116's finding, never a
#: DS113 missing-asset finding, and is never stat-ed or opened.
SYMLINK_CASE = "asset_symlink_outside"

#: The 13 ``default``-setup scenarios exercised through both detect() and scan().
DEFAULT_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: All 15 committed scenarios in a stable order.
ALL_CASES: tuple[str, ...] = DEFAULT_CASES + (PDF_CASE, SYMLINK_CASE)

#: The full fast-profile rule set, in registry order, run alongside DS113.
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

#: Legitimate non-DS113 findings a full fast scan adds on the default scenarios, each
#: owned by its rightful rule and transcribed from the fixture content. A missing
#: Markdown image is DS101's dangling link *and* DS113's missing asset (documented
#: overlap, never a triple with DS116). The ``docs/`` inline-code span in the nested
#: clean fixture is DS103's unresolvable-path finding, independent of DS113. HTML
#: ``<img>``/``srcset``/``<a href>`` references are DS113's alone because DS101's
#: matcher only sees Markdown ``[text](target)`` syntax.
EXPECTED_SIBLINGS: dict[str, tuple[tuple[str, int], ...]] = {
    "asset_path_from_subdir": (("DS103", 3),),
    "missing_markdown_image": (("DS101", 5),),
    "percent_encoded_asset_path": (("DS101", 5),),
    "multiple_missing_images": (("DS101", 5), ("DS101", 7)),
}


def _ds113(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS113 findings from a mixed tuple, preserving order.

    :param findings: Findings from a detector or scan.
    :returns: The DS113 subset in the original order.
    """
    return tuple(finding for finding in findings if finding.rule == "DS113")


def _siblings(findings: tuple[models.Finding, ...]) -> tuple[tuple[str, int], ...]:
    """Return the non-DS113 ``(rule, line)`` pairs of a finding tuple, sorted.

    :param findings: Findings from a full fast scan.
    :returns: Sorted ``(rule, line)`` pairs for every non-DS113 finding.
    """
    return tuple(sorted((finding.rule, finding.line) for finding in findings if finding.rule != "DS113"))


class _FsRecorder:
    """Records filesystem path arguments, split into *stat-like* and *open-like* calls.

    DS113's containment contract has two distinct obligations the shared DS116
    recorder does not separate: nothing outside the root may be ``stat``/``lstat``-ed,
    and *no asset path* may ever be ``open``-ed (a FIFO/device open would block or
    read unbounded). This recorder keeps the two buckets apart so each can be asserted
    independently.

    :ivar touched: Normalized paths passed to any stat/lstat/readlink/scandir/access/
        realpath/exists entry point.
    :ivar opened: Normalized paths passed to ``open``/``read_text`` entry points.
    """

    def __init__(self):
        """Initialize empty stat and open recording sets."""
        self.touched: set[str] = set()
        self.opened: set[str] = set()

    def note_touch(self, candidate: object):
        """Record one path-like argument to a stat-like call.

        :param candidate: The first argument passed to a patched stat-like call.
        """
        if isinstance(candidate, (str, os.PathLike)):
            self.touched.add(os.path.normpath(os.fspath(candidate)))

    def note_open(self, candidate: object):
        """Record one path-like argument to an open-like call.

        :param candidate: The first argument passed to a patched open-like call.
        """
        if isinstance(candidate, (str, os.PathLike)):
            self.opened.add(os.path.normpath(os.fspath(candidate)))


def _install_fs_recorder(monkeypatch: pytest.MonkeyPatch, recorder: _FsRecorder):
    """Patch every reachable filesystem entry point to record its path argument.

    Each wrapper records the path into the stat or open bucket, then delegates to the
    saved original so DS113 behaves normally; this records Python-level call arguments
    without changing behavior.

    :param monkeypatch: The pytest monkeypatch fixture.
    :param recorder: The recorder collecting path arguments.
    """
    for module, name in (
        (os, "stat"),
        (os, "lstat"),
        (os, "readlink"),
        (os, "scandir"),
        (os, "access"),
        (os.path, "realpath"),
        (os.path, "exists"),
        (os.path, "lexists"),
    ):
        original = getattr(module, name)

        def touch_wrapper(path: object, *args: object, _original=original, **kwargs: object) -> object:
            """Record a stat-like path then delegate to the original callable."""
            recorder.note_touch(path)
            return _original(path, *args, **kwargs)

        monkeypatch.setattr(module, name, touch_wrapper)

    for module, name in ((os, "open"), (builtins, "open")):
        original = getattr(module, name)

        def open_wrapper(path: object, *args: object, _original=original, **kwargs: object) -> object:
            """Record an open-like path then delegate to the original callable."""
            recorder.note_open(path)
            return _original(path, *args, **kwargs)

        monkeypatch.setattr(module, name, open_wrapper)

    for method in ("stat", "lstat", "exists", "is_file", "is_dir", "resolve", "readlink", "iterdir"):
        original_method = getattr(Path, method)

        def touch_method(self: Path, *args: object, _original=original_method, **kwargs: object) -> object:
            """Record the bound Path on a stat-like method then delegate."""
            recorder.note_touch(self)
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(Path, method, touch_method)

    for method in ("open", "read_text"):
        original_method = getattr(Path, method)

        def open_method(self: Path, *args: object, _original=original_method, **kwargs: object) -> object:
            """Record the bound Path on an open-like method then delegate."""
            recorder.note_open(self)
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(Path, method, open_method)


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors missing local media assets ds113: verifies the local catalog totals.

    Scenario:
        Given the committed ds113 asset directories and this suite's expectation table
        When the clean, finding, exact-config and runtime-symlink scenarios are counted
        Then there are exactly 8 clean, 7 finding, 0 error and 15 total scenarios matching Task 02,
        the clean and finding sets are disjoint, and every default scenario has a primary document.

    Boundaries:
        - Focus: the expectation table is complete, non-overlapping and matches the 8/7/0 split
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in both CLEAN_CASES and the finding sets or lacks a primary document
    """
    finding_cases = set(FINDING_EXPECTATIONS) | {PDF_CASE, SYMLINK_CASE}
    assert len(CLEAN_CASES) == 8
    assert len(finding_cases) == 7
    assert len(set(ALL_CASES)) == 15
    assert set(CLEAN_CASES).isdisjoint(finding_cases)
    assert set(PRIMARY_DOCUMENT) == set(DEFAULT_CASES)


def test_ds113_is_registered_as_an_exact_fast_rule_without_opt_in():
    """
    [Integration] detectors missing local media assets ds113: verifies always-active registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS113 is present with error severity, its title and an empty opt_in_option, proving it is
        an ordinary always-active rule rather than an opt-in policy rule like DS110.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.assets registered DS113 on import
        - Whether DS113 drifted profile/severity or grew an opt_in_option
    """
    fast = {rule.code: rule for rule in rules_for_profile("fast")}
    assert "DS113" in fast
    rule = fast["DS113"]
    assert rule.severity == "error"
    assert rule.title == "Missing local media and document assets"
    assert rule.opt_in_option == ""


@pytest.mark.parametrize("case", DEFAULT_CASES)
def test_detect_matches_expectation_for_each_default_case(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies detect per committed case.

    Scenario:
        Given one default-setup ds113 scenario materialized into a fresh tmp_path
        When assets.detect runs over all its documents with the shipped default config
        Then clean cases yield no DS113 finding and finding cases yield exactly the expected DS113 error
        findings at the expected one-based line(s), path and full message, in ascending source order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes, independent of the engine
        - Fixtures/params: parametrized over the 13 default-setup scenarios; asset_case

    On failure, first check:
        - The expected (lines, messages) in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown or a companion asset file was altered (both must stay byte-for-byte)
    """
    loaded = asset_case("ds113", case)
    findings = _ds113(assets.detect(loaded.root, loaded.documents()))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    expected_lines, expected_messages = FINDING_EXPECTATIONS[case]
    assert tuple(finding.line for finding in findings) == expected_lines
    assert tuple(finding.message for finding in findings) == expected_messages
    for finding in findings:
        assert finding.rule == "DS113"
        assert finding.severity == "error"
        assert finding.path == PRIMARY_DOCUMENT[case]


@pytest.mark.parametrize("case", DEFAULT_CASES)
def test_scan_matches_expectation_and_ownership_split(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies full-scan ownership split.

    Scenario:
        Given one default-setup ds113 scenario scanned under the full fast profile
        When DS101-DS117 run together
        Then DS113 ran (enabled_rules carries it, no rule pending), finding cases emit exactly the
        expected DS113 errors at the expected lines, and the only non-DS113 findings are the documented
        EXPECTED_SIBLINGS - a missing Markdown image is DS101 + DS113 (never a third DS116 report), an
        HTML image/srcset/href is DS113's alone, and the ``docs/`` code span is DS103's - proving the
        ownership split holds.

    Boundaries:
        - Focus: cross-rule ownership and the absence of triple reporting
        - Fixtures/params: parametrized over the 13 default-setup scenarios; asset_case

    On failure, first check:
        - Whether a new sibling finding appeared beyond the documented EXPECTED_SIBLINGS overlap
        - Whether DS113 dropped out of enabled_rules (a clean result must mean it ran)
    """
    loaded = asset_case("ds113", case)
    result = scan(loaded.root, config=Config(profile="fast"))

    assert result.enabled_rules == FAST_RULE_ORDER
    assert result.pending == ()
    assert _siblings(result.findings) == EXPECTED_SIBLINGS.get(case, ())

    own = _ds113(result.findings)
    if case in CLEAN_CASES:
        assert own == ()
    else:
        expected_lines, expected_messages = FINDING_EXPECTATIONS[case]
        assert tuple(finding.line for finding in own) == expected_lines
        assert tuple(finding.message for finding in own) == expected_messages
        assert all(finding.path == PRIMARY_DOCUMENT[case] for finding in own)


def test_missing_pdf_attachment_needs_the_asset_extensions_gate(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies the link-shaped extension gate.

    Scenario:
        Given the missing_pdf_attachment fixture (an HTML ``<a href="docs/manual.pdf">`` whose PDF is
            absent) with an explicit ``asset_extensions=["pdf"]`` config
        When assets.detect and the full scan run
        Then DS113 reports exactly one error at line 3 for the missing ``docs/manual.pdf`` - a
            link-shaped reference is checked only because its extension is in the gate - and no non-DS113
            rule fires, because DS101's matcher never sees an HTML ``href``.

    Boundaries:
        - Focus: R1/R5 - the ``asset_extensions`` gate admits a link-shaped HTML href reference
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether the extension gate stopped admitting a configured ``pdf`` href
        - Whether DS101 began matching HTML ``<a href>`` syntax
    """
    loaded = asset_case("ds113", PDF_CASE)
    config = Config(profile="fast", asset_extensions=("pdf",))

    findings = _ds113(assets.detect(loaded.root, loaded.documents(), config))
    assert [(finding.line, finding.message) for finding in findings] == [(3, f"{MISSING_PREFIX}docs/manual.pdf")]

    result = scan(loaded.root, config=config)
    assert _siblings(result.findings) == ()
    assert [(finding.line, finding.message) for finding in _ds113(result.findings)] == [
        (3, f"{MISSING_PREFIX}docs/manual.pdf")
    ]


def test_symlink_outside_is_ds116_only_and_never_statted(
    asset_case: Callable[[str, str], AssetCase],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors missing local media assets ds113: verifies the symlink-out containment.

    Scenario:
        Given the committed asset_symlink_outside README copied into a scan root, an in-root ``evil.png``
            symlink pointing at a sibling out-of-root target holding a real secret image, and a filesystem
            recorder wrapping every reachable stat/open entry point
        When a full fast scan runs under the recorder
        Then DS113 reports nothing for ``evil.png`` while DS116 owns the symlink-escape finding at line 6,
            and no recorded stat path reaches the out-of-root tree or the secret, and ``evil.png`` and the
            secret are never opened - DS113 defers the escape to DS116 without dereferencing it.

    Boundaries:
        - Focus: R2/R3 containment - a symlink-out asset is DS116's, never a DS113 missing finding, and is
          never stat-ed or opened
        - Fixtures/params: asset_case (committed owner), tmp_path, monkeypatch, the FS recorder

    On failure, first check:
        - Whether DS113 stopped calling escapes_via_symlink before its os.stat
        - Whether the walk began stat-ing or opening the out-of-root target instead of reading it lexically
    """
    owner_text = asset_case("ds113", SYMLINK_CASE).read_text("README.md")
    root = tmp_path / "scanroot"
    root.mkdir()
    (root / "README.md").write_text(owner_text, encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.png"
    secret.write_text("out-of-root secret bytes", encoding="utf-8")
    # The in-root symlink points at the out-of-root directory. A detector that dropped
    # the escapes_via_symlink guard and let os.stat follow the link would then classify
    # it as a (non-regular) directory and wrongly emit a DS113 finding, so the
    # zero-DS113 assertion below genuinely exercises the guard rather than relying on
    # the target happening to be a regular file.
    _symlink_or_skip(root / "evil.png", "../outside")

    canonical = Path(os.path.realpath(root))
    secret_real = os.path.normpath(os.path.realpath(secret))
    evil_real = os.path.normpath(str(canonical / "evil.png"))

    # Warm up lazy imports before recording so the window holds only scan I/O.
    scan(root, config=Config(profile="fast"))

    recorder = _FsRecorder()
    guard = GitMarkerGuard(str(canonical))
    with pytest.MonkeyPatch.context() as patch:
        _install_fs_recorder(patch, recorder)
        install_git_marker_guard(patch, guard)
        result = scan(root, config=Config(profile="fast"))

    assert _ds113(result.findings) == ()
    ds116 = {(finding.path, finding.line): finding for finding in result.findings if finding.rule == "DS116"}
    assert ("README.md", 6) in ds116
    assert "symlink that escapes the documentation root" in ds116[("README.md", 6)].message

    assert recorder.touched, "recorder captured no filesystem access; the scan did not run"
    root_str, outside_str = str(canonical), str(outside)
    for recorded in recorder.touched:
        assert recorded != secret_real, f"stat-ed the out-of-root secret: {recorded}"
        assert not _is_under(recorded, outside_str), f"stat-ed a path under the out-of-root tree: {recorded}"
        if is_git_marker_probe(recorded, root_str) or is_project_marker_probe(recorded, root_str):
            continue  # link_root: an lstat existence check of <ancestor>/.git or a project marker only
        assert _is_under(recorded, root_str) or _is_under(root_str, recorded), f"stat-ed outside the root: {recorded}"
    assert secret_real not in recorder.opened, "opened the out-of-root secret"
    assert evil_real not in recorder.opened, "opened the in-root symlink asset"
    assert not any(
        is_git_marker_probe(opened, root_str) or is_project_marker_probe(opened, root_str) for opened in recorder.opened
    ), "opened a link_root probe"
    assert guard.violations == [], f"went past an existence check of a .git path: {guard.violations}"


def test_in_root_symlink_to_regular_file_is_a_valid_asset(tmp_path: Path):
    """
    [Integration] detectors missing local media assets ds113: verifies an in-root symlink asset is valid.

    Scenario:
        Given an in-root ``link.png`` symlink whose target is an in-root regular ``real.png`` and a
            document whose image points at the symlink
        When assets.detect runs
        Then no DS113 finding is produced, because an in-root symlink resolving to an in-root regular file
            is a valid asset (ruling R3).

    Boundaries:
        - Focus: R3 - a contained symlink to a regular file is not a missing/non-regular finding
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether escapes_via_symlink wrongly flagged a fully in-root symlink
        - Whether the final os.stat stopped following the in-root symlink to its regular target
    """
    (tmp_path / "real.png").write_text("image bytes", encoding="utf-8")
    _symlink_or_skip(tmp_path / "link.png", "real.png")
    (tmp_path / "README.md").write_text("# Home\n\n![logo](link.png)\n", encoding="utf-8")

    findings = _ds113(assets.detect(tmp_path, (models.Document("README.md", 0),)))

    assert findings == ()


def test_missing_asset_policy_off_performs_no_stat(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors missing local media assets ds113: verifies ``off`` short-circuits with no I/O.

    Scenario:
        Given the missing_markdown_image fixture and a filesystem recorder
        When assets.detect runs with ``missing_asset_policy="off"``
        Then no finding is produced and the detector performs no filesystem access at all - neither the
            document is opened nor the ``diagrams/flow.svg`` candidate stat-ed - proving the ``off`` branch
            short-circuits before any I/O. A direct check_text call under ``off`` confirms the inner guard
            also returns before the resolved candidate is stat-ed.

    Boundaries:
        - Focus: the ``off`` policy performs zero filesystem work (threat model verdict item 1)
        - Fixtures/params: asset_case, monkeypatch, the FS recorder

    On failure, first check:
        - Whether either ``missing_asset_policy == "off"`` guard (detect and check_text) still returns early
        - Whether the recorder observed any open or os.stat under ``off``
    """
    loaded = asset_case("ds113", "missing_markdown_image")
    candidate = os.path.normpath(str(loaded.root / "diagrams" / "flow.svg"))
    text = loaded.read_text("README.md")
    # Build the document tuple (which stats each file) before the recorder is installed
    # so the recorded window holds only the detector's own filesystem calls.
    documents = loaded.documents()

    recorder = _FsRecorder()
    _install_fs_recorder(monkeypatch, recorder)
    findings = assets.detect(loaded.root, documents, Config(missing_asset_policy="off"))
    # check_text is handed the text directly, so any stat under off is the inner guard failing.
    inline = assets.check_text(text, "README.md", loaded.root, Config(missing_asset_policy="off"))

    assert findings == ()
    assert inline == ()
    assert recorder.touched == set(), f"off policy performed stat-like I/O: {recorder.touched}"
    assert recorder.opened == set(), f"off policy opened a file: {recorder.opened}"
    assert candidate not in recorder.touched


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
@pytest.mark.parametrize(("policy", "expected_severity"), [("off", None), ("warn", "warning"), ("error", "error")])
def test_missing_asset_policy_propagates_from_both_config_files(
    config_file: str,
    policy: str,
    expected_severity: Optional[str],
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors missing local media assets ds113: verifies missing_asset_policy propagation.

    Scenario:
        Given the missing_html_image fixture carrying a standalone docsentinel.toml or a
            [tool.doc_sentinel] table that sets missing_asset_policy to off, warn or error
        When scan discovers that config (no injected Config)
        Then ``off`` silences DS113 entirely, ``warn`` keeps the finding but downgrades its severity to
            warning (while the rule metadata stays error), and ``error`` emits the blocking error at line 5.

    Boundaries:
        - Focus: config discovery and the detector's severity/suppression branch for each policy value
        - Fixtures/params: parametrized over the two config-file forms and the three policy values; asset_case

    On failure, first check:
        - The missing_asset_policy short-circuit and severity selection in check_text
        - Whether load_config reads missing_asset_policy from the given file form
    """
    case = asset_case("ds113", "missing_html_image")
    if config_file == "docsentinel.toml":
        body = f'profile = "fast"\nmissing_asset_policy = "{policy}"\n'
    else:
        body = f'[tool.doc_sentinel]\nprofile = "fast"\nmissing_asset_policy = "{policy}"\n'
    (case.root / config_file).write_text(body, encoding="utf-8")

    findings = _ds113(scan(case.root).findings)

    if expected_severity is None:
        assert findings == ()
    else:
        assert len(findings) == 1
        assert findings[0].severity == expected_severity
        assert findings[0].line == 5


@pytest.mark.parametrize(
    ("case", "toggle"),
    [
        ("missing_markdown_image", "check_markdown_images"),
        ("missing_html_image", "check_html_asset_tags"),
        ("missing_srcset_candidate", "check_srcset"),
        ("missing_srcset_candidate", "check_html_asset_tags"),
    ],
)
def test_check_toggle_suppresses_its_reference_kind(
    case: str,
    toggle: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors missing local media assets ds113: verifies each check toggle gates its kind.

    Scenario:
        Given a finding fixture whose only defect is a Markdown image, an HTML image, or a ``srcset``
            candidate, scanned once with its governing check toggle left on (default, firing) and once with
            it turned off
        When assets.detect runs each time
        Then the toggle-on run reports the DS113 finding and the toggle-off run reports nothing - and
            because a ``srcset`` candidate needs both ``check_srcset`` and ``check_html_asset_tags``,
            disabling either silences it.

    Boundaries:
        - Focus: the independent ``check_markdown_images``/``check_html_asset_tags``/``check_srcset`` gates
        - Fixtures/params: parametrized over the three toggles plus the srcset/html interaction; asset_case

    On failure, first check:
        - The toggle branch in _collect_candidates for this reference kind
        - Whether a ``srcset`` candidate stopped requiring both srcset and html toggles
    """
    loaded = asset_case("ds113", case)

    on = _ds113(assets.detect(loaded.root, loaded.documents(), Config()))
    assert len(on) == 1

    off = _ds113(assets.detect(loaded.root, loaded.documents(), Config(**{toggle: False})))
    assert off == ()


def test_fifo_asset_is_reported_without_opening_or_blocking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors missing local media assets ds113: verifies a FIFO asset never blocks or opens.

    Scenario:
        Given a committed-at-runtime FIFO at an in-root asset path referenced by a Markdown image, and a
            filesystem recorder
        When assets.detect runs inside a worker thread guarded by a hard join timeout
        Then the detector completes promptly (the thread is not alive after the join), reports the FIFO as
            "asset is not a regular file" at the image's line, and never opens the FIFO path - so a crafted
            special file can neither wedge the scan nor trigger an unbounded read (threat model HIGH).

    Boundaries:
        - Focus: the no-open special-files control (os.stat + S_ISREG only, never open)
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder; skipped where mkfifo is unavailable

    On failure, first check:
        - Whether _classify_path started opening the asset instead of os.stat + stat.S_ISREG
        - Whether the regular-file check followed a content sniff that blocks on a FIFO
    """
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo unavailable on this platform")
    fifo = tmp_path / "pipe.png"
    try:
        os.mkfifo(fifo)
    except OSError as error:
        pytest.skip(f"mkfifo failed: {error}")
    (tmp_path / "README.md").write_text("# Home\n\n![pipe](pipe.png)\n", encoding="utf-8")
    fifo_real = os.path.normpath(str(fifo))

    recorder = _FsRecorder()
    _install_fs_recorder(monkeypatch, recorder)

    box: dict[str, tuple[models.Finding, ...]] = {}

    def _run():
        """Run DS113 over the FIFO document, storing the findings for the main thread."""
        box["findings"] = assets.detect(tmp_path, (models.Document("README.md", 0),))

    # A daemon worker so a regression that opens (and blocks on) the FIFO fails this
    # assertion after the join timeout instead of wedging interpreter shutdown.
    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout=15)

    assert not worker.is_alive(), "detect blocked on the FIFO asset; the regular-file check opened it"
    findings = _ds113(box["findings"])
    assert [(finding.line, finding.message) for finding in findings] == [(3, f"{NOT_REGULAR_PREFIX}pipe.png")]
    assert fifo_real not in recorder.opened, "opened the FIFO asset path"


def test_directory_asset_is_reported_as_non_regular(tmp_path: Path):
    """
    [Integration] detectors missing local media assets ds113: verifies a directory asset is a finding.

    Scenario:
        Given an in-root directory at an asset path referenced by a Markdown image
        When assets.detect runs
        Then DS113 reports it as "asset is not a regular file" rather than silently passing, so a
            directory cannot masquerade as a present asset (ruling R3).

    Boundaries:
        - Focus: an existing non-regular in-root path is a finding, not a silent clean
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether _classify_path returned None (clean) for a directory instead of _NOT_REGULAR
        - Whether the stat result's S_ISREG branch was inverted
    """
    (tmp_path / "gallery").mkdir()
    (tmp_path / "README.md").write_text("# Home\n\n![gallery](gallery)\n", encoding="utf-8")

    findings = _ds113(assets.detect(tmp_path, (models.Document("README.md", 0),)))

    assert [(finding.line, finding.message) for finding in findings] == [(3, f"{NOT_REGULAR_PREFIX}gallery")]


def test_data_uri_srcset_never_stats_the_base64_fragment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors missing local media assets ds113: verifies the srcset/data-URI split is safe.

    Scenario:
        Given an HTML ``srcset`` whose first candidate is an inline ``data:image/png;base64,<payload>`` URI
            and whose second candidate is an existing in-root ``real.png``, plus a filesystem recorder
        When assets.detect runs
        Then DS113 reports nothing and never stat-s the base64 fragment, because the shared ``_srcset_urls``
            keeps the whole ``data:`` URI a single external candidate rather than splitting on its internal
            comma into a spurious in-root probe (the HIGH srcset/data-URI finding of the threat model).

    Boundaries:
        - Focus: the srcset/data-URI split fix - a data URI candidate never becomes a RESOLVED probe
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder

    On failure, first check:
        - Whether _srcset_urls reverted to a naive comma split
        - Whether the recorder observed a stat of a path containing the base64 fragment
    """
    (tmp_path / "real.png").write_text("image bytes", encoding="utf-8")
    body = '# Home\n\n<img srcset="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg== 1x, real.png 2x" alt="r">\n'
    (tmp_path / "README.md").write_text(body, encoding="utf-8")

    recorder = _FsRecorder()
    _install_fs_recorder(monkeypatch, recorder)
    findings = _ds113(assets.detect(tmp_path, (models.Document("README.md", 0),)))

    assert findings == ()
    assert not any("iVBORw0KGgo" in recorded for recorded in recorder.touched | recorder.opened)


def test_case_insensitive_extension_matching_admits_uppercase(tmp_path: Path):
    """
    [Integration] detectors missing local media assets ds113: verifies the extension gate is case-insensitive.

    Scenario:
        Given an HTML ``<a href="manual.PDF">`` whose uppercase-extension PDF is absent, scanned with
            ``asset_extensions=["pdf"]``
        When assets.detect runs
        Then DS113 still reports the missing asset, because the extension gate lower-cases the suffix before
            matching, so the scope decision adds no second case trap (threat model requirement 8).

    Boundaries:
        - Focus: case-insensitive matching of the ``asset_extensions`` scope gate (not filesystem case)
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether _has_asset_extension stopped lower-casing the suffix
        - Whether the href reference stopped being extension-gated
    """
    (tmp_path / "README.md").write_text('# Home\n\n<a href="manual.PDF">manual</a>\n', encoding="utf-8")

    findings = _ds113(assets.detect(tmp_path, (models.Document("README.md", 0),), Config(asset_extensions=("pdf",))))

    assert [(finding.line, finding.message) for finding in findings] == [(3, f"{MISSING_PREFIX}manual.PDF")]


def test_select_narrows_to_ds113_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies select activates only DS113.

    Scenario:
        Given the missing_html_image scenario (a DS113-only defect) scanned with select pinned to DS113
        When the engine resolves the active rule set
        Then only DS113 is enabled and its single expected error finding at line 5 is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS113 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds113", "missing_html_image")

    result = scan(case.root, config=Config(profile="fast", select=("DS113",)))

    assert result.enabled_rules == ("DS113",)
    assert [(finding.rule, finding.line) for finding in result.findings] == [("DS113", 5)]


def test_prefix_select_and_ignore_semantics_for_ds113(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies DS11/DS1/DS2 select and ignore.

    Scenario:
        Given the missing_html_image scenario (a DS113-only defect) scanned under the fast profile
        When it is selected by the genuine ``DS11`` prefix (today DS110/DS113/DS116/DS117), the whole-set
            ``DS1`` prefix and the non-matching ``DS2`` prefix, and then ignored by the exact code, by
            ``DS11`` and by ``DS2``
        Then ``DS11`` and ``DS1`` keep DS113 active and still reporting line 5, ``DS2`` activates no fast
            rule, the exact and ``DS11`` ignores drop DS113 and its finding, and ``DS2`` leaves it active -
            all expectations derived from FAST_RULE_ORDER, not hard-coded.

    Boundaries:
        - Focus: prefix select and ignore precedence for DS113 against the live fast rule set
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast rule codes
        - Whether a new DS11x rule shifted DS11_PREFIXED out of sync
    """
    case = asset_case("ds113", "missing_html_image")

    ds11x = scan(case.root, config=Config(profile="fast", select=("DS11",)))
    assert ds11x.enabled_rules == DS11_PREFIXED
    assert [finding.line for finding in _ds113(ds11x.findings)] == [5]

    whole_fast = scan(case.root, config=Config(profile="fast", select=("DS1",)))
    assert whole_fast.enabled_rules == FAST_RULE_ORDER
    assert [finding.line for finding in _ds113(whole_fast.findings)] == [5]

    none = scan(case.root, config=Config(profile="fast", select=("DS2",)))
    assert none.enabled_rules == ()
    assert _ds113(none.findings) == ()

    exact = scan(case.root, config=Config(profile="fast", ignore=("DS113",)))
    assert "DS113" not in exact.enabled_rules
    assert _ds113(exact.findings) == ()

    by_prefix = scan(case.root, config=Config(profile="fast", ignore=("DS11",)))
    assert by_prefix.enabled_rules == tuple(code for code in FAST_RULE_ORDER if not code.startswith("DS11"))
    assert _ds113(by_prefix.findings) == ()

    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",)))
    assert "DS113" in unaffected.enabled_rules
    assert [finding.line for finding in _ds113(unaffected.findings)] == [5]


def test_baseline_suppresses_known_ds113_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies baseline suppression round-trips.

    Scenario:
        Given the multiple_missing_images scenario whose two DS113 findings are recorded into a baseline
        When the same tree is rescanned with that baseline configured
        Then both previously known DS113 findings are filtered out while the first scan still reported them,
            so the fingerprints are stable across the two scans.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS113 error findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS113 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds113", "multiple_missing_images")
    first = scan(case.root, config=Config(profile="fast", select=("DS113",)))
    assert len(_ds113(first.findings)) == 2

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS113",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds113(suppressed.findings) == ()


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies repeated scans are stable.

    Scenario:
        Given the multiple_missing_images scenario scanned twice over the same materialized root
        When the two DS113 finding tuples are compared
        Then they are equal and report lines 5 and 7, so the detector holds no order-dependent state and
            the per-document existence memo does not leak between runs.

    Boundaries:
        - Focus: determinism of DS113 over a real asset tree, with asserted line counts
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the scanner or detector
        - Whether the per-document existence memo leaked across documents or runs
    """
    case = asset_case("ds113", "multiple_missing_images")
    first = _ds113(scan(case.root, config=Config(profile="fast", select=("DS113",))).findings)
    second = _ds113(scan(case.root, config=Config(profile="fast", select=("DS113",))).findings)
    assert first == second
    assert [finding.line for finding in first] == [5, 7]


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies text/json/github report stability.

    Scenario:
        Given a DS113 finding scan result
        When it is rendered as text, json and github output
        Then each format carries the DS113 error deterministically (schema v1 json, an ``::error``
            annotation with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS113 error across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path, line and message
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds113", "missing_html_image")
    result = scan(case.root, config=Config(profile="fast", select=("DS113",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert "error: README.md:5: missing asset: media/missing.png" in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS113"]
    assert payload["findings"][0]["rule"] == "DS113"
    assert payload["findings"][0]["severity"] == "error"
    assert payload["findings"][0]["line"] == 5

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::error file=README.md,line=5,title=DS113::")


def test_hostile_targets_are_bounded_and_repr_escaped(tmp_path: Path):
    """
    [Integration] detectors missing local media assets ds113: verifies hostile targets cannot inject output.

    Scenario:
        Given in-root (so DS113-owned) image targets - a 10,000-character name, a right-to-left override
            and a fullwidth-dot confusable - each genuinely missing
        When the scan result is rendered as text
        Then every message is bounded to the detector's echo limit, repr-escapes the non-ASCII bytes,
            carries only the author's raw target (never a resolved absolute path), and the text output holds
            no raw control byte; control-byte, newline and scheme-like targets are intentionally deferred to
            DS116 or classified external, so DS113 never echoes them in the first place.

    Boundaries:
        - Focus: output-injection and information-disclosure safety of DS113 messages (threat model MEDIUM)
        - Fixtures/params: tmp_path

    On failure, first check:
        - _echo's unicode_escape bound and whether a message leaked a resolved absolute path
        - Whether DS113 began echoing a deferred control/escape target
    """
    hostile_targets = ("a" * 10_000 + ".png", "a\u202eb.png", "\uff0e\uff0e_c.png")
    body = "# Home\n\n" + "".join(f"![t{index}]({target})\n\n" for index, target in enumerate(hostile_targets))
    (tmp_path / "README.md").write_text(body, encoding="utf-8")

    result = scan(tmp_path, config=Config(profile="fast", select=("DS113",)))
    own = _ds113(result.findings)
    assert len(own) == len(hostile_targets)

    max_message = len(NOT_REGULAR_PREFIX) + assets._MAX_ECHO + len("...")
    for finding in own:
        assert "\x1b" not in finding.message and "\x00" not in finding.message
        assert "\n" not in finding.message and "\r" not in finding.message
        assert "\u202e" not in finding.message and "\uff0e" not in finding.message
        assert len(finding.message) <= max_message
        assert not os.path.isabs(finding.message.partition(": ")[2])  # never a resolved absolute path

    text = render(result, "text")
    assert "\u202e" not in text
    assert "\\u202e" in text  # repr-escaped, not raw
    assert str(tmp_path) not in text  # the resolved root never leaks


def test_cli_fast_json_scan_reports_ds113_and_exits_one_without_strict(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors missing local media assets ds113: verifies an error finding blocks without strict.

    Scenario:
        Given the missing_html_image scenario (a DS113-only defect) scanned via the CLI with
            --profile fast --format json and no --strict
        When the command runs
        Then it prints a JSON report containing the DS113 error at line 5 and exits 1, because an
            error-severity finding is blocking even without --strict; a second run with --strict also exits 1.

    Boundaries:
        - Focus: the CLI exit-code mapping for an error-severity rule, strict and non-strict
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for error-severity findings
        - Whether DS113 still produced its finding through the CLI path
    """
    case = asset_case("ds113", "missing_html_image")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds113 = [finding for finding in payload["findings"] if finding["rule"] == "DS113"]
    assert len(ds113) == 1
    assert ds113[0]["severity"] == "error"
    assert ds113[0]["line"] == 5
    assert exit_code == 1

    strict_code = cli.main(["scan", str(case.root), "--profile", "fast", "--strict"])
    capsys.readouterr()
    assert strict_code == 1


def test_cli_warn_policy_exits_zero_without_strict_and_one_with_strict(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors missing local media assets ds113: verifies the warn-policy exit codes.

    Scenario:
        Given the missing_html_image scenario with a docsentinel.toml setting missing_asset_policy="warn"
        When it is scanned via the CLI under the fast profile without and then with --strict
        Then the downgraded warning is non-blocking (exit 0) by default and becomes blocking (exit 1) under
            --strict, so the policy knob gives operators an advisory mode without losing the rule.

    Boundaries:
        - Focus: the warn-policy severity downgrade mapped through the CLI exit codes
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether the warn policy still downgrades the DS113 severity to warning
        - The CLI exit-code mapping for a warning-only result, strict and non-strict
    """
    case = asset_case("ds113", "missing_html_image")
    (case.root / "docsentinel.toml").write_text('profile = "fast"\nmissing_asset_policy = "warn"\n', encoding="utf-8")

    exit_code = cli.main(["scan", str(case.root), "--format", "json-v1"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds113 = [finding for finding in payload["findings"] if finding["rule"] == "DS113"]
    assert len(ds113) == 1
    assert ds113[0]["severity"] == "warning"
    assert exit_code == 0

    strict_code = cli.main(["scan", str(case.root), "--strict"])
    capsys.readouterr()
    assert strict_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors missing local media assets ds113: verifies a clean case exits zero.

    Scenario:
        Given a clean scenario with an existing asset scanned via the CLI under the fast profile
        When the command runs
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: the non-blocking exit code when DS113 and its siblings find nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS113 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds113", "relative_image_exists")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds113_without_an_opt_in_marker(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors missing local media assets ds113: verifies `docsentinel rules` surfaces DS113.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS113 and its title appear with no ``[opt-in: ...]`` marker, unlike DS110, because DS113 is an
            ordinary always-active rule.

    Boundaries:
        - Focus: rules-command surfacing of DS113 as a non-opt-in rule
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS113
        - Whether DS113 grew an opt_in_option that added a marker
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    ds113_lines = [line for line in captured.out.splitlines() if "DS113:" in line]
    assert ds113_lines == ["  DS113: Missing local media and document assets"]
    assert "opt-in" not in ds113_lines[0]


def test_cli_doctor_counts_ds113_as_an_ordinary_fast_rule(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors missing local media assets ds113: verifies `docsentinel doctor` counts DS113.

    Scenario:
        Given the installed rule registry
        When the doctor command reports environment readiness
        Then the fast-rule tally reads exactly
            "16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)",
            so DS113 is inside the registered count and is not one of the opt-in rules.

    Boundaries:
        - Focus: doctor's separate accounting of opt-in versus always-active fast rules
        - Fixtures/params: capsys

    On failure, first check:
        - Whether the registered fast-rule count changed when a rule was added
        - Whether DS113 was miscounted as opt-in
    """
    exit_code = cli.main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS113" in {rule.code for rule in rules_for_profile("fast")}
    assert "fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)" in captured.out


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("missing_asset_policy", '"sometimes"'),
        ("check_html_asset_tags", '"nope"'),
        ("check_markdown_images", '"nope"'),
        ("check_srcset", '"nope"'),
    ],
)
def test_invalid_ds113_option_raises_config_error(option: str, value: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors missing local media assets ds113: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml that sets one DS113 option to an invalid value (an out-of-vocabulary enum
            string or a non-boolean)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it.

    Boundaries:
        - Focus: the config allowlist rejects invalid enum/bool values for every DS113 option
        - Fixtures/params: parametrized over the four options; asset_case

    On failure, first check:
        - The enum/bool validation for the named option in config.py
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds113", "missing_html_image")
    (case.root / "docsentinel.toml").write_text(f'profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(case.root)


def test_crlf_line_numbers_point_at_the_offending_reference(tmp_path: Path):
    """
    [Integration] detectors missing local media assets ds113: verifies CRLF line fidelity.

    Scenario:
        Given a CRLF-terminated document whose missing image sits on line 5
        When assets.detect runs over it
        Then the single finding reports line 5, proving carriage returns do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF input for the offending reference
        - Fixtures/params: tmp_path

    On failure, first check:
        - CRLF handling in the shared scanner's line splitting
        - That the reported line is the image's line, not its body
    """
    (tmp_path / "README.md").write_bytes(b"# Title\r\n\r\nIntro prose.\r\n\r\n![x](missing.png)\r\n")

    findings = _ds113(assets.detect(tmp_path, (models.Document("README.md", 1),)))

    assert len(findings) == 1
    assert findings[0].line == 5
    assert findings[0].message == f"{MISSING_PREFIX}missing.png"


def test_invalid_utf8_scan_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors missing local media assets ds113: verifies invalid UTF-8 is not a silent clean.

    Scenario:
        Given a Markdown document holding invalid UTF-8 bytes beneath a missing image
        When a fast scan reads it with DS113 selected
        Then a decode error propagates instead of a misleading zero-finding result.

    Boundaries:
        - Focus: unreadable input raises rather than masquerading as clean (contract B.4)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The UTF-8 read in assets._read_text
        - That the engine does not swallow the decode error into a clean scan
    """
    (tmp_path / "README.md").write_bytes(b"# Title\n\n![x](missing.png)\n\xff\xfe\n")

    with pytest.raises(UnicodeDecodeError):
        scan(tmp_path, config=Config(profile="fast", select=("DS113",)))


def test_unreadable_file_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors missing local media assets ds113: verifies an unreadable file is not a silent clean.

    Scenario:
        Given a Markdown document whose read permission is removed
        When a fast scan tries to read it with DS113 selected
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
    target.write_text("# Title\n\n![x](missing.png)\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            scan(tmp_path, config=Config(profile="fast", select=("DS113",)))
    finally:
        target.chmod(0o644)


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors missing local media assets ds113: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When assets.detect runs over every default-setup finding scenario
        Then all expected findings are still produced, proving DS113 opens no socket, makes no connection
            and never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS113 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object):
        """Fail the test if DS113 ever constructs a socket."""
        raise AssertionError("DS113 must not create a socket")

    def _no_connect(*args: object, **kwargs: object):
        """Fail the test if DS113 ever opens an outbound connection."""
        raise AssertionError("DS113 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object):
        """Fail the test if DS113 ever launches a subprocess."""
        raise AssertionError("DS113 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case, (lines, _messages) in FINDING_EXPECTATIONS.items():
        loaded = asset_case("ds113", case)
        findings = _ds113(assets.detect(loaded.root, loaded.documents("README.md")))
        assert tuple(finding.line for finding in findings) == lines


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors missing local media assets ds113: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS113 detector and runs it
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported, proving the
            fast DS113 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS113's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether assets or markdown_blocks gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from pathlib import Path\n"
        "from docsentinel.detectors import assets\n"
        "assert assets.check_text('![x](missing.png)\\n', 'README.md', Path('/scanroot'))\n"
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


def test_hostile_corpus_touches_no_outside_path_and_opens_no_asset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors missing local media assets ds113: verifies the no-outside-root I/O invariant.

    Scenario:
        Given a hostile corpus in one document - a ``../`` root escape, a Windows drive path, a UNC path, a
            control-byte target, an in-root ``evil.png`` symlink pointing at a sibling out-of-root secret, a
            ``data:`` URI ``srcset`` candidate beside an existing ``real.png``, and a single genuinely
            missing in-root ``missing.png`` - run under a filesystem recorder
        When assets.detect scans it
        Then DS113 emits exactly one finding (the missing in-root image); no recorded stat path leaves the
            canonical root (the only outside-root object, the secret, is never stat-ed or opened because the
            in-root symlink is read lexically); the base64 fragment is never probed; and the only opened path
            is the Markdown document - no asset path is ever opened.

    Boundaries:
        - Focus: the HIGH containment invariant (zero outside-root stat, no asset open) across the escape,
          special-category, symlink-out and data-URI vectors at once
        - Fixtures/params: tmp_path, monkeypatch, the FS recorder; skipped where symlinks are unavailable

    On failure, first check:
        - Whether a DS116-owned or symlink-out target was resolved/stat-ed instead of deferred
        - Whether any asset path (not the Markdown document) was opened
    """
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.png"
    secret.write_text("out-of-root secret", encoding="utf-8")
    (root / "real.png").write_text("image bytes", encoding="utf-8")
    # Point the in-root symlink at the out-of-root directory so a dropped
    # escapes_via_symlink guard would make os.stat follow it to a directory and emit a
    # spurious DS113 finding, which the exact finding-count assertion below catches.
    _symlink_or_skip(root / "evil.png", "../outside")

    body = (
        "# Home\n\n"
        "![escape](../../etc/passwd.png)\n\n"
        "![drive](C:\\\\drive.png)\n\n"
        "![unc](\\\\\\\\server\\\\share.png)\n\n"
        "![control](a\x1bb.png)\n\n"
        "![symlink](evil.png)\n\n"
        "![missing](missing.png)\n\n"
        '<img srcset="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg== 1x, real.png 2x" alt="r">\n'
    )
    (root / "README.md").write_text(body, encoding="utf-8")

    canonical = Path(os.path.realpath(root))
    secret_real = os.path.normpath(os.path.realpath(secret))
    readme_real = os.path.normpath(str(canonical / "README.md"))

    # Warm up before recording so only the detector's own filesystem calls are seen.
    assets.detect(root, (models.Document("README.md", 0),))

    recorder = _FsRecorder()
    with pytest.MonkeyPatch.context() as patch:
        _install_fs_recorder(patch, recorder)
        findings = _ds113(assets.detect(root, (models.Document("README.md", 0),)))

    assert [(finding.line, finding.message) for finding in findings] == [(13, f"{MISSING_PREFIX}missing.png")]

    assert recorder.touched, "recorder captured no filesystem access; the detector did not run"
    root_str, outside_str = str(canonical), str(outside)
    for recorded in recorder.touched:
        assert recorded != secret_real, f"stat-ed the out-of-root secret: {recorded}"
        assert not _is_under(recorded, outside_str), f"stat-ed a path under the out-of-root tree: {recorded}"
        assert _is_under(recorded, root_str) or _is_under(root_str, recorded), f"stat-ed outside the root: {recorded}"
        assert "iVBORw0KGgo" not in recorded, "probed the data-URI base64 fragment"
    assert recorder.opened <= {readme_real}, f"opened a non-document path: {recorder.opened - {readme_real}}"


def _single_line_image_flood(scale: int) -> str:
    """Return one non-fenced line of ``scale`` distinct missing Markdown images.

    Each ``![t{i}](m{i}.png)`` targets a non-repeating missing file, so every unit yields exactly one
    finding and the ``(line, message)`` dedup never collapses the count.

    :param scale: Number of distinct missing images to pack onto the single line.
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + " ".join(f"![t{index}](m{index}.png)" for index in range(scale)) + "\n"


def _multi_line_image_flood(scale: int) -> str:
    """Return ``scale`` lines, each one distinct missing Markdown image.

    :param scale: Number of lines (one missing image each).
    :returns: The Markdown source text.
    """
    return "# Flood\n\n" + "".join(f"![t{index}](m{index}.png)\n" for index in range(scale))


def _srcset_candidate_flood(scale: int) -> str:
    """Return a single ``<img srcset>`` with ``scale`` distinct missing candidates.

    Each candidate is a distinct missing ``r{i}.png`` with its own width descriptor, so a long ``srcset``
    produces exactly one finding per candidate and the dedup never collapses the count.

    :param scale: Number of distinct missing candidates in the one ``srcset``.
    :returns: The Markdown source text.
    """
    candidates = ", ".join(f"r{index}.png {index + 1}w" for index in range(scale))
    return f'# Flood\n\n<img srcset="{candidates}" alt="flood">\n'


#: Representative adversarial flood shapes mapped to a builder and an exact
#: finding-count formula. Each is deliberately non-fenced prose with strictly
#: non-repeating targets so no unit is masked and no dedup collapse hides a count.
#: This suite proves only that detect() routes real files through check_text with
#: exact counts and no super-linear blow-up over the file path.
FLOOD_SHAPES: dict[str, Callable[[int], str]] = {
    "single_line_image_flood": _single_line_image_flood,
    "multi_line_image_flood": _multi_line_image_flood,
    "srcset_candidate_flood": _srcset_candidate_flood,
}


@pytest.mark.parametrize("shape", sorted(FLOOD_SHAPES))
def test_adversarial_floods_stay_linear(shape: str, tmp_path: Path):
    """
    [Integration] detectors missing local media assets ds113: verifies linear-time adversarial handling.

    Scenario:
        Given large, non-fenced Markdown of one representative shape - one giant line of distinct missing
            images, many single-image lines, or one ``srcset`` with many distinct missing candidates
        When assets.detect routes a doubling input series through the shared scaling helper
        Then every scale produces the exact deterministic finding count (so the pass is never vacuous) and
            the scaling stays under the shared linear bound, proving the per-reference stat is memoised and
            the shared scanner never rescans a line tail per bracket.

    Boundaries:
        - Focus: detect() routing of real files through check_text with bounded time (threat model MEDIUM DoS)
        - Non-goal: the exhaustive algorithmic shapes, which live in the shared-scanner unit tests
        - Fixtures/params: parametrized over the representative flood shapes; tmp_path

    On failure, first check:
        - Any accidentally quadratic rescan or a stat that is no longer memoised per distinct path
        - That the exact finding count for this shape still holds at every scale
    """
    build = FLOOD_SHAPES[shape]

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
        lambda documents: assets.detect(tmp_path, documents, Config()),
        (500, 1_000, 2_000, 4_000),
        expected_count=lambda scale: scale,
        label=f"ds113-{shape}",
    )
