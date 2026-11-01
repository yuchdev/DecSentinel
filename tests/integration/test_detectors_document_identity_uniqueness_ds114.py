"""Integration tests for DS114 over committed Markdown assets in ``tests/assets/ds114``.

This is Story 12.0 Task 03, the always-active duplicate-stable-document-identifier
rule. Every one of the 14 committed scenarios is loaded in isolation through the
``asset_case`` fixture and asserted against an explicit, checked-in expectation table
(:data:`SETUP`, :data:`CLEAN_CASES`, :data:`FINDING_EXPECTATIONS`, :data:`ERROR_CASE`
and :data:`ERROR_EXPECTATION`) transcribed from the Task 02 manifest, the
``fixture-matrix`` DS114 rows and the detector's stable message contract, never
derived from whatever the analyzer currently emits. The 12 ``default``-setup
scenarios are also executed by the generic Milestone 0005 catalog; the two
non-default scenarios (``casefold_ids_optin`` with ``document_id_case_sensitive=false``
and ``missing_ids_required`` with ``document_id_required=true``) carry their exact
config here. For every CLEAN/FINDING scenario the outcome is asserted through both the
pure ``document_ids.detect`` entry point and the shared ``scan`` engine: zero findings
for the seven CLEAN cases and the exact one-based line, offending path and message for
the six FINDING cases.

The lone ERROR row ``invalid_nested_metadata`` is special by ruling: an unsupported id
value shape is reported as exactly **one** explicit own ``error`` finding that names the
field only (never the raw value) and excludes the document from uniqueness, rather than
aborting the scan with a ``ConfigError`` (exit 2) -- the catalog's
``FINDING_SATISFIES_ERROR`` allowlist encodes this and this suite pins its line, path,
severity and message and asserts the document never participates in a collision.
Malformed/unterminated/over-long frontmatter and duplicate id keys stay silent (DS111
territory), proven by the ``duplicate_key_one_document`` CLEAN case.

DS114 is a ``fast``-profile always-active rule at ``error`` severity with no opt-in
marker, so a single collision makes the CLI exit 1 even without ``--strict``. The file
also exercises the four typed options (``document_id_field``, ``document_id_scope``,
``document_id_case_sensitive``, ``document_id_required``) through both
``docsentinel.toml`` and ``[tool.doc_sentinel]`` including invalid values; the
config-injection trust boundary (an injected invalid ``document_id_scope`` fails closed
with a ``ConfigError`` rather than degrading to ``corpus``); ``select``/``ignore``
(exact and the ``DS11``/``DS1``/``DS2`` prefixes); baseline round-trips;
determinism across repeated scans and independence from document discovery order;
text/json/github report stability and hostile-id output safety (ESC, newline,
``::error``, RTL, NUL and a 10,000-character id are bounded and ``repr``-escaped with no
absolute path leaked); CRLF and BOM line fidelity; an invalid-UTF-8 head contributing no
identity without crashing; an unreadable document surfacing rather than a false clean; a
symlinked Markdown file never inventoried; the bounded head read over a document far
larger than the head bound; the DS104-vs-DS114 namespace split (a body ``id=`` HTML
anchor or a heading is never a document identity); the fast stdlib-only import with no
network or content execution; the CLI exit paths and ``docsentinel rules``/``doctor``
surfacing; and the linear-time requirement on adversarial document and frontmatter floods
routed through ``detect`` end to end. The exhaustive algorithmic shape coverage lives in
``tests/unit/test_detectors_document_ids.py`` and the syscall-level containment proofs in
``tests/mock/test_detectors_document_ids_oracle.py``; this suite proves the committed
scenarios and the cross-module behaviour.
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
from docsentinel.detectors import document_ids
from docsentinel.engine import scan
from docsentinel.reporting import render
from docsentinel.rules import rules_for_profile
from tests.asset_helpers import AssetCase
from tests.mock.test_detectors_document_ids_oracle import _install_recorder, _is_under, _Recorder
from tests.mock.test_path_boundaries_oracle import _symlink_or_skip
from tests.timing_helpers import assert_scales_linearly

#: The exact ``Config`` override each committed scenario requires, transcribed from the
#: ``setup`` column of ``fixture-matrix`` (Task 02). Only the two non-default scenarios
#: carry an override; every other scenario scans under the shipped defaults. These values
#: drive this suite's assertions and are never derived from the analyzer.
SETUP: dict[str, dict[str, object]] = {
    "distinct_frontmatter_ids": {},
    "missing_optional_ids": {},
    "same_h1_distinct_ids": {},
    "case_distinct_ids_default": {},
    "frontmatter_like_prose": {},
    "id_in_code_fence": {},
    "duplicate_key_one_document": {},
    "identical_ids_two_docs": {},
    "unicode_normalized_ids": {},
    "whitespace_normalized_ids": {},
    "three_duplicate_document_ids": {},
    "casefold_ids_optin": {"document_id_case_sensitive": False},
    "missing_ids_required": {"document_id_required": True},
    "invalid_nested_metadata": {},
}

#: The seven committed CLEAN scenarios: distinct ids, two missing-but-optional ids, a
#: shared H1 with distinct ids, case-distinct ids under the default case-sensitive policy,
#: an ``id:`` line in body prose, an ``id:`` line inside a code fence, and a duplicate id
#: key within one block (DS111 territory). Each must leave DS114 registered and executed
#: yet report zero DS114 findings.
CLEAN_CASES: tuple[str, ...] = (
    "distinct_frontmatter_ids",
    "missing_optional_ids",
    "same_h1_distinct_ids",
    "case_distinct_ids_default",
    "frontmatter_like_prose",
    "id_in_code_fence",
    "duplicate_key_one_document",
)

#: The six FINDING scenarios, mapped to the ordered ``(line, path, message)`` tuple of each
#: expected DS114 ``error``. The collision is always attributed to the later sorted path at
#: the one-based line of its identity field and names the original document; the Unicode
#: pair echoes the NFC-normalized identity ``repr``-escaped (``caf\xe9-guide``); the
#: whitespace pair echoes the collapsed value; the required-policy case carries ``line=None``
#: because the absence has no representable source line. Fixed by the committed fixtures and
#: the message contract, not derived from the analyzer.
FINDING_EXPECTATIONS: dict[str, tuple[tuple[Optional[int], str, str], ...]] = {
    "identical_ids_two_docs": ((2, "b.md", 'duplicate document id "alpha" (already declared in a.md)'),),
    "unicode_normalized_ids": ((2, "b.md", 'duplicate document id "caf\\xe9-guide" (already declared in a.md)'),),
    "whitespace_normalized_ids": ((2, "b.md", 'duplicate document id "release notes" (already declared in a.md)'),),
    "three_duplicate_document_ids": (
        (2, "b.md", 'duplicate document id "shared-guide" (already declared in a.md)'),
        (2, "c.md", 'duplicate document id "shared-guide" (already declared in a.md)'),
    ),
    "casefold_ids_optin": ((2, "b.md", 'duplicate document id "alpha" (already declared in a.md)'),),
    "missing_ids_required": ((None, "a.md", 'document declares no "id" identity'),),
}

#: The lone ERROR scenario and its exact own-finding expectation. By the Story 12.0 ruling
#: an unsupported nested id value is reported as one explicit ``error`` finding that names
#: only the field and excludes the document from uniqueness -- it is NOT a ConfigError and
#: the document never appears as a collision original.
ERROR_CASE = "invalid_nested_metadata"
ERROR_EXPECTATION: tuple[Optional[int], str, str] = (
    2,
    "README.md",
    'document id field "id" has an unsupported value shape (not evaluated for uniqueness)',
)

#: The 13 CLEAN + FINDING scenarios asserted through detect() and scan() for an outcome.
OUTCOME_CASES: tuple[str, ...] = CLEAN_CASES + tuple(FINDING_EXPECTATIONS)

#: All 14 committed scenarios in a stable order.
ALL_CASES: tuple[str, ...] = OUTCOME_CASES + (ERROR_CASE,)

#: The full fast-profile rule set, in registry order, run alongside DS114.
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

#: The DS11x rules the genuine ``DS11`` prefix matches today, derived live so the test
#: tracks the registry rather than a brittle hard-coded set.
DS11_PREFIXED: tuple[str, ...] = tuple(code for code in FAST_RULE_ORDER if code.startswith("DS11"))


def _config(case: str, **overrides: object) -> Config:
    """Return the fast-profile ``Config`` for ``case`` using its exact matrix setup.

    :param case: The committed scenario slug.
    :param overrides: Extra ``Config`` keyword overrides merged over the matrix setup.
    :returns: The ``Config`` with ``profile="fast"`` and the scenario's DS114 setup.
    """
    return Config(profile="fast", **{**SETUP[case], **overrides})  # type: ignore[arg-type]


def _ds114(findings: tuple[models.Finding, ...]) -> tuple[models.Finding, ...]:
    """Return only the DS114 findings from a mixed finding tuple, preserving order.

    :param findings: Findings from a detector or scan.
    :returns: The DS114 subset in the original order.
    """
    return tuple(finding for finding in findings if finding.rule == "DS114")


def _triples(findings: tuple[models.Finding, ...]) -> list[tuple[Optional[int], str, str]]:
    """Return ordered ``(line, path, message)`` triples for a finding tuple.

    :param findings: Findings to describe.
    :returns: The ordered ``(line, path, message)`` triples.
    """
    return [(finding.line, finding.path, finding.message) for finding in findings]


def test_catalog_counts_match_the_committed_manifest():
    """
    [Integration] detectors document identity uniqueness ds114: verifies the local catalog totals.

    Scenario:
        Given the committed ds114 asset directories and this suite's expectation table
        When the clean, finding and error scenarios are counted
        Then there are exactly 7 clean, 6 finding, 1 error and 14 total scenarios matching Task 02, the
        clean and finding sets are disjoint and error-free, and every scenario carries an exact matrix setup.

    Boundaries:
        - Focus: the expectation table is complete, non-overlapping and matches the 7/6/1 split
        - Fixtures/params: none

    On failure, first check:
        - Whether a scenario slug was added or removed from Task 02/the fixture matrix
        - Whether a case appears in two outcome sets or is missing from SETUP
    """
    assert len(CLEAN_CASES) == 7
    assert len(FINDING_EXPECTATIONS) == 6
    assert len(set(ALL_CASES)) == 14
    assert set(CLEAN_CASES).isdisjoint(FINDING_EXPECTATIONS)
    assert ERROR_CASE not in CLEAN_CASES and ERROR_CASE not in FINDING_EXPECTATIONS
    assert set(SETUP) == set(ALL_CASES)


def test_ds114_is_registered_as_an_exact_fast_rule_without_opt_in():
    """
    [Integration] detectors document identity uniqueness ds114: verifies always-active registration.

    Scenario:
        Given the shipped rule registry after importing the detectors package
        When the fast-profile rule list is inspected
        Then DS114 is present with error severity, its title and an empty opt_in_option, proving it is an
        ordinary always-active rule rather than an opt-in policy rule like DS110 or DS112.

    Boundaries:
        - Focus: registration and metadata as seen through the public registry
        - Fixtures/params: none

    On failure, first check:
        - Whether docsentinel.detectors.document_ids registered DS114 on import
        - Whether DS114 drifted profile/severity or grew an opt_in_option
    """
    fast = {rule.code: rule for rule in rules_for_profile("fast")}
    assert "DS114" in fast
    rule = fast["DS114"]
    assert rule.severity == "error"
    assert rule.title == "Duplicate stable document identifiers"
    assert rule.opt_in_option == ""


@pytest.mark.parametrize("case", OUTCOME_CASES)
def test_detect_matches_expectation_for_each_scenario(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies detect per committed case.

    Scenario:
        Given one CLEAN or FINDING ds114 scenario materialized into a fresh tmp_path
        When document_ids.detect runs over all its documents with the exact matrix setup config
        Then clean cases yield no DS114 finding and finding cases yield exactly the expected DS114 error
        findings at the expected one-based line (or None for a required-policy absence), offending path and
        full message, in sorted-path order.

    Boundaries:
        - Focus: the pure detect entry point over real asset bytes under the exact per-case config
        - Fixtures/params: parametrized over the 13 outcome scenarios; asset_case

    On failure, first check:
        - The expected (line, path, message) in FINDING_EXPECTATIONS for this case
        - Whether the fixture Markdown was altered (it must stay byte-for-byte) or SETUP drifted
    """
    loaded = asset_case("ds114", case)
    findings = _ds114(document_ids.detect(loaded.root, loaded.documents(), _config(case)))

    if case in CLEAN_CASES:
        assert findings == ()
        return

    assert _triples(findings) == list(FINDING_EXPECTATIONS[case])
    for finding in findings:
        assert finding.rule == "DS114"
        assert finding.severity == "error"


@pytest.mark.parametrize("case", OUTCOME_CASES)
def test_scan_matches_expectation_and_ownership_split(case: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies the full-scan ownership split.

    Scenario:
        Given one CLEAN or FINDING ds114 scenario scanned under the full fast profile with the exact matrix
            setup config
        When DS101-DS117 run together
        Then DS114 ran (enabled_rules carries the full fast set, nothing pending), finding cases emit exactly
        the expected DS114 errors, and no non-DS114 rule fires on any ds114 fixture - the frontmatter and
        prose/fence fixtures carry no dangling link, bad path or other sibling defect - proving the identity
        check never cascades across rules.

    Boundaries:
        - Focus: the engine reproduces the detector outcome and the clean cross-rule ownership split
        - Fixtures/params: parametrized over the 13 outcome scenarios; asset_case

    On failure, first check:
        - Whether a sibling rule began firing on a ds114 fixture (none should)
        - Whether the engine still forwards the effective Config to DS114 (keyword dispatch)
    """
    loaded = asset_case("ds114", case)
    result = scan(loaded.root, config=_config(case))

    assert result.enabled_rules == FAST_RULE_ORDER
    assert result.pending == ()
    siblings = tuple((finding.rule, finding.line) for finding in result.findings if finding.rule != "DS114")
    assert siblings == ()

    own = _ds114(result.findings)
    if case in CLEAN_CASES:
        assert own == ()
    else:
        assert _triples(own) == list(FINDING_EXPECTATIONS[case])


def test_invalid_nested_metadata_is_one_own_finding_not_a_config_error(
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies the ERROR row flags one finding.

    Scenario:
        Given the invalid_nested_metadata scenario whose README.md declares an unsupported nested id value
        When document_ids.detect and the full fast scan run with the default config
        Then DS114 emits exactly one error finding at README.md line 2 whose message names only the field
        (never the raw nested value) and states the document was not evaluated for uniqueness, no ConfigError
        is raised (the scan is not aborted to exit 2), and README.md never appears as a collision original -
        the unsupported shape is isolated to its own document.

    Boundaries:
        - Focus: the Story 12.0 ruling - an unsupported id shape is one own finding, excluded from collisions
        - Fixtures/params: asset_case

    On failure, first check:
        - The UNSUPPORTED branch of check_documents emitting the finding then continuing (no originals entry)
        - Whether the unsupported shape was escalated to a ConfigError or silently dropped
    """
    loaded = asset_case("ds114", ERROR_CASE)

    findings = _ds114(document_ids.detect(loaded.root, loaded.documents(), _config(ERROR_CASE)))
    assert _triples(findings) == [ERROR_EXPECTATION]
    assert findings[0].severity == "error"
    # The message names only the field, never the raw nested value content from the fixture.
    assert "nested" not in findings[0].message

    result = scan(loaded.root, config=_config(ERROR_CASE))
    own = _ds114(result.findings)
    assert _triples(own) == [ERROR_EXPECTATION]
    assert all("already declared" not in finding.message for finding in own)


def test_multi_line_continuation_is_one_unsupported_finding_never_a_collision(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies a continuation id never collides.

    Scenario:
        Given two documents whose frontmatter id uses a multi-line plain continuation (id: alpha then an
            indented continuation line) - which a real YAML parser folds into one scalar - scanned under
            the full fast profile
        When the engine runs DS114 end to end
        Then each document yields exactly one UNSUPPORTED error finding at its id line and the two never
            collide, so the review's MEDIUM false collision (both read as the truncated "alpha") and the
            hidden collision (one read as the folded value) are both converted into an honest unsupported
            diagnostic rather than a blocking duplicate-id error.

    Boundaries:
        - Focus: end-to-end, a continuation value flags once and is excluded from uniqueness
        - Fixtures/params: tmp_path

    On failure, first check:
        - The next_is_indented branch of _interpret_value and _next_block_line_is_indented
        - Whether the continuation documents were bucketed as a collision on the truncated first line
    """
    (tmp_path / "a.md").write_text("---\nid: alpha\n  continued\n---\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("---\nid: alpha\n  continued\n---\n", encoding="utf-8")

    own = _ds114(scan(tmp_path, config=Config(profile="fast", select=("DS114",))).findings)

    assert _triples(own) == [
        (2, "a.md", 'document id field "id" has an unsupported value shape (not evaluated for uniqueness)'),
        (2, "b.md", 'document id field "id" has an unsupported value shape (not evaluated for uniqueness)'),
    ]
    assert all("already declared" not in finding.message for finding in own)
    assert all(finding.severity == "error" for finding in own)


def test_required_policy_does_not_falsely_flag_a_quoted_key_id(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies a quoted-key id survives required mode.

    Scenario:
        Given document_id_required=true and a document whose id is declared only under a quoted key
            ("id": present) - a valid identity a real parser honours - scanned under the fast profile
        When the engine runs DS114 end to end
        Then no "declares no id" finding is produced, because the quoted-key spelling is DEFERRED rather
            than read as ABSENT, closing the review's MEDIUM false "declares no id" block for the
            required policy, while a genuinely id-less document is still flagged.

    Boundaries:
        - Focus: end-to-end, an alternative key spelling defers so document_id_required does not misfire
        - Fixtures/params: tmp_path

    On failure, first check:
        - The has_shadow_field defer preceding the ABSENT+required branch in check_documents
        - _unquote_key recognition of the quoted field spelling
    """
    (tmp_path / "quoted.md").write_text('---\n"id": present\n---\n', encoding="utf-8")
    (tmp_path / "none.md").write_text("# no frontmatter\n", encoding="utf-8")

    config = Config(profile="fast", select=("DS114",), document_id_required=True)
    own = _ds114(scan(tmp_path, config=config).findings)

    # Only the genuinely id-less document is flagged; the quoted-key document is deferred, not absent.
    assert _triples(own) == [(None, "none.md", 'document declares no "id" identity')]


def test_unsupported_double_quoted_escape_flags_once_and_never_collides(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies a numeric escape defers, no false collision.

    Scenario:
        Given one document whose id is the literal double-quoted text "x41" and another whose id is the
            double-quoted "\\x41" (a numeric escape a real parser decodes to "A"), scanned under the fast
            profile
        When the engine runs DS114 end to end
        Then the "\\x41" document yields exactly one UNSUPPORTED error finding (the reader refuses to
            mis-decode the escape by dropping the backslash) and the two documents do not collide,
            closing the review's MEDIUM mis-decode false collision.

    Boundaries:
        - Focus: end-to-end, an unsupported double-quote escape defers rather than inventing "x41"
        - Fixtures/params: tmp_path

    On failure, first check:
        - The None return for an unrecognised escape in _parse_double_quoted
        - Whether the escaped document was bucketed with the literal "x41" document
    """
    (tmp_path / "a.md").write_text('---\nid: "x41"\n---\n', encoding="utf-8")
    (tmp_path / "b.md").write_text('---\nid: "\\x41"\n---\n', encoding="utf-8")

    own = _ds114(scan(tmp_path, config=Config(profile="fast", select=("DS114",))).findings)

    assert _triples(own) == [
        (2, "b.md", 'document id field "id" has an unsupported value shape (not evaluated for uniqueness)'),
    ]
    assert all("already declared" not in finding.message for finding in own)


def test_three_duplicates_make_two_findings_each_referencing_the_first(
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies the n-1 ordering and original.

    Scenario:
        Given the three_duplicate_document_ids scenario whose a.md, b.md and c.md all declare id: shared-guide
        When document_ids.detect runs with the default config
        Then exactly two findings are produced, one for b.md and one for c.md in sorted-path order, each at
        its own line 2 and each naming a.md (the first occurrence) as the original, proving the n-1 contract
        attributes every later duplicate to the first document rather than to its immediate predecessor.

    Boundaries:
        - Focus: the exact n-1 count, sorted-path ordering and first-document attribution
        - Fixtures/params: asset_case

    On failure, first check:
        - Whether originals stores the first path and is never overwritten by a later duplicate
    """
    loaded = asset_case("ds114", "three_duplicate_document_ids")
    findings = _ds114(document_ids.detect(loaded.root, loaded.documents(), Config(profile="fast")))

    assert [finding.path for finding in findings] == ["b.md", "c.md"]
    assert all(finding.line == 2 for finding in findings)
    assert all(finding.message.endswith("(already declared in a.md)") for finding in findings)


def test_collision_is_attributed_to_the_later_path_independent_of_document_order(
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies later-path attribution and order independence.

    Scenario:
        Given the identical_ids_two_docs scenario whose a.md and b.md share id: alpha
        When document_ids.detect runs over the documents in natural order and again over the reversed tuple
        Then both runs produce the identical single finding attributed to the later sorted path b.md at its id
        line 2 naming a.md, proving attribution follows sorted path order and is independent of the order in
        which discovery hands documents to the detector.

    Boundaries:
        - Focus: later-sorted-path attribution and independence from document discovery order
        - Fixtures/params: asset_case

    On failure, first check:
        - The sorted() call over entries in check_documents
        - Whether the finding flipped to a.md when the input order was reversed
    """
    loaded = asset_case("ds114", "identical_ids_two_docs")
    documents = loaded.documents()

    forward = _ds114(document_ids.detect(loaded.root, documents, Config(profile="fast")))
    reverse = _ds114(document_ids.detect(loaded.root, tuple(reversed(documents)), Config(profile="fast")))

    assert _triples(forward) == [(2, "b.md", 'duplicate document id "alpha" (already declared in a.md)')]
    assert forward == reverse


@pytest.mark.parametrize("scope", ["corpus", "directory"])
def test_document_id_scope_isolates_namespaces(scope: str, tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies both scope enum values.

    Scenario:
        Given a tree with the same id declared in x/a.md, x/b.md and y/c.md
        When document_ids.detect runs with document_id_scope set to corpus and then to directory
        Then corpus scope reports both x/b.md and y/c.md as duplicates of x/a.md (one namespace), while
        directory scope reports only x/b.md (y/c.md is the sole id in its own directory), proving the
        namespace key is the whole corpus or the parent directory.

    Boundaries:
        - Focus: the document_id_scope corpus/directory namespace keying through detect
        - Fixtures/params: parametrized over the two enum values; tmp_path

    On failure, first check:
        - The _scope_key dirname computation and the bucket key in check_documents
    """
    (tmp_path / "x").mkdir()
    (tmp_path / "y").mkdir()
    (tmp_path / "x" / "a.md").write_text("---\nid: shared\n---\n", encoding="utf-8")
    (tmp_path / "x" / "b.md").write_text("---\nid: shared\n---\n", encoding="utf-8")
    (tmp_path / "y" / "c.md").write_text("---\nid: shared\n---\n", encoding="utf-8")
    documents = (
        models.Document("x/a.md", 0),
        models.Document("x/b.md", 0),
        models.Document("y/c.md", 0),
    )

    findings = _ds114(document_ids.detect(tmp_path, documents, Config(profile="fast", document_id_scope=scope)))

    if scope == "corpus":
        assert [finding.path for finding in findings] == ["x/b.md", "y/c.md"]
    else:
        assert [finding.path for finding in findings] == ["x/b.md"]


def test_injected_invalid_scope_fails_closed_with_a_config_error(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies an injected bad scope fails closed.

    Scenario:
        Given an injected Config (bypassing load_config's enum validation) whose document_id_scope is an
            out-of-vocabulary value
        When document_ids.check_documents and document_ids.detect run
        Then each raises a ConfigError naming the option rather than silently degrading to the corpus
        namespace, so a config-injection caller cannot slip DS114 into an unintended scope.

    Boundaries:
        - Focus: the config-injection trust boundary - an injected invalid scope fails closed (DS112 precedent)
        - Fixtures/params: tmp_path

    On failure, first check:
        - The _VALID_SCOPES guard at the top of check_documents
        - Whether the detector read the scope without validating an injected Config
    """
    (tmp_path / "a.md").write_text("---\nid: x\n---\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="document_id_scope"):
        document_ids.check_documents((("a.md", "---\nid: x\n---\n"),), Config(document_id_scope="sideways"))
    with pytest.raises(ConfigError, match="document_id_scope"):
        document_ids.detect(tmp_path, (models.Document("a.md", 0),), Config(document_id_scope="sideways"))


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_case_sensitive_option_propagates_from_both_config_files(
    config_file: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies document_id_case_sensitive loads from both files.

    Scenario:
        Given the casefold_ids_optin fixture (ids Alpha and alpha) carrying either a standalone
            docsentinel.toml or a [tool.doc_sentinel] table that sets document_id_case_sensitive=false
        When scan discovers that config (no injected Config)
        Then the case-insensitive policy collapses Alpha and alpha into one identity and flags b.md at line 6,
        proving the option loads and reaches DS114 through each config-file form, while the shipped
        case-sensitive default leaves the pair distinct.

    Boundaries:
        - Focus: config discovery and propagation of document_id_case_sensitive via both forms
        - Fixtures/params: parametrized over the two config-file forms; asset_case

    On failure, first check:
        - Whether load_config reads document_id_case_sensitive from the given file form
        - The casefold branch selecting the comparison key in check_documents
    """
    case = asset_case("ds114", "casefold_ids_optin")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (case.root / config_file).write_text(f'{prefix}profile = "fast"\n', encoding="utf-8")
    assert _ds114(scan(case.root).findings) == ()

    (case.root / config_file).write_text(
        f'{prefix}profile = "fast"\ndocument_id_case_sensitive = false\n', encoding="utf-8"
    )
    flagged = _ds114(scan(case.root).findings)
    assert _triples(flagged) == [(2, "b.md", 'duplicate document id "alpha" (already declared in a.md)')]


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_required_option_propagates_from_both_config_files(
    config_file: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies document_id_required loads from both files.

    Scenario:
        Given the missing_ids_required fixture (a.md declares no id, b.md declares one) carrying either a
            standalone docsentinel.toml or a [tool.doc_sentinel] table that sets document_id_required=true
        When scan discovers that config
        Then the required policy flags a.md alone with a no-identity finding (line None) and leaves b.md
        clean, proving the option loads through each config-file form, while the shipped default reports
        nothing.

    Boundaries:
        - Focus: config discovery and propagation of document_id_required via both forms
        - Fixtures/params: parametrized over the two config-file forms; asset_case

    On failure, first check:
        - Whether load_config reads document_id_required from the given file form
        - The ABSENT + required branch in check_documents
    """
    case = asset_case("ds114", "missing_ids_required")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (case.root / config_file).write_text(f'{prefix}profile = "fast"\n', encoding="utf-8")
    assert _ds114(scan(case.root).findings) == ()

    (case.root / config_file).write_text(f'{prefix}profile = "fast"\ndocument_id_required = true\n', encoding="utf-8")
    flagged = _ds114(scan(case.root).findings)
    assert _triples(flagged) == [(None, "a.md", 'document declares no "id" identity')]


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_scope_option_propagates_from_both_config_files(config_file: str, tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies document_id_scope loads from both files.

    Scenario:
        Given a tree with the same id in x/a.md, x/b.md and y/c.md carrying either a standalone
            docsentinel.toml or a [tool.doc_sentinel] table that selects DS114 and sets
            document_id_scope="directory"
        When scan discovers that config
        Then only x/b.md is reported (its directory namespace), proving document_id_scope loads through each
        config-file form, while the corpus default would also report y/c.md.

    Boundaries:
        - Focus: config discovery and propagation of document_id_scope via both forms
        - Fixtures/params: parametrized over the two config-file forms; tmp_path

    On failure, first check:
        - Whether load_config reads and validates document_id_scope from the given file form
        - The _scope_key dirname keying in check_documents
    """
    (tmp_path / "x").mkdir()
    (tmp_path / "y").mkdir()
    for relative in ("x/a.md", "x/b.md", "y/c.md"):
        (tmp_path / relative).write_text("---\nid: shared\n---\n", encoding="utf-8")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (tmp_path / config_file).write_text(f'{prefix}profile = "fast"\nselect = ["DS114"]\n', encoding="utf-8")
    assert [finding.path for finding in _ds114(scan(tmp_path).findings)] == ["x/b.md", "y/c.md"]

    (tmp_path / config_file).write_text(
        f'{prefix}profile = "fast"\nselect = ["DS114"]\ndocument_id_scope = "directory"\n', encoding="utf-8"
    )
    assert [finding.path for finding in _ds114(scan(tmp_path).findings)] == ["x/b.md"]


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
def test_field_option_propagates_from_both_config_files(config_file: str, tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies document_id_field loads from both files.

    Scenario:
        Given two documents keyed by a custom slug frontmatter field with the same value, carrying either a
            standalone docsentinel.toml or a [tool.doc_sentinel] table that selects DS114 and sets
            document_id_field="slug"
        When scan discovers that config
        Then b.md is reported as a slug duplicate of a.md, proving the configured field name loads through
        each config-file form and is the key the reader looks up, while the default id field finds nothing.

    Boundaries:
        - Focus: config discovery and propagation of document_id_field via both forms
        - Fixtures/params: parametrized over the two config-file forms; tmp_path

    On failure, first check:
        - Whether load_config reads document_id_field from the given file form
        - Whether the field name flows from Config into extract_frontmatter_field
    """
    (tmp_path / "a.md").write_text("---\nslug: shared\n---\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("---\nslug: shared\n---\n", encoding="utf-8")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"

    (tmp_path / config_file).write_text(f'{prefix}profile = "fast"\nselect = ["DS114"]\n', encoding="utf-8")
    assert _ds114(scan(tmp_path).findings) == ()

    (tmp_path / config_file).write_text(
        f'{prefix}profile = "fast"\nselect = ["DS114"]\ndocument_id_field = "slug"\n', encoding="utf-8"
    )
    assert [finding.path for finding in _ds114(scan(tmp_path).findings)] == ["b.md"]


@pytest.mark.parametrize("config_file", ["docsentinel.toml", "pyproject.toml"])
@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("document_id_scope", '"sideways"'),
        ("document_id_field", '"bad name"'),
        ("document_id_case_sensitive", '"yes"'),
        ("document_id_required", '"yes"'),
    ],
)
def test_invalid_option_raises_config_error_from_both_config_files(
    config_file: str,
    option: str,
    value: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies invalid options are rejected.

    Scenario:
        Given a docsentinel.toml or [tool.doc_sentinel] table that sets one DS114 option to an invalid value
            (an out-of-vocabulary scope, a field name with a space, or a non-boolean flag)
        When scan loads that config
        Then a ConfigError naming the offending option is raised rather than silently coercing it, for every
        one of the four options through both config-file forms.

    Boundaries:
        - Focus: the config allowlist rejects invalid values for all four DS114 options via both forms
        - Fixtures/params: parametrized over the two config-file forms and the four options; asset_case

    On failure, first check:
        - The enum/bool/field-name validation for the named option in config.py
        - Whether an invalid value was coerced instead of raising
    """
    case = asset_case("ds114", "distinct_frontmatter_ids")
    prefix = "" if config_file == "docsentinel.toml" else "[tool.doc_sentinel]\n"
    (case.root / config_file).write_text(f'{prefix}profile = "fast"\n{option} = {value}\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=option):
        scan(case.root)


def test_select_narrows_to_ds114_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies select activates only DS114.

    Scenario:
        Given the identical_ids_two_docs scenario (a DS114-only collision) scanned with select pinned to DS114
        When the engine resolves the active rule set
        Then only DS114 is enabled and its single expected error finding at b.md line 2 is produced.

    Boundaries:
        - Focus: exact-code select resolution for a fast rule
        - Fixtures/params: asset_case

    On failure, first check:
        - effective_rules handling of an exact DS114 selector
        - Whether another rule leaked into enabled_rules
    """
    case = asset_case("ds114", "identical_ids_two_docs")

    result = scan(case.root, config=Config(profile="fast", select=("DS114",)))

    assert result.enabled_rules == ("DS114",)
    assert [(finding.rule, finding.path, finding.line) for finding in result.findings] == [("DS114", "b.md", 2)]


def test_prefix_select_and_ignore_semantics_for_ds114(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies DS11/DS1/DS2 select and ignore.

    Scenario:
        Given the identical_ids_two_docs scenario (a DS114-only collision) scanned under the fast profile
        When it is selected by the genuine ``DS11`` prefix, the whole-set ``DS1`` prefix and the non-matching
            ``DS2`` prefix, and then ignored by the exact code, by ``DS11`` and by ``DS2``
        Then ``DS11`` and ``DS1`` keep DS114 active and still reporting b.md line 2, ``DS2`` activates no fast
        rule, the exact and ``DS11`` ignores drop DS114 and its finding, and ``DS2`` leaves it active - all
        expectations derived from FAST_RULE_ORDER, not hard-coded.

    Boundaries:
        - Focus: prefix select and ignore precedence for DS114 against the live fast rule set
        - Fixtures/params: asset_case

    On failure, first check:
        - matches_selector prefix logic for DS11/DS1 against the fast rule codes
        - Whether a new DS11x rule shifted DS11_PREFIXED out of sync
    """
    case = asset_case("ds114", "identical_ids_two_docs")

    ds11x = scan(case.root, config=Config(profile="fast", select=("DS11",)))
    assert ds11x.enabled_rules == DS11_PREFIXED
    assert [finding.path for finding in _ds114(ds11x.findings)] == ["b.md"]

    whole_fast = scan(case.root, config=Config(profile="fast", select=("DS1",)))
    assert whole_fast.enabled_rules == FAST_RULE_ORDER
    assert [finding.path for finding in _ds114(whole_fast.findings)] == ["b.md"]

    none = scan(case.root, config=Config(profile="fast", select=("DS2",)))
    assert none.enabled_rules == ()
    assert _ds114(none.findings) == ()

    exact = scan(case.root, config=Config(profile="fast", ignore=("DS114",)))
    assert "DS114" not in exact.enabled_rules
    assert _ds114(exact.findings) == ()

    by_prefix = scan(case.root, config=Config(profile="fast", ignore=("DS11",)))
    assert by_prefix.enabled_rules == tuple(code for code in FAST_RULE_ORDER if not code.startswith("DS11"))
    assert _ds114(by_prefix.findings) == ()

    unaffected = scan(case.root, config=Config(profile="fast", ignore=("DS2",)))
    assert "DS114" in unaffected.enabled_rules
    assert [finding.path for finding in _ds114(unaffected.findings)] == ["b.md"]


def test_baseline_suppresses_known_ds114_findings(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies baseline suppression round-trips.

    Scenario:
        Given the three_duplicate_document_ids scenario whose two DS114 findings are recorded into a baseline
        When the same tree is rescanned with that baseline configured
        Then both previously known DS114 findings are filtered out while the first scan still reported them,
        so the fingerprints are stable across the two scans.

    Boundaries:
        - Focus: fingerprint-based baseline suppression applied to multiple DS114 error findings
        - Fixtures/params: asset_case

    On failure, first check:
        - fingerprint stability for the DS114 findings between the two scans
        - Whether the baseline path resolved relative to the scan root
    """
    case = asset_case("ds114", "three_duplicate_document_ids")
    first = scan(case.root, config=Config(profile="fast", select=("DS114",)))
    assert len(_ds114(first.findings)) == 2

    baseline_path = case.root / ".docsentinel-baseline.json"
    baseline.save_baseline(baseline_path, first.findings)

    suppressed = scan(
        case.root,
        config=Config(profile="fast", select=("DS114",), baseline=".docsentinel-baseline.json"),
    )
    assert _ds114(suppressed.findings) == ()


def test_repeated_scans_are_deterministic(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies repeated scans are stable.

    Scenario:
        Given the three_duplicate_document_ids scenario scanned twice over the same materialized root
        When the two DS114 finding tuples are compared
        Then they are equal and report b.md and c.md, so the detector holds no order-dependent state and the
        originals bookkeeping does not leak between runs.

    Boundaries:
        - Focus: determinism of DS114 over a real asset tree, with asserted paths
        - Fixtures/params: asset_case

    On failure, first check:
        - Module-level mutable caches in the detector
        - Whether the originals dict leaked across runs
    """
    case = asset_case("ds114", "three_duplicate_document_ids")
    first = _ds114(scan(case.root, config=Config(profile="fast", select=("DS114",))).findings)
    second = _ds114(scan(case.root, config=Config(profile="fast", select=("DS114",))).findings)
    assert first == second
    assert [finding.path for finding in first] == ["b.md", "c.md"]


def test_reports_are_stable_across_formats(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies text/json/github report stability.

    Scenario:
        Given a DS114 collision scan result
        When it is rendered as text, json and github output
        Then each format carries the DS114 error deterministically (schema v1 json, an ``::error`` annotation
        with file and line) and repeated renders are byte-identical.

    Boundaries:
        - Focus: report serialization of a DS114 error across the three formats
        - Fixtures/params: asset_case

    On failure, first check:
        - reporting.render output for the finding's path, line and message
        - Whether repeated renders diverge (nondeterminism)
    """
    case = asset_case("ds114", "identical_ids_two_docs")
    result = scan(case.root, config=Config(profile="fast", select=("DS114",)))

    text = render(result, "text")
    assert render(result, "text") == text
    assert 'error: b.md: duplicate document id "alpha" (already declared in a.md)' in text

    payload = json.loads(render(result, "json-v1"))
    assert payload["schema_version"] == 1
    assert payload["enabled_rules"] == ["DS114"]
    assert payload["findings"][0]["rule"] == "DS114"
    assert payload["findings"][0]["severity"] == "error"
    assert payload["findings"][0]["line"] == 2

    github = render(result, "github")
    assert render(result, "github") == github
    assert github.startswith("::error file=b.md,line=2,title=DS114::")


def test_hostile_ids_are_bounded_and_repr_escaped(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies hostile ids cannot inject output.

    Scenario:
        Given two documents sharing one hostile frontmatter id containing an ESC byte, a NUL byte, a
            right-to-left override, a ``::error`` injection token and 10,000 trailing characters, plus a
            second pair whose double-quoted id embeds a newline escape
        When the collision scan is rendered as text
        Then the collision message is bounded to the echo limit, repr-escapes every control and non-ASCII
        byte (so no raw ESC, NUL, RTL, or newline reaches it), carries only the author's raw id and the
        relative original path (never a resolved absolute root), ends with a truncation marker, and the text
        report holds no raw control byte and no absolute path.

    Boundaries:
        - Focus: output-injection and information-disclosure safety of DS114 collision messages
        - Fixtures/params: tmp_path

    On failure, first check:
        - _echo's unicode_escape bound and whether a message leaked a resolved absolute path
        - Whether normalize/_display collapsed the embedded newline before the echo
    """
    hostile = "X\x1b\x00‮::error" + ("a" * 10_000)
    (tmp_path / "a.md").write_text(f"---\nid: {hostile}\n---\n", encoding="utf-8")
    (tmp_path / "b.md").write_text(f"---\nid: {hostile}\n---\n", encoding="utf-8")

    result = scan(tmp_path, config=Config(profile="fast", select=("DS114",)))
    own = _ds114(result.findings)
    assert len(own) == 1
    message = own[0].message
    assert message.isascii()
    assert not any(ord(character) < 0x20 or ord(character) == 0x7F for character in message)
    assert "‮" not in message
    assert str(tmp_path) not in message
    assert "..." in message

    text = render(result, "text")
    assert "\x1b" not in text and "\x00" not in text and "‮" not in text
    assert "\\x1b" in text  # repr-escaped, not raw
    assert str(tmp_path) not in text

    # A double-quoted id embedding a newline escape collapses to a space, so no raw newline leaks.
    (tmp_path / "c.md").write_text('---\nid: "a\\nb"\n---\n', encoding="utf-8")
    (tmp_path / "d.md").write_text('---\nid: "a   b"\n---\n', encoding="utf-8")
    newline_pair = _ds114(
        document_ids.detect(
            tmp_path,
            (models.Document("c.md", 0), models.Document("d.md", 0)),
            Config(profile="fast"),
        )
    )
    assert len(newline_pair) == 1
    assert newline_pair[0].message == 'duplicate document id "a b" (already declared in c.md)'
    assert "\n" not in newline_pair[0].message


def test_crlf_and_bom_line_fidelity(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies CRLF and BOM line fidelity.

    Scenario:
        Given one CRLF-terminated document and one BOM-prefixed document, each declaring id: alpha with a
            title line before the id so the id sits on a known one-based line
        When document_ids.detect runs over both
        Then they collide and the later sorted document (crlf.md) is reported at the id's correct one-based
        line 3, proving carriage returns and a leading BOM do not shift line counting.

    Boundaries:
        - Focus: one-based line accuracy on CRLF and BOM input for the identity field
        - Fixtures/params: tmp_path

    On failure, first check:
        - The BOM strip and per-line rstrip("\\r") in _split_lines
        - The ``offset + 2`` line computation in extract_frontmatter_field
    """
    (tmp_path / "bom.md").write_bytes("﻿---\ntitle: T\nid: alpha\n---\n".encode("utf-8"))
    (tmp_path / "crlf.md").write_bytes(b"---\r\ntitle: T\r\nid: alpha\r\n---\r\n")

    findings = _ds114(
        document_ids.detect(
            tmp_path,
            (models.Document("bom.md", 0), models.Document("crlf.md", 0)),
            Config(profile="fast"),
        )
    )

    assert _triples(findings) == [(3, "crlf.md", 'duplicate document id "alpha" (already declared in bom.md)')]


def test_invalid_utf8_head_contributes_no_identity_and_does_not_crash(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies an invalid UTF-8 head is not a collision.

    Scenario:
        Given a valid document declaring id: alpha and a second document whose head is invalid UTF-8 (its
            raw bytes would read as id: alpha were they decodable)
        When a fast scan reads both with DS114 selected
        Then the scan completes with no finding - the undecodable document contributes no identity and cannot
        collide - rather than crashing or being conflated as a duplicate.

    Boundaries:
        - Focus: an invalid-UTF-8 head yields no identity (documented) without a crash or a false collision
        - Fixtures/params: tmp_path

    On failure, first check:
        - The _decode_head incremental-decoder branch returning None on invalid bytes
        - Whether the undecodable document was still bucketed as an identity
    """
    (tmp_path / "good.md").write_text("---\nid: alpha\n---\n# ok\n", encoding="utf-8")
    (tmp_path / "bad.md").write_bytes(b"---\nid: \xff\xfe alpha\n---\n")

    result = scan(tmp_path, config=Config(profile="fast", select=("DS114",)))

    assert _ds114(result.findings) == ()


def test_unreadable_document_surfaces_rather_than_false_clean(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies an unreadable document is not a silent clean.

    Scenario:
        Given a Markdown document whose read permission is removed
        When a fast scan tries to read it with DS114 selected
        Then a PermissionError propagates instead of a misleading zero-finding result, matching how the other
        fast detectors surface a genuine filesystem read failure rather than masking it.

    Boundaries:
        - Focus: a filesystem read error surfaces instead of masquerading as clean (not masked in _read_head)
        - Fixtures/params: tmp_path (skipped when running as root, which bypasses the mode)

    On failure, first check:
        - Whether _read_head swallowed the OSError into a clean scan
        - Whether the test runs as root, where chmod 000 does not block reads
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("running as root bypasses the unreadable-file permission check")
    target = tmp_path / "README.md"
    target.write_text("---\nid: alpha\n---\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            scan(tmp_path, config=Config(profile="fast", select=("DS114",)))
    finally:
        target.chmod(0o644)


def test_symlinked_markdown_is_not_inventoried(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies a symlinked Markdown file is skipped.

    Scenario:
        Given a real a.md declaring id: alpha and an in-root b.md symlink pointing at it (so following the
            link would surface a second id: alpha)
        When a fast scan runs with DS114 selected
        Then discovery never inventories the symlinked b.md, so no collision is produced - a symlinked
        document cannot smuggle a duplicate identity into the corpus.

    Boundaries:
        - Focus: discovery excludes symlinked files, so DS114 never sees a symlinked duplicate
        - Fixtures/params: tmp_path (skipped when symlinks are unavailable)

    On failure, first check:
        - Whether discovery still skips symlinked files
        - Whether DS114 began resolving a path discovery did not hand it
    """
    (tmp_path / "a.md").write_text("---\nid: alpha\n---\n", encoding="utf-8")
    _symlink_or_skip(tmp_path / "b.md", "a.md")

    result = scan(tmp_path, config=Config(profile="fast", select=("DS114",)))

    assert [document.path for document in result.documents] == ["a.md"]
    assert _ds114(result.findings) == ()


def test_huge_document_read_is_bounded_to_the_head(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] detectors document identity uniqueness ds114: verifies a huge document is read bounded to its head.

    Scenario:
        Given a small a.md and a big.md whose top frontmatter declares the same id but whose body is far
            larger than the head bound, scanned through detect under a filesystem recorder, and then a second
            document whose closing frontmatter delimiter sits beyond a temporarily lowered head bound
        When document_ids.detect runs
        Then the collision on big.md is still reported (the top is read), the bytes read from big.md never
        exceed the head bound while its on-disk size does, no path outside the root is touched, and lowering
        the head bound below the second document's closer makes its block read as unterminated so it
        contributes no identity - proving the reader reads a bounded head, never the whole file.

    Boundaries:
        - Focus: the bounded head read (_MAX_HEAD_BYTES) against a memory-exhaustion document
        - Fixtures/params: tmp_path, monkeypatch, the DS114 byte-counting recorder

    On failure, first check:
        - Whether _read_head still passes _MAX_HEAD_BYTES to stream.read
        - Whether the head bound was read from the module global at call time
    """
    root = tmp_path / "scanroot"
    root.mkdir()
    (root / "a.md").write_text("---\nid: dup\n---\n# A\n", encoding="utf-8")
    oversized = "---\nid: dup\n---\n\n" + ("padding line\n" * 200_000)
    (root / "big.md").write_text(oversized, encoding="utf-8")
    canonical = Path(os.path.realpath(root))
    documents = (models.Document("a.md", 0), models.Document("big.md", 0))
    # Materialize the lowered-cap tree now, before the recorder wraps Path.open (its
    # counting proxy delegates reads only, so a later write_text would fail under it).
    far = tmp_path / "far"
    far.mkdir()
    (far / "a.md").write_text("---\nid: dup\n---\n", encoding="utf-8")
    (far / "b.md").write_text("---\nid: dup\n" + ("pad: x\n" * 50) + "---\n", encoding="utf-8")
    far_docs = (models.Document("a.md", 0), models.Document("b.md", 0))

    document_ids.detect(canonical, documents, Config(profile="fast"))  # warm up before recording

    recorder = _Recorder()
    _install_recorder(monkeypatch, recorder)
    findings = _ds114(document_ids.detect(canonical, documents, Config(profile="fast")))

    assert [finding.path for finding in findings] == ["big.md"]
    big_path = os.path.normpath(os.fspath(canonical / "big.md"))
    assert recorder.bytes_read.get(big_path, 0) <= document_ids._MAX_HEAD_BYTES
    assert (canonical / "big.md").stat().st_size > document_ids._MAX_HEAD_BYTES
    root_str = str(canonical)
    for recorded in recorder.paths:
        assert _is_under(recorded, root_str) or _is_under(root_str, recorded), f"touched outside root: {recorded}"

    # A closer beyond a lowered head bound reads as unterminated, so the document has no identity.
    assert len(_ds114(document_ids.detect(far, far_docs, Config(profile="fast")))) == 1
    monkeypatch.setattr(document_ids, "_MAX_HEAD_BYTES", 24)
    assert _ds114(document_ids.detect(far, far_docs, Config(profile="fast"))) == ()


def test_body_html_anchor_and_heading_are_a_separate_namespace(tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies DS104 body anchors are not DS114 identities.

    Scenario:
        Given two documents that share a body HTML ``id=`` anchor and an identical H1 heading but declare
            distinct frontmatter ids (and a second pair with no frontmatter id at all)
        When a full fast scan runs
        Then DS114 reports no collision, proving a body ``id=`` anchor or a heading - DS104's local-anchor
        namespace - is never treated as a stable document identity.

    Boundaries:
        - Focus: the DS104-vs-DS114 namespace split (body anchors/headings are not document identities)
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether DS114 began mining headings or HTML id= attributes for identities
        - The byte-0 opening-fence requirement in extract_frontmatter_field
    """
    (tmp_path / "a.md").write_text('---\nid: alpha\n---\n\n# Shared Title\n\n<a id="dup"></a>\n', encoding="utf-8")
    (tmp_path / "b.md").write_text('---\nid: beta\n---\n\n# Shared Title\n\n<a id="dup"></a>\n', encoding="utf-8")
    (tmp_path / "c.md").write_text('# Shared Title\n\n<a id="same"></a>\n', encoding="utf-8")
    (tmp_path / "d.md").write_text('# Shared Title\n\n<a id="same"></a>\n', encoding="utf-8")

    result = scan(tmp_path, config=Config(profile="fast", select=("DS114",)))

    assert _ds114(result.findings) == ()


def test_detect_performs_no_network_or_subprocess_io(
    asset_case: Callable[[str, str], AssetCase],
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies no network or content execution.

    Scenario:
        Given sockets, outbound connections and subprocess launches wired to fail hard
        When document_ids.detect runs over every FINDING scenario
        Then all expected findings are still produced, proving DS114 opens no socket, makes no connection and
        never executes embedded documentation content.

    Boundaries:
        - Focus: the security invariant that recognition is pure, offline and non-executing
        - Fixtures/params: monkeypatch; asset_case

    On failure, first check:
        - Any accidental network client or subprocess call on the DS114 path
        - Whether a lazily imported dependency opened a socket during the scan
    """

    def _no_socket(*args: object, **kwargs: object) -> object:
        """Fail the test if DS114 ever constructs a socket."""
        raise AssertionError("DS114 must not create a socket")

    def _no_connect(*args: object, **kwargs: object) -> object:
        """Fail the test if DS114 ever opens an outbound connection."""
        raise AssertionError("DS114 must not open a network connection")

    def _no_subprocess(*args: object, **kwargs: object) -> object:
        """Fail the test if DS114 ever launches a subprocess."""
        raise AssertionError("DS114 must not execute documentation content")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "create_connection", _no_connect)
    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)

    for case in FINDING_EXPECTATIONS:
        loaded = asset_case("ds114", case)
        findings = _ds114(document_ids.detect(loaded.root, loaded.documents(), _config(case)))
        assert _triples(findings) == list(FINDING_EXPECTATIONS[case])


def test_detect_import_path_pulls_no_standard_extras():
    """
    [Integration] detectors document identity uniqueness ds114: verifies the detector stays stdlib-only.

    Scenario:
        Given a fresh isolated interpreter that imports the DS114 detector and runs its corpus core
        When the loaded modules are inspected
        Then none of the optional heavy dependencies (scikit-learn, textstat, docsig, spacy, textacy) are imported, proving the
        fast DS114 path needs no optional heavy dependency.

    Boundaries:
        - Focus: fast-profile import isolation for DS114's own code path
        - Also asserted: spacy and textacy stay unimported now the deep analyzer loads them lazily
        - Fixtures/params: none

    On failure, first check:
        - Whether document_ids gained a standard-extra import
        - The subprocess probe output listing the offending module
    """
    probe = (
        "import sys\n"
        "from docsentinel.detectors import document_ids\n"
        "entries = (('a.md', '---\\nid: x\\n---\\n'), ('b.md', '---\\nid: x\\n---\\n'))\n"
        "assert document_ids.check_documents(entries)\n"
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


def test_cli_fast_json_scan_reports_ds114_and_exits_one_without_strict(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies a collision blocks without strict.

    Scenario:
        Given the identical_ids_two_docs scenario (a DS114-only collision) scanned via the CLI with
            --profile fast --format json and no --strict
        When the command runs
        Then it prints a JSON report containing the DS114 error at b.md line 2 and exits 1, because an
        error-severity finding is blocking even without --strict.

    Boundaries:
        - Focus: the CLI exit-code mapping for an error-severity rule without strict
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - The CLI exit-code mapping for error-severity findings
        - Whether DS114 still produced its finding through the CLI path
    """
    case = asset_case("ds114", "identical_ids_two_docs")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast", "--format", "json-v1"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    ds114 = [finding for finding in payload["findings"] if finding["rule"] == "DS114"]
    assert len(ds114) == 1
    assert ds114[0]["severity"] == "error"
    assert ds114[0]["path"] == "b.md"
    assert ds114[0]["line"] == 2
    assert exit_code == 1


def test_cli_fast_scan_on_clean_case_exits_zero(
    asset_case: Callable[[str, str], AssetCase],
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies a clean case exits zero.

    Scenario:
        Given the distinct_frontmatter_ids clean scenario scanned via the CLI under the fast profile
        When the command runs
        Then no finding is reported and the process exits 0.

    Boundaries:
        - Focus: the non-blocking exit code when DS114 and its siblings find nothing
        - Fixtures/params: asset_case, capsys

    On failure, first check:
        - Whether a clean fixture accidentally triggers DS114 or a sibling rule
        - The CLI exit-code mapping when no finding exists
    """
    case = asset_case("ds114", "distinct_frontmatter_ids")

    exit_code = cli.main(["scan", str(case.root), "--profile", "fast"])

    capsys.readouterr()
    assert exit_code == 0


def test_cli_rules_lists_ds114_without_an_opt_in_marker(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies `docsentinel rules` surfaces DS114.

    Scenario:
        Given the installed rule registry
        When the rules command prints the active catalog
        Then DS114 and its title appear with no ``[opt-in: ...]`` marker, unlike DS110/DS112, because DS114 is
        an ordinary always-active rule.

    Boundaries:
        - Focus: rules-command surfacing of DS114 as a non-opt-in rule
        - Fixtures/params: capsys

    On failure, first check:
        - Whether rules_for_profile('fast') still returns DS114
        - Whether DS114 grew an opt_in_option that added a marker
    """
    exit_code = cli.main(["rules"])

    captured = capsys.readouterr()
    assert exit_code == 0
    ds114_lines = [line for line in captured.out.splitlines() if "DS114:" in line]
    assert ds114_lines == ["  DS114: Duplicate stable document identifiers"]
    assert "opt-in" not in ds114_lines[0]


def test_cli_doctor_counts_ds114_as_an_ordinary_fast_rule(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] detectors document identity uniqueness ds114: verifies `docsentinel doctor` counts DS114.

    Scenario:
        Given the installed rule registry
        When the doctor command reports environment readiness
        Then the fast-rule tally reads exactly
            "16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)",
            so DS114 is inside the registered count and is not one of the opt-in rules.

    Boundaries:
        - Focus: doctor's separate accounting of opt-in versus always-active fast rules
        - Fixtures/params: capsys

    On failure, first check:
        - Whether the registered fast-rule count changed when a rule was added
        - Whether DS114 was miscounted as opt-in
    """
    exit_code = cli.main(["doctor"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DS114" in {rule.code for rule in rules_for_profile("fast")}
    assert "fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)" in captured.out


def _multi_document_corpus(tmp_path: Path, shape: str, size: int) -> tuple[Path, tuple[models.Document, ...]]:
    """Write a per-size corpus of ``size`` documents for a flood shape and return it.

    :param tmp_path: The pytest temporary directory.
    :param shape: ``"distinct_ids"`` (every id unique) or ``"identical_ids"`` (one shared id).
    :param size: Number of documents to materialize.
    :returns: The ``(root, documents)`` pair for one detect run.
    """
    root = tmp_path / f"{shape}_{size}"
    root.mkdir()
    documents: list[models.Document] = []
    for index in range(size):
        identity = f"unique{index}" if shape == "distinct_ids" else "shared"
        name = f"doc{index:06d}.md"
        (root / name).write_text(f"---\nid: {identity}\n---\n", encoding="utf-8")
        documents.append(models.Document(name, 0))
    return root, tuple(documents)


@pytest.mark.parametrize(("shape", "expected"), [("distinct_ids", lambda n: 0), ("identical_ids", lambda n: n - 1)])
def test_multi_document_floods_stay_linear(
    shape: str,
    expected: Callable[[int], int],
    tmp_path: Path,
):
    """
    [Integration] detectors document identity uniqueness ds114: verifies many-document corpora scale near-linearly.

    Scenario:
        Given a doubling series of real-file corpora with either pairwise-distinct ids or one shared id
        When document_ids.detect routes each corpus end to end through the shared scaling helper
        Then the exact finding count holds at every size (0 for distinct, n-1 for the shared id) and the
        scaling stays under the shared linear bound, proving the collision check is one pass over dict
        membership rather than a pairwise comparison.

    Boundaries:
        - Focus: detect() end-to-end O(n) corpus collision detection, never O(n^2) pairwise
        - Fixtures/params: parametrized over the distinct and identical multi-document floods; tmp_path

    On failure, first check:
        - Whether the originals dict lookup degraded into a per-document scan
        - That the exact finding count for this shape still holds at every size
    """

    def _build(size: int) -> tuple[Path, tuple[models.Document, ...]]:
        """Materialize the shape's corpus at ``size`` and return it (untimed).

        :param size: The corpus size to build.
        :returns: The ``(root, documents)`` pair for detect().
        """
        return _multi_document_corpus(tmp_path, shape, size)

    def _run(payload: tuple[Path, tuple[models.Document, ...]]) -> tuple[models.Finding, ...]:
        """Run detect over one pre-built corpus.

        :param payload: The ``(root, documents)`` pair from ``_build``.
        :returns: The DS114 findings.
        """
        root, documents = payload
        return document_ids.detect(root, documents, Config(profile="fast"))

    assert_scales_linearly(
        _build,
        _run,
        (250, 500, 1_000, 2_000),
        expected_count=expected,
        label=f"ds114-{shape}",
    )


#: Single-document frontmatter flood shapes: one document grows along one dimension (a
#: giant single value line, or many keys kept under the reader's line cap), each yielding
#: zero findings, mapped to a builder and its doubling sizes.
_SINGLE_DOC_FLOODS: dict[str, tuple[Callable[[int], str], tuple[int, ...]]] = {
    "giant_identity_line": (
        lambda n: "---\nid: " + "a" * n + "\n---\n",
        (8_000, 16_000, 32_000, 56_000),
    ),
    "many_frontmatter_keys": (
        lambda n: "---\n" + "".join(f"k{i}: v{i}\n" for i in range(n)) + "id: tail\n---\n",
        (200, 400, 800, 1_600),
    ),
}


@pytest.mark.parametrize("shape", sorted(_SINGLE_DOC_FLOODS))
def test_single_document_frontmatter_floods_stay_linear(shape: str, tmp_path: Path):
    """
    [Integration] detectors document identity uniqueness ds114: verifies a giant frontmatter scales near-linearly.

    Scenario:
        Given a doubling series of single documents whose frontmatter has either one very long id value line
            or very many keys, written as real files
        When document_ids.detect routes each through the shared scaling helper
        Then zero findings are produced at every size and the scaling stays under the linear bound, proving
        the bounded head read makes one linear pass with no quadratic value or line handling.

    Boundaries:
        - Focus: detect() end-to-end single linear pass over the head (no tail rescans, no quadratic)
        - Fixtures/params: parametrized over the giant-line and many-keys floods; tmp_path

    On failure, first check:
        - Whether _find_key_colon, the comment strip, or the quote parser rescanned the value
        - That zero findings still hold at every size
    """
    build, sizes = _SINGLE_DOC_FLOODS[shape]

    def _build(size: int) -> tuple[Path, tuple[models.Document, ...]]:
        """Write the shape's single document at ``size`` and return it (untimed).

        :param size: The flood size to materialize.
        :returns: The ``(root, documents)`` pair for detect().
        """
        root = tmp_path / f"{shape}_{size}"
        root.mkdir()
        (root / "only.md").write_text(build(size), encoding="utf-8")
        return root, (models.Document("only.md", 0),)

    def _run(payload: tuple[Path, tuple[models.Document, ...]]) -> tuple[models.Finding, ...]:
        """Run detect over one pre-built single-document corpus.

        :param payload: The ``(root, documents)`` pair from ``_build``.
        :returns: The DS114 findings.
        """
        root, documents = payload
        return document_ids.detect(root, documents, Config(profile="fast"))

    assert_scales_linearly(_build, _run, sizes, expected_count=lambda _n: 0, label=f"ds114-{shape}")
