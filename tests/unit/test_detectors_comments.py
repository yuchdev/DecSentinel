"""Unit tests for DS102 helper logic: rule metadata and fenced-block blanking.

Detection over documents is covered by ``tests/integration/test_detectors_comments_ds102.py``.
"""

import importlib
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Optional
from unittest import mock

import pytest

from docsentinel import models, rules

comments: types.ModuleType


@pytest.fixture(scope="module", autouse=True)
def isolate_rule_registration() -> Iterator[None]:
    """Isolate rule registrations before and after running tests in this module."""
    saved_rules = rules.RULES.copy()
    global comments
    comments = importlib.import_module("docsentinel.detectors.comments")
    yield
    rules.RULES.clear()
    rules.RULES.update(saved_rules)


def test_rule_metadata_is_exact():
    """
    [Unit] detectors comments: verifies rule metadata is exact.

    Scenario:
        Given test inputs and fixtures for rule metadata is exact
        When test_rule_metadata_is_exact executes the target flow
        Then the expected outcome for rule metadata is exact is confirmed.

    Boundaries:
        - Focus: rule metadata is exact
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to rule metadata is exact
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by detectors comments
    """
    assert rules.RULES["DS102"] is comments.DS102
    assert comments.DS102.code == "DS102"
    assert comments.DS102.profile == "fast"
    assert comments.DS102.title == "Stray HTML comment"
    assert comments.DS102.description == "An HTML comment was left in rendered Markdown."
    assert comments.DS102.severity == "warning"


def test_strip_fenced_blocks_blanks_fence_lines_and_body_preserving_offsets():
    """
    [Unit] detectors comments: verifies strip fenced blocks blanks fence lines and body preserving offsets.

    Scenario:
        Given test inputs and fixtures for strip fenced blocks blanks fence lines and body preserving offsets
        When test_strip_fenced_blocks_blanks_fence_lines_and_body_preserving_offsets executes the target flow
        Then the expected outcome for strip fenced blocks blanks fence lines and body preserving offsets is confirmed.

    Boundaries:
        - Focus: strip fenced blocks blanks fence lines and body preserving offsets
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to strip fenced blocks blanks fence lines and body preserving offsets
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by detectors comments
    """
    text = "intro\n```html\n<!-- example -->\n```\ntext\n"

    stripped = comments._strip_fenced_blocks(text)

    assert len(stripped) == len(text)
    assert stripped.count("\n") == text.count("\n")
    assert stripped.splitlines()[0] == "intro"
    assert stripped.splitlines()[4] == "text"
    assert "<!--" not in stripped
    assert "```" not in stripped


def test_strip_fenced_blocks_leaves_unfenced_text_untouched():
    """
    [Unit] detectors comments: verifies strip fenced blocks leaves unfenced text untouched.

    Scenario:
        Given test inputs and fixtures for strip fenced blocks leaves unfenced text untouched
        When test_strip_fenced_blocks_leaves_unfenced_text_untouched executes the target flow
        Then the expected outcome for strip fenced blocks leaves unfenced text untouched is confirmed.

    Boundaries:
        - Focus: strip fenced blocks leaves unfenced text untouched
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to strip fenced blocks leaves unfenced text untouched
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by detectors comments
    """
    text = "before\n<!-- visible -->\nafter\n"

    assert comments._strip_fenced_blocks(text) == text


def test_strip_fenced_blocks_requires_matching_marker_to_close_fence():
    """
    [Unit] detectors comments: verifies strip fenced blocks requires matching marker to close fence.

    Scenario:
        Given test inputs and fixtures for strip fenced blocks requires matching marker to close fence
        When test_strip_fenced_blocks_requires_matching_marker_to_close_fence executes the target flow
        Then the expected outcome for strip fenced blocks requires matching marker to close fence is confirmed.

    Boundaries:
        - Focus: strip fenced blocks requires matching marker to close fence
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to strip fenced blocks requires matching marker to close fence
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by detectors comments
    """
    text = "```html\n~~~\n<!-- still fenced -->\n```\n<!-- visible -->\n"

    stripped = comments._strip_fenced_blocks(text)

    assert "still fenced" not in stripped
    assert "<!-- visible -->" in stripped


@pytest.mark.parametrize(
    ("text", "expected"),
    (
        ("é🙂 <!-- a --><!-- b -->", [(1, 4), (1, 14)]),
        ("\n  <!-- a --> x <!-- b -->", [(2, 3), (2, 16)]),
        ("é <!-- a\nb -->🙂<!-- c -->", [(1, 3), (2, 7)]),
        ("<!-- a -->\n\n gap\né <!-- b -->", [(1, 1), (4, 3)]),
        ("<!-- unclosed\n", []),
    ),
    ids=("same-line-unicode", "cached-line-start", "multiline", "gaps", "unclosed"),
)
def test_detect_locations_search_only_since_previous_match(
    tmp_path: Path, text: str, expected: list[tuple[int, int]]
):
    """
    [Unit] detectors comments: preserves locations with bounded newline searches.

    Scenario:
        Given comments on the same line, across lines, after gaps, or unclosed
        When detection locates each comment
        Then exact code-point locations and disjoint search intervals are preserved.

    Boundaries:
        - Focus: cached line start and incremental newline searches
        - Fixtures/params: isolated root, Markdown text, expected locations
        - Scope: detector logic with document reading and fence stripping mocked

    On failure, first check:
        - Newline search bounds and cached line start in comments.detect

    :param tmp_path: The isolated scan root.
    :param text: Already unfenced Markdown supplied by the mocked reader.
    :param expected: Exact one-based line and code-point column pairs.
    """
    searches: list[tuple[int, int]] = []

    class TrackedText(str):
        """Record newline-search bounds without changing string semantics."""

        def rfind(self, sub: str, start: int = 0, end: Optional[int] = None) -> int:
            """Record newline intervals and delegate to the built-in search.

            :param sub: The searched substring.
            :param start: The inclusive lower bound.
            :param end: The exclusive upper bound, or the string length.
            :returns: The rightmost matching offset, or minus one.
            """
            stop = len(self) if end is None else end
            if sub == "\n":
                searches.append((start, stop))
            return super().rfind(sub, start, stop)

    tracked = TrackedText(text)
    document = models.Document(path="README.md", bytes=len(text.encode("utf-8")))
    with (
        mock.patch.object(comments, "_read_text", return_value=tracked),
        mock.patch.object(comments, "_strip_fenced_blocks", return_value=tracked),
    ):
        findings = comments.detect(tmp_path, (document,))

    assert [(finding.line, finding.column) for finding in findings] == expected
    starts = [match.start() for match in comments._COMMENT_RE.finditer(text)]
    previous_starts = [0, *starts[:-1]] if starts else []
    assert searches == list(zip(previous_starts, starts, strict=True))
