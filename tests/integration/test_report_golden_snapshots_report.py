"""Golden snapshots of today's ``render(result, fmt)`` output (Milestone 0007, Story 01.0 Task 01).

Each case under ``tests/assets/report/<case>/`` stores a serialized ``result.json`` input plus the
byte-exact ``expected.txt``, ``expected.json`` and ``expected.github`` renderings captured from the
renderer before the telemetry package restructure. They prove later reporting work is inert for the
existing three formats. ``ScanResult`` objects are built directly from the stored input rather than
via a live scan, so the snapshots never depend on detector wording or optional extras.
"""

import json
from collections.abc import Callable

import pytest

from docsentinel.models import Document, Finding, ScanResult
from docsentinel.reporting import render
from tests.asset_helpers import AssetCase

#: Asset group holding the report snapshot cases.
_ASSET_GROUP: str = "report"

#: Snapshot cases: one per profile plus a hostile control/bidi character case.
_CASES: tuple[str, ...] = ("fast", "standard", "deep", "hostile_controls")

#: Output format mapped to the expected-output file name in each case.
_EXPECTED_FILES: dict[str, str] = {
    "text": "expected.txt",
    "json": "expected.json",
    "github": "expected.github",
}


def _read_exact(case: AssetCase, relative_path: str) -> str:
    """Read a case file as UTF-8 without any newline translation.

    :param case: The materialized asset case.
    :param relative_path: File path relative to the case root.
    :returns: The decoded file content, byte-for-byte.
    """
    return case.path(relative_path).read_bytes().decode("utf-8")


def _load_result(case: AssetCase) -> ScanResult:
    """Build the ``ScanResult`` stored in a case's ``result.json``.

    :param case: The materialized asset case.
    :returns: The reconstructed scan result.
    """
    data = json.loads(_read_exact(case, "result.json"))
    return ScanResult(
        schema_version=data["schema_version"],
        profile=data["profile"],
        documents=tuple(Document(**document) for document in data["documents"]),
        findings=tuple(Finding(**finding) for finding in data["findings"]),
        enabled_rules=tuple(data["enabled_rules"]),
        pending=tuple(data["pending"]),
        notice=data["notice"],
    )


@pytest.mark.parametrize("fmt", sorted(_EXPECTED_FILES))
@pytest.mark.parametrize("case_name", _CASES)
def test_render_matches_golden_snapshot(
    case_name: str,
    fmt: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] report golden snapshots: verifies render output is byte-identical to the stored snapshot.

    Scenario:
        Given a stored ScanResult for the fast, standard or deep profile, or one with hostile controls
        When it is rendered as text, json or github
        Then the output equals the committed expected file byte-for-byte.

    Boundaries:
        - Focus: the public ``render(result, fmt)`` contract for all three existing formats
        - Fixtures/params: parametrized over four cases and three formats (twelve snapshots)
        - Scope: rendering only; no discovery or detector runs

    On failure, first check:
        - Whether a reporting change was intended; if so the snapshot needs a deliberate, reviewed update
        - Control/bidi neutralisation in ``reporting._neutralize_controls`` for the hostile case
    """
    case = asset_case(_ASSET_GROUP, case_name)
    expected = _read_exact(case, _EXPECTED_FILES[fmt])

    assert render(_load_result(case), fmt) == expected


def test_hostile_snapshot_contains_no_raw_control_characters(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] report golden snapshots: verifies the hostile case input really carries controls but no output does.

    Scenario:
        Given the hostile_controls case whose paths and messages carry ESC, CR/LF, BEL, NUL, DEL, bidi and zero-width
        When it is rendered in every format
        Then no rendered output contains any of those raw code points.

    Boundaries:
        - Focus: guards that the hostile snapshot stays meaningful (input hostile, output inert)
        - Fixtures/params: the hostile_controls case only
        - Scope: rendering only

    On failure, first check:
        - Whether ``result.json`` was regenerated without its escaped control characters
        - Which code point leaked through the named format
    """
    case = asset_case(_ASSET_GROUP, "hostile_controls")
    result = _load_result(case)
    hostile = ("\x1b", "\r", "\x07", "\x00", "\x7f", "‮", "⁦", "​", " ", "﻿")
    raw_input = "".join(document.path for document in result.documents) + "".join(
        finding.path + finding.message for finding in result.findings
    )
    assert all(character in raw_input for character in hostile)

    for fmt in _EXPECTED_FILES:
        rendered = render(result, fmt)
        leaked = [repr(character) for character in hostile if character in rendered]
        assert not leaked, f"{fmt}: leaked {leaked}"
