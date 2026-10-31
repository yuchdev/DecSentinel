"""Unit tests for ``Finding`` enrichment and structured rule diagnostics (Milestone 0007 Story 01.0 Task 02)."""

import dataclasses
import json

import pytest

from docsentinel.baseline import fingerprint
from docsentinel.engine import evaluated_notice
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.reporting import render

_PLAIN = Finding(rule="DS101", path="a.md", message="dangling link -> x.md", severity="error", line=3)
_ENRICHED = Finding(
    rule="DS101",
    path="a.md",
    message="dangling link -> x.md",
    severity="error",
    line=3,
    column=7,
    value="x.md",
    type="dangling link",
)


def test_fingerprint_ignores_enrichment_fields():
    """
    [Unit] finding enrichment: verifies the baseline fingerprint is unchanged by column/value/type.

    Scenario:
        Given the same finding with and without the enrichment fields
        When both are fingerprinted
        Then the fingerprints are identical and keep the historical ``rule:path:hash`` shape.

    Boundaries:
        - Focus: ``baseline.fingerprint`` invariance
        - Fixtures/params: none
        - Scope: pure function

    On failure, first check:
        - Whether ``fingerprint`` started hashing a new field
    """
    assert fingerprint(_ENRICHED) == fingerprint(_PLAIN)
    assert fingerprint(_PLAIN).startswith("DS101:a.md:")


def test_asdict_gains_only_none_keys_for_unenriched_finding():
    """
    [Unit] finding enrichment: verifies ``asdict`` of a plain finding adds only three ``None`` keys.

    Scenario:
        Given a finding built without the enrichment fields
        When it is converted with ``dataclasses.asdict``
        Then the legacy five keys keep their values and column/value/type are ``None``, in field order.

    Boundaries:
        - Focus: the additive dataclass contract
        - Fixtures/params: none
        - Scope: pure dataclass behaviour

    On failure, first check:
        - Field order and defaults on ``models.Finding``
    """
    assert dataclasses.asdict(_PLAIN) == {
        "rule": "DS101",
        "path": "a.md",
        "message": "dangling link -> x.md",
        "severity": "error",
        "line": 3,
        "column": None,
        "value": None,
        "type": None,
    }
    assert list(dataclasses.asdict(_PLAIN))[:5] == ["rule", "path", "message", "severity", "line"]


def test_enrichment_is_excluded_from_equality_and_hash():
    """
    [Unit] finding enrichment: verifies enriched and plain findings compare and hash equal.

    Scenario:
        Given the same finding with and without the enrichment fields
        When they are compared and hashed
        Then they are equal with equal hashes, while a legacy field difference still breaks equality.

    Boundaries:
        - Focus: ``compare=False`` on the new fields
        - Fixtures/params: none
        - Scope: pure dataclass behaviour

    On failure, first check:
        - The ``field(compare=False)`` declarations on ``models.Finding``
    """
    assert _ENRICHED == _PLAIN
    assert hash(_ENRICHED) == hash(_PLAIN)
    assert dataclasses.replace(_PLAIN, line=4) != _PLAIN


def test_enrichment_fields_follow_line_positionally():
    """
    [Unit] finding enrichment: verifies the new fields are appended after ``line`` positionally.

    Scenario:
        Given a finding built with eight positional arguments
        When its fields are read
        Then the sixth to eighth arguments land in column, value and type, and a ninth is rejected.

    Boundaries:
        - Focus: positional field order (legacy five-argument calls stay valid)
        - Fixtures/params: none
        - Scope: pure dataclass behaviour

    On failure, first check:
        - Whether a field was inserted before ``line``
    """
    finding = Finding("DS103", "b.md", "m", "warning", 1, 2, "v", "t")

    assert (finding.line, finding.column, finding.value, finding.type) == (1, 2, "v", "t")
    with pytest.raises(TypeError):
        Finding("DS103", "b.md", "m", "warning", 1, 2, "v", "t", "extra")


@pytest.mark.parametrize(
    ("profile", "evaluated", "off", "expected"),
    [
        ("fast", 16, (), "16 fast rule(s) evaluated."),
        (
            "fast",
            12,
            (("DS110", "require_fence_languages"), ("DS112", "navigation_indexes")),
            "12 fast rule(s) evaluated; opt-in rule(s) not enabled: "
            "DS110 (set require_fence_languages), DS112 (set navigation_indexes).",
        ),
        ("standard", 4, (), "4 standard rule(s) evaluated."),
        ("deep", 1, (), "1 deep rule(s) evaluated (heuristic, advisory-only)."),
        (
            "fast",
            0,
            (("DS118", "documentation_naming"),),
            "0 fast rule(s) evaluated; opt-in rule(s) not enabled: DS118 (set documentation_naming).",
        ),
    ],
)
def test_evaluated_notice_matches_legacy_text(profile: str, evaluated: int, off: tuple, expected: str):
    """
    [Unit] finding enrichment: verifies the legacy notice is rebuilt from ``rules_evaluated``/``opt_in_off``.

    Scenario:
        Given a profile, an evaluated count and the off opt-in pairs
        When ``evaluated_notice`` builds the notice
        Then it equals the byte-identical legacy string, including the all-opt-in-off edge case.

    Boundaries:
        - Focus: single-source notice construction
        - Fixtures/params: parametrized over fast/standard/deep and opt-in combinations
        - Scope: pure function

    On failure, first check:
        - Punctuation and separators in ``engine.evaluated_notice``
    """
    assert evaluated_notice(profile, evaluated, off) == expected


def test_v1_json_render_excludes_new_fields():
    """
    [Unit] finding enrichment: verifies schema-1 JSON output is identical with and without the new fields.

    Scenario:
        Given two scan results differing only in enrichment and structured diagnostics
        When both are rendered as JSON
        Then the outputs are byte-identical and carry none of the new keys.

    Boundaries:
        - Focus: ``reporting._schema_v1_dict`` exclusions
        - Fixtures/params: none
        - Scope: rendering of in-memory results

    On failure, first check:
        - ``_V1_EXCLUDED_RESULT_KEYS`` / ``_V1_EXCLUDED_FINDING_KEYS`` in ``reporting.py``
    """
    base = {
        "profile": "fast",
        "documents": (Document("a.md", 10),),
        "enabled_rules": ("DS101", "DS110"),
        "pending": (),
        "notice": "1 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages).",
    }
    plain = ScanResult(findings=(_PLAIN,), **base)
    enriched = ScanResult(
        findings=(_ENRICHED,),
        rules_evaluated=1,
        opt_in_off=(("DS110", "require_fence_languages"),),
        **base,
    )

    rendered = render(enriched, "json")
    data = json.loads(rendered)

    assert rendered == render(plain, "json")
    assert set(data) == {"schema_version", "profile", "documents", "findings", "enabled_rules", "pending", "notice"}
    assert set(data["findings"][0]) == {"rule", "path", "message", "severity", "line"}
    assert enriched.findings[0].column == 7  # render must not mutate the result
