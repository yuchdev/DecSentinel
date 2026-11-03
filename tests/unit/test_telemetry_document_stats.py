"""Unit tests for ``builtin:document_stats`` and the builtin cost bound (Milestone 0007 Story 04.0 Task 02).

Pins threat model ``docs/security/threat-model-0007-extensions-2026-11-03.md`` M34 (``bytes: null``,
zero-byte documents, deterministic tie-break, at most five worst documents) and M18 (both builtins
stay linear on 50k documents).
"""

import json
import time
from pathlib import Path

import pytest

from docsentinel.config import Config
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.reporting import render
from docsentinel.telemetry.builtin import BUILTIN_EXTENSIONS, RESERVED_BUILTIN_NAMES, domain
from docsentinel.telemetry.builtin.document_stats import WORST_DOCUMENTS, problem_count_per_kb
from docsentinel.telemetry.extensions import resolve_extensions
from docsentinel.telemetry.model import ReportModel

BOTH = ("builtin:domain", "builtin:document_stats")


def _result(documents: tuple[Document, ...], findings: tuple[Finding, ...]) -> ScanResult:
    """Return a fast-profile scan result."""
    return ScanResult(profile="fast", documents=documents, findings=findings, enabled_rules=("DS101",), pending=())


def _finding(path: str) -> Finding:
    """Return one DS101 error on ``path``."""
    return Finding("DS101", path, "dangling link -> x.md", "error", 1)


def _context(result: ScanResult) -> dict:
    """Build the context with ``builtin:document_stats`` resolved through the static table."""
    settings = Config()
    loaded = resolve_extensions(
        ("builtin:document_stats",), config=settings, allow_python=False, root=Path.cwd(), cwd=Path.cwd()
    )
    return ReportModel.build(result, settings, extensions=loaded)


@pytest.mark.parametrize(
    ("problems", "size", "expected"),
    [
        (2, 80, 25.6),
        (1, 68, 15.059),
        (0, 100, 0.0),
        (3, 0, 0.0),
        (0, 0, 0.0),
        (1, None, None),
        (1, True, None),
        (-1, 10, None),
        (1, 3, 341.333),
    ],
)
def test_problem_count_per_kb_handles_null_zero_and_rounding(problems: object, size: object, expected: object):
    """
    [Unit] document stats: verifies the density formula, ``bytes: null`` and zero-byte documents (M34).

    Scenario:
        Given problem counts and byte sizes including ``None``, ``0``, a bool and a negative count
        When ``problem_count_per_kb`` computes the density
        Then it is ``round(problems / (bytes / 1024), 3)``, ``0.0`` for zero bytes, and ``None`` otherwise.

    Boundaries:
        - Focus: the M34 edge cases; never NaN or infinite
        - Fixtures/params: one (problems, bytes) pair per case
        - Scope: ``document_stats.problem_count_per_kb``

    On failure, first check:
        - the exact-int guards in ``problem_count_per_kb``
    """
    assert problem_count_per_kb(problems, size) == expected
    if expected is not None:
        assert type(expected) is float


def test_out_of_inventory_finding_gets_null_and_is_not_ranked():
    """
    [Unit] document stats: verifies a finding outside the inventory (``bytes: null``) is null and unranked (M34).

    Scenario:
        Given a DS204 finding on ``src/x.py`` (not a discovered document) and one DS101 finding on ``a.md``
        When the context is built with ``builtin:document_stats``
        Then ``src/x.py`` has ``problem_count_per_kb: None`` and ``worst_documents`` lists only ``a.md``.

    Boundaries:
        - Focus: the standard-profile DS204 case that would otherwise raise TypeError (T13)
        - Fixtures/params: none
        - Scope: ``DocumentStatsExtension`` via ``ReportModel.build``

    On failure, first check:
        - ``document_stats._ranked``
    """
    orphan = Finding("DS204", "src/x.py", "docstring mismatch", "warning", 2)
    context = _context(_result((Document("a.md", 512),), (_finding("a.md"), orphan)))

    stats = {doc["path"]: doc["ext"]["document_stats"] for doc in context["documents"]}
    assert stats == {"a.md": {"problem_count_per_kb": 2.0}, "src/x.py": {"problem_count_per_kb": None}}
    assert [entry["path"] for entry in context["ext"]["document_stats"]["worst_documents"]] == ["a.md"]


def test_zero_byte_document_with_problems_is_zero_density():
    """
    [Unit] document stats: verifies an empty document with a problem is ``0.0``, not a division error (M34).

    Scenario:
        Given a zero-byte document carrying one finding
        When the context is built with ``builtin:document_stats``
        Then its density is ``0.0`` and it is ranked with that density.

    Boundaries:
        - Focus: no ZeroDivisionError, no infinity
        - Fixtures/params: none
        - Scope: ``DocumentStatsExtension``

    On failure, first check:
        - the ``size == 0`` branch of ``problem_count_per_kb``
    """
    context = _context(_result((Document("empty.md", 0),), (_finding("empty.md"),)))

    assert context["documents"][0]["ext"]["document_stats"] == {"problem_count_per_kb": 0.0}
    assert context["ext"]["document_stats"]["worst_documents"] == [
        {"path": "empty.md", "bytes": 0, "problem_count": 1, "problem_count_per_kb": 0.0}
    ]


def test_worst_documents_breaks_ties_by_path_and_keeps_five():
    """
    [Unit] document stats: verifies the ``(-density, path)`` order, the five-entry cap and clean documents left out.

    Scenario:
        Given eight equally dense documents named out of order, one denser document and one clean document
        When the context is built with ``builtin:document_stats``
        Then ``worst_documents`` holds five entries: the densest first, then the tied ones in path order.

    Boundaries:
        - Focus: deterministic tie-break and the heap of size five (M34)
        - Fixtures/params: none
        - Scope: ``DocumentStatsExtension.provide_run``

    On failure, first check:
        - the ``heapq.nsmallest`` key in ``provide_run``
    """
    tied = [f"t{index}.md" for index in (7, 2, 5, 0, 6, 1, 4, 3)]
    documents = (*(Document(path, 1024) for path in tied), Document("dense.md", 512), Document("clean.md", 10))
    findings = (*(_finding(path) for path in tied), _finding("dense.md"))

    worst = _context(_result(documents, findings))["ext"]["document_stats"]["worst_documents"]

    assert len(worst) == WORST_DOCUMENTS == 5
    assert [entry["path"] for entry in worst] == ["dense.md", "t0.md", "t1.md", "t2.md", "t3.md"]
    assert [entry["problem_count_per_kb"] for entry in worst] == [2.0, 1.0, 1.0, 1.0, 1.0]


def test_two_runs_produce_identical_bytes():
    """
    [Unit] document stats: verifies the rendered report is byte-identical across runs (M34).

    Scenario:
        Given a scan with tied densities and both builtins requested
        When the packaged ``json`` report is rendered twice, each time in a fresh render
        Then the two outputs are equal byte for byte.

    Boundaries:
        - Focus: determinism of floats, ordering and the domain memo
        - Fixtures/params: none
        - Scope: ``reporting.render``

    On failure, first check:
        - any iteration over a set or dict without a defined order
    """
    documents = (Document("b.md", 100), Document("a.md", 100), Document("c.md", 0))
    result = _result(documents, (_finding("b.md"), _finding("a.md"), _finding("c.md")))
    settings = Config(telemetry_domains=(("**", "docs"),))

    first = render(result, "json", config=settings, extensions=BOTH)
    second = render(result, "json", config=settings, extensions=BOTH)

    assert first == second
    assert json.loads(first)["documents"][0]["domain"] == "docs"


def test_both_builtins_are_registered_and_reserved():
    """
    [Unit] document stats: verifies the static table holds exactly the two shipped builtins.

    Scenario:
        Given the builtin package
        When its table and reserved names are read
        Then both ``domain`` and ``document_stats`` are present and reserved.

    Boundaries:
        - Focus: registration in ``builtin/__init__.py`` (M25)
        - Fixtures/params: none
        - Scope: ``telemetry.builtin``

    On failure, first check:
        - ``BUILTIN_EXTENSIONS``
    """
    assert set(BUILTIN_EXTENSIONS) == {"domain", "document_stats"}
    assert RESERVED_BUILTIN_NAMES == frozenset({"domain", "document_stats"})


def test_both_builtins_stay_linear_on_fifty_thousand_documents(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] document stats: verifies both builtins on 50k documents stay within an op-count and time bound (M18).

    Scenario:
        Given 50,000 documents (half with a finding) under a three-entry domain table and both builtins loaded
        When ``ReportModel.build`` runs every hook
        Then each path is glob-matched at most once per table entry, and the build finishes within 60 seconds.

    Boundaries:
        - Focus: O(D + F) builtins, memoized ``domain_for``, ``worst_documents`` computed once
        - Fixtures/params: counting ``domain.glob_matches``
        - Scope: ``ReportModel.build`` with the resolved builtins

    On failure, first check:
        - ``DomainTable.lookup`` memo and ``DocumentStatsExtension.provide_run``
    """
    count = 50_000
    documents = tuple(Document(f"d{index // 100}/f{index}.md", 1000 + index % 7) for index in range(count))
    findings = tuple(_finding(document.path) for document in documents[::2])
    table = (("docs/**", "docs"), (".claude/**", "agent"), ("**", "other"))
    settings = Config(telemetry_domains=table, telemetry_extensions=BOTH)
    calls = []
    real = domain.glob_matches

    def counting(pattern: tuple[str, ...], path: list[str]) -> bool:
        """Count one glob comparison, then run the real one."""
        calls.append(1)
        return real(pattern, path)

    monkeypatch.setattr(domain, "glob_matches", counting)
    loaded = resolve_extensions((), config=settings, allow_python=False, root=Path.cwd(), cwd=Path.cwd())

    started = time.perf_counter()
    context = ReportModel.build(_result(documents, findings), settings, extensions=loaded)
    elapsed = time.perf_counter() - started

    assert len(calls) <= count * len(table)
    assert elapsed < 60.0
    assert len(context["ext"]["document_stats"]["worst_documents"]) == 5
    assert {doc["domain"] for doc in context["documents"]} == {"other"}
