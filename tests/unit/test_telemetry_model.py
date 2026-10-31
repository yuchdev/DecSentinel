"""Unit tests for ``docsentinel.telemetry.model`` and ``classify`` (Milestone 0007 Story 01.0 Task 02)."""

import importlib
import json
import re
from collections.abc import Mapping

import pytest

from docsentinel.config import Config
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.telemetry.classify import DEFAULT_DOMAIN, UNMAPPED_FAULT_CLASS, classify
from docsentinel.telemetry.model import (
    ADVISORY_BANNER,
    CONTEXT_SCHEMA,
    TRUSTED,
    UNTRUSTED,
    ReportModel,
    Variable,
)

# Importing the engine registers the fast rules; DS301 registers on import of its module.
for _module in ("docsentinel.engine", "docsentinel.detectors.contradictions"):
    importlib.import_module(_module)

_DS101 = Finding(
    rule="DS101",
    path="b.md",
    message="dangling link -> x.md",
    severity="error",
    line=2,
    column=5,
    value="x.md",
    type="dangling link",
)
_DS102 = Finding(rule="DS102", path="b.md", message="stray HTML comment: '<!-- a -->'", severity="warning", line=4)
_DS117 = Finding(rule="DS117", path="c.md", message="table row has 3 cells", severity="warning", line=9)


def _result(findings: tuple[Finding, ...] = (_DS101, _DS102, _DS117), profile: str = "fast") -> ScanResult:
    """Build a tiny scan result over three documents (``a.md`` clean)."""
    return ScanResult(
        profile=profile,
        documents=(Document("a.md", 1), Document("b.md", 2), Document("c.md", 3)),
        findings=findings,
        enabled_rules=("DS101", "DS102", "DS110", "DS117"),
        pending=(),
        notice="3 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages).",
        rules_evaluated=3,
        opt_in_off=(("DS110", "require_fence_languages"),),
    )


def _assert_json_shaped(value: object):
    """Recursively assert ``value`` contains only JSON types with string keys."""
    if isinstance(value, dict):
        for key, item in value.items():
            assert isinstance(key, str), key
            _assert_json_shaped(item)
    elif isinstance(value, list):
        for item in value:
            _assert_json_shaped(item)
    else:
        assert value is None or type(value) in (str, int, float, bool), repr(value)


def _assert_matches_schema(value: Mapping[str, object], schema: Mapping[str, Variable]):
    """Assert a context mapping has exactly the non-opt-in schema keys, recursively."""
    assert set(value) == {name for name, var in schema.items() if not var.opt_in}
    for name, var in schema.items():
        if var.fields and name in value:
            items = value[name] if isinstance(value[name], list) else [value[name]]
            for item in items:
                _assert_matches_schema(item, var.fields)


def test_build_groups_problems_under_their_document():
    """
    [Unit] report model: verifies problems attach to the right document and clean documents have none.

    Scenario:
        Given three documents and findings on b.md (two) and c.md (one)
        When the report model is built
        Then a.md has ``problems == []``, b.md holds both findings in order, and counts add up.

    Boundaries:
        - Focus: document grouping, per-document and run-level counts
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - The ``setdefault`` grouping loop in ``ReportModel.build``
    """
    context = ReportModel.build(_result(), Config())

    by_path = {doc["path"]: doc for doc in context["documents"]}
    assert [doc["path"] for doc in context["documents"]] == ["a.md", "b.md", "c.md"]
    assert by_path["a.md"]["problems"] == [] and by_path["a.md"]["problem_count"] == 0
    assert [p["rule"] for p in by_path["b.md"]["problems"]] == ["DS101", "DS102"]
    assert by_path["b.md"]["severity_counts"] == {"error": 1, "warning": 1}
    assert [doc["path"] for doc in context["documents_with_problems"]] == ["b.md", "c.md"]
    assert context["documents_count"] == 3
    assert context["documents_with_problems_count"] == 2
    assert context["findings_count"] == 3 == sum(doc["problem_count"] for doc in context["documents"])
    assert context["severity_counts"] == {"error": 1, "warning": 2}
    assert context["rule_counts"] == {"DS101": 1, "DS102": 1, "DS117": 1}
    assert [p["document_path"] for p in context["findings"]] == ["b.md", "b.md", "c.md"]


def test_build_problem_fields_and_derived_type():
    """
    [Unit] report model: verifies problem fields, classification and title-derived type.

    Scenario:
        Given an enriched DS101 finding and unenriched DS102/DS117 findings
        When the report model is built
        Then DS101 keeps its detector type/value/column and the others derive type from the rule title.

    Boundaries:
        - Focus: per-problem mapping and ``type`` fallback
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - ``_derived_type`` and ``_problem`` in ``telemetry/model.py``
    """
    problems = ReportModel.build(_result(), Config())["findings"]

    assert problems[0] == {
        "rule": "DS101",
        "rule_title": "Dangling link or anchor",
        "type": "dangling link",
        "message": "dangling link -> x.md",
        "value": "x.md",
        "severity": "error",
        "line": 2,
        "column": 5,
        "fault_class": "dangling_reference",
        "tier": "deterministic",
        "outcome": "rejected",
        "document_path": "b.md",
    }
    assert (problems[1]["type"], problems[1]["value"], problems[1]["outcome"]) == (
        "stray HTML comment",
        None,
        "advisory",
    )
    assert problems[2]["type"] == "malformed GFM pipe-table structure"


def test_build_run_scalars_and_opt_in_list():
    """
    [Unit] report model: verifies run-level scalars, structured opt-in list and default-off values.

    Scenario:
        Given a fast result with one opt-in rule off
        When the report model is built with defaults
        Then ``opt_in_off`` is a list of code/option objects, advisory/model are null and ``run`` is absent.

    Boundaries:
        - Focus: run-level context variables
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - The context literal in ``ReportModel.build``
    """
    context = ReportModel.build(_result(), Config())

    assert context["opt_in_off"] == [{"code": "DS110", "option": "require_fence_languages"}]
    assert (context["rules_evaluated"], context["rules_type"], context["profile"]) == (3, "fast", "fast")
    assert context["enabled_rules"] == ["DS101", "DS102", "DS110", "DS117"]
    assert context["advisory"] is None
    assert context["model"] is None
    assert context["report_schema_version"] == 2
    assert "run" not in context


def test_build_is_json_shaped_and_matches_schema():
    """
    [Unit] report model: verifies the context is pure JSON data whose keys equal the declared schema.

    Scenario:
        Given a tiny result
        When the model is built and serialized
        Then every node is a JSON type and every mapping has exactly the ``CONTEXT_SCHEMA`` keys.

    Boundaries:
        - Focus: JSON-shape guarantee and schema/model parity for the Story 02.0 loader
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - A key added to the model but not to ``CONTEXT_SCHEMA`` (or vice versa)
    """
    context = ReportModel.build(_result(), Config())

    _assert_json_shaped(context)
    _assert_matches_schema(context, CONTEXT_SCHEMA)
    json.dumps(context)


def test_schema_trust_tags_mark_content_derived_variables_untrusted():
    """
    [Unit] report model: verifies the trust tags required by the template-format spec section 6.

    Scenario:
        Given the declared context schema
        When the trust tags of content-derived variables are read
        Then path, message, value, pending and document_path are untrusted and run-level scalars trusted.

    Boundaries:
        - Focus: ``CONTEXT_SCHEMA`` trust tags
        - Fixtures/params: none
        - Scope: module constants

    On failure, first check:
        - The ``UNTRUSTED`` entries in ``telemetry/model.py``
    """
    document = CONTEXT_SCHEMA["documents"].fields
    problem = CONTEXT_SCHEMA["documents"].fields["problems"].fields
    flat = CONTEXT_SCHEMA["findings"].fields

    assert CONTEXT_SCHEMA["pending"].trust == UNTRUSTED
    assert document["path"].trust == UNTRUSTED
    assert problem["message"].trust == UNTRUSTED
    assert problem["value"].trust == UNTRUSTED
    assert flat["document_path"].trust == UNTRUSTED
    assert "document_path" not in problem
    assert CONTEXT_SCHEMA["profile"].trust == TRUSTED
    assert CONTEXT_SCHEMA["run"].opt_in is True


def test_build_is_deterministic():
    """
    [Unit] report model: verifies two builds of the same input are equal.

    Scenario:
        Given the same result and config
        When the model is built twice
        Then the two contexts and their JSON serializations are equal.

    Boundaries:
        - Focus: determinism without run metadata
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - Any per-run value leaking into the default context
    """
    first = ReportModel.build(_result(), Config())
    second = ReportModel.build(_result(), Config())

    assert first == second
    assert json.dumps(first) == json.dumps(second)


def test_run_meta_only_on_request():
    """
    [Unit] report model: verifies ``run.generated_at``/``run.id`` appear only when requested.

    Scenario:
        Given a tiny result
        When the model is built with ``report_include_run_meta=True``
        Then ``run`` holds an RFC-3339 Z timestamp and a hex id, and the rest of the context is unchanged.

    Boundaries:
        - Focus: opt-in per-run values
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - The ``report_include_run_meta`` branch in ``ReportModel.build``
    """
    plain = ReportModel.build(_result(), Config())
    with_meta = ReportModel.build(_result(), Config(), report_include_run_meta=True)

    run = with_meta.pop("run")
    assert set(run) == {"generated_at", "id"}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z", run["generated_at"])
    assert re.fullmatch(r"[0-9a-f]{32}", run["id"])
    assert with_meta == plain


def test_finding_outside_inventory_gets_a_document_entry():
    """
    [Unit] report model: verifies a finding whose path is not discovered still appears under a document.

    Scenario:
        Given a finding on ``src/calc.py`` that is not in the document inventory
        When the model is built
        Then an extra document with ``bytes`` null holds it after the discovered documents.

    Boundaries:
        - Focus: no finding is dropped from document grouping (edge case, e.g. DS204 sources)
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - The orphan ``setdefault`` in ``ReportModel.build``
    """
    orphan = Finding(rule="DS204", path="src/calc.py", message="param mismatch", severity="warning", line=1)

    context = ReportModel.build(_result((orphan,), profile="standard"), Config(profile="standard"))

    assert [doc["path"] for doc in context["documents"]] == ["a.md", "b.md", "c.md", "src/calc.py"]
    assert context["documents"][-1]["bytes"] is None
    assert context["documents"][-1]["problems"][0]["fault_class"] == "contract_mismatch"


def test_empty_result_has_empty_collections():
    """
    [Unit] report model: verifies a scan without findings yields empty problem lists and counts.

    Scenario:
        Given a result with no findings
        When the model is built
        Then documents_with_problems, findings and both count maps are empty.

    Boundaries:
        - Focus: empty-input edge case
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - Counter handling of empty sequences
    """
    context = ReportModel.build(_result(()), Config())

    assert context["documents_with_problems"] == [] and context["findings"] == []
    assert context["severity_counts"] == {} and context["rule_counts"] == {}
    assert all(doc["problems"] == [] for doc in context["documents"])


def test_extensions_are_refused_until_implemented():
    """
    [Unit] report model: verifies a non-empty extension list fails closed instead of being ignored.

    Scenario:
        Given an extension object
        When the model is built with it
        Then ``NotImplementedError`` is raised.

    Boundaries:
        - Focus: invalid-input handling of the not-yet-implemented extension hook
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - The guard at the top of ``ReportModel.build``
    """
    with pytest.raises(NotImplementedError):
        ReportModel.build(_result(), Config(), extensions=(object(),))


def test_deep_result_carries_advisory_banner_and_heuristic_outcome():
    """
    [Unit] report model: verifies the deep banner moves into context data and deep findings are advisory.

    Scenario:
        Given a deep-profile result with an error-severity DS301 finding
        When the model is built
        Then ``advisory`` is the banner and the problem is heuristic/advisory.

    Boundaries:
        - Focus: ``advisory`` variable and heuristic outcome mapping
        - Fixtures/params: none
        - Scope: in-memory model building

    On failure, first check:
        - The ``advisory`` expression and ``classify`` heuristic branch
    """
    deep = Finding(rule="DS301", path="a.md", message="candidate", severity="error", line=1)

    context = ReportModel.build(_result((deep,), profile="deep"), Config(profile="deep"))

    assert context["advisory"] == ADVISORY_BANNER
    assert (context["findings"][0]["tier"], context["findings"][0]["outcome"]) == ("heuristic", "advisory")


@pytest.mark.parametrize(
    ("severity", "strict", "expected"),
    [
        ("error", False, "rejected"),
        ("warning", False, "advisory"),
        ("warning", True, "rejected"),
        ("info", False, None),
    ],
)
def test_classify_outcome_mapping(severity: str, strict: bool, expected: object):
    """
    [Unit] classify: verifies the contract outcome mapping for deterministic findings.

    Scenario:
        Given a DS102 finding with a given severity and strictness
        When it is classified
        Then the outcome follows fault-event contract section 2.2 (unknown severity maps to null).

    Boundaries:
        - Focus: ``classify`` outcome branch
        - Fixtures/params: parametrized severity and ``strict``
        - Scope: pure function

    On failure, first check:
        - The severity branches in ``telemetry/classify.py``
    """
    finding = Finding(rule="DS102", path="a.md", message="m", severity=severity)

    labels = classify(finding, Config(), strict=strict)

    assert labels.outcome == expected
    assert (labels.fault_class, labels.tier, labels.domain) == ("residual_markup", "deterministic", DEFAULT_DOMAIN)


def test_classify_unregistered_rule_is_unmapped_and_uses_config_profile():
    """
    [Unit] classify: verifies an unknown rule falls back to ``unmapped`` and the config profile tier.

    Scenario:
        Given a finding from an unregistered rule code under a deep config
        When it is classified
        Then the fault class is ``unmapped`` and the tier is heuristic.

    Boundaries:
        - Focus: fallback behaviour for a missing table row
        - Fixtures/params: none
        - Scope: pure function

    On failure, first check:
        - ``UNMAPPED_FAULT_CLASS`` and the tier fallback in ``classify``
    """
    labels = classify(Finding(rule="DS999", path="a.md", message="m"), Config(profile="deep"))

    assert (labels.fault_class, labels.tier, labels.outcome) == (UNMAPPED_FAULT_CLASS, "heuristic", "advisory")
