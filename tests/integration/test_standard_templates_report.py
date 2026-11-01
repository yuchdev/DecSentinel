"""Golden tests for the five packaged report templates (Milestone 0007, Story 03.0 Task 01).

Each case under ``tests/assets/report/<case>/`` stores a serialized ``result.json``. It is rendered
through ``ReportModel.build`` and the template engine with every packaged template, and compared
byte-for-byte with ``expected.template-<name>``; ``json-v1`` is compared with the Story 01.0
pre-move snapshot ``expected.json`` itself (and with the legacy ``render(result, "json")``). The
cases are built from stored input, never a live scan, so detector wording cannot move the goldens.

Problem ``type`` falls back to the rule title from the static ``RULE_TITLES`` table, so the bytes do
not depend on whether the lazily loaded ``DS2xx`` detectors ran; a subprocess test proves it.
"""

import json
import re
import subprocess
import sys
import textwrap
from collections.abc import Callable

import pytest

from docsentinel.config import Config
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.reporting import render
from docsentinel.telemetry import engine as engine_module
from docsentinel.telemetry.engine import MAX_STEPS, render_template
from docsentinel.telemetry.loader import PACKAGED_TEMPLATES_DIR, load_template
from docsentinel.telemetry.model import ReportModel
from tests.asset_helpers import AssetCase

#: Asset group holding the report cases.
_ASSET_GROUP: str = "report"

#: The Story 01.0 snapshot cases plus the Story 03.0 columns / clean-document / opt-in case.
_CASES: tuple[str, ...] = ("fast", "standard", "deep", "hostile_controls", "columns_clean_docs")

#: The Story 01.0 cases whose ``expected.github`` is the pre-milestone GitHub output.
_LEGACY_CASES: tuple[str, ...] = ("fast", "standard", "deep", "hostile_controls")

#: Packaged templates with an ``expected.template-<name>`` golden.
_GOLDEN_TEMPLATES: tuple[str, ...] = ("text", "github", "json", "json-documents")

#: Every packaged template Story 03.0 Task 01 ships.
_PACKAGED: tuple[str, ...] = ("text", "github", "json", "json-v1", "json-documents")

#: The ten keys of every schema-2 problem record (spec §5), in order.
_PROBLEM_KEYS: tuple[str, ...] = (
    "rule",
    "type",
    "message",
    "value",
    "severity",
    "line",
    "column",
    "fault_class",
    "tier",
    "outcome",
)

#: A finding line of the text template: two spaces, the severity, a colon.
_FINDING_LINE = re.compile(r"^  (error|warning): ")


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
    :returns: The reconstructed scan result; ``rules_evaluated``/``opt_in_off`` default when absent.
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
        rules_evaluated=data.get("rules_evaluated", 0),
        opt_in_off=tuple((code, option) for code, option in data.get("opt_in_off", ())),
    )


def _render(result: ScanResult, name: str, **build_options: object) -> str:
    """Render ``result`` through the report model and one packaged template.

    :param result: The scan result.
    :param name: The packaged template name.
    :param build_options: Extra keyword arguments for ``ReportModel.build``.
    :returns: The rendered report.
    """
    return render_template(load_template(name), ReportModel.build(result, Config(), **build_options))


@pytest.mark.parametrize("name", _PACKAGED)
def test_packaged_template_loads_by_name(name: str):
    """
    [Integration] standard templates report: verifies every packaged template loads by name.

    Scenario:
        Given the five template files under ``telemetry/templates``
        When each is loaded by its bare name
        Then it validates as a packaged template whose name equals its file stem and needs no extension.

    Boundaries:
        - Focus: ``load_template`` packaged-name resolution and the strict validator
        - Fixtures/params: parametrized over the five packaged names
        - Scope: loading only; no rendering

    On failure, first check:
        - The loader ``TemplateError`` text, which names the offending key or variable
        - Whether the file was renamed so its ``name`` no longer equals the stem
    """
    template = load_template(name)

    assert template.name == name
    assert template.origin == "packaged"
    assert template.requires_extensions == ()
    assert (PACKAGED_TEMPLATES_DIR / f"{name}.json").is_file()


@pytest.mark.parametrize("case_name", _CASES)
def test_json_v1_template_equals_pre_move_snapshot(case_name: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard templates report: verifies ``json-v1`` reproduces the schema-1 report byte-for-byte.

    Scenario:
        Given a stored ScanResult per profile, the hostile case and the columns case
        When it is rendered with the ``json-v1`` template
        Then the output equals the pre-move ``expected.json`` snapshot and today's ``render(result, "json")``.

    Boundaries:
        - Focus: schema-1 key order, nesting, the deep-only ``advisory`` key and inventory-only documents
        - Fixtures/params: parametrized over five cases
        - Scope: rendering only; no discovery or detector runs

    On failure, first check:
        - The ``inventory`` context variable (the standard case has a DS204 path outside the inventory)
        - The ``$omit_if`` on ``advisory`` for the deep case
    """
    case = asset_case(_ASSET_GROUP, case_name)
    result = _load_result(case)

    rendered = _render(result, "json-v1")

    assert rendered == _read_exact(case, "expected.json")
    assert rendered == render(result, "json")


@pytest.mark.parametrize("name", _GOLDEN_TEMPLATES)
@pytest.mark.parametrize("case_name", _CASES)
def test_template_matches_golden(
    case_name: str,
    name: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] standard templates report: verifies each packaged template matches its golden output.

    Scenario:
        Given a stored ScanResult
        When it is rendered with the text, github, json or json-documents template
        Then the output equals ``expected.template-<name>`` byte-for-byte.

    Boundaries:
        - Focus: the intended Story 03.0 report shapes
        - Fixtures/params: five cases by four templates; DS2xx detectors deliberately not loaded
        - Scope: rendering only

    On failure, first check:
        - Whether a template change was intended; if so the golden needs a deliberate, reviewed update
        - Whether ``RULE_TITLES`` changed (it feeds the derived problem ``type``)
    """
    case = asset_case(_ASSET_GROUP, case_name)

    assert _render(_load_result(case), name) == _read_exact(case, f"expected.template-{name}")


@pytest.mark.parametrize("case_name", ("deep", "columns_clean_docs", "standard"))
def test_text_findings_sit_under_their_document(case_name: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard templates report: verifies text findings follow their document line and clean documents hide.

    Scenario:
        Given a multi-document case with a clean document and findings out of document order
        When it is rendered with the text template
        Then every finding line follows its own document line with no other document line between,
        and no document without findings appears.

    Boundaries:
        - Focus: spec §4 grouping (the Story 03.0 definition of done for text)
        - Fixtures/params: the deep, columns_clean_docs and standard (out-of-inventory path) cases
        - Scope: rendering only

    On failure, first check:
        - The ``documents_with_problems`` outer loop of ``text.json``
        - The ``doc.bytes`` null branch for a path outside the inventory
    """
    case = asset_case(_ASSET_GROUP, case_name)
    result = _load_result(case)
    lines = _render(result, "text").split("\n")
    flagged = {finding.path for finding in result.findings}
    clean = {document.path for document in result.documents} - flagged
    body = [line for line in lines if not line.startswith(("Schema version:", "Profile:", "Documents:", "Enabled"))]

    current = None
    seen_findings = 0
    for line in body:
        match = _FINDING_LINE.match(line)
        if match is not None:
            assert current is not None, line
            assert line.startswith(f"  {match.group(1)}: {current}: ")
            seen_findings += 1
        elif any(line == path or line.startswith(f"{path} (") for path in flagged):
            current = next(path for path in flagged if line == path or line.startswith(f"{path} ("))
    assert seen_findings == len(result.findings)
    assert not [line for line in lines for path in clean if line.startswith(f"{path} (")]


@pytest.mark.parametrize("case_name", _LEGACY_CASES)
def test_github_template_matches_legacy_escaping(case_name: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard templates report: verifies github lines equal the legacy lines plus the title property.

    Scenario:
        Given a Story 01.0 case (none carry a column) including CR/LF, ``::``, ESC and U+202E in paths and messages
        When it is rendered with the github template
        Then each line equals the pre-milestone ``expected.github`` line with ``,title=<rule>`` added
        before the second ``::``, so escaping of the shared fields is byte-identical.

    Boundaries:
        - Focus: well-formed command, level routing and ``gha_property``/``gha_data`` parity
        - Fixtures/params: the four Story 01.0 cases
        - Scope: rendering only

    On failure, first check:
        - The severity ``group`` branches of ``github.json``
        - Whether findings were reordered (the template groups by document order)
    """
    case = asset_case(_ASSET_GROUP, case_name)
    result = _load_result(case)
    legacy = _read_exact(case, "expected.github").split("\n")
    expected = []
    for line, finding in zip(legacy, result.findings, strict=True):
        _, command, message = line.split("::", 2)
        expected.append(f"::{command},title={finding.rule}::{message}")

    assert _render(result, "github").split("\n") == expected


def test_github_template_routes_levels_and_location(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard templates report: verifies github level and line/col omission come from the template.

    Scenario:
        Given the columns case with errors, warnings, a located column and a column without a line
        When it is rendered with the github template
        Then errors start ``::error``, warnings ``::warning``, ``col`` appears only with a line, and
        ``line`` is omitted when null.

    Boundaries:
        - Focus: the ``when``-driven severity and location branches
        - Fixtures/params: the columns_clean_docs case
        - Scope: rendering only

    On failure, first check:
        - The ``p.line``/``p.column`` null conditions in ``github.json``
    """
    case = asset_case(_ASSET_GROUP, "columns_clean_docs")
    lines = _render(_load_result(case), "github").split("\n")

    assert lines[0] == "::error file=README.md,line=5,col=10,title=DS101::dangling link -> /docs/adr/README.md"
    assert lines[2] == "::warning file=README.md,title=DS103::Unresolvable path: scripts/run.sh"
    assert lines[4] == "::warning file=docs/z.md,line=9,col=1,title=DS102::Stray HTML comment"


@pytest.mark.parametrize("case_name", _CASES)
def test_json_schema2_round_trips_with_ten_key_problems(
    case_name: str,
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] standard templates report: verifies the schema-2 json shape and the bare-list example.

    Scenario:
        Given a stored ScanResult
        When it is rendered with the json and json-documents templates
        Then both parse, every problem has exactly the ten keys, every document (clean ones with
        ``problems: []``) is present, and json-documents is the json ``documents`` list.

    Boundaries:
        - Focus: spec §5 envelope and the clean-document denominator
        - Fixtures/params: parametrized over five cases
        - Scope: rendering only

    On failure, first check:
        - The ``documents`` ``$for`` of ``json.json``
    """
    case = asset_case(_ASSET_GROUP, case_name)
    result = _load_result(case)

    report = json.loads(_render(result, "json"))
    bare = json.loads(_render(result, "json-documents"))

    assert list(report) == ["schema_version", "profile", "run", "summary", "rules", "documents", "pending"]
    assert report["schema_version"] == 2
    assert bare == report["documents"]
    assert {document.path for document in result.documents} <= {entry["path"] for entry in report["documents"]}
    for entry in report["documents"]:
        assert entry["domain"] == "docs"
        assert all(tuple(problem) == _PROBLEM_KEYS for problem in entry["problems"])
    flagged = {finding.path for finding in result.findings}
    for entry in report["documents"]:
        if entry["path"] not in flagged:
            assert entry["problems"] == []
    assert sum(len(entry["problems"]) for entry in report["documents"]) == len(result.findings)


@pytest.mark.parametrize("name", _PACKAGED)
def test_templates_ignore_run_metadata(name: str, asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard templates report: verifies standard templates stay deterministic with run metadata on.

    Scenario:
        Given the columns case
        When it is rendered with and without ``report_include_run_meta``
        Then the bytes are identical, because no standard template references ``run.*``.

    Boundaries:
        - Focus: Task 01 note that standard templates never read ``run.generated_at``/``run.id``
        - Fixtures/params: parametrized over the five packaged templates
        - Scope: rendering only

    On failure, first check:
        - Whether a template started referencing ``run``
    """
    result = _load_result(asset_case(_ASSET_GROUP, "columns_clean_docs"))

    assert _render(result, name, report_include_run_meta=True) == _render(result, name)


def _synthetic_result(documents: int, findings: int) -> ScanResult:
    """Build a deterministic scan result shaped like a large real repository.

    :param documents: Number of inventory documents.
    :param findings: Number of findings, spread round-robin over the documents.
    :returns: A fast-profile result mixing levels, null lines and null columns.
    """
    inventory = tuple(Document(f"docs/{index:05d}.md", 1000 + index) for index in range(documents))
    problems = tuple(
        Finding(
            "DS101" if index % 3 else "DS102",
            inventory[index % documents].path,
            f"dangling link -> /docs/x{index}.md",
            "error" if index % 3 else "warning",
            None if index % 7 == 0 else index % 400 + 1,
            column=None if index % 2 else 5,
            value=f"/docs/x{index}.md",
            type="dangling link",
        )
        for index in range(findings)
    )
    return ScanResult(
        profile="fast",
        documents=inventory,
        findings=problems,
        enabled_rules=("DS101", "DS102"),
        pending=(),
        notice="2 fast rule(s) evaluated.",
        rules_evaluated=2,
    )


@pytest.mark.parametrize("name", _PACKAGED)
def test_templates_render_a_large_report_within_the_step_budget(name: str, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] standard templates report: verifies a 358-document, 5000-finding report fits the budgets.

    Scenario:
        Given a synthetic result at CanonixEngine scale (358 documents, 5000 findings)
        When it is rendered with each packaged template
        Then rendering succeeds and uses under a tenth of ``MAX_STEPS`` (measured: github about 106k,
        json about 62k, text about 38k, json-v1 about 36k).

    Boundaries:
        - Focus: the R5 step cap as the effective size limit (Story 02.0 follow-up)
        - Fixtures/params: the five packaged templates; the budget is observed through a wrapped ``step``
        - Scope: rendering only

    On failure, first check:
        - Whether a template gained per-problem conditions (github costs about 21 steps per problem)
    """
    peak = {"steps": 0}
    original = engine_module._Budget.step

    def counting_step(self: engine_module._Budget, count: int = 1):
        """Delegate to the real step and record the running total."""
        original(self, count)
        peak["steps"] = max(peak["steps"], self.steps)

    monkeypatch.setattr(engine_module._Budget, "step", counting_step)

    rendered = _render(_synthetic_result(358, 5000), name)

    assert rendered
    assert 0 < peak["steps"] < MAX_STEPS // 10


#: Probe run in a fresh isolated interpreter: render the stored result with every golden template
#: before and after loading the standard detectors, and report both renderings as JSON.
_LOAD_STATE_PROBE: str = """
    import json, pathlib, sys
    from docsentinel.config import Config
    from docsentinel.errors import ExtraNotInstalledError
    from docsentinel.models import Document, Finding, ScanResult
    from docsentinel.telemetry.engine import render_template
    from docsentinel.telemetry.loader import load_template
    from docsentinel.telemetry.model import ReportModel

    data = json.loads(pathlib.Path(sys.argv[1]).read_bytes().decode("utf-8"))
    result = ScanResult(
        schema_version=data["schema_version"],
        profile=data["profile"],
        documents=tuple(Document(**document) for document in data["documents"]),
        findings=tuple(Finding(**finding) for finding in data["findings"]),
        enabled_rules=tuple(data["enabled_rules"]),
        pending=tuple(data["pending"]),
        notice=data["notice"],
        rules_evaluated=data.get("rules_evaluated", 0),
        opt_in_off=tuple((code, option) for code, option in data.get("opt_in_off", ())),
    )
    names = ("text", "github", "json", "json-documents")

    def render_all():
        return {name: render_template(load_template(name), ReportModel.build(result, Config())) for name in names}

    preloaded = "docsentinel.detectors.standard" in sys.modules
    before = render_all()
    try:
        from docsentinel.detectors.loader import ensure_standard_loaded
        ensure_standard_loaded()
        after = render_all()
    except ExtraNotInstalledError:
        after = None
    print(json.dumps({"preloaded": preloaded, "before": before, "after": after}))
"""


def test_problem_type_is_independent_of_standard_load_state(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard templates report: verifies DS2xx output is identical before and after the lazy load.

    Scenario:
        Given the standard case (DS201-DS204 findings without a detector ``type``)
        When a fresh interpreter renders it with each golden template, then loads the standard
        detectors and renders it again
        Then the standard package was not loaded for the first rendering, both renderings are
        identical, and both equal the checked-in goldens.

    Boundaries:
        - Focus: regression for the order-dependent ``type``/``rule_title`` of lazily registered rules
        - Fixtures/params: the standard case; one isolated subprocess, so no earlier import can mask it
        - Scope: rendering only; skips the after-load half when ``docsentinel[standard]`` is missing

    On failure, first check:
        - ``RULE_TITLES`` and ``rule_title`` in ``telemetry/classify.py``
        - Whether ``telemetry/model.py`` started reading titles from ``RULES`` again
    """
    case = asset_case(_ASSET_GROUP, "standard")
    completed = subprocess.run(
        [sys.executable, "-I", "-c", textwrap.dedent(_LOAD_STATE_PROBE), str(case.path("result.json"))],
        capture_output=True,
        text=True,
        check=True,
    )
    report = json.loads(completed.stdout)

    assert report["preloaded"] is False
    for name, rendered in report["before"].items():
        assert rendered == _read_exact(case, f"expected.template-{name}"), name
    if report["after"] is None:
        pytest.skip("docsentinel[standard] is not installed; only the unloaded rendering was checked")
    assert report["after"] == report["before"]


def test_header_counts_inventory_documents_only(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] standard templates report: verifies document counts exclude out-of-inventory finding paths.

    Scenario:
        Given the standard case with two inventory documents and a DS204 finding on ``src/calc.py``
        When it is rendered with the text and json templates
        Then the text header reads ``Documents: 2 (2 with problems)`` like the legacy ``Documents: 2``,
        the json summary counts 2 and 2, and ``src/calc.py`` is still listed with its finding.

    Boundaries:
        - Focus: regression for the header counting the appended out-of-inventory document
        - Fixtures/params: the standard case
        - Scope: rendering only

    On failure, first check:
        - ``documents_count``/``documents_with_problems_count`` in ``ReportModel.build``
    """
    case = asset_case(_ASSET_GROUP, "standard")
    result = _load_result(case)

    text = _render(result, "text").split("\n")
    report = json.loads(_render(result, "json"))

    assert text[2] == "Documents: 2 (2 with problems)"
    assert _read_exact(case, "expected.txt").split("\n")[2] == f"Documents: {len(result.documents)}"
    assert "src/calc.py" in text
    assert report["summary"]["documents"] == 2
    assert report["summary"]["documents_with_problems"] == 2
    assert [entry["path"] for entry in report["documents"]] == ["docs/a.md", "docs/b.md", "src/calc.py"]
    assert report["documents"][-1]["bytes"] is None and len(report["documents"][-1]["problems"]) == 1
