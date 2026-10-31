"""Integration tests: loader + ``ReportModel`` + renderer against the legacy report sinks.

Milestone 0007 Story 02.0 Task 02. A severity-routing ``github``-sink template --
``when`` conditions wrapping literal ``::error``/``::warning`` lines -- is validated
by the Task 01 loader, rendered over :meth:`ReportModel.build` of an in-memory scan
with hostile paths and messages, and compared byte-for-byte with the pre-milestone
``reporting.render(result, "github")`` (threat model M6 golden). No asset is read:
the hostile strings are built in the test body. Non-printable code points are
spelled with ``chr()``.
"""

from typing import Any

import pytest

from docsentinel import reporting
from docsentinel.config import Config
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.telemetry import engine
from docsentinel.telemetry.engine import render_template
from docsentinel.telemetry.filters import TemplateError, neutralize
from docsentinel.telemetry.loader import LineNode, LoopNode, VarRef, validate_template
from docsentinel.telemetry.model import ReportModel

ESC = chr(0x1B)
RLO = chr(0x202E)
ZWSP = chr(0x200B)

_HOSTILE_PATH = f"docs/evil{ESC}[31m\r\n::error::spoofed,title=x:{RLO}%0A.md"
_HOSTILE_MESSAGE = f"dangling link -> ##[stop-commands]tok\r\n::warning::forged {ZWSP}100%{chr(0xD800)}"


def _command(level: str, with_line: bool) -> str:
    """Return one literal workflow command line of the routing template."""
    location = "file={p.document_path|gha_property}"
    if with_line:
        location += ",line={p.line|gha_property}"
    return f"::{level} {location}::{{p.message|gha_data}}"


def _routed(level: str, severity: dict[str, Any], with_line: bool) -> dict[str, Any]:
    """Return a ``line`` node routed by severity and by whether ``p.line`` is null."""
    has_line = {"not": {"var": "p.line", "eq": None}} if with_line else {"var": "p.line", "eq": None}
    used = ["p.document_path", "p.message"] + (["p.line"] if with_line else [])
    return {
        "type": "line",
        "text": _command(level, with_line),
        "variables_used": used,
        "when": {"all": [severity, has_line]},
    }


_IS_ERROR: dict[str, Any] = {"var": "p.severity", "eq": "error"}
_NOT_ERROR: dict[str, Any] = {"not": _IS_ERROR}

#: Severity-routing github template mirroring the legacy ``_render_github`` output.
GITHUB_ROUTING: dict[str, Any] = {
    "template_version": 1,
    "name": "github-routing",
    "type": "text",
    "output": {"sink": "github"},
    "lines": [
        {
            "type": "loop",
            "over": "findings",
            "as": "p",
            "body": [
                _routed("error", _IS_ERROR, True),
                _routed("error", _IS_ERROR, False),
                _routed("warning", _NOT_ERROR, True),
                _routed("warning", _NOT_ERROR, False),
            ],
        }
    ],
}


def _result() -> ScanResult:
    """Return a scan with hostile, located and unlocated findings over three severities."""
    findings = (
        Finding(rule="DS101", path=_HOSTILE_PATH, message=_HOSTILE_MESSAGE, severity="error", line=7),
        Finding(rule="DS102", path="docs/a.md", message="stray comment: a,b", severity="warning", line=None),
        Finding(rule="DS103", path="docs/a.md", message=f"missing {RLO}path", severity="error", line=None),
        Finding(rule="DS301", path=_HOSTILE_PATH, message="contradiction %", severity="info", line=2),
    )
    return ScanResult(
        profile="fast",
        documents=(Document(path="docs/a.md", bytes=3), Document(path=_HOSTILE_PATH, bytes=9)),
        findings=findings,
        enabled_rules=("DS101", "DS102", "DS103"),
        pending=(),
    )


def test_severity_routing_github_template_matches_legacy_sink_byte_for_byte():
    """
    [Integration] renderer: verifies a severity-routing github template reproduces reporting's github output.

    Scenario:
        Given hostile CR/LF, ESC, U+202E, ``::``, ``,``, ``:``, ``%``, ``##[`` and a lone surrogate in paths
            and messages, with located and unlocated findings at error, warning and info severity
        When the routing template renders ``ReportModel.build`` of the scan
        Then the output equals ``reporting.render(result, "github")`` byte for byte.

    Boundaries:
        - Focus: threat model M6 golden; level routing is data (``when``), not Python
        - Fixtures/params: in-memory ScanResult, default Config
        - Scope: validate_template -> ReportModel.build -> render_template

    On failure, first check:
        - ``filters.gha_property`` / ``gha_data`` against ``reporting._escape_*``
        - Condition evaluation of ``eq null`` / ``not``
    """
    result = _result()
    template = validate_template(GITHUB_ROUTING)

    rendered = render_template(template, ReportModel.build(result, Config()))

    assert rendered == reporting.render(result, "github")
    lines = rendered.split("\n")
    assert [line.split(" ", 1)[0] for line in lines] == ["::error", "::warning", "::error", "::warning"]
    assert all(neutralize(line) == line for line in lines)
    assert "##[stop-commands]tok%0D%0A::warning::forged" in lines[0]


def test_github_routing_template_pins_gha_property_on_file_and_gha_data_on_message():
    """
    [Integration] renderer: verifies the github golden routes file=/line= through gha_property and the message through gha_data.

    Scenario:
        Given the validated routing template
        When the filter chain of every variable is inspected, and ``neutralize`` is swapped in for ``file=``
        Then ``file``/``line`` end with ``gha_property``, the message with ``gha_data``, and the swap is rejected.

    Boundaries:
        - Focus: threat model M6 (only gha_* count as sinks under github)
        - Fixtures/params: none
        - Scope: parsed template form and validate_template

    On failure, first check:
        - ``GITHUB_ROUTING`` text, then the loader's ``_check_ref``
    """
    template = validate_template(GITHUB_ROUTING)
    loop = template.lines[0]
    assert isinstance(loop, LoopNode)
    chains: dict[str, set[str]] = {}
    for node in loop.body:
        assert isinstance(node, LineNode) and node.text.parts[0].startswith(("::error ", "::warning "))
        for part in node.text.parts:
            if isinstance(part, VarRef):
                chains.setdefault(part.name, set()).add(part.filters[-1].name)
    assert chains == {"p.document_path": {"gha_property"}, "p.line": {"gha_property"}, "p.message": {"gha_data"}}

    weakened = {
        **GITHUB_ROUTING,
        "lines": [{**GITHUB_ROUTING["lines"][0], "body": [dict(GITHUB_ROUTING["lines"][0]["body"][0])]}],
    }
    weakened["lines"][0]["body"][0]["text"] = _command("error", True).replace(
        "document_path|gha_property", "document_path|neutralize"
    )
    with pytest.raises(TemplateError):
        validate_template(weakened)


def test_spec_text_excerpt_renders_findings_under_their_document():
    """
    [Integration] renderer: verifies the spec §4 text excerpt renders a scan with findings under their document.

    Scenario:
        Given the spec §4 header, opt-in append loop and document/problem block loops
        When rendered over ``ReportModel.build`` of a hostile scan
        Then each finding line directly follows its document line, clean documents are absent,
            and hostile code points are neutralized exactly as the legacy text sink does.

    Boundaries:
        - Focus: cross-module normal case (model + loader + renderer + filters)
        - Fixtures/params: in-memory ScanResult, default Config
        - Scope: validate_template -> ReportModel.build -> render_template

    On failure, first check:
        - ``ReportModel.build`` grouping, then ``_Renderer._loop``
    """
    result = ScanResult(
        profile="fast",
        documents=(Document(path="docs/clean.md", bytes=1),) + _result().documents,
        findings=_result().findings[:3],
        enabled_rules=("DS101",),
        pending=(),
        rules_evaluated=12,
        opt_in_off=(("DS110", "require_fence_languages"),),
    )
    lines: list[dict[str, Any]] = [
        {"type": "line", "text": "Profile: {profile}", "variables_used": ["profile"]},
        {"type": "line", "text": "Enabled rules: {enabled_rules|json}", "variables_used": ["enabled_rules"]},
        {
            "type": "line",
            "when": {"var": "opt_in_off", "truthy": True},
            "text": "{rules_evaluated} {rules_type} rule(s) evaluated; opt-in rule(s) not enabled: ",
            "variables_used": ["rules_evaluated", "rules_type"],
        },
        {
            "type": "loop",
            "over": "opt_in_off",
            "as": "rule",
            "placement": "append",
            "separator": ", ",
            "text": "{rule.code} (set {rule.option})",
            "variables_used": ["rule.code", "rule.option"],
        },
        {
            "type": "loop",
            "over": "documents_with_problems",
            "as": "doc",
            "body": [
                {
                    "type": "line",
                    "text": "{doc.path|neutralize} ({doc.bytes} bytes)",
                    "variables_used": ["doc.path", "doc.bytes"],
                },
                {
                    "type": "loop",
                    "over": "doc.problems",
                    "as": "p",
                    "body": [
                        {
                            "type": "line",
                            "text": "  {p.severity}: {doc.path|neutralize}: {p.message|neutralize}",
                            "variables_used": ["p.severity", "doc.path", "p.message"],
                        }
                    ],
                },
            ],
        },
    ]
    template = validate_template({"template_version": 1, "name": "text", "type": "text", "lines": lines})

    rendered = render_template(template, ReportModel.build(result, Config())).split("\n")

    hostile = reporting._neutralize_controls(_HOSTILE_PATH)
    assert rendered == [
        "Profile: fast",
        'Enabled rules: ["DS101"]',
        "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages)",
        "docs/a.md (3 bytes)",
        "  warning: docs/a.md: stray comment: a,b",
        "  error: docs/a.md: " + reporting._neutralize_controls(f"missing {RLO}path"),
        f"{hostile} (9 bytes)",
        f"  error: {hostile}: " + reporting._neutralize_controls(_HOSTILE_MESSAGE),
    ]
    assert all(neutralize(line) == line for line in rendered)


def test_realistic_report_stays_far_below_the_step_budget(monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] renderer: verifies a 358-document, 5000-finding report uses under a tenth of MAX_STEPS (R5).

    Scenario:
        Given an in-memory scan of 358 documents and 5000 located error/warning findings
        When the severity-routing github template renders ``ReportModel.build`` of it under the real caps
        Then it equals ``reporting.render(result, "github")`` and the steps charged stay below
            ``MAX_STEPS // 10`` (the margin the engine documents).

    Boundaries:
        - Focus: the R5 step cap must never reject a realistic report (ADR 0003 corpus size)
        - Fixtures/params: synthetic ScanResult; spy on ``engine._Budget.step``
        - Scope: validate_template -> ReportModel.build -> render_template

    On failure, first check:
        - The value of ``engine.MAX_STEPS`` and the per-node ``step`` charges in ``_Renderer``
    """
    documents = tuple(Document(path=f"docs/d{index:03d}.md", bytes=1000) for index in range(358))
    findings = tuple(
        Finding(
            rule="DS101",
            path=documents[index % 358].path,
            message="dangling link -> x.md",
            severity=("error", "warning")[index % 2],
            line=index + 1,
        )
        for index in range(5000)
    )
    result = ScanResult(profile="fast", documents=documents, findings=findings, enabled_rules=("DS101",), pending=())
    total = {"steps": 0}
    real = engine._Budget.step

    def step(self: Any, count: int = 1):
        """Add ``count`` to the total, then take the real step."""
        total["steps"] += count
        real(self, count)

    monkeypatch.setattr(engine._Budget, "step", step)

    rendered = render_template(validate_template(GITHUB_ROUTING), ReportModel.build(result, Config()))

    assert rendered == reporting.render(result, "github")
    assert 0 < total["steps"] < engine.MAX_STEPS // 10
