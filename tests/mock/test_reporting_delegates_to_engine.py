"""``reporting.render`` performs no formatting of its own (Milestone 0007 Story 03.0 Task 02).

The template engine and the report model are replaced with stubs: whatever the stubbed engine
returns is exactly what ``render`` returns, and the stubs see the resolved template, the scan and
the configuration-derived options. A template error from the engine surfaces as ``ValueError``.
"""

from typing import Any

import pytest

from docsentinel import reporting
from docsentinel.config import Config
from docsentinel.models import Finding, ScanResult
from docsentinel.telemetry.filters import TemplateError
from docsentinel.telemetry.loader import load_template

_RESULT = ScanResult(
    profile="fast",
    documents=(),
    findings=(Finding(rule="DS101", path="a.md", message="m", severity="error", line=1),),
    enabled_rules=("DS101",),
    pending=(),
)


def test_render_returns_the_engine_output_verbatim(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] reporting delegation (mock): verifies ``render`` returns the stubbed engine output untouched.

    Scenario:
        Given ``ReportModel.build`` and ``render_template`` replaced with recording stubs
        When ``render`` runs with ``format="github"``, a config with both report flags on, and ``strict``
        Then it returns the stub's sentinel string, the engine got the packaged ``github`` template and the
            stub context, and the model got the scan plus the flags.

    Boundaries:
        - Focus: render is resolve -> build -> engine, with no formatting step
        - Fixtures/params: monkeypatched engine and model
        - Scope: the ``reporting`` module only

    On failure, first check:
        - Whether ``render`` post-processes the engine output or bypasses ``ReportModel.build``
    """
    calls: dict[str, Any] = {}
    sentinel_context = {"stub": True}

    def build(result: ScanResult, config: Config, **options: Any) -> dict[str, Any]:
        """Record the model arguments and return a stub context."""
        calls["build"] = (result, config, options)
        return sentinel_context

    def engine(template: Any, context: Any, **options: Any) -> str:
        """Record the engine arguments and return a sentinel report."""
        calls["engine"] = (template, context)
        calls["engine_options"] = options
        return "<<engine output>>"

    monkeypatch.setattr(reporting.ReportModel, "build", staticmethod(build))
    monkeypatch.setattr(reporting, "render_template", engine)
    config = Config(report_show_clean_documents=True, report_include_run_meta=True)

    rendered = reporting.render(_RESULT, "github", config=config, strict=True)

    assert rendered == "<<engine output>>"
    template, context = calls["engine"]
    assert template.name == "github" and template.origin == "packaged"
    assert context is sentinel_context
    result, used_config, options = calls["build"]
    assert result is _RESULT and used_config is config
    assert options["strict"] is True
    assert options["show_clean_documents"] is True
    assert options["report_include_run_meta"] is True
    # One registry feeds both the model hooks and the engine's filter table (M9, M30).
    assert calls["engine_options"]["extensions"] is options["extensions"]
    assert not options["extensions"]


def test_render_passes_a_loaded_template_through(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] reporting delegation (mock): verifies a ``Template`` object passed as ``template=`` is used as-is.

    Scenario:
        Given a loaded ``json-v1`` template and a stubbed engine
        When ``render`` runs with ``format="text"`` and ``template=<json-v1>``
        Then the engine receives that same template object (``template`` wins over ``format``).

    Boundaries:
        - Focus: template precedence without any re-load
        - Fixtures/params: monkeypatched engine
        - Scope: the ``reporting`` module only

    On failure, first check:
        - The ``isinstance(template, Template)`` branch of ``reporting._resolve``
    """
    seen: list[Any] = []
    monkeypatch.setattr(reporting, "render_template", lambda template, context, **_: seen.append(template) or "")
    loaded = load_template("json-v1")

    reporting.render(_RESULT, "text", template=loaded)

    assert seen == [loaded]


def test_engine_template_error_becomes_value_error(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] reporting delegation (mock): verifies an engine ``TemplateError`` surfaces as a chained ``ValueError``.

    Scenario:
        Given an engine stub that raises ``TemplateError``
        When ``render`` runs
        Then a ``ValueError`` with the same message is raised, chained to the ``TemplateError``.

    Boundaries:
        - Focus: API compatibility of the error type (``ValueError``)
        - Fixtures/params: monkeypatched engine
        - Scope: the ``reporting`` module only

    On failure, first check:
        - The ``except TemplateError`` clause of ``render``
    """

    def failing(template: Any, context: Any, **_: Any) -> str:
        """Raise like a render past a cap."""
        raise TemplateError("render output exceeds the cap")

    monkeypatch.setattr(reporting, "render_template", failing)

    with pytest.raises(ValueError, match="render output exceeds the cap") as raised:
        reporting.render(_RESULT)

    assert isinstance(raised.value.__cause__, TemplateError)
