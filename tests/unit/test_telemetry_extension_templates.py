"""Unit tests for extension data and filters in templates (Milestone 0007 Story 04.0 Task 01).

Pins the loader trust rules and the engine runtime for ``ext.*`` variables and ``ext.<n>.<f>``
filters: threat model ``docs/security/threat-model-0007-extensions-2026-11-03.md`` M7-M12, M30, M31.
"""

import json
import math
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from docsentinel.config import Config
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.telemetry import builtin
from docsentinel.telemetry.engine import render_template
from docsentinel.telemetry.extensions import (
    ExtensionFilter,
    LoadedExtensions,
    admit_extensions,
    check_template,
    missing_extensions_message,
)
from docsentinel.telemetry.filters import TemplateError
from docsentinel.telemetry.loader import Template, validate_template
from docsentinel.telemetry.model import ReportModel

ESC = chr(0x1B)
RLO = chr(0x202E)

_FINDING = Finding(rule="DS101", path="b.md", message="dangling link -> x.md", severity="error", line=2)
_RESULT = ScanResult(
    profile="fast",
    documents=(Document("a.md", 1), Document("b.md", 2)),
    findings=(_FINDING,),
    enabled_rules=("DS101",),
    pending=(),
    notice="1 fast rule(s) evaluated.",
    rules_evaluated=1,
)


def _line(text: str, used: list[str]) -> dict[str, Any]:
    """Return a text ``line`` node."""
    return {"type": "line", "text": text, "variables_used": used}


def _docs(*body: dict[str, Any]) -> dict[str, Any]:
    """Return a loop node over ``documents`` (as ``doc``) holding ``body``."""
    return {"type": "loop", "over": "documents", "as": "doc", "body": list(body)}


def _problems(*body: dict[str, Any]) -> dict[str, Any]:
    """Return a loop over each document's ``problems`` (as ``p``) holding ``body``."""
    return _docs({"type": "loop", "over": "doc.problems", "as": "p", "body": list(body)})


def _text(*lines: dict[str, Any], requires: tuple[str, ...] = ("calc",), sink: str = "terminal") -> dict[str, Any]:
    """Return a raw text template holding ``lines``."""
    return {
        "template_version": 1,
        "name": "t",
        "type": "text",
        "requires_extensions": list(requires),
        "output": {"sink": sink},
        "lines": list(lines),
    }


def _rejects(raw: dict[str, Any], fragment: str):
    """Assert that validating ``raw`` raises a TemplateError containing ``fragment``."""
    with pytest.raises(TemplateError) as caught:
        validate_template(raw)
    assert fragment in str(caught.value), str(caught.value)


def _ext(name: str = "calc", **hooks: Any) -> SimpleNamespace:
    """Return an in-memory extension object named ``name`` with ``hooks``."""
    return SimpleNamespace(name=name, **hooks)


def _render(template: Template, loaded: LoadedExtensions) -> str:
    """Render ``template`` over the fixed scan result with ``loaded``."""
    context = ReportModel.build(_RESULT, Config(), extensions=loaded)
    return render_template(template, context, extensions=loaded)


def _calc(**filters: ExtensionFilter) -> LoadedExtensions:
    """Admit a ``calc`` extension with run/document/problem data and ``filters``."""
    return admit_extensions(
        [
            _ext(
                provide_run=lambda model: {"label": ESC + "[2J" + RLO + "run", "items": ["a", "b"], "n": 3},
                provide_document=lambda doc, model: {"name": ESC + "x" + doc["path"]},
                provide_problem=lambda p, d, m: {"tag": p["rule"]},
                filters=lambda: {f"ext.calc.{key}": value for key, value in filters.items()},
            )
        ]
    )


def _scalar_filter(function: Any, arity: int = 0, kinds: frozenset[str] = frozenset({"scalar"})) -> ExtensionFilter:
    """Return an ExtensionFilter wrapping ``function``."""
    return ExtensionFilter(function=function, arity=arity, input_kinds=kinds)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- M11, M12 ext variables


def test_ext_variable_needs_a_text_sink_and_renders_neutralized():
    """
    [Unit] extension templates: verifies ``{doc.ext.calc.name}`` is untrusted in text (M11).

    Scenario:
        Given a terminal template emitting ``doc.ext.calc.name`` raw, and one with ``|neutralize``
        When each is validated, and the second rendered with a hook returning ESC
        Then the raw one is rejected and the neutralized one renders the escape visibly.

    Boundaries:
        - Focus: ``any`` kind is always untrusted
        - Fixtures/params: none
        - Scope: validate_template, ReportModel.build, render_template

    On failure, first check:
        - ``loader._Validator._resolve`` ext branches and ``model.EXT_VARIABLE``
    """
    _rejects(_text(_docs(_line("{doc.ext.calc.name}", ["doc.ext.calc.name"]))), "must end its filter chain")
    template = validate_template(_text(_docs(_line("{doc.ext.calc.name|neutralize}", ["doc.ext.calc.name"]))))

    rendered = _render(template, _calc())

    assert rendered.splitlines() == ["\\x1bxa.md", "\\x1bxb.md"]


def test_ext_variable_under_github_needs_a_well_formed_command():
    """
    [Unit] extension templates: verifies ext data is refused on plain github lines and in append loops (M11).

    Scenario:
        Given github-sink templates with ``doc.ext.calc.name`` on a plain line, in an append loop, and in
        the data segment of a well-formed ``::error`` command
        When validated
        Then the first two are rejected and the command line is accepted.

    Boundaries:
        - Focus: T2-R1 rules applied to ext data
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``loader._Validator._check_ref`` command_line handling
    """
    used = ["doc.ext.calc.name"]
    _rejects(_text(_docs(_line("Doc {doc.ext.calc.name|gha_data}", used)), sink="github"), "well-formed")
    append = {
        "type": "loop",
        "over": "documents",
        "as": "doc",
        "placement": "append",
        "text": "x{doc.ext.calc.name|gha_property}",
        "variables_used": used,
    }
    _rejects(_text(_line("Start", []), append, sink="github"), "well-formed")
    validate_template(_text(_docs(_line("::error title=x::{doc.ext.calc.name|gha_data}", used)), sink="github"))


def test_ext_member_is_a_container_and_needs_requires_extensions():
    """
    [Unit] extension templates: verifies ``{doc.ext.calc}`` is a container and ext needs requires_extensions (M11, M12).

    Scenario:
        Given ``{doc.ext.calc|neutralize}``, ``{doc.ext.calc.name|neutralize}`` without requires_extensions, and
        ``{ext.other.x|neutralize}`` naming an unlisted extension
        When validated
        Then each is rejected at load time.

    Boundaries:
        - Focus: load-time static checking of ext references
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``loader._Validator._extension_member``
    """
    _rejects(_text(_docs(_line("{doc.ext.calc|neutralize}", ["doc.ext.calc"]))), "cannot take the dict value")
    _rejects(_text(_docs(_line("{doc.ext.calc}", ["doc.ext.calc"]))), "is a dict")
    _rejects(
        _text(_docs(_line("{doc.ext.calc.name|neutralize}", ["doc.ext.calc.name"])), requires=()),
        "needs extension calc listed in requires_extensions",
    )
    _rejects(_text(_line("{ext.other.x|neutralize}", ["ext.other.x"])), "needs extension other")


def test_json_var_of_an_ext_subtree_is_embedded_as_escaped_data():
    """
    [Unit] extension templates: verifies $var of an ext subtree holding $-keys and ESC/U+202E renders as data (M11).

    Scenario:
        Given a run hook returning ``{"$var": "profile", "$for": [...], "s": ESC + RLO}``
        When a json template embeds ``{"$var": "ext.calc"}``
        Then the output parses back to the same data and holds only ASCII.

    Boundaries:
        - Focus: operators come from template nodes only; ensure_ascii forced
        - Fixtures/params: none
        - Scope: ReportModel.build and render_template

    On failure, first check:
        - ``engine._Renderer._json_var``
    """
    tree = {"$var": "profile", "$for": ["documents"], "s": ESC + "[2J" + RLO}
    loaded = admit_extensions([_ext(provide_run=lambda model: tree)])
    template = validate_template(
        {
            "template_version": 1,
            "name": "t",
            "type": "json",
            "requires_extensions": ["calc"],
            "body": {"data": {"$var": "ext.calc"}},
        }
    )

    rendered = _render(template, loaded)

    assert rendered.isascii()
    assert json.loads(rendered) == {"data": tree}


def test_any_values_loop_and_compare_with_render_time_checks():
    """
    [Unit] extension templates: verifies an ``any`` list loops and a non-list ``any`` fails at render (M11).

    Scenario:
        Given a loop over ``ext.calc.items`` (a list) and one over ``ext.calc.n`` (an int)
        When rendered
        Then the first renders each item and the second is a TemplateError.

    Boundaries:
        - Focus: ``any`` accepted where a list is expected only with a render-time check
        - Fixtures/params: none
        - Scope: validate_template and render_template

    On failure, first check:
        - ``loader._Validator._list_var`` and ``engine._Renderer._items``
    """
    good = validate_template(
        _text({"type": "loop", "over": "ext.calc.items", "as": "item", "body": [_line("{item|neutralize}", ["item"])]})
    )
    bad = validate_template(
        _text({"type": "loop", "over": "ext.calc.n", "as": "item", "body": [_line("{item|neutralize}", ["item"])]})
    )

    assert _render(good, _calc()) == "a\nb"
    with pytest.raises(TemplateError, match="not a list"):
        _render(bad, _calc())


# --------------------------------------------------------------------------- M7, M8 filter taint


def test_chain_with_an_extension_filter_is_untrusted():
    """
    [Unit] extension templates: verifies any chain holding an ext filter is untrusted (M7, M8).

    Scenario:
        Given ``{p.message|ext.calc.f}`` and ``{profile|ext.calc.f}`` in text, ``{profile|ext.calc.f|gha_data}``
        on a plain github line, and the same inside a well-formed ``::error`` data segment
        When validated
        Then the first three are rejected and the last is accepted, as is a terminal chain ending in neutralize.

    Boundaries:
        - Focus: trust laundering through extension filters (T3)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - the ``tainted`` flag in ``loader._Validator._check_ref``
    """
    _rejects(_text(_problems(_line("{p.message|ext.calc.f}", ["p.message"]))), "must end its filter chain")
    _rejects(_text(_line("{profile|ext.calc.f}", ["profile"])), "must end its filter chain")
    _rejects(_text(_line("Run {profile|ext.calc.f|gha_data}", ["profile"]), sink="github"), "well-formed")
    validate_template(_text(_line("::error title=x::{profile|ext.calc.f|gha_data}", ["profile"]), sink="github"))
    validate_template(_text(_line("{profile|ext.calc.f|neutralize}", ["profile"])))


def test_extension_filter_needs_requires_extensions():
    """
    [Unit] extension templates: verifies an ext filter of an unlisted extension is a load-time error (M12).

    Scenario:
        Given ``{profile|ext.calc.f|neutralize}`` in a template without requires_extensions
        When validated
        Then it is rejected naming requires_extensions.

    Boundaries:
        - Focus: static checkability
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``loader._Validator._extension_filter``
    """
    _rejects(_text(_line("{profile|ext.calc.f|neutralize}", ["profile"]), requires=()), "requires_extensions")


def test_extension_filter_uses_are_recorded_and_bound_before_rendering():
    """
    [Unit] extension templates: verifies uses are recorded and checked against the registry (M9, M30).

    Scenario:
        Given a template using ``ext.calc.f`` with one argument on a scalar
        When checked against registries without the filter, with arity 0, with list-only input, and a matching one
        Then the first three are TemplateErrors and the last passes.

    Boundaries:
        - Focus: load-time arity/input-kind check
        - Fixtures/params: none
        - Scope: Template.extension_filters and check_template

    On failure, first check:
        - ``extensions.check_template``
    """
    template = validate_template(_text(_line('{profile|ext.calc.f("x")|neutralize}', ["profile"])))
    assert template.extension_filters == (("ext.calc.f", 1, "scalar"),)

    with pytest.raises(TemplateError, match="no loaded extension registers"):
        check_template(template, _calc())
    with pytest.raises(TemplateError, match="takes 0 argument"):
        check_template(template, _calc(f=_scalar_filter(lambda v: v)))
    with pytest.raises(TemplateError, match="cannot take a scalar"):
        check_template(template, _calc(f=_scalar_filter(lambda v, a: a, 1, frozenset({"list"}))))
    check_template(template, _calc(f=_scalar_filter(lambda v, a: a, 1)))


def test_extension_filter_renders_and_its_output_is_sinked():
    """
    [Unit] extension templates: verifies a valid ext filter runs at render time and its output is escaped (M10).

    Scenario:
        Given ``ext.calc.shout`` returning its argument plus ESC
        When ``{profile|ext.calc.shout("!")|neutralize}`` renders
        Then the result is the filter output with ESC escaped.

    Boundaries:
        - Focus: normal case of the runtime registry
        - Fixtures/params: none
        - Scope: render_template

    On failure, first check:
        - ``engine._Renderer._extension_filter`` and ``extensions.BoundFilter.__call__``
    """
    template = validate_template(_text(_line('{profile|ext.calc.shout("!")|neutralize}', ["profile"])))
    loaded = _calc(shout=_scalar_filter(lambda value, mark: value.upper() + mark + ESC, 1))

    assert _render(template, loaded) == "FAST!\\x1b"


class _StrSub(str):
    """A ``str`` subclass (not an exact JSON scalar)."""


@pytest.mark.parametrize(
    ("function", "fragment"),
    [
        (lambda value: {"a": 1}, "must return a JSON scalar"),
        (lambda value: _StrSub("x"), "must return a JSON scalar"),
        (lambda value: math.nan, "must return a JSON scalar"),
        (lambda value: 10**30, "must return a JSON scalar"),
        (lambda value: (_ for _ in ()).throw(RuntimeError(ESC + "boom" * 200)), "failed: RuntimeError"),
        (lambda value: (_ for _ in ()).throw(SystemExit(0)), "failed: SystemExit"),
    ],
    ids=["dict", "str-subclass", "nan", "huge-int", "raises", "system-exit"],
)
def test_bad_extension_filter_results_fail_closed(function: Any, fragment: str):
    """
    [Unit] extension templates: verifies a filter returning non-scalars or raising is a bounded TemplateError (M10).

    Scenario:
        Given an ext filter returning a dict, a str subclass, NaN or a huge int, or raising
        When the template renders
        Then a TemplateError is raised with a bounded, neutralized message.

    Boundaries:
        - Focus: runtime contract of extension filters
        - Fixtures/params: one bad filter per case
        - Scope: render_template

    On failure, first check:
        - ``extensions.BoundFilter.__call__``
    """
    template = validate_template(_text(_line("{profile|ext.calc.f|neutralize}", ["profile"])))
    with pytest.raises(TemplateError) as caught:
        _render(template, _calc(f=_scalar_filter(function)))
    message = str(caught.value)
    assert fragment in message
    assert ESC not in message and len(message) <= 512


def test_extension_filter_input_containers_are_frozen():
    """
    [Unit] extension templates: verifies a container passed to an ext filter cannot be mutated (M10, M13).

    Scenario:
        Given ``ext.calc.size`` declared for lists that tries to append to its input
        When ``{enabled_rules|ext.calc.size|neutralize}`` renders
        Then the append fails inside the filter (a TemplateError) and the context is unchanged.

    Boundaries:
        - Focus: read-only filter inputs
        - Fixtures/params: none
        - Scope: render_template

    On failure, first check:
        - ``freeze`` in ``extensions.BoundFilter.__call__``
    """

    def size(value: Any) -> int:
        """Try to mutate the input, then return its length."""
        value.append("x")
        return len(value)

    template = validate_template(_text(_line("{enabled_rules|ext.calc.size|neutralize}", ["enabled_rules"])))
    loaded = _calc(size=_scalar_filter(size, 0, frozenset({"list"})))
    context = ReportModel.build(_RESULT, Config(), extensions=loaded)

    with pytest.raises(TemplateError, match="AttributeError"):
        render_template(template, context, extensions=loaded)
    assert context["enabled_rules"] == ["DS101"]


def test_names_only_render_refuses_a_template_using_extension_filters():
    """
    [Unit] extension templates: verifies bare extension names cannot satisfy a template that uses ext filters.

    Scenario:
        Given a template using ``ext.calc.f`` rendered with ``extensions=("calc",)``
        When rendered
        Then a TemplateError asks for the loaded registry.

    Boundaries:
        - Focus: names and filters come from the same registry (T14)
        - Fixtures/params: none
        - Scope: render_template

    On failure, first check:
        - ``engine._check_extensions``
    """
    template = validate_template(_text(_line("{profile|ext.calc.f|neutralize}", ["profile"])))
    with pytest.raises(TemplateError, match="registry"):
        render_template(template, {"profile": "fast"}, extensions=("calc",))


# --------------------------------------------------------------------------- M30, M31 requires check


def test_missing_extension_message_never_suggests_the_gate():
    """
    [Unit] extension templates: verifies the missing-extension message for builtin and other names (M31).

    Scenario:
        Given a template requiring ``domain`` and ``evil``
        When checked against an empty registry
        Then the message suggests ``--extension builtin:domain`` for domain, and for ``evil`` neither the gate
        flag nor ``python:`` nor a module path.

    Boundaries:
        - Focus: social-engineering channel (T11)
        - Fixtures/params: none
        - Scope: check_template and missing_extensions_message

    On failure, first check:
        - ``extensions.missing_extensions_message``
    """
    template = validate_template(_text(_line("x", []), requires=("domain", "evil")))
    with pytest.raises(TemplateError) as caught:
        check_template(template, LoadedExtensions())
    message = str(caught.value)

    assert "--extension builtin:domain" in message
    evil_part = missing_extensions_message(["evil"])
    assert "evil" in evil_part
    assert "--allow-python-extensions" not in evil_part and "python:" not in evil_part


def test_requires_check_never_loads_anything(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extension templates: verifies a template requiring ``domain`` does not load builtin:domain (M30).

    Scenario:
        Given a builtin table whose ``domain`` factory records calls, and a template requiring ``domain``
        When the template is validated and checked against an empty registry
        Then the check fails and the factory was never called.

    Boundaries:
        - Focus: listing a name never loads anything
        - Fixtures/params: patched builtin table
        - Scope: validate_template and check_template

    On failure, first check:
        - that ``check_template`` only compares names
    """
    calls: list[int] = []
    monkeypatch.setattr(
        builtin, "BUILTIN_EXTENSIONS", MappingProxyType({"domain": lambda: calls.append(1) or _ext("domain")})
    )
    template = validate_template(_text(_line("x", []), requires=("domain",)))

    with pytest.raises(TemplateError, match="domain"):
        check_template(template, LoadedExtensions())
    assert calls == []


# --------------------------------------------------------------------------- close-review regressions (2026-11-03)


def _two() -> LoadedExtensions:
    """Two extensions, ``calc`` and ``other``, each adding run, document and problem data."""
    return admit_extensions(
        [
            _ext(
                name,
                provide_run=lambda model, n=name: {"who": n},
                provide_document=lambda doc, model, n=name: {"who": n},
                provide_problem=lambda p, d, m, n=name: {"who": n},
            )
            for name in ("calc", "other")
        ]
    )


@pytest.mark.parametrize(
    "raw",
    [
        _text(_docs(_line("{doc|json}", ["doc"])), requires=()),
        _text(_line("{documents|json}", ["documents"]), requires=()),
        _text(_line("{findings|json}", ["findings"]), requires=()),
        _text(_line("{documents_with_problems|json}", ["documents_with_problems"]), requires=()),
        {"template_version": 1, "name": "j", "type": "json", "requires_extensions": [], "body": {"$var": "documents"}},
    ],
    ids=["doc-json", "documents-json", "findings-json", "with-problems-json", "json-var-documents"],
)
def test_whole_object_sinks_emit_no_ext_data_without_requires(raw: dict[str, Any]):
    """
    [Unit] extension templates: verifies {doc|json}, {documents|json} and $var documents carry no ext data (M12).

    Scenario:
        Given two loaded extensions adding data at every level, and a template listing no requires_extensions
        When it renders a whole document, problem or list object
        Then the output is byte-identical to the render without any extension loaded.

    Boundaries:
        - Focus: close-review finding 6 (auditor probe p03 "no requires" cases)
        - Fixtures/params: one whole-object sink per case
        - Scope: render_template via extensions.scope_extension_data

    On failure, first check:
        - ``extensions.scope_extension_data`` and its call in ``engine.render_template``
    """
    template = validate_template(raw)
    plain = render_template(template, ReportModel.build(_RESULT, Config()))

    rendered = _render(template, _two())

    assert rendered == plain
    assert "who" not in rendered


def test_only_required_extension_data_reaches_a_whole_object_sink():
    """
    [Unit] extension templates: verifies a template requiring one extension sees only that extension's data (M12).

    Scenario:
        Given extensions ``calc`` and ``other`` loaded and a json template requiring only ``calc``
        When it embeds ``{"$var": "documents"}`` and ``{"$var": "findings"}``
        Then every ``ext`` object holds ``calc`` and never ``other``, and the context itself is unchanged.

    Boundaries:
        - Focus: finding 6 partial scope (normal case)
        - Fixtures/params: none
        - Scope: render_template

    On failure, first check:
        - ``extensions._scoped``
    """
    loaded = _two()
    template = validate_template(
        {
            "template_version": 1,
            "name": "j",
            "type": "json",
            "requires_extensions": ["calc"],
            "body": {"docs": {"$var": "documents"}, "flat": {"$var": "findings"}},
        }
    )
    context = ReportModel.build(_RESULT, Config(), extensions=loaded)

    rendered = json.loads(render_template(template, context, extensions=loaded))

    holders = [*rendered["docs"], *[p for d in rendered["docs"] for p in d["problems"]], *rendered["flat"]]
    assert holders and all(set(item["ext"]) <= {"calc"} for item in holders)
    assert any(item["ext"] == {"calc": {"who": "calc"}} for item in holders)
    assert set(context["documents"][1]["ext"]) == {"calc", "other"}  # never mutated


@pytest.mark.parametrize("leaf", ["__init__", "_x", "_"])
def test_extension_filter_leaf_must_start_with_a_letter(leaf: str):
    """
    [Unit] extension templates: verifies ``ext.<n>.<filter>`` leaves starting with ``_`` are rejected (finding 8).

    Scenario:
        Given a template using ``ext.calc.<leaf>`` for a leaf such as ``__init__``
        When validated
        Then it is rejected.

    Boundaries:
        - Focus: filter name grammar ``[a-z][a-z0-9_]{0,63}``
        - Fixtures/params: one leaf per case
        - Scope: validate_template

    On failure, first check:
        - ``loader._EXT_FILTER_LEAF_PATTERN``
    """
    with pytest.raises(TemplateError):
        validate_template(_text(_line(f"{{profile|ext.calc.{leaf}|neutralize}}", ["profile"])))
