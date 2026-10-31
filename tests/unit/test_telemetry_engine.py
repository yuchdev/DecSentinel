"""Unit tests for ``docsentinel.telemetry.engine`` (Milestone 0007 Story 02.0 Task 02).

Each case validates a tiny inline template mapping with the Task 01 loader, then
renders it against a tiny inline context; no file is read. Threat-model mitigations
(``docs/security/threat-model-0007-template-engine-2026-10-31.md``) are named in the
docstrings. Non-printable code points are spelled with ``chr()``.
"""

import ast
import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from docsentinel.telemetry import engine
from docsentinel.telemetry.engine import MAX_OUTPUT_CHARS, render_template
from docsentinel.telemetry.filters import TemplateError, neutralize
from docsentinel.telemetry.loader import JsonOutput, Template, validate_template

ESC = chr(0x1B)
RLO = chr(0x202E)


def _line(text: str, used: list[str], **extra: Any) -> dict[str, Any]:
    """Return a ``line`` node."""
    return {"type": "line", "text": text, "variables_used": used, **extra}


def _inline(over: str, alias: str, text: str, used: list[str], placement: str, **extra: Any) -> dict[str, Any]:
    """Return an inline (``one-line``/``append``) loop node."""
    return {
        "type": "loop",
        "over": over,
        "as": alias,
        "placement": placement,
        "text": text,
        "variables_used": used,
        **extra,
    }


def _block(over: str, alias: str, *body: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """Return a ``block`` loop node."""
    return {"type": "loop", "over": over, "as": alias, "body": list(body), **extra}


def _text(*lines: dict[str, Any], **envelope: Any) -> Template:
    """Validate a ``text`` template around ``lines``."""
    return validate_template({"template_version": 1, "name": "t", "type": "text", "lines": list(lines), **envelope})


def _json(body: Any, **envelope: Any) -> Template:
    """Validate a ``json`` template around ``body``."""
    raw = {"template_version": 1, "name": "t", "type": "json", "schema_version": 2, "body": body, **envelope}
    return validate_template(raw)


def _context(**overrides: Any) -> dict[str, Any]:
    """Return a small JSON-shaped context with two documents and three problems."""
    first = {
        "path": "docs/a.md",
        "bytes": 10,
        "problem_count": 2,
        "severity_counts": {"error": 1, "warning": 1},
        "problems": [
            {"rule": "DS101", "message": "dangling link -> x.md", "severity": "error", "line": 3, "value": "x.md"},
            {"rule": "DS102", "message": "stray comment", "severity": "warning", "line": None, "value": None},
        ],
    }
    second = {
        "path": "docs/b.md",
        "bytes": None,
        "problem_count": 1,
        "severity_counts": {"error": 1},
        "problems": [{"rule": "DS103", "message": "missing path", "severity": "error", "line": 1, "value": None}],
    }
    clean = {"path": "docs/c.md", "bytes": 5, "problem_count": 0, "severity_counts": {}, "problems": []}
    context: dict[str, Any] = {
        "schema_version": 1,
        "profile": "fast",
        "enabled_rules": ["DS101", "DS102", "DS103"],
        "documents_count": 3,
        "rules_evaluated": 12,
        "rules_type": "fast",
        "opt_in_off": [{"code": "DS110", "option": "require_fence_languages"}, {"code": "DS112", "option": "nav"}],
        "notice": "12 fast rule(s) evaluated.",
        "advisory": None,
        "pending": ["p1"],
        "model": None,
        "documents": [first, second, clean],
        "documents_with_problems": [first, second],
    }
    context.update(overrides)
    return context


# --------------------------------------------------------------------------- text placements


def test_block_loops_render_findings_under_their_document():
    """
    [Unit] engine: verifies nested block loops emit each document line followed by its problem lines.

    Scenario:
        Given the spec §4 document/problem block loops
        When rendered over two documents with problems
        Then every problem line directly follows its document line, in order.

    Boundaries:
        - Focus: normal case of ``block`` placement and loop scoping by ``as``
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - ``_Renderer._loop`` block branch and alias binding
    """
    template = _text(
        _block(
            "documents_with_problems",
            "doc",
            _line("{doc.path|neutralize} ({doc.bytes} bytes)", ["doc.path", "doc.bytes"]),
            _block(
                "doc.problems",
                "p",
                _line(
                    "  {p.severity}: {doc.path|neutralize}: {p.message|neutralize}",
                    ["p.severity", "doc.path", "p.message"],
                ),
            ),
        )
    )

    assert render_template(template, _context()).split("\n") == [
        "docs/a.md (10 bytes)",
        "  error: docs/a.md: dangling link -> x.md",
        "  warning: docs/a.md: stray comment",
        "docs/b.md (null bytes)",
        "  error: docs/b.md: missing path",
    ]


def test_one_line_joins_items_with_prefix_and_suffix():
    """
    [Unit] engine: verifies a one-line loop joins items with separator inside prefix/suffix on a new line.

    Scenario:
        Given a header line and a ``one-line`` loop over ``enabled_rules``
        When rendered
        Then the loop yields one new line ``[DS101 | DS102 | DS103]``.

    Boundaries:
        - Focus: normal case of ``one-line`` placement
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - ``_Renderer._loop`` inline branch
    """
    template = _text(
        _line("Rules:", []),
        _inline("enabled_rules", "r", "{r}", ["r"], "one-line", separator=" | ", prefix="[", suffix="]"),
    )

    assert render_template(template, _context()) == "Rules:\n[DS101 | DS102 | DS103]"


def test_one_line_over_empty_list_emits_nothing():
    """
    [Unit] engine: verifies a one-line loop over an empty list emits no line and no prefix/suffix.

    Scenario:
        Given a ``one-line`` loop with prefix/suffix between two lines
        When rendered with an empty ``enabled_rules``
        Then only the two surrounding lines appear.

    Boundaries:
        - Focus: edge case: empty list (prefix/suffix only when non-empty, spec §4)
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - The ``if not items`` early return in ``_Renderer._loop``
    """
    template = _text(
        _line("before", []),
        _inline("enabled_rules", "r", "{r}", ["r"], "one-line", separator=", ", prefix="<", suffix=">"),
        _line("after", []),
    )

    assert render_template(template, _context(enabled_rules=[])) == "before\nafter"


def test_append_extends_the_previous_line():
    """
    [Unit] engine: verifies an append loop continues the previously emitted line.

    Scenario:
        Given the spec §4 "opt-in rule(s) not enabled: " line and its append loop
        When rendered over two opt-in rules
        Then one line ``...not enabled: DS110 (set require_fence_languages), DS112 (set nav)`` results.

    Boundaries:
        - Focus: normal case of ``append`` placement
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - ``lines[-1] += segment`` in ``_Renderer._loop``
    """
    template = _text(
        _line(
            "{rules_evaluated} {rules_type} rule(s) evaluated; opt-in rule(s) not enabled: ",
            ["rules_evaluated", "rules_type"],
        ),
        _inline(
            "opt_in_off",
            "rule",
            "{rule.code} (set {rule.option})",
            ["rule.code", "rule.option"],
            "append",
            separator=", ",
        ),
        _line("next", []),
    )

    assert render_template(template, _context()) == (
        "12 fast rule(s) evaluated; opt-in rule(s) not enabled: DS110 (set require_fence_languages), DS112 (set nav)\nnext"
    )


def test_append_over_empty_list_is_a_no_op():
    """
    [Unit] engine: verifies an append loop over an empty list changes nothing, prefix included.

    Scenario:
        Given a line and an append loop with a prefix
        When rendered with an empty ``opt_in_off``
        Then the line is unchanged and no line is added.

    Boundaries:
        - Focus: edge case: empty list under ``append`` (spec §4)
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - The ``if not items`` early return in ``_Renderer._loop``
    """
    template = _text(
        _line("head", []),
        _inline("opt_in_off", "rule", "{rule.code}", ["rule.code"], "append", prefix=": "),
    )

    assert render_template(template, _context(opt_in_off=[])) == "head"


def test_append_with_no_previous_line_starts_one():
    """
    [Unit] engine: verifies an append loop that runs first starts the first output line.

    Scenario:
        Given a template whose only node is an append loop
        When rendered
        Then its segment is the single output line.

    Boundaries:
        - Focus: edge case: nothing to append to
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - The ``node.placement == PLACEMENT_APPEND and lines`` test
    """
    template = _text(_inline("enabled_rules", "r", "{r}", ["r"], "append", separator=","))

    assert render_template(template, _context()) == "DS101,DS102,DS103"


def test_group_and_when_guards():
    """
    [Unit] engine: verifies group bodies and line/loop ``when`` guards render only when they hold.

    Scenario:
        Given a group on ``profile eq fast``, one on ``profile eq deep`` and a guarded loop
        When rendered
        Then only the holding group's lines and no guarded-out loop output appear.

    Boundaries:
        - Focus: ``group`` node and ``when`` on line/loop
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - ``_Renderer._nodes`` and ``_holds``
    """
    template = _text(
        {"type": "group", "when": {"var": "profile", "eq": "fast"}, "body": [_line("fast!", [])]},
        {"type": "group", "when": {"var": "profile", "eq": "deep"}, "body": [_line("deep!", [])]},
        _line("{advisory}", ["advisory"], when={"var": "advisory", "truthy": True}),
        _block(
            "pending",
            "reason",
            _line("Pending: {reason|neutralize}", ["reason"]),
            when={"var": "pending", "falsy": True},
        ),
    )

    assert render_template(template, _context()) == "fast!"


@pytest.mark.parametrize(
    ("trailing", "lines", "expected"),
    [(False, ["a", "b"], "a\nb"), (True, ["a", "b"], "a\nb\n"), (True, [], "")],
    ids=["no-trailing", "trailing", "trailing-empty-output"],
)
def test_output_join_and_trailing_newline(trailing: bool, lines: list[str], expected: str):
    """
    [Unit] engine: verifies lines join with "\\n" and trailing_newline adds one after non-empty output.

    Scenario:
        Given literal lines and ``output.trailing_newline``
        When rendered
        Then the joined text ends with ``\\n`` only when requested and non-empty.

    Boundaries:
        - Focus: ``output`` settings; edge case of an empty report
        - Fixtures/params: trailing on/off, empty output
        - Scope: render_template, text

    On failure, first check:
        - ``_Renderer.text``
    """
    template = _text(*(_line(text, []) for text in lines), output={"trailing_newline": trailing})

    assert render_template(template, _context()) == expected


# --------------------------------------------------------------------------- conditions


@pytest.mark.parametrize(
    ("condition", "holds"),
    [
        ({"var": "profile", "eq": "fast"}, True),
        ({"var": "profile", "ne": "fast"}, False),
        ({"var": "profile", "in": ["deep", "fast"]}, True),
        ({"var": "rules_evaluated", "gt": 11}, True),
        ({"var": "rules_evaluated", "lt": 12}, False),
        ({"var": "advisory", "falsy": True}, True),
        ({"var": "pending", "truthy": True}, True),
        ({"all": [{"var": "profile", "eq": "fast"}, {"var": "rules_evaluated", "gt": 0}]}, True),
        ({"any": [{"var": "profile", "eq": "deep"}, {"var": "advisory", "truthy": True}]}, False),
        ({"not": {"var": "profile", "eq": "deep"}}, True),
        ({"var": "model", "eq": None}, True),
        ({"var": "documents_count", "eq": True}, False),
        ({"var": "advisory", "gt": 0}, False),
        ({"var": "notice", "lt": 5}, False),
        ({"var": "run.id", "truthy": True}, False),
        ({"var": "run.id", "eq": None}, True),
    ],
    ids=[
        "eq",
        "ne",
        "in",
        "gt",
        "lt",
        "falsy-null",
        "truthy-list",
        "all",
        "any",
        "not",
        "eq-null",
        "bool-is-not-number",
        "gt-null-is-false",
        "lt-string-is-false",
        "absent-is-falsy",
        "absent-is-null",
    ],
)
def test_condition_operators(condition: dict[str, Any], holds: bool):
    """
    [Unit] engine: verifies every condition operator and combinator of the closed grammar.

    Scenario:
        Given a guarded literal line
        When rendered over the inline context
        Then the line appears exactly when the condition is expected to hold.

    Boundaries:
        - Focus: eq/ne/in/gt/lt/truthy/falsy/all/any/not; edge cases: null, bool vs number,
          non-number ordering, absent opt-in ``run``
        - Fixtures/params: one case per operator and edge
        - Scope: render_template, text

    On failure, first check:
        - ``_Renderer._compare`` and ``engine._equal``
    """
    template = _text(_line("yes", [], when=condition))

    assert render_template(template, _context()) == ("yes" if holds else "")


# --------------------------------------------------------------------------- json


def test_json_var_keeps_types_and_default_applies():
    """
    [Unit] engine: verifies $var embeds by type, null stays null and $default replaces null or absent.

    Scenario:
        Given ``$var`` of a list, a null, a null with ``$default`` and absent ``run.id`` with ``$default``
        When rendered
        Then the list stays a list, null is ``null`` and both defaults apply.

    Boundaries:
        - Focus: normal case of ``$var`` and ``$default`` (Task 02 test list)
        - Fixtures/params: inline context
        - Scope: render_template, json

    On failure, first check:
        - ``_Renderer._json_var``
    """
    template = _json(
        {
            "rules": {"$var": "enabled_rules"},
            "advisory": {"$var": "advisory"},
            "model": {"$var": "model", "$default": "unknown"},
            "run_id": {"$var": "run.id", "$default": {"none": [1, 2]}},
            "count": {"$var": "documents_count", "$default": 0},
        }
    )

    assert json.loads(render_template(template, _context())) == {
        "rules": ["DS101", "DS102", "DS103"],
        "advisory": None,
        "model": "unknown",
        "run_id": {"none": [1, 2]},
        "count": 3,
    }


def test_json_for_if_str_and_omit_if():
    """
    [Unit] engine: verifies $for, $if (with and without else), $str with filters and $omit_if.

    Scenario:
        Given a per-document ``$for`` with a ``$str`` location, a ``$if`` level and an omitted key
        When rendered
        Then each document maps to the expected record and ``bytes`` is dropped when null.

    Boundaries:
        - Focus: normal case of every json operator (spec §5)
        - Fixtures/params: inline context
        - Scope: render_template, json

    On failure, first check:
        - ``_Renderer._evaluate``
    """
    each = {
        "where": {"$str": "{doc.path|upper}#{doc.problem_count}"},
        "bytes": {"$omit_if": {"var": "doc.bytes", "eq": None}, "value": {"$var": "doc.bytes"}},
        "state": {"$if": {"var": "doc.problem_count", "gt": 0}, "then": "dirty", "else": "clean"},
        "flag": {"$if": {"var": "doc.problem_count", "gt": 1}, "then": True},
        "levels": {"$for": "doc.problems", "as": "p", "each": {"$var": "p.severity"}},
    }
    template = _json({"$for": "documents", "as": "doc", "each": each}, output={"indent": None})

    assert json.loads(render_template(template, _context())) == [
        {"where": "DOCS/A.MD#2", "bytes": 10, "state": "dirty", "flag": True, "levels": ["error", "warning"]},
        {"where": "DOCS/B.MD#1", "state": "dirty", "flag": None, "levels": ["error"]},
        {"where": "DOCS/C.MD#0", "bytes": 5, "state": "clean", "flag": None, "levels": []},
    ]


def test_json_output_indent_and_sort_keys():
    """
    [Unit] engine: verifies output.indent and output.sort_keys reach json.dumps.

    Scenario:
        Given a literal object ``{"b": 1, "a": [true]}`` with indent 2 and sort_keys
        When rendered
        Then the text equals ``json.dumps(..., indent=2, sort_keys=True)``.

    Boundaries:
        - Focus: json serialization settings
        - Fixtures/params: none
        - Scope: render_template, json

    On failure, first check:
        - ``_Renderer.json``
    """
    template = _json({"b": 1, "a": [True]}, output={"indent": 2, "sort_keys": True})

    assert render_template(template, _context()) == json.dumps({"a": [True], "b": 1}, indent=2, sort_keys=True)


def test_json_ensure_ascii_is_forced_even_when_the_template_object_says_false():
    """
    [Unit] engine: verifies ensure_ascii is always true for json templates, custom ones included (M8).

    Scenario:
        Given a validated custom json template, and a copy whose output claims ``ensure_ascii=False``
        When both render a path holding ESC, U+202E, a lone surrogate and ``é``
        Then both outputs are pure ASCII with ``\\u`` escapes and are identical.

    Boundaries:
        - Focus: threat model M8 pin; a hand-built Template cannot turn escaping off
        - Fixtures/params: inline context
        - Scope: render_template, json

    On failure, first check:
        - The hard-coded ``ensure_ascii=True`` in ``_Renderer.json``
    """
    hostile = f"x{ESC}{RLO}{chr(0xD800)}{chr(0xE9)}"
    template = _json({"$var": "documents.0.path"})
    unsafe_flag = Template(**{**template.__dict__, "output": JsonOutput(indent=None, ensure_ascii=False)})
    context = _context()
    context["documents"][0]["path"] = hostile

    rendered = render_template(template, context)
    assert rendered == render_template(unsafe_flag, context) == '"x\\u001b\\u202e\\ud800\\u00e9"'
    assert rendered.isascii()


# --------------------------------------------------------------------------- M14 render-time


def test_substituted_values_are_never_rescanned():
    """
    [Unit] engine: verifies substitution is single-pass, so template syntax in data stays literal (M14).

    Scenario:
        Given a message ``{run.id}{{doc.__class__}}%s {0}`` rendered in text and through json ``$str``
        When rendered
        Then the message appears byte-for-byte, with no lookup, brace unescaping or formatting.

    Boundaries:
        - Focus: threat model T7 template injection
        - Fixtures/params: inline context
        - Scope: render_template, text and json

    On failure, first check:
        - ``_Renderer._interpolate`` appends values without re-parsing
    """
    message = "{run.id}{{doc.__class__}}%s {0}"
    context = _context()
    context["documents"][0]["problems"][0]["message"] = message
    text = _text(
        _block("documents", "doc", _block("doc.problems", "p", _line("{p.message|neutralize}", ["p.message"])))
    )
    json_template = _json({"$str": "{documents.0.problems.0.message}"})

    assert render_template(text, context).split("\n")[0] == message
    assert json.loads(render_template(json_template, context)) == message


def test_operator_keys_in_context_data_are_emitted_as_data():
    """
    [Unit] engine: verifies $-prefixed keys inside a $var sub-tree are never evaluated as operators (M14).

    Scenario:
        Given a context value ``{"$var": "notice", "$for": "documents"}`` embedded with ``$var``
        When rendered
        Then the object is emitted unchanged as data.

    Boundaries:
        - Focus: operators come from template nodes only
        - Fixtures/params: inline context
        - Scope: render_template, json

    On failure, first check:
        - ``_Renderer._json_var`` returns the value without calling ``_evaluate``
    """
    trap = {"$var": "notice", "$for": "documents", "as": "d", "each": {"$str": "{d.path}"}}
    context = _context(severity_counts=trap)
    template = _json({"$var": "severity_counts"})

    assert json.loads(render_template(template, context)) == trap


@pytest.mark.parametrize(
    "bad",
    [
        {"profile": object()},
        {"enabled_rules": ("DS101",)},
        {"severity_counts": {1: 2}},
        {"rules_evaluated": float("inf")},
        {"documents": [{"path": b"bytes"}]},
    ],
    ids=["object", "tuple", "non-string-key", "infinity", "bytes"],
)
def test_context_that_is_not_json_shaped_is_rejected(bad: dict[str, Any]):
    """
    [Unit] engine: verifies a context node that is not JSON data raises TemplateError before rendering (M14).

    Scenario:
        Given a context holding an object, a tuple, an int key, infinity or bytes
        When any template is rendered
        Then ``TemplateError`` is raised and the value is not echoed.

    Boundaries:
        - Focus: invalid input: the renderer only sees JSON-shaped trees
        - Fixtures/params: one case per non-JSON kind
        - Scope: render_template, ``_check_context``

    On failure, first check:
        - ``engine._check_context``
    """
    with pytest.raises(TemplateError, match="not JSON data|non-string object key") as caught:
        render_template(_text(_line("x", [])), _context(**bad))
    assert "bytes'" not in str(caught.value) and "object at" not in str(caught.value)


def test_context_root_must_be_a_dict():
    """
    [Unit] engine: verifies a non-dict context root is refused.

    Scenario:
        Given a list as the context
        When rendered
        Then ``TemplateError`` is raised.

    Boundaries:
        - Focus: invalid input
        - Fixtures/params: none
        - Scope: render_template

    On failure, first check:
        - ``engine._check_context`` root check
    """
    with pytest.raises(TemplateError, match="JSON object"):
        render_template(_text(_line("x", [])), [])  # type: ignore[arg-type]


def test_shared_subtrees_are_accepted():
    """
    [Unit] engine: verifies a document dict shared by two lists (as ReportModel builds) passes the context check.

    Scenario:
        Given ``documents`` and ``documents_with_problems`` sharing the same dicts
        When a template iterating both is rendered
        Then it succeeds and both loops see the same data.

    Boundaries:
        - Focus: edge case: a DAG is JSON-shaped
        - Fixtures/params: inline context
        - Scope: render_template

    On failure, first check:
        - The ``seen`` set in ``engine._check_context``
    """
    template = _text(
        _inline("documents", "d", "{d.path|neutralize}", ["d.path"], "one-line", separator=","),
        _inline("documents_with_problems", "d", "{d.path|neutralize}", ["d.path"], "one-line", separator=","),
    )

    assert render_template(template, _context()) == "docs/a.md,docs/b.md,docs/c.md\ndocs/a.md,docs/b.md"


# --------------------------------------------------------------------------- render-time errors


def test_absent_variable_in_text_is_an_error_unless_defaulted():
    """
    [Unit] engine: verifies an absent variable raises at render time and ``default`` rescues it.

    Scenario:
        Given ``{run.id}`` with no ``run`` in the context, and ``{run.id|default('none')}``
        When rendered
        Then the first raises ``TemplateError`` naming ``run.id``; the second emits ``none``.

    Boundaries:
        - Focus: invalid input: never a silent empty string (spec §3)
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - ``_Renderer._value``
    """
    with pytest.raises(TemplateError, match="run.id"):
        render_template(_text(_line("id={run.id}", ["run.id"])), _context())
    assert render_template(_text(_line("id={run.id|default('none')}", ["run.id"])), _context()) == "id=none"


def test_absent_json_var_without_default_is_an_error():
    """
    [Unit] engine: verifies an absent ``$var`` with no ``$default`` raises.

    Scenario:
        Given ``{"$var": "run"}`` and no ``run`` in the context
        When rendered
        Then ``TemplateError`` names ``run``.

    Boundaries:
        - Focus: invalid input
        - Fixtures/params: inline context
        - Scope: render_template, json

    On failure, first check:
        - ``_Renderer._json_var``
    """
    with pytest.raises(TemplateError, match="variable run is not present"):
        render_template(_json({"$var": "run"}), _context())


def test_loop_over_a_non_list_value_is_an_error():
    """
    [Unit] engine: verifies a loop whose context value is not a list raises TemplateError.

    Scenario:
        Given ``pending`` replaced by a string in the context
        When a block loop over ``pending`` renders
        Then ``TemplateError`` says it is not a list.

    Boundaries:
        - Focus: invalid input: context deviating from the schema
        - Fixtures/params: inline context
        - Scope: render_template

    On failure, first check:
        - ``_Renderer._items``
    """
    template = _text(_block("pending", "reason", _line("P {reason|neutralize}", ["reason"])))
    with pytest.raises(TemplateError, match="not a list"):
        render_template(template, _context(pending="oops"))


def test_filter_given_wrong_kind_at_render_time_raises_template_error():
    """
    [Unit] engine: verifies a context value of the wrong kind for a filter gives TemplateError, not TypeError.

    Scenario:
        Given ``profile`` replaced by a list while the template applies ``upper``
        When rendered
        Then ``TemplateError`` naming the variable and filter is raised.

    Boundaries:
        - Focus: invalid input; filters are total (Task 02 contract)
        - Fixtures/params: inline context
        - Scope: render_template

    On failure, first check:
        - The ``except TemplateError`` wrap in ``_Renderer._value``
    """
    with pytest.raises(TemplateError, match="profile.*upper"):
        render_template(_text(_line("P {profile|upper}", ["profile"])), _context(profile=["x"]))


def test_unfiltered_trusted_value_with_a_control_character_is_refused():
    """
    [Unit] engine: verifies a rendered line holding a raw control from a mis-tagged trusted value is refused.

    Scenario:
        Given a trusted ``notice`` that (contrary to the model) holds ESC and CR
        When ``{notice}`` renders unfiltered
        Then ``TemplateError`` is raised instead of emitting the raw bytes.

    Boundaries:
        - Focus: defence in depth behind the load-time trust rule (T1/T2)
        - Fixtures/params: inline context
        - Scope: render_template, text

    On failure, first check:
        - The neutral-line check in ``_Renderer.text``
    """
    with pytest.raises(TemplateError, match="control or format"):
        render_template(_text(_line("{notice}", ["notice"])), _context(notice=f"a{ESC}[2J\rb"))


def test_missing_required_extension_is_an_error():
    """
    [Unit] engine: verifies requires_extensions must all be loaded, and a non-template is refused.

    Scenario:
        Given a template requiring ``domain``
        When rendered without and with ``extensions=("domain",)``, and when a dict is passed as template
        Then the first raises, the second renders, the third raises.

    Boundaries:
        - Focus: spec §2/§10 missing extension; invalid input
        - Fixtures/params: none
        - Scope: render_template

    On failure, first check:
        - ``engine._check_extensions``
    """
    template = _text(_line("x", []), requires_extensions=["domain"])

    with pytest.raises(TemplateError, match="domain"):
        render_template(template, _context())
    assert render_template(template, _context(), extensions=("domain",)) == "x"
    with pytest.raises(TemplateError, match="validated Template"):
        render_template({"type": "text"}, _context())  # type: ignore[arg-type]
    with pytest.raises(TemplateError, match="extension names"):
        render_template(template, _context(), extensions="domain")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- M13 caps


def test_output_cap_stops_with_an_error_at_the_default_limit():
    """
    [Unit] engine: verifies output past MAX_OUTPUT_CHARS raises TemplateError rather than truncating (M13).

    Scenario:
        Given a 1 MiB trusted ``notice`` emitted once per item of a 70-item list (70 MiB > 64 MiB)
        When rendered with the real default cap
        Then ``TemplateError`` is raised; no partial output is returned.

    Boundaries:
        - Focus: threat model T6 output amplification
        - Fixtures/params: synthetic context
        - Scope: render_template, text

    On failure, first check:
        - ``_Budget.charge`` calls in ``_emit``
    """
    big = "n" * (1024 * 1024)
    template = _text(_block("enabled_rules", "r", _line("{notice}", ["notice"])))
    context = _context(notice=big, enabled_rules=["r"] * 70)

    with pytest.raises(TemplateError, match="output larger than"):
        render_template(template, context)
    assert MAX_OUTPUT_CHARS == 64 * 1024 * 1024


@pytest.mark.parametrize("placement", ["one-line", "append"])
def test_inline_loop_output_cap(monkeypatch: pytest.MonkeyPatch, placement: str):
    """
    [Unit] engine: verifies an inline loop building one huge line hits the output cap.

    Scenario:
        Given ``MAX_OUTPUT_CHARS`` lowered to 50 and an inline loop over 30 rule codes
        When rendered
        Then ``TemplateError`` is raised.

    Boundaries:
        - Focus: M13 for single-line amplification
        - Fixtures/params: both inline placements; lowered cap
        - Scope: render_template, text

    On failure, first check:
        - The per-item ``charge`` in ``_Renderer._loop``
    """
    monkeypatch.setattr(engine, "MAX_OUTPUT_CHARS", 50)
    template = _text(_inline("enabled_rules", "r", "{r}", ["r"], placement, separator=", "))

    with pytest.raises(TemplateError, match="output larger than 50"):
        render_template(template, _context(enabled_rules=["DS101"] * 30))


def test_nested_loop_iteration_budget(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] engine: verifies nested loops past MAX_ITERATIONS stop with an error (M13).

    Scenario:
        Given ``MAX_ITERATIONS`` lowered to 1000 and four nested loops over a 10-item list (11110 items)
        When rendered as text and as json ``$for``
        Then both raise ``TemplateError`` about loop items.

    Boundaries:
        - Focus: threat model T6 nested amplification (loader caps depth at 4)
        - Fixtures/params: lowered budget, synthetic context
        - Scope: render_template, text and json

    On failure, first check:
        - ``_Budget.iterate`` calls in ``_loop`` and the ``$for`` branch
    """
    monkeypatch.setattr(engine, "MAX_ITERATIONS", 1000)
    context = _context(enabled_rules=[str(index) for index in range(10)])
    inner = _line("{a}{b}{c}{d}", ["a", "b", "c", "d"])
    text = _text(
        _block(
            "enabled_rules",
            "a",
            _block("enabled_rules", "b", _block("enabled_rules", "c", _block("enabled_rules", "d", inner))),
        )
    )
    each: Any = {"$var": "d"}
    for alias in ("d", "c", "b", "a"):
        each = {"$for": "enabled_rules", "as": alias, "each": each}

    with pytest.raises(TemplateError, match="more than 1000 loop items"):
        render_template(text, context)
    with pytest.raises(TemplateError, match="more than 1000 loop items"):
        render_template(_json(each), context)


def test_json_embed_counts_against_output_cap(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] engine: verifies embedding a whole sub-tree per item is charged against the output cap.

    Scenario:
        Given ``MAX_OUTPUT_CHARS`` lowered to 500 and a ``$for`` embedding ``documents`` per document
        When rendered
        Then ``TemplateError`` is raised before serialization.

    Boundaries:
        - Focus: M13 for json ``$var`` amplification
        - Fixtures/params: lowered cap
        - Scope: render_template, json

    On failure, first check:
        - ``engine._size`` and the charge in ``_json_var``
    """
    monkeypatch.setattr(engine, "MAX_OUTPUT_CHARS", 500)
    template = _json({"$for": "documents", "as": "d", "each": {"$var": "documents"}})

    with pytest.raises(TemplateError, match="output larger than 500"):
        render_template(template, _context())


# --------------------------------------------------------------------------- determinism and sweep


def test_rendering_is_deterministic_and_does_not_mutate_context():
    """
    [Unit] engine: verifies rendering twice yields identical bytes and leaves the context untouched.

    Scenario:
        Given a text and a json template over the same context
        When each is rendered twice
        Then the outputs match byte for byte and the context equals its deep copy.

    Boundaries:
        - Focus: determinism (spec §1) and purity
        - Fixtures/params: inline context
        - Scope: render_template

    On failure, first check:
        - Alias cleanup in ``_Renderer._loop`` / ``$for``
    """
    context = _context()
    snapshot = copy.deepcopy(context)
    text = _text(
        _block("documents", "doc", _line("{doc.path|neutralize}", ["doc.path"])),
        _inline("opt_in_off", "r", "{r.code}", ["r.code"], "one-line", separator=","),
    )
    as_json = _json({"docs": {"$for": "documents", "as": "doc", "each": {"$var": "doc"}}}, output={"indent": 2})

    for template in (text, as_json):
        assert render_template(template, context).encode() == render_template(template, context).encode()
    assert context == snapshot


def _swept_code_points() -> list[str]:
    """Return one string per code point of the C0/C1/DEL/bidi/zero-width/separator/surrogate sets."""
    points = list(range(0x00, 0x20)) + [0x7F] + list(range(0x80, 0xA0))
    points += [0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0x2028, 0x2029]
    points += list(range(0x202A, 0x202F)) + [0x2066, 0x2067, 0x2068, 0x2069] + list(range(0xD800, 0xE000))
    return [f"a{chr(point)}b" for point in points]


def test_neutralize_sweep_leaves_no_unsafe_code_point_in_text_output():
    """
    [Unit] engine: verifies a text template using |neutralize emits no control/bidi/zero-width/surrogate code point.

    Scenario:
        Given ``pending`` holding one string per code point of every neutralized range
        When ``Pending: {reason|neutralize}`` renders once per entry
        Then every line is printable, ``neutralize`` leaves it unchanged, and the only LF is the joiner.

    Boundaries:
        - Focus: property sweep over the full ranges (hypothesis-free, Task 02 test list)
        - Fixtures/params: swept code points
        - Scope: render_template, text

    On failure, first check:
        - ``filters._build_control_table`` ranges
    """
    values = _swept_code_points()
    template = _text(_block("pending", "reason", _line("Pending: {reason|neutralize}", ["reason"])))

    lines = render_template(template, _context(pending=values)).split("\n")

    assert len(lines) == len(values)
    assert all(line.isascii() and line.isprintable() and neutralize(line) == line for line in lines)


@pytest.mark.parametrize("module", ["engine.py", "filters.py"])
def test_renderer_modules_import_only_stdlib_and_telemetry_siblings(module: str):
    """
    [Unit] engine: verifies the renderer and filter modules import only the stdlib and telemetry siblings.

    Scenario:
        Given the source of ``telemetry/engine.py`` and ``telemetry/filters.py``
        When their import statements are parsed
        Then every module is stdlib or ``docsentinel.telemetry.*``, and ``filters`` imports no docsentinel module.

    Boundaries:
        - Focus: Story 02.0 DoD import rule; ``filters`` is the cycle-free bottom layer
        - Fixtures/params: the two module files
        - Scope: static AST inspection, no import

    On failure, first check:
        - A new import in the named module
    """
    source = Path(engine.__file__).with_name(module).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    local = {name for name in imported if name.split(".")[0] == "docsentinel"}
    assert all(name.startswith("docsentinel.telemetry.") for name in local), local
    assert all(name.split(".")[0] in sys.stdlib_module_names for name in imported - local), imported
    if module == "filters.py":
        assert not local
