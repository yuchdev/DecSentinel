"""Unit tests for ``docsentinel.telemetry.loader`` (Milestone 0007 Story 02.0 Task 01).

Every case validates a tiny inline template mapping; no file is read. The threat-model
mitigation each test pins is named in its docstring
(``docs/security/threat-model-0007-template-engine-2026-10-31.md``).
"""

import dataclasses
import json
from typing import Any

import pytest

from docsentinel.telemetry import loader
from docsentinel.telemetry.loader import (
    MAX_ECHO,
    MAX_FILTER_ARG,
    MAX_MESSAGE,
    MAX_NODES,
    AllOf,
    Compare,
    JsonFor,
    JsonIf,
    JsonObject,
    JsonStr,
    JsonVar,
    LineNode,
    LoopNode,
    Not,
    Template,
    TemplateError,
    VarRef,
    load_template,
    validate_template,
)
from docsentinel.telemetry.model import CONTEXT_SCHEMA, MODEL_ID_PATTERN, TRUSTED


def _line(text: str, used: list[str], **extra: Any) -> dict[str, Any]:
    """Return a ``line`` node."""
    return {"type": "line", "text": text, "variables_used": used, **extra}


def _text(*lines: dict[str, Any], **envelope: Any) -> dict[str, Any]:
    """Return a minimal ``text`` template around ``lines``."""
    return {"template_version": 1, "name": "t", "type": "text", "lines": list(lines), **envelope}


def _json(body: Any, **envelope: Any) -> dict[str, Any]:
    """Return a minimal ``json`` template around ``body``."""
    return {"template_version": 1, "name": "t", "type": "json", "schema_version": 2, "body": body, **envelope}


def _in_loop(over: str, alias: str, *body: dict[str, Any]) -> dict[str, Any]:
    """Return a ``block`` loop node."""
    return {"type": "loop", "over": over, "as": alias, "body": list(body)}


def _over_problems(*body: dict[str, Any]) -> dict[str, Any]:
    """Return ``documents`` -> ``doc.problems`` nested block loops around ``body``."""
    return _in_loop("documents", "doc", _in_loop("doc.problems", "p", *body))


def _github(*lines: dict[str, Any]) -> dict[str, Any]:
    """Return a ``text`` template with the ``github`` sink."""
    return _text(*lines, output={"sink": "github"})


def _rejects(raw: dict[str, Any], *fragments: str) -> str:
    """Assert ``raw`` is rejected; every fragment must appear in the message."""
    with pytest.raises(TemplateError) as caught:
        validate_template(raw)
    message = str(caught.value)
    for fragment in fragments:
        assert fragment in message, message
    return message


_SPEC_TEXT_EXAMPLE: dict[str, Any] = _text(
    _line("Schema version: {schema_version}", ["schema_version"]),
    _line(
        "Documents: {documents_count} ({documents_with_problems_count} with problems)",
        ["documents_count", "documents_with_problems_count"],
    ),
    _line("Enabled rules: {enabled_rules|json}", ["enabled_rules"]),
    _line(
        "{rules_evaluated} {rules_type} rule(s) evaluated; opt-in rule(s) not enabled: ",
        ["rules_evaluated", "rules_type"],
        when={"var": "opt_in_off", "truthy": True},
    ),
    {
        "type": "loop",
        "over": "opt_in_off",
        "as": "rule",
        "placement": "append",
        "separator": ", ",
        "when": {"var": "opt_in_off", "truthy": True},
        "text": "{rule.code} (set {rule.option})",
        "variables_used": ["rule.code", "rule.option"],
    },
    {
        "type": "loop",
        "over": "documents_with_problems",
        "as": "doc",
        "body": [
            _line("{doc.path|neutralize} ({doc.bytes} bytes)", ["doc.path", "doc.bytes"]),
            _in_loop(
                "doc.problems",
                "p",
                _line(
                    "  {p.severity}: {doc.path|neutralize}: {p.message|neutralize}",
                    ["p.severity", "doc.path", "p.message"],
                ),
            ),
        ],
    },
    _in_loop("pending", "reason", _line("Pending: {reason|neutralize}", ["reason"])),
    output={"join": "\n", "trailing_newline": False},
)


def test_spec_text_example_loads_into_immutable_form():
    """
    [Unit] loader: verifies the spec §4 text excerpt validates into the frozen parsed form.

    Scenario:
        Given the report-template-format §4 example as an inline mapping
        When it is validated
        Then nodes, placements, aliases, filters and conditions are parsed as declared.

    Boundaries:
        - Focus: normal case of every text node type and the variable parser
        - Fixtures/params: none
        - Scope: validate_template on an inline mapping

    On failure, first check:
        - ``_Validator._text_node`` / ``_loop`` / ``_interpolation``
    """
    template = validate_template(_SPEC_TEXT_EXAMPLE)

    assert isinstance(template, Template) and template.type == "text" and template.origin == "mapping"
    assert template.output.sink == "terminal" and template.output.join == "\n"
    first, *_rest = template.lines
    assert isinstance(first, LineNode) and first.text.parts == (
        "Schema version: ",
        VarRef("schema_version", ("schema_version",)),
    )
    append = template.lines[4]
    assert isinstance(append, LoopNode) and append.placement == "append" and append.separator == ", "
    assert append.variables_used == frozenset({"rule.code", "rule.option"})
    assert isinstance(append.when, Compare) and append.when.op == "truthy"
    nested = template.lines[5].body[1]
    assert isinstance(nested, LoopNode) and nested.over.path == ("doc", "problems") and nested.alias == "p"
    message_ref = nested.body[0].text.parts[-1]
    assert message_ref.name == "p.message" and [f.name for f in message_ref.filters] == ["neutralize"]


def test_json_template_operators_parse():
    """
    [Unit] loader: verifies every json operator parses (``$var``/``$default``/``$for``/``$if``/``$str``/``$omit_if``).

    Scenario:
        Given a json template using each operator once
        When it is validated
        Then the body is the matching tree of frozen operator nodes.

    Boundaries:
        - Focus: normal case of spec §5 operators
        - Fixtures/params: none
        - Scope: validate_template on an inline mapping

    On failure, first check:
        - ``_Validator._json_value`` / ``_json_operator``
    """
    body = {
        "count": {"$var": "findings_count", "$default": 0},
        "model": {"$omit_if": {"var": "model", "eq": None}, "value": {"$var": "model"}},
        "docs": {"$for": "documents", "as": "doc", "each": {"$str": "{doc.path}:{doc.bytes}"}},
        "deep": {"$if": {"var": "profile", "eq": "deep"}, "then": True, "else": False},
        "raw": {"$var": "run"},
    }
    template = validate_template(_json(body, output={"indent": 2, "ensure_ascii": True, "sort_keys": True}))

    assert template.type == "json" and template.schema_version == 2 and template.output.indent == 2
    assert isinstance(template.body, JsonObject)
    members = {member.key: member for member in template.body.members}
    assert isinstance(members["count"].value, JsonVar) and members["count"].value.default == 0
    assert members["model"].omit_if is not None and isinstance(members["model"].value, JsonVar)
    assert isinstance(members["docs"].value, JsonFor) and isinstance(members["docs"].value.each, JsonStr)
    assert isinstance(members["deep"].value, JsonIf)


def test_json_template_needs_no_sink_filter():
    """
    [Unit] loader: verifies the trust rule does not apply to json templates (serialization is the sink).

    Scenario:
        Given a json ``$str`` interpolating untrusted ``doc.path`` and ``p.message`` with no filter
        When it is validated
        Then it is accepted.

    Boundaries:
        - Focus: spec §8 json exemption
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``self._type != "text"`` early return in ``_check_ref``
    """
    each = {"$for": "doc.problems", "as": "p", "each": {"$str": "{doc.path}: {p.message}"}}
    validate_template(_json({"$for": "documents", "as": "doc", "each": each}))


# --------------------------------------------------------------------------- envelope (rule 2)


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ({"template_version": 2}, "template_version"),
        ({"template_version": True}, "template_version"),
        ({"template_version": "1"}, "template_version"),
        ({"type": "html"}, "type must be"),
        ({"extra": 1}, "unknown key(s): extra"),
        ({"name": "Not_Kebab"}, "kebab-case"),
        ({"name": "a" * 65}, "kebab-case"),
        ({"description": 3}, "expected a string"),
        ({"requires_extensions": "domain"}, "requires_extensions"),
        ({"requires_extensions": ["domain", "domain"]}, "duplicate extension"),
        ({"requires_extensions": ["Bad-Name"]}, "invalid extension name"),
        ({"output": {"joiner": "x"}}, "unknown key(s): joiner"),
        ({"output": {"sink": "slack"}}, "output.sink"),
        ({"output": {"trailing_newline": 1}}, "output.trailing_newline"),
    ],
)
def test_envelope_violations_are_rejected(change: dict[str, Any], fragment: str):
    """
    [Unit] loader: verifies each envelope rule fails closed.

    Scenario:
        Given a valid minimal text template with one envelope key changed
        When it is validated
        Then a TemplateError names the offending key.

    Boundaries:
        - Focus: Task 01 rule 2 (version, type, name, unknown keys at the top and in ``output``)
        - Fixtures/params: one invalid envelope per case
        - Scope: validate_template

    On failure, first check:
        - ``_Validator.template`` / ``_text_output`` / ``_extensions``
    """
    _rejects({**_text(_line("x", [])), **change}, fragment)


def test_envelope_requires_lines_or_body():
    """
    [Unit] loader: verifies the type-specific required keys and their mutual exclusion.

    Scenario:
        Given a text template without ``lines`` and a json template carrying ``lines``
        When they are validated
        Then both are rejected.

    Boundaries:
        - Focus: Task 01 rule 2 required/forbidden keys per type
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The per-type key sets in ``_Validator.template``
    """
    _rejects({"template_version": 1, "name": "t", "type": "text"}, "missing key(s): lines")
    _rejects({**_json(1), "lines": []}, "unknown key(s): lines")
    _rejects(_json(1, schema_version=0), "schema_version")


def test_unknown_key_typo_in_a_node_is_rejected():
    """
    [Unit] loader: verifies the ``varibles_used`` typo is an unknown-key error at the node's JSON path.

    Scenario:
        Given a line node spelling ``varibles_used``
        When it is validated
        Then the error names ``lines[0]`` and the unknown key, so the typo cannot silently drop content.

    Boundaries:
        - Focus: Task 01 rule 2 "no unknown keys at any level"
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._object``
    """
    _rejects(_text({"type": "line", "text": "x", "varibles_used": []}), "lines[0]", "unknown key(s): varibles_used")


def test_error_names_the_json_path_of_the_offending_node():
    """
    [Unit] loader: verifies errors carry the JSON path of the offending node (``lines[N].over``).

    Scenario:
        Given a loop at ``lines[1]`` iterating an unknown variable
        When it is validated
        Then the message contains ``lines[1].over``.

    Boundaries:
        - Focus: Task 01 error contract (JSON path in message)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``where`` paths threaded through ``_Validator``
    """
    _rejects(_text(_line("x", []), _in_loop("nope", "x", _line("x", []))), "lines[1].over", "unknown variable: nope")


# --------------------------------------------------------------------------- variables and filters (rule 3)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("{nope}", "unknown variable: nope"),
        ("{doc.path}", "unknown variable: doc.path"),
        ("{documents.0.__class__}", "unknown variable"),
        ("{documents.0.keys}", "unknown variable"),
        ("{findings.0.message.upper}", "unknown variable"),
        ("{profile.0}", "unknown variable"),
        ("{profile|shout}", "unknown filter: shout"),
        ("{profile|ext.domain.name}", "needs extension domain listed in requires_extensions"),
        ("{profile|join}", "takes 1 argument"),
        ('{profile|lower("x")}', "takes 0 argument"),
        ('{documents|join(", ")|neutralize}', "cannot take"),
        ('{profile|join(", ")}', "cannot take"),
        ("{}", "invalid variable path"),
        ("{ profile }", "invalid variable path"),
        ("{profile", "unterminated"),
        ("profile}", "unmatched"),
        ("{profile|}", "invalid filter name"),
        ("{profile|lower x}", "invalid variable expression"),
    ],
)
def test_invalid_variable_references_are_rejected(text: str, fragment: str):
    """
    [Unit] loader: verifies unknown variables, unknown filters and malformed expressions fail at load (M14).

    Scenario:
        Given a line whose text holds one bad reference
        When it is validated
        Then a TemplateError names the reason; attribute-style paths never reach an object.

    Boundaries:
        - Focus: Task 01 rule 3 and M14 load-time part (``__class__``/``keys`` are unknown)
        - Fixtures/params: one bad reference per case
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._resolve`` / ``_expression`` / ``_check_ref``
    """
    _rejects(_text(_line(text, [])), fragment)


def test_valid_references_cover_paths_indexes_dicts_and_filters():
    """
    [Unit] loader: verifies list indexes, dict-valued keys, loop aliases and filter arguments resolve.

    Scenario:
        Given references to ``documents.0.bytes``, ``severity_counts.error``, ``{{``/``}}`` escapes and
        ``join``/``default`` arguments in single or double quotes
        When they are validated
        Then the template loads, braces are unescaped and list indexes become ints.

    Boundaries:
        - Focus: spec §3 syntax normal case
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._parse_path`` / ``_argument``
    """
    template = validate_template(
        _text(
            _line(
                "{{x}} {documents.0.bytes} {severity_counts.error} {enabled_rules|join(', ')} {advisory|default(\"-\")}",
                ["documents.0.bytes", "severity_counts.error", "enabled_rules", "advisory"],
            )
        )
    )
    parts = template.lines[0].text.parts
    assert parts[0] == "{x} " and parts[1].path == ("documents", 0, "bytes")
    assert parts[5].filters[0].args == (", ",)


def test_list_index_segment_is_bounded_to_six_digits():
    """
    [Unit] loader: verifies list-index segments are non-negative decimals of at most six digits (M12).

    Scenario:
        Given ``documents.999999.bytes`` and ``documents.1234567.bytes``
        When they are validated
        Then the first is accepted and the seven-digit index is rejected.

    Boundaries:
        - Focus: M12 index bound, edge at six digits
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_INDEX_PATTERN``
    """
    validate_template(_text(_line("{documents.999999.bytes}", ["documents.999999.bytes"])))
    _rejects(_text(_line("{documents.1234567.bytes}", ["documents.1234567.bytes"])), "invalid variable path")
    _rejects(_text(_line("{documents.-1.bytes}", ["documents.-1.bytes"])), "invalid variable path")


def test_filter_argument_is_a_bounded_quoted_literal():
    """
    [Unit] loader: verifies filter arguments are quoted literals of at most 256 characters, never evaluated (M12).

    Scenario:
        Given ``join`` with a 256-char, a 257-char, an unquoted and a two-argument call
        When they are validated
        Then only the 256-char quoted argument is accepted.

    Boundaries:
        - Focus: M12 filter-argument bound and no ``eval``
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._argument``
    """
    ok = "x" * MAX_FILTER_ARG
    validate_template(_text(_line(f"{{enabled_rules|join('{ok}')}}", ["enabled_rules"])))
    _rejects(_text(_line(f"{{enabled_rules|join('{ok}x')}}", ["enabled_rules"])), "longer than")
    _rejects(_text(_line("{enabled_rules|join(__import__)}", ["enabled_rules"])), "quoted string literal")
    _rejects(_text(_line("{enabled_rules|join('a', 'b')}", ["enabled_rules"])), "exactly one quoted argument")
    _rejects(_text(_line("{enabled_rules|join('a}", ["enabled_rules"])), "unterminated filter argument")


@pytest.mark.parametrize("alias", ["profile", "doc", "ext", "Bad"])
def test_loop_alias_cannot_shadow_or_be_malformed(alias: str):
    """
    [Unit] loader: verifies a loop alias may not shadow a core name or an enclosing alias.

    Scenario:
        Given an inner loop whose ``as`` is a core name, the outer alias, ``ext`` or not an identifier
        When it is validated
        Then it is rejected.

    Boundaries:
        - Focus: Task 02 contract item "shadowing a core name is a load-time error (Task 01)"
        - Fixtures/params: one alias per case
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._alias``
    """
    _rejects(_text(_in_loop("documents", "doc", _in_loop("doc.problems", alias, _line("x", [])))), "alias")


def test_loop_over_must_be_a_list_and_alias_is_loop_scoped():
    """
    [Unit] loader: verifies ``over`` must be a list and an alias is invisible outside its loop.

    Scenario:
        Given a loop over a scalar, and a line after a loop referencing its alias
        When they are validated
        Then both are rejected.

    Boundaries:
        - Focus: lexical scoping of ``as`` (spec §4)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._list_var`` and the per-loop scope copy in ``_loop``
    """
    _rejects(_text(_in_loop("profile", "x", _line("x", []))), "not a list")
    _rejects(
        _text(_in_loop("documents", "doc", _line("x", [])), _line("{doc.bytes}", ["doc.bytes"])),
        "unknown variable: doc.bytes",
    )


# --------------------------------------------------------------------------- variables_used (rule 4)


@pytest.mark.parametrize(
    ("node", "fragment"),
    [
        ({"type": "line", "text": "{profile}"}, "missing key(s): variables_used"),
        (_line("{profile}", []), "used but not declared: profile"),
        (_line("x", ["profile"]), "declared but not used: profile"),
        (_line("{profile}", ["profile", "profile"]), "twice"),
        (_line("{profile}", "profile"), "list of variable names"),
        (
            {"type": "loop", "over": "enabled_rules", "as": "r", "placement": "one-line", "text": "{r}"},
            "missing key(s): variables_used",
        ),
        (
            {
                "type": "loop",
                "over": "enabled_rules",
                "as": "r",
                "placement": "one-line",
                "text": "{r}",
                "variables_used": ["r", "profile"],
            },
            "declared but not used: profile",
        ),
    ],
)
def test_variables_used_must_equal_the_referenced_set(node: dict[str, Any], fragment: str):
    """
    [Unit] loader: verifies ``variables_used`` is mandatory and checked in both directions.

    Scenario:
        Given a line or inline loop with a missing, short, extra, duplicated or mistyped declaration
        When it is validated
        Then it is rejected.

    Boundaries:
        - Focus: Task 01 rule 4
        - Fixtures/params: one declaration defect per case
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._variables_used``
    """
    _rejects(_text(node), fragment)


# --------------------------------------------------------------------------- conditions (rule 5)


def test_condition_grammar_accepts_every_operator():
    """
    [Unit] loader: verifies all ten condition forms parse.

    Scenario:
        Given ``when`` guards using eq/ne/in/gt/lt/truthy/falsy combined by all/any/not
        When they are validated
        Then the parsed condition tree mirrors them.

    Boundaries:
        - Focus: Task 01 rule 5 normal case
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._condition``
    """
    when = {
        "all": [
            {"var": "profile", "eq": "deep"},
            {"var": "profile", "ne": "fast"},
            {"var": "profile", "in": ["fast", "deep"]},
            {"var": "findings_count", "gt": 0},
            {"var": "findings_count", "lt": 10.5},
            {"any": [{"var": "opt_in_off", "truthy": True}, {"var": "pending", "falsy": True}]},
            {"not": {"var": "advisory", "eq": None}},
        ]
    }
    template = validate_template(_text(_line("x", [], when=when)))
    condition = template.lines[0].when
    assert isinstance(condition, AllOf) and len(condition.conditions) == 7
    assert isinstance(condition.conditions[-1], Not)
    assert condition.conditions[2].operand == ("fast", "deep")


@pytest.mark.parametrize(
    ("when", "fragment"),
    [
        ({"var": "profile", "matches": "f.*"}, "unknown or missing condition operator"),
        ({"var": "profile"}, "unknown or missing condition operator"),
        ({"var": "profile", "eq": "a", "ne": "b"}, "unknown or missing condition operator"),
        ({"var": "opt_in_off", "truthy": False}, "takes the value true"),
        ({"var": "findings_count", "gt": "1"}, "takes a number"),
        ({"var": "findings_count", "gt": True}, "takes a number"),
        ({"var": "profile", "in": "fast"}, "list of at most"),
        ({"var": "profile", "in": [["fast"]]}, "list of scalars"),
        ({"var": "documents", "eq": 1}, "needs a scalar variable"),
        ({"var": "nope", "eq": 1}, "unknown variable"),
        ({"var": "profile|lower", "eq": "x"}, "invalid variable path"),
        ({"all": []}, "non-empty list"),
        ({"any": {"var": "profile", "eq": "x"}}, "non-empty list"),
        ({"xor": []}, "one of all/any/not"),
        ([], "must be an object"),
    ],
)
def test_condition_grammar_is_closed(when: Any, fragment: str):
    """
    [Unit] loader: verifies anything outside the closed condition grammar is a TemplateError.

    Scenario:
        Given a ``when`` with an unknown operator, wrong operand type or malformed combinator
        When it is validated
        Then it is rejected.

    Boundaries:
        - Focus: Task 01 rule 5 invalid input
        - Fixtures/params: one bad condition per case
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._condition``
    """
    _rejects(_text(_line("x", [], when=when)), fragment)


# --------------------------------------------------------------------------- trust rule (rule 6, T1, T2)


def test_trust_rule_basic_cases():
    """
    [Unit] loader: verifies ``{p.message}`` is rejected, ``|neutralize`` accepted, ``{p.line}`` needs no filter.

    Scenario:
        Given problem lines emitting message raw, message neutralized, and the trusted line number
        When they are validated
        Then only the raw message is rejected.

    Boundaries:
        - Focus: Task 01 rule 6 / spec §8
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._check_ref`` trust branch
    """
    _rejects(_text(_over_problems(_line("{p.message}", ["p.message"]))), "untrusted variable p.message")
    validate_template(_text(_over_problems(_line("{p.message|neutralize}", ["p.message"]))))
    validate_template(_text(_over_problems(_line("{p.line}", ["p.line"]))))


@pytest.mark.parametrize(
    ("template", "fragment"),
    [
        (_text(_in_loop("pending", "reason", _line("{reason}", ["reason"]))), "untrusted variable reason"),
        (_text(_line("{pending|join(', ')}", ["pending"])), "untrusted variable pending"),
        (_text(_line("{documents}", ["documents"])), "is a list"),
        (_text(_in_loop("documents", "doc", _line("{doc.problems}", ["doc.problems"]))), "is a list"),
        (_text(_in_loop("documents", "doc", _line("{doc}", ["doc"]))), "is a dict"),
        (_text(_line("{opt_in_off.0}", ["opt_in_off.0"])), "is a dict"),
        (_text(_over_problems(_line("{p.message}", ["p.message"]))), "untrusted variable p.message"),
        (_text(_line("{documents|json|lower}", ["documents"])), "untrusted variable documents"),
        (_text(_line("{documents|len}", ["documents"])), "untrusted variable documents"),
        (_text(_in_loop("findings", "f", _line("{f.document_path}", ["f.document_path"]))), "untrusted"),
    ],
)
def test_trust_survives_aliases_and_containers(template: dict[str, Any], fragment: str):
    """
    [Unit] loader: verifies T1 -- trust is not lost through loop aliases or container variables (M1-M3).

    Scenario:
        Given an alias over the untrusted ``pending`` list, a ``join`` of it, a raw container, and a nested
        problem alias
        When they are validated
        Then each is rejected: element trust is inherited (M1), a None-tagged container with untrusted members
        is untrusted (M2), and a non-scalar is never emitted (M3).

    Boundaries:
        - Focus: threat model T1 mandatory tests
        - Fixtures/params: one bypass attempt per case
        - Scope: validate_template

    On failure, first check:
        - ``_element`` / ``_untrusted`` / the M3 kind check in ``_check_ref``
    """
    _rejects(template, fragment)


@pytest.mark.parametrize(
    "template",
    [
        _text(_in_loop("pending", "reason", _line("{reason|neutralize}", ["reason"]))),
        _text(_line("{pending|join(', ')|neutralize}", ["pending"])),
        _text(_line("{documents|json}", ["documents"])),
        _text(_line("{documents|len|neutralize}", ["documents"])),
        _text(_in_loop("opt_in_off", "rule", _line("{rule.code}", ["rule.code"]))),
        _text(_line("{enabled_rules|join(', ')}", ["enabled_rules"])),
    ],
)
def test_sanctioned_untrusted_and_trusted_container_forms_are_accepted(template: dict[str, Any]):
    """
    [Unit] loader: verifies the T1 counterparts -- a terminal sink after reduction, or trusted members, pass.

    Scenario:
        Given ``|neutralize`` after an alias or a ``join``, ``|json`` of a container, and trusted members
        When they are validated
        Then they load.

    Boundaries:
        - Focus: threat model T1 accepted counterparts
        - Fixtures/params: one accepted form per case
        - Scope: validate_template

    On failure, first check:
        - ``FILTERS`` sink sets and ``_untrusted`` for all-trusted members
    """
    validate_template(template)


def test_sink_must_end_the_chain():
    """
    [Unit] loader: verifies M4 -- a transform after the sink re-taints the value.

    Scenario:
        Given ``{p.message|neutralize|upper}`` and ``{p.message|upper|neutralize}``
        When they are validated
        Then the first is rejected and the second accepted.

    Boundaries:
        - Focus: threat model T2(a)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``last`` filter check in ``_check_ref``
    """
    _rejects(_text(_over_problems(_line("{p.message|neutralize|upper}", ["p.message"]))), "must end")
    validate_template(_text(_over_problems(_line("{p.message|upper|neutralize}", ["p.message"]))))


def test_github_sink_accepts_only_gha_filters():
    """
    [Unit] loader: verifies M5/M6 -- under ``output.sink: github`` neutralize and json are not sinks.

    Scenario:
        Given a github-sink template emitting ``doc.path`` on a ``::notice`` command line through neutralize,
            json, gha_data (data segment) and gha_property (property segment)
        When they are validated
        Then neutralize and json are rejected; gha_data and gha_property are accepted.

    Boundaries:
        - Focus: threat model T2(b)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``FilterSpec.sinks`` of ``neutralize``/``json``
    """
    for chain in ("neutralize", "json"):
        line = _line(f"::notice::Path: {{doc.path|{chain}}}", ["doc.path"])
        _rejects(_github(_in_loop("documents", "doc", line)), "github sink")
    data = _line("::notice::Path: {doc.path|gha_data}", ["doc.path"])
    prop = _line("::notice title={doc.path|gha_property}::path", ["doc.path"])
    validate_template(_github(_in_loop("documents", "doc", data, prop)))


_LINE_START = "an emitted line must start with literal text"


def test_github_line_led_by_variable_is_rejected():
    """
    [Unit] loader: verifies T2/M5 -- a github-sink line may not start with a variable (regression).

    Scenario:
        Given github-sink lines whose first emitted part is ``{p.message|gha_data}``, ``{doc.path|gha_property}``,
            the trusted ``{profile}``, or a variable led only by whitespace or a lone ``:``
        When they are validated
        Then every one is rejected, so a message such as ``::stop-commands::`` can never begin a line.

    Boundaries:
        - Focus: threat model T2 (line-start workflow command), security review regression
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``lead`` check in ``_emitted_text``
    """
    _rejects(_github(_over_problems(_line("{p.message|gha_data}", ["p.message"]))), _LINE_START)
    _rejects(_github(_in_loop("documents", "doc", _line("{doc.path|gha_property}", ["doc.path"]))), _LINE_START)
    _rejects(_github(_line("{profile}", ["profile"])), _LINE_START)
    _rejects(_github(_over_problems(_line("   {p.message|gha_data}", ["p.message"]))), _LINE_START)
    _rejects(_github(_over_problems(_line(" :{p.message|gha_data}", ["p.message"]))), _LINE_START)


def test_github_line_with_literal_lead_is_accepted():
    """
    [Unit] loader: verifies T2 -- a github-sink line led by safe literal text, or a literal command, is accepted.

    Scenario:
        Given github-sink lines ``::notice::Note: {p.message|gha_data}``, a space-indented command, a
            literal-only line, an empty line, a plain line with a trusted variable and the standard
            ``::error file=...::...`` form
        When they are validated
        Then all are accepted.

    Boundaries:
        - Focus: threat model T2 (no over-rejection of the packaged github style)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``lead`` check in ``_emitted_text``
    """
    validate_template(_github(_over_problems(_line("::notice::Note: {p.message|gha_data}", ["p.message"]))))
    validate_template(_github(_over_problems(_line("  ::warning::{p.message|gha_data}", ["p.message"]))))
    validate_template(_github(_line("::notice::scan finished", []), _line("", [])))
    validate_template(_github(_line("Profile: {profile}", ["profile"])))
    standard = "::error file={doc.path|gha_property},line={p.line|gha_property}::{p.message|gha_data}"
    validate_template(_github(_over_problems(_line(standard, ["doc.path", "p.line", "p.message"]))))


def _inline(placement: str, text: str, used: list[str], **extra: Any) -> dict[str, Any]:
    """Return an inline ``one-line``/``append`` loop over ``documents`` aliased ``doc``."""
    return {
        "type": "loop",
        "over": "documents",
        "as": "doc",
        "placement": placement,
        "text": text,
        "variables_used": used,
        **extra,
    }


def test_github_loop_body_line_led_by_variable_is_rejected():
    """
    [Unit] loader: verifies T2 -- a block-loop body line under the github sink is held to the line-start rule.

    Scenario:
        Given a nested block-loop body line ``{p.message|gha_data} at {doc.path|gha_data}``
        When it is validated
        Then it is rejected; the same text on a well-formed ``::warning::`` command line is accepted.

    Boundaries:
        - Focus: threat model T2 (loop body lines)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_text_node`` passing ``line_prefix=""`` to ``_emitted_text``
    """
    used = ["p.message", "doc.path"]
    _rejects(_github(_over_problems(_line("{p.message|gha_data} at {doc.path|gha_data}", used))), _LINE_START)
    validate_template(_github(_over_problems(_line("::warning::{p.message|gha_data} at {doc.path|gha_data}", used))))


def test_github_one_line_loop_led_by_variable_is_rejected():
    """
    [Unit] loader: verifies T2 -- a github-sink ``one-line`` loop must start its line with a literal.

    Scenario:
        Given one-line loops with no prefix, a whitespace prefix, and a lone ``:`` prefix before ``{doc.path}``
        When they are validated
        Then all are rejected; a ``::notice::Docs: `` prefix is accepted.

    Boundaries:
        - Focus: threat model T2 (one-line placement)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_loop`` passing the prefix as ``line_prefix``
    """
    text, used = "{doc.path|gha_data}", ["doc.path"]
    _rejects(_github(_inline("one-line", text, used)), _LINE_START)
    _rejects(_github(_inline("one-line", text, used, prefix="  ")), _LINE_START)
    _rejects(_github(_inline("one-line", text, used, prefix=":")), _LINE_START)
    validate_template(_github(_inline("one-line", text, used, prefix="::notice::Docs: ", separator=", ")))


def test_github_one_line_command_items_need_gha_property():
    """
    [Unit] loader: verifies T2 -- items of a one-line loop whose prefix opens a command property need gha_property.

    Scenario:
        Given a one-line loop with prefix ``::notice title=`` emitting ``{doc.path|gha_data}``, and one with the
            complete ``::notice::`` prefix
        When they are validated
        Then the first is rejected (property segment) and the second, in the data segment, is accepted.

    Boundaries:
        - Focus: threat model T2 SHOULD (property segment), one-line placement
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``repeated`` branch in ``_emitted_text``
    """
    text, used = "{doc.path|gha_data}", ["doc.path"]
    _rejects(_github(_inline("one-line", text, used, prefix="::notice title=")), "needs gha_property")
    validate_template(_github(_inline("one-line", text, used, prefix="::notice::", separator=", ")))


def test_github_append_continuation_is_checked():
    """
    [Unit] loader: verifies T2 -- an ``append`` loop is held to the line-start rule and needs gha_property.

    Scenario:
        Given an ``append`` loop after a literal line, emitting ``{doc.path|gha_data}`` with no prefix, then with a
            ``Docs: `` prefix, then the trusted ``{r|gha_property}`` over ``enabled_rules`` with that prefix
        When they are validated
        Then the unprefixed one is rejected (it may start a line when no line precedes it), the gha_data one is
            rejected (it may continue a command property), and the trusted one is accepted.

    Boundaries:
        - Focus: threat model T2 (append continuation)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``append`` branch in ``_emitted_text``
    """
    head = _line("::notice::documents", [])
    _rejects(_github(head, _inline("append", "{doc.path|gha_data}", ["doc.path"])), _LINE_START)
    data = _inline("append", "{doc.path|gha_data}", ["doc.path"], prefix="Docs: ")
    _rejects(_github(head, data), "command property needs gha_property")
    good = {
        "type": "loop",
        "over": "enabled_rules",
        "as": "r",
        "placement": "append",
        "prefix": "Rules: ",
        "separator": ", ",
        "text": "{r|gha_property}",
        "variables_used": ["r"],
    }
    validate_template(_github(head, good))


def test_trusted_variable_in_command_property_needs_gha_property():
    """
    [Unit] loader: verifies T2 -- a trusted variable in a command property needs gha_property.

    Scenario:
        Given ``::notice title={model}::done`` and ``::notice title={p.line}::done`` under the github sink
        When they are validated
        Then both are rejected; the ``gha_property`` forms and ``{model}`` in the data segment are accepted.

    Boundaries:
        - Focus: threat model T2 SHOULD (property segment), MODEL_ID_PATTERN allows ``:``
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``property_segment`` check in ``_check_ref`` running before the trust early return
    """
    _rejects(_github(_line("::notice title={model}::done", ["model"])), "model", "needs gha_property")
    _rejects(_github(_over_problems(_line("::notice title={p.line}::done", ["p.line"]))), "needs gha_property")
    validate_template(_github(_line("::notice title={model|gha_property}::done", ["model"])))
    validate_template(_github(_line("::notice::model {model}", ["model"])))


def test_github_property_segment_needs_gha_property():
    """
    [Unit] loader: verifies an untrusted variable before the second ``::`` must end with ``gha_property``.

    Scenario:
        Given ``::error file={doc.path|gha_data}::...`` and the correct ``gha_property`` form
        When they are validated
        Then the data-escaped property is rejected and the correct line is accepted.

    Boundaries:
        - Focus: threat model T2 SHOULD (property segment)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``markers`` count in ``_emitted_text``
    """
    bad = "::error file={doc.path|gha_data},line={p.line|gha_property}::{p.message|gha_data}"
    good = "::error file={doc.path|gha_property},line={p.line|gha_property}::{p.message|gha_data}"
    used = ["doc.path", "p.line", "p.message"]
    _rejects(_github(_over_problems(_line(bad, used))), "command property needs gha_property")
    validate_template(_github(_over_problems(_line(good, used))))


_NOT_COMMAND = "is only allowed in a well-formed workflow command line"
_STANDARD_COMMAND = "::error file={p.document_path|gha_property},line={p.line|gha_property}::{p.message|gha_data}"
_STANDARD_USED = ["p.document_path", "p.line", "p.message"]


def _over_findings(placement: str, text: str, used: list[str], **extra: Any) -> dict[str, Any]:
    """Return an inline loop over the flat ``findings`` list aliased ``p``."""
    return {
        "type": "loop",
        "over": "findings",
        "as": "p",
        "placement": placement,
        "text": text,
        "variables_used": used,
        **extra,
    }


def test_github_untrusted_variable_outside_command_line_is_rejected():
    """
    [Unit] loader: verifies T2-R1 -- an untrusted variable only on a well-formed workflow command line (regression).

    Scenario:
        Given github-sink lines that the runner's V2 parser rejects, so its legacy ``##[`` parser scans them: a
            plain line ``Finding: {p.message|gha_data}``, an ``append`` loop after a plain line and after a
            command line, ``::warning {p.message|gha_property}`` (no second ``::``), a variable as the command
            name, an unlisted command name, and a name glued to a variable
        When they are validated
        Then every one is rejected, so a value such as ``##[stop-commands]tok`` can never become a command.

    Boundaries:
        - Focus: threat model T2-R1 (security-auditor re-review of 5b9704d)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``well_formed`` in ``_emitted_text`` and the ``command_line`` check in ``_check_ref``
    """
    _rejects(_github(_over_problems(_line("Finding: {p.message|gha_data}", ["p.message"]))), _NOT_COMMAND)
    append = _inline("append", " - {doc.path|gha_property}", ["doc.path"])
    _rejects(_github(_line("Paths:", []), append), _NOT_COMMAND)
    _rejects(_github(_line("::notice::Paths:", []), append), _NOT_COMMAND)
    _rejects(_github(_over_problems(_line("::warning {p.message|gha_property}", ["p.message"]))), _NOT_COMMAND)
    name_slot = "::{p.message|gha_property}::{p.message|gha_data}"
    _rejects(_github(_over_problems(_line(name_slot, ["p.message"]))), _NOT_COMMAND)
    _rejects(_github(_over_problems(_line("::stop-commands::{p.message|gha_data}", ["p.message"]))), _NOT_COMMAND)
    _rejects(_github(_over_problems(_line("::error{p.message|gha_property}::x", ["p.message"]))), _NOT_COMMAND)
    _rejects(_github(_over_findings("one-line", "Docs: {p.document_path|gha_data}", ["p.document_path"])), _NOT_COMMAND)


def test_github_variable_after_hash_literal_is_rejected():
    """
    [Unit] loader: verifies T2-R1 -- a variable may not directly follow a literal ending in ``#`` (split ``##[``).

    Scenario:
        Given github-sink texts where ``#``/``##`` ends the literal before a variable: in a command line, in a
            plain line with a trusted variable, in a one-line loop prefix, in its separator, and at the end of
            its item text joined by an empty separator
        When they are validated
        Then all are rejected; ``# `` followed by a space before the variable is accepted.

    Boundaries:
        - Focus: threat model T2-R1 (``##[`` completed by a ``[``-leading value)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_reject_hash_join``
    """
    hash_join = 'may not follow a literal ending in "#"'
    _rejects(_github(_over_problems(_line("::notice::##{p.message|gha_data}", ["p.message"]))), hash_join)
    _rejects(_github(_over_problems(_line("Line #{p.line}", ["p.line"]))), hash_join)
    data = "{p.document_path|gha_data}"
    _rejects(_github(_over_findings("one-line", data, ["p.document_path"], prefix="::notice::##")), hash_join)
    looped = _over_findings("one-line", data, ["p.document_path"], prefix="::notice::", separator="#")
    _rejects(_github(looped), hash_join)
    tail = _over_findings("one-line", data + "#", ["p.document_path"], prefix="::notice::")
    _rejects(_github(tail), hash_join)
    validate_template(_github(_over_problems(_line("::notice::# {p.message|gha_data}", ["p.message"]))))


def test_github_command_data_needs_gha_data():
    """
    [Unit] loader: verifies T2-R1 -- an untrusted variable after the second ``::`` must end with ``gha_data``.

    Scenario:
        Given ``::notice::{p.message|gha_property}`` and the trusted ``::notice::line {p.line}``
        When they are validated
        Then the untrusted one is rejected and the trusted one is accepted unfiltered.

    Boundaries:
        - Focus: threat model T2-R1 (data segment filter)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``data_segment`` check in ``_check_ref``
    """
    _rejects(_github(_over_problems(_line("::notice::{p.message|gha_property}", ["p.message"]))), "needs gha_data")
    validate_template(_github(_over_problems(_line("::notice::line {p.line}", ["p.line"]))))


def test_github_standard_command_is_accepted_in_every_placement():
    """
    [Unit] loader: verifies T2-R1 and the one-line fix -- the standard ``::error file=...::...`` form loads everywhere.

    Scenario:
        Given the standard command as a line node in nested loops, as a block-loop body over ``findings``, as the
            full item text of a one-line loop (regression: its ``::`` markers were not counted), split between a
            one-line prefix and its text, and with the whole header in the prefix
        When they are validated
        Then all are accepted, so the future packaged ``github.json`` is expressible.

    Boundaries:
        - Focus: threat model T2-R1 (no over-rejection), feature-reviewer one-line ``::`` count
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The per-item ``markers`` count in ``_emitted_text``
    """
    nested = "::error file={doc.path|gha_property},line={p.line|gha_property}::{p.message|gha_data}"
    validate_template(_github(_over_problems(_line(nested, ["doc.path", "p.line", "p.message"]))))
    validate_template(_github(_in_loop("findings", "p", _line(_STANDARD_COMMAND, _STANDARD_USED))))
    validate_template(_github(_over_findings("one-line", _STANDARD_COMMAND, _STANDARD_USED, separator=" ")))
    split = _STANDARD_COMMAND[len("::error file=") :]
    validate_template(_github(_over_findings("one-line", split, _STANDARD_USED, prefix="::error file=")))
    header = _over_findings(
        "one-line",
        "{p.document_path|gha_data}: {p.message|gha_data}",
        ["p.document_path", "p.message"],
        prefix="::error title=DocSentinel::",
        separator="; ",
    )
    validate_template(_github(header))


def test_github_one_line_full_command_text_still_checks_segments():
    """
    [Unit] loader: verifies the per-item ``::`` count still holds each segment to its filter.

    Scenario:
        Given a one-line loop whose item text is the full command but with ``gha_data`` in the property segment,
            and one with ``gha_property`` in the data segment
        When they are validated
        Then the first needs gha_property and the second needs gha_data.

    Boundaries:
        - Focus: feature-reviewer one-line ``::`` count (no under-checking after the fix)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The per-item ``markers`` count in ``_emitted_text``
    """
    bad_property = _STANDARD_COMMAND.replace("{p.document_path|gha_property}", "{p.document_path|gha_data}")
    _rejects(_github(_over_findings("one-line", bad_property, _STANDARD_USED)), "needs gha_property")
    bad_data = _STANDARD_COMMAND.replace("{p.message|gha_data}", "{p.message|gha_property}")
    _rejects(_github(_over_findings("one-line", bad_data, _STANDARD_USED)), "needs gha_data")


def test_workflow_command_line_requires_github_sink():
    """
    [Unit] loader: verifies a terminal-sink template cannot start a line with ``::``.

    Scenario:
        Given a terminal-sink line and a one-line loop prefix starting with ``::``
        When they are validated
        Then both are rejected, so a GitHub template cannot omit its sink declaration.

    Boundaries:
        - Focus: M5 (sink must be declared)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``command`` check in ``_emitted_text`` and the prefix check in ``_loop``
    """
    _rejects(_text(_line("::notice::{profile}", ["profile"])), 'requires output.sink "github"')
    loop = {
        "type": "loop",
        "over": "enabled_rules",
        "as": "r",
        "placement": "one-line",
        "prefix": "::notice::",
        "text": "{r}",
        "variables_used": ["r"],
    }
    _rejects(_text(loop), 'requires output.sink "github"')


def test_model_is_trusted_only_because_it_is_bounded():
    """
    [Unit] loader: verifies ``{model}`` is accepted unfiltered and that this relies on the M15 bound.

    Scenario:
        Given a line emitting ``{model}`` with no filter
        When it is validated
        Then it loads, and the schema tags ``model`` trusted only while ``MODEL_ID_PATTERN`` exists.

    Boundaries:
        - Focus: threat model T8 (Task 01 part)
        - Fixtures/params: none
        - Scope: validate_template and the context schema

    On failure, first check:
        - ``CONTEXT_SCHEMA["model"]`` and ``ReportModel.build`` model validation
    """
    validate_template(_text(_line("Model: {model}", ["model"])))
    assert CONTEXT_SCHEMA["model"].trust == TRUSTED
    assert MODEL_ID_PATTERN.fullmatch("\x1b[31m") is None


# --------------------------------------------------------------------------- literal hygiene (M7, M8)


@pytest.mark.parametrize(
    "bad", ["\x1b[2J", "a\rb", "a\nb", "\x85", chr(0x202E), chr(0x200B), chr(0xD800), chr(0x2028), "\t"]
)
@pytest.mark.parametrize("where", ["text", "separator", "key", "join", "description"])
def test_control_code_points_in_template_strings_are_rejected(bad: str, where: str):
    """
    [Unit] loader: verifies M7 -- no template string or key may hold a neutralize-table code point.

    Scenario:
        Given ESC, CR, LF, RLO, ZWSP, a lone surrogate, C1 NEL, LINE SEPARATOR or TAB in a line text, a
        separator, an object key, ``output.join`` or the description
        When the template is validated
        Then it is rejected without echoing the raw code point.

    Boundaries:
        - Focus: threat model T3 / M7
        - Fixtures/params: nine code points x five positions
        - Scope: validate_template

    On failure, first check:
        - ``_precheck`` and ``_is_neutral``
    """
    loop = {
        "type": "loop",
        "over": "enabled_rules",
        "as": "r",
        "placement": "one-line",
        "text": "{r}",
        "variables_used": ["r"],
        "separator": ", ",
    }
    template = _text(_line("ok", []), loop)
    if where == "text":
        template["lines"][0]["text"] = f"x{bad}y"
    elif where == "separator":
        loop["separator"] = bad
    elif where == "key":
        template["lines"][0][f"k{bad}"] = 1
    elif where == "join":
        template["output"] = {"join": f"{bad}x"}
    else:
        template["description"] = bad
    with pytest.raises(TemplateError) as caught:
        validate_template(template)
    assert bad not in str(caught.value)


def test_output_join_may_only_be_a_newline():
    """
    [Unit] loader: verifies ``output.join`` accepts exactly ``"\\n"`` (the M7 exemption) and nothing else.

    Scenario:
        Given join ``"\\n"``, ``"\\r\\n"`` and ``" | "``
        When they are validated
        Then only ``"\\n"`` is accepted.

    Boundaries:
        - Focus: M7 join rule, edge of the exemption
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``join`` tag in ``_precheck`` and ``_text_output``
    """
    validate_template(_text(_line("x", []), output={"join": "\n"}))
    _rejects(_text(_line("x", []), output={"join": "\r\n"}), "control")
    _rejects(_text(_line("x", []), output={"join": " | "}), "output.join")
    _rejects(_text(_line("\n", [])), "control")


@pytest.mark.parametrize(
    ("output", "ok"),
    [
        ({"indent": None}, True),
        ({"indent": 0}, True),
        ({"indent": 8}, True),
        ({"indent": 9}, False),
        ({"indent": -1}, False),
        ({"indent": "  "}, False),
        ({"indent": True}, False),
        ({"ensure_ascii": True}, True),
        ({"ensure_ascii": False}, False),
        ({"sort_keys": "yes"}, False),
        ({"pretty": True}, False),
    ],
)
def test_json_output_settings_are_bounded(output: dict[str, Any], ok: bool):
    """
    [Unit] loader: verifies M8 -- indent is null or 0..8 and ensure_ascii must be true.

    Scenario:
        Given json ``output`` settings at and beyond each bound
        When they are validated
        Then only the in-bound settings load.

    Boundaries:
        - Focus: threat model T3 / M8
        - Fixtures/params: one setting per case
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._json_output``
    """
    template = _json(1, output=output)
    if ok:
        validate_template(template)
    else:
        _rejects(template, "output")


# --------------------------------------------------------------------------- json operators (M14)


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({"$foo": 1}, "unknown operator: $foo"),
        ({"$var": "profile", "extra": 1}, "unknown key(s): extra"),
        ({"$var": "nope"}, "unknown variable"),
        ({"$var": "profile|lower"}, "invalid variable path"),
        ({"$var": "profile", "$default": {"$var": "model"}}, "operator key inside a literal default"),
        ({"$omit_if": {"var": "model", "eq": None}, "value": 1}, "only valid as the value of an object member"),
        ({"k": {"$omit_if": {"var": "model", "eq": None}}}, "missing key(s): value"),
        ({"$for": "profile", "as": "x", "each": 1}, "not a list"),
        ({"$for": "documents", "each": 1}, "missing key(s): as"),
        ({"$if": {"var": "profile", "eq": "x"}}, "missing key(s): then"),
        ({"$str": "{documents}"}, "is a list"),
        ({"$str": 3}, "expected a string"),
    ],
)
def test_json_operator_violations_are_rejected(body: Any, fragment: str):
    """
    [Unit] loader: verifies the json operator set is closed and shape-checked (M14 load-time part).

    Scenario:
        Given an unknown ``$`` key, extra keys, a misplaced ``$omit_if``, or an operator smuggled into a default
        When the json template is validated
        Then it is rejected rather than emitted as a literal.

    Boundaries:
        - Focus: spec §5 operators, threat model T7
        - Fixtures/params: one defect per case
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._json_operator``
    """
    _rejects(_json(body), fragment)


# --------------------------------------------------------------------------- placements


@pytest.mark.parametrize(
    ("loop", "fragment"),
    [
        ({"placement": "inline", "body": []}, "placement must be"),
        ({"body": [], "text": "x"}, "unknown key(s): text"),
        ({"placement": "one-line", "body": []}, "unknown key(s): body"),
        ({"placement": "append", "text": "{r}", "variables_used": ["r"], "body": []}, "unknown key(s): body"),
        ({"placement": "one-line", "text": "{r}", "variables_used": ["r"], "separator": 1}, "expected a string"),
    ],
)
def test_loop_placement_keys_are_enforced(loop: dict[str, Any], fragment: str):
    """
    [Unit] loader: verifies block loops take ``body`` and inline loops take ``text``, never both.

    Scenario:
        Given loops with a bad placement or the other placement's keys
        When they are validated
        Then they are rejected.

    Boundaries:
        - Focus: spec §4 ``loop.placement`` keys
        - Fixtures/params: one defect per case
        - Scope: validate_template

    On failure, first check:
        - The per-placement key sets in ``_Validator._loop``
    """
    _rejects(_text({"type": "loop", "over": "enabled_rules", "as": "r", **loop}), fragment)


def test_unknown_node_type_and_group_shape():
    """
    [Unit] loader: verifies node ``type`` is closed and ``group`` requires ``when`` and ``body``.

    Scenario:
        Given a ``table`` node, a group without ``when``, and a valid group
        When they are validated
        Then the first two are rejected.

    Boundaries:
        - Focus: spec §4 node types
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_Validator._text_node``
    """
    _rejects(_text({"type": "table"}), "node type must be")
    _rejects(_text({"type": "group", "body": []}), "missing key(s): when")
    validate_template(_text({"type": "group", "when": {"var": "pending", "truthy": True}, "body": [_line("x", [])]}))


# --------------------------------------------------------------------------- bombs (M12, M13)


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ('{"a": 1, "a": 2}', "duplicate object key: a"),
        ('{"a": NaN}', "non-finite"),
        ('{"a": -Infinity}', "non-finite"),
        ('{"a": 1e999}', "non-finite"),
        ('{"a": ' + "9" * 5000 + "}", "invalid JSON number"),
        ("[" * 200_000 + "]" * 200_000, "nesting is too deep"),
        ('{"a": ', "invalid JSON at line 1"),
    ],
)
def test_parse_bombs_become_bounded_template_errors(text: str, fragment: str):
    """
    [Unit] loader: verifies M12 parse guards -- duplicates, NaN/Infinity, overflow, huge ints, deep nesting.

    Scenario:
        Given template text holding one parse bomb
        When it is parsed
        Then a bounded TemplateError is raised instead of a traceback.

    Boundaries:
        - Focus: threat model T5 / M12
        - Fixtures/params: one bomb per case
        - Scope: ``loader._parse_json``

    On failure, first check:
        - ``_parse_json`` hooks and exception mapping
    """
    with pytest.raises(TemplateError) as caught:
        loader._parse_json(text, "t.json")
    assert fragment in str(caught.value)
    assert len(str(caught.value)) <= MAX_MESSAGE


def test_structural_depth_and_node_bounds():
    """
    [Unit] loader: verifies raw depth, condition nesting and node count are bounded before deep recursion.

    Scenario:
        Given a 150-deep raw list, a 40-deep ``not`` chain, and a json body of 10,001 literals
        When they are validated
        Then each raises TemplateError; a 30-deep ``not`` chain is accepted.

    Boundaries:
        - Focus: M12 (nesting <= 32, nodes <= 10,000, iterative precheck)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - ``_precheck`` and ``_Validator._tick``
    """
    deep: Any = 1
    for _ in range(150):
        deep = [deep]
    _rejects(_json(deep), "JSON nesting deeper than")

    def chain(levels: int) -> dict[str, Any]:
        """Return a condition wrapped in ``levels`` ``not`` operators."""
        condition: dict[str, Any] = {"var": "profile", "eq": "x"}
        for _ in range(levels):
            condition = {"not": condition}
        return condition

    validate_template(_text(_line("x", [], when=chain(30))))
    _rejects(_text(_line("x", [], when=chain(40))), "nesting deeper than 32")
    _rejects(_json(list(range(MAX_NODES + 1))), f"more than {MAX_NODES} nodes")


def test_loop_nesting_is_bounded_to_four():
    """
    [Unit] loader: verifies M13 load-time part -- at most four nested loops (text and json).

    Scenario:
        Given four and five nested block loops, and five nested ``$for``
        When they are validated
        Then four loads and five is rejected in both template types.

    Boundaries:
        - Focus: threat model T6 / M13 (depth part)
        - Fixtures/params: none
        - Scope: validate_template

    On failure, first check:
        - The ``loops`` counter in ``_loop`` and ``_json_operator``
    """
    lists = [("documents", "a"), ("findings", "b"), ("pending", "c"), ("enabled_rules", "d"), ("opt_in_off", "e")]

    def nest(depth: int) -> dict[str, Any]:
        """Return ``depth`` nested block loops around one line."""
        node: dict[str, Any] = _line("x", [])
        for over, alias in reversed(lists[:depth]):
            node = _in_loop(over, alias, node)
        return node

    def nest_json(depth: int) -> Any:
        """Return ``depth`` nested ``$for`` operators around a literal."""
        node: Any = 1
        for over, alias in reversed(lists[:depth]):
            node = {"$for": over, "as": alias, "each": node}
        return node

    validate_template(_text(nest(4)))
    _rejects(_text(nest(5)), "loops nest deeper than 4")
    validate_template(_json(nest_json(4)))
    _rejects(_json(nest_json(5)), "loops nest deeper than 4")


# --------------------------------------------------------------------------- errors (M16), immutability (M17)


def test_error_messages_are_bounded_and_neutralized():
    """
    [Unit] loader: verifies M16 -- hostile keys and long variable names never reach the message raw or unbounded.

    Scenario:
        Given a node key holding ESC and U+202E, and a 1 KiB unknown variable
        When they are validated
        Then each message is at most MAX_MESSAGE characters and holds no raw ESC or RLO.

    Boundaries:
        - Focus: threat model T9 / M16
        - Fixtures/params: none
        - Scope: validate_template and TemplateError

    On failure, first check:
        - ``_echo`` / ``_echo_path`` and ``TemplateError.__init__``
    """
    hostile = _text(_line("x", []))
    hostile["lines"][0]["\x1b[31m" + chr(0x202E) + "evil" + "k" * 1000] = 1
    long_name = "v" * 1024
    for template in (hostile, _text(_line(f"{{{long_name}}}", [long_name]))):
        message = _rejects(template)
        assert "\x1b" not in message and chr(0x202E) not in message
        assert len(message) <= MAX_MESSAGE
    assert long_name[: MAX_ECHO + 1] not in _rejects(_text(_line(f"{{{long_name}}}", [long_name])))
    assert str(TemplateError("a\x1bb" * 400)).count("\x1b") == 0 and len(str(TemplateError("x" * 9999))) == MAX_MESSAGE


def test_parsed_template_is_immutable():
    """
    [Unit] loader: verifies M17 -- a returned template cannot be mutated in place.

    Scenario:
        Given a loaded text template and a json template with a list/object ``$default``
        When an attribute, a node tuple, or the frozen default is mutated
        Then each mutation raises.

    Boundaries:
        - Focus: threat model T10 / M17
        - Fixtures/params: none
        - Scope: the parsed dataclasses

    On failure, first check:
        - ``frozen=True`` on every dataclass and ``_freeze_literal``
    """
    template = validate_template(_SPEC_TEXT_EXAMPLE)
    with pytest.raises(dataclasses.FrozenInstanceError):
        template.name = "x"  # type: ignore[misc]
    with pytest.raises(TypeError):
        template.lines[0] = template.lines[1]  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        template.lines[0].text.parts[1].filters = ()  # type: ignore[misc]
    frozen = validate_template(_json({"$var": "pending", "$default": {"a": [1]}})).body
    with pytest.raises(TypeError):
        frozen.default["a"] = 2
    assert frozen.default["a"] == (1,)


def test_mapping_source_is_validated_and_unknown_name_is_rejected():
    """
    [Unit] loader: verifies ``load_template`` validates a mapping and refuses an unknown name.

    Scenario:
        Given a valid mapping and a name that is neither packaged nor in a templates dir
        When ``load_template`` is called
        Then the mapping loads and the name raises ``unknown template``.

    Boundaries:
        - Focus: source dispatch of ``load_template``
        - Fixtures/params: none
        - Scope: load_template

    On failure, first check:
        - ``load_template`` / ``_load_by_name``
    """
    assert load_template(_SPEC_TEXT_EXAMPLE).origin == "mapping"
    with pytest.raises(TemplateError, match="unknown template: no-such-template-xyz"):
        load_template("no-such-template-xyz")
    assert json.loads(json.dumps(_SPEC_TEXT_EXAMPLE)) == _SPEC_TEXT_EXAMPLE


@pytest.mark.parametrize(
    ("raw", "fragment"),
    [
        ([], "must be a JSON object"),
        (_text(_line("x", []), description=object()), "not JSON data"),
        ({**_text(), 1: 2}, "keys must be strings"),
        (_json(float("nan")), "non-finite"),
        (_json([0] * 60_000), "more than 50000 JSON values"),
        ({**_text(), "lines": {}}, "expected a list of nodes"),
        (_text("line"), "node type must be"),
    ],
)
def test_non_json_shapes_are_rejected_before_validation(raw: Any, fragment: str):
    """
    [Unit] loader: verifies the iterative precheck rejects non-JSON data and oversized trees from mapping sources.

    Scenario:
        Given a non-object root, a Python object, a non-string key, NaN, 60,000 values, or a non-list ``lines``
        When it is validated
        Then TemplateError names the defect.

    Boundaries:
        - Focus: M12 precheck for already-decoded (test) sources
        - Fixtures/params: one shape defect per case
        - Scope: validate_template

    On failure, first check:
        - ``loader._precheck``
    """
    _rejects(raw, fragment)


def test_templates_dir_and_config_paths_need_a_root():
    """
    [Unit] loader: verifies a templates dir or config-named path without a scan root fails closed.

    Scenario:
        Given ``templates_dir`` without ``root``, and ``from_config=True`` without ``root``
        When ``load_template`` is called
        Then TemplateError is raised before any filesystem access under the dir.

    Boundaries:
        - Focus: invalid call shapes of ``load_template``
        - Fixtures/params: none
        - Scope: load_template

    On failure, first check:
        - The ``root is None`` guards in ``_load_by_name`` and ``load_template``
    """
    with pytest.raises(TemplateError, match="needs a scan root"):
        load_template("no-such-template-xyz", templates_dir="templates")
    with pytest.raises(TemplateError, match="needs a scan root"):
        load_template("templates/x.json", from_config=True)
