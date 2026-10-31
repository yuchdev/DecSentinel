"""Report template renderer (Milestone 0007 Story 02.0 Task 02).

:func:`render_template` renders a :class:`~docsentinel.telemetry.loader.Template`
-- already validated by :mod:`docsentinel.telemetry.loader`, which this module never
re-validates -- against a JSON-shaped context such as the one
:meth:`docsentinel.telemetry.model.ReportModel.build` returns. The contract is
``docs/specs/report-template-format.md`` §4-§7. The renderer holds no format names,
no literal report lines and no escaping rules: escaping lives in the closed filter
table of :mod:`docsentinel.telemetry.filters`.

It is additive: :func:`docsentinel.reporting.render` does not use it until the
Story 03.0 cut-over.

Rendering semantics:

* **text** -- the top-level ``lines`` are walked in order. ``line`` emits one
  output line; ``group`` renders its body when its condition holds; a ``block``
  loop renders its body once per item; a ``one-line`` loop joins the per-item text
  with ``separator`` into one new line, framed by ``prefix``/``suffix``; an
  ``append`` loop extends the last emitted line (or starts the first one) the same
  way. An inline loop over an empty list emits nothing at all. Lines are joined
  with ``output.join`` (``"\\n"``); ``trailing_newline`` adds one more after a
  non-empty output.
* **json** -- the ``body`` is evaluated (``$var`` by type with ``$default`` for a
  null or absent value, ``$for``, ``$if``, ``$str``, ``$omit_if``) and serialized
  with ``json.dumps(indent, ensure_ascii=True, sort_keys)``. ``ensure_ascii`` is
  forced ``True`` whatever the template object says (threat model M8).
* **values** -- a variable is emitted through its filter chain; a string is emitted
  as-is and any other scalar in its JSON spelling (``null``, ``true``, ``3``). A
  variable absent from the context (an opt-in ``run`` that was not requested, an
  out-of-range ``items.0``) is a :class:`TemplateError`, never an empty string,
  unless its chain starts with ``default``. In a condition an absent variable is
  ``null``. ``gt``/``lt`` hold only for numbers; ``eq``/``ne``/``in`` never equate
  a boolean with a number.

Security contract (``docs/security/threat-model-0007-template-engine-2026-10-31.md``):

* **M8** -- ``ensure_ascii`` is always ``True`` for ``json`` templates, custom ones
  included, so every control and non-ASCII code point is escaped by serialization.
* **M13 (render part)** -- every loop item counts against :data:`MAX_ITERATIONS`
  and every emitted character against :data:`MAX_OUTPUT_CHARS`; passing either
  stops rendering with a :class:`TemplateError`. Output is never truncated.
* **M14 (render part)** -- substitution is single-pass: a substituted value is
  appended to the output and never re-scanned, so ``{run.id}`` or ``{{`` inside a
  message stays literal. There is no ``str.format``, ``format_map``, ``%``, ``eval``
  or ``getattr``; traversal is only ``dict[key]`` and ``list[int]`` on exact
  ``dict``/``list`` instances. Operators are evaluated on template nodes only: a
  ``$var`` value is embedded as data, so ``$``-keys inside context data are never
  operators. A context node that is not JSON-shaped (an object, a tuple, a
  non-string key, a non-finite float) is rejected before rendering starts.
* **Defence in depth** -- a rendered ``text`` line that still holds a code point the
  ``neutralize`` table escapes (only possible through a mis-tagged trusted value) is
  a :class:`TemplateError` rather than output.
* **Purity** -- rendering performs no I/O and never reads files, environment
  variables or the clock (a mock test patches all three to raise).
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, Final, Optional

from docsentinel.telemetry.filters import TemplateError, apply_filter, neutralize, to_text
from docsentinel.telemetry.loader import (
    PLACEMENT_APPEND,
    PLACEMENT_BLOCK,
    PLACEMENT_ONE_LINE,
    AllOf,
    AnyOf,
    Compare,
    Condition,
    GroupNode,
    Interpolation,
    JsonArray,
    JsonFor,
    JsonIf,
    JsonLiteral,
    JsonNode,
    JsonObject,
    JsonOutput,
    JsonStr,
    JsonVar,
    LineNode,
    LoopNode,
    Not,
    Template,
    TextNode,
    TextOutput,
    VarRef,
)

#: Cap on rendered characters (M13). Rendering stops with an error once passed.
MAX_OUTPUT_CHARS: Final[int] = 64 * 1024 * 1024

#: Cap on loop items rendered across all ``loop``/``$for`` nodes (M13).
MAX_ITERATIONS: Final[int] = 5_000_000

#: Maximum characters of a variable name echoed in an error.
_MAX_NAME_ECHO = 80

JsonValue = Any


class _Missing:
    """Sentinel type for a path that is absent from the context."""

    __slots__ = ()

    def __repr__(self) -> str:
        """Return a stable debug representation."""
        return "<missing>"


_MISSING: Final[_Missing] = _Missing()


def _echo_name(ref: VarRef) -> str:
    """Return a bounded, neutralized variable name for an error message.

    :param ref: The reference.
    :returns: At most :data:`_MAX_NAME_ECHO` characters of its name.
    """
    name = ref.name
    bounded = neutralize(name[:_MAX_NAME_ECHO])
    return f"{bounded}..." if len(name) > _MAX_NAME_ECHO else bounded


def _check_context(context: object):
    """Reject a context that is not a JSON-shaped tree (M14).

    Walks iteratively, so depth cannot overflow the stack; a container reached twice
    (shared sub-trees such as ``documents_with_problems``) is checked once.

    :param context: The render context.
    :raises TemplateError: When the root is not a ``dict``, or any node is not an
        exact ``dict``/``list``/``str``/``int``/``bool``/``None`` or finite ``float``,
        or a key is not a string. The offending value is never echoed.
    """
    if type(context) is not dict:
        raise TemplateError("the render context must be a JSON object")
    seen: set[int] = set()
    stack: list[object] = [context]
    while stack:
        value = stack.pop()
        kind = type(value)
        if kind is dict:
            if id(value) in seen:
                continue
            seen.add(id(value))
            for key, item in value.items():
                if type(key) is not str:
                    raise TemplateError("the render context has a non-string object key")
                stack.append(item)
        elif kind is list:
            if id(value) in seen:
                continue
            seen.add(id(value))
            stack.extend(value)
        elif value is None or kind in (str, int, bool):
            continue
        elif kind is float and math.isfinite(value):
            continue
        else:
            raise TemplateError("the render context holds a value that is not JSON data")


def _thaw(value: Any) -> JsonValue:
    """Return a mutable JSON copy of a frozen template literal (M17 form).

    :param value: A literal from the parsed template (tuples, ``MappingProxyType``).
    :returns: The same value with lists and dicts.
    """
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _is_number(value: object) -> bool:
    """Return whether ``value`` is an ``int`` or ``float`` but not a ``bool``.

    :param value: Any value.
    :returns: ``True`` for a number.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _equal(left: object, right: object) -> bool:
    """Compare two JSON values without equating booleans and numbers.

    :param left: The context value.
    :param right: The template operand.
    :returns: ``True`` when they are equal JSON values.
    """
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if _is_number(left) and _is_number(right):
        return left == right
    return type(left) is type(right) and left == right


class _Budget:
    """Iteration and output-size budget of one render call (M13)."""

    __slots__ = ("chars", "iterations")

    def __init__(self):
        """Start an empty budget."""
        self.chars = 0
        self.iterations = 0

    def iterate(self):
        """Count one loop item.

        :raises TemplateError: When :data:`MAX_ITERATIONS` is passed.
        """
        self.iterations += 1
        if self.iterations > MAX_ITERATIONS:
            raise TemplateError(f"rendering stopped: more than {MAX_ITERATIONS} loop items")

    def charge(self, count: int):
        """Count ``count`` emitted characters.

        :param count: Characters about to be emitted.
        :raises TemplateError: When :data:`MAX_OUTPUT_CHARS` is passed.
        """
        self.chars += count
        if self.chars > MAX_OUTPUT_CHARS:
            raise TemplateError(f"rendering stopped: output larger than {MAX_OUTPUT_CHARS} characters")


def _size(value: JsonValue) -> int:
    """Estimate the serialized size of a JSON value, iteratively.

    :param value: A context sub-tree.
    :returns: At least one per node, plus the length of every string and key.
    """
    total = 0
    stack: list[JsonValue] = [value]
    while stack:
        item = stack.pop()
        total += 1
        if isinstance(item, dict):
            total += sum(len(key) for key in item)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            total += len(item)
    return total


class _Renderer:
    """One render pass over a fixed context; loop aliases are bound in place."""

    def __init__(self, context: Mapping[str, JsonValue]):
        """Bind the context.

        :param context: The checked, JSON-shaped context.
        """
        self._context = context
        self._aliases: dict[str, JsonValue] = {}
        self._budget = _Budget()

    # ---- values

    def _lookup(self, ref: VarRef) -> JsonValue:
        """Resolve a reference by ``dict[key]``/``list[int]`` traversal only (M14).

        :param ref: The reference.
        :returns: The value, or :data:`_MISSING` when any step is absent.
        """
        head = ref.path[0]
        if head in self._aliases:
            current = self._aliases[head]
        elif head in self._context:
            current = self._context[head]
        else:
            return _MISSING
        for step in ref.path[1:]:
            if type(step) is int:
                if type(current) is not list or step >= len(current):
                    return _MISSING
                current = current[step]
            elif type(current) is dict and step in current:
                current = current[step]
            else:
                return _MISSING
        return current

    def _value(self, ref: VarRef) -> JsonValue:
        """Resolve a reference and apply its filter chain left to right.

        :param ref: The reference.
        :returns: The filtered value.
        :raises TemplateError: When the variable is absent (and the chain does not
            start with ``default``) or a filter rejects its input.
        """
        value = self._lookup(ref)
        if value is _MISSING:
            if not ref.filters or ref.filters[0].name != "default":
                raise TemplateError(f"variable {_echo_name(ref)} is not present in the render context")
            value = None
        for call in ref.filters:
            try:
                value = apply_filter(call.name, value, call.args)
            except TemplateError as exc:
                raise TemplateError(f"variable {_echo_name(ref)}: {exc}") from None
        return value

    def _interpolate(self, text: Interpolation) -> str:
        """Render an interpolation in a single pass (M14).

        :param text: The parsed text.
        :returns: Literals and substituted values concatenated; values are never
            re-scanned for ``{...}``.
        """
        pieces: list[str] = []
        for part in text.parts:
            if isinstance(part, str):
                pieces.append(part)
                continue
            value = self._value(part)
            try:
                pieces.append(to_text(value))
            except TemplateError as exc:
                raise TemplateError(f"variable {_echo_name(part)}: {exc}") from None
        return "".join(pieces)

    def _items(self, ref: VarRef) -> list[JsonValue]:
        """Return the list a loop iterates.

        :param ref: The iterated reference.
        :returns: The list.
        :raises TemplateError: When the value is absent or not a list.
        """
        value = self._lookup(ref)
        if type(value) is not list:
            state = "not present in the render context" if value is _MISSING else "not a list"
            raise TemplateError(f"loop variable {_echo_name(ref)} is {state}")
        return value

    # ---- conditions

    def _holds(self, condition: Optional[Condition]) -> bool:
        """Evaluate a condition from the closed grammar; ``None`` always holds.

        :param condition: The parsed condition.
        :returns: Whether it holds.
        """
        if condition is None:
            return True
        if isinstance(condition, Compare):
            value = self._lookup(condition.var)
            if value is _MISSING:
                value = None
            return self._compare(value, condition.op, condition.operand)
        if isinstance(condition, AllOf):
            return all(self._holds(item) for item in condition.conditions)
        if isinstance(condition, AnyOf):
            return any(self._holds(item) for item in condition.conditions)
        if isinstance(condition, Not):
            return not self._holds(condition.condition)
        raise TemplateError("unknown condition node")

    @staticmethod
    def _compare(value: JsonValue, op: str, operand: Any) -> bool:
        """Apply one comparison operator.

        :param value: The context value (``None`` when absent).
        :param op: The operator.
        :param operand: The literal template operand.
        :returns: Whether the comparison holds.
        """
        if op == "truthy":
            return bool(value)
        if op == "falsy":
            return not value
        if op == "eq":
            return _equal(value, operand)
        if op == "ne":
            return not _equal(value, operand)
        if op == "in":
            return any(_equal(value, item) for item in operand)
        if op in ("gt", "lt"):
            if not (_is_number(value) and _is_number(operand)):
                return False
            return value > operand if op == "gt" else value < operand
        raise TemplateError("unknown condition operator")

    # ---- text

    def text(self, template: Template) -> str:
        """Render a ``text`` template.

        :param template: The validated template.
        :returns: The report text.
        """
        output = template.output
        if not isinstance(output, TextOutput) or output.join != "\n":
            raise TemplateError("a text template needs a text output with join \\n")
        lines: list[str] = []
        self._nodes(template.lines, lines)
        for line in lines:
            if neutralize(line) != line:
                raise TemplateError("a rendered line holds a control or format character from an unfiltered value")
        rendered = output.join.join(lines)
        if output.trailing_newline and lines:
            rendered += output.join
        return rendered

    def _nodes(self, nodes: Sequence[TextNode], lines: list[str]):
        """Render text nodes into ``lines``.

        :param nodes: The nodes.
        :param lines: The output lines, extended in place.
        """
        for node in nodes:
            if isinstance(node, LineNode):
                if self._holds(node.when):
                    self._emit(lines, self._interpolate(node.text))
            elif isinstance(node, GroupNode):
                if self._holds(node.when):
                    self._nodes(node.body, lines)
            elif isinstance(node, LoopNode):
                if self._holds(node.when):
                    self._loop(node, lines)
            else:
                raise TemplateError("unknown text node")

    def _emit(self, lines: list[str], line: str):
        """Append one output line, charging the budget.

        :param lines: The output lines.
        :param line: The new line.
        """
        self._budget.charge(len(line) + 1)
        lines.append(line)

    def _loop(self, node: LoopNode, lines: list[str]):
        """Render a loop in its placement.

        :param node: The loop node (its ``when`` already holds).
        :param lines: The output lines.
        """
        items = self._items(node.over)
        if node.placement == PLACEMENT_BLOCK:
            for item in items:
                self._budget.iterate()
                self._aliases[node.alias] = item
                self._nodes(node.body, lines)
            self._aliases.pop(node.alias, None)
            return
        if node.placement not in (PLACEMENT_ONE_LINE, PLACEMENT_APPEND) or node.text is None:
            raise TemplateError("unknown loop placement")
        if not items:
            return
        pieces: list[str] = []
        self._budget.charge(len(node.prefix) + len(node.suffix))
        for position, item in enumerate(items):
            self._budget.iterate()
            self._aliases[node.alias] = item
            piece = self._interpolate(node.text)
            separator = node.separator if position else ""
            self._budget.charge(len(separator) + len(piece))
            pieces.append(separator)
            pieces.append(piece)
        self._aliases.pop(node.alias, None)
        segment = node.prefix + "".join(pieces) + node.suffix
        if node.placement == PLACEMENT_APPEND and lines:
            lines[-1] += segment
        else:
            self._budget.charge(1)
            lines.append(segment)

    # ---- json

    def json(self, template: Template) -> str:
        """Render a ``json`` template; ``ensure_ascii`` is forced ``True`` (M8).

        :param template: The validated template.
        :returns: The serialized document.
        """
        output = template.output
        if not isinstance(output, JsonOutput) or template.body is None:
            raise TemplateError("a json template needs a json output and a body")
        body = self._evaluate(template.body)
        try:
            rendered = json.dumps(body, indent=output.indent, ensure_ascii=True, sort_keys=output.sort_keys)
        except (TypeError, ValueError, RecursionError):
            raise TemplateError("the rendered json value could not be serialized") from None
        if len(rendered) > MAX_OUTPUT_CHARS:
            raise TemplateError(f"rendering stopped: output larger than {MAX_OUTPUT_CHARS} characters")
        return rendered

    def _evaluate(self, node: JsonNode) -> JsonValue:
        """Evaluate one json template node; operators come from template nodes only (M14).

        :param node: The parsed node.
        :returns: The JSON value.
        """
        if isinstance(node, JsonLiteral):
            self._budget.charge(_size(node.value))
            return node.value
        if isinstance(node, JsonArray):
            return [self._evaluate(item) for item in node.items]
        if isinstance(node, JsonObject):
            result: dict[str, JsonValue] = {}
            for member in node.members:
                if member.omit_if is not None and self._holds(member.omit_if):
                    continue
                self._budget.charge(len(member.key) + 1)
                result[member.key] = self._evaluate(member.value)
            return result
        if isinstance(node, JsonVar):
            return self._json_var(node)
        if isinstance(node, JsonFor):
            values: list[JsonValue] = []
            for item in self._items(node.over):
                self._budget.iterate()
                self._aliases[node.alias] = item
                values.append(self._evaluate(node.each))
            self._aliases.pop(node.alias, None)
            return values
        if isinstance(node, JsonIf):
            if self._holds(node.condition):
                return self._evaluate(node.then)
            return None if node.otherwise is None else self._evaluate(node.otherwise)
        if isinstance(node, JsonStr):
            text = self._interpolate(node.text)
            self._budget.charge(len(text))
            return text
        raise TemplateError("unknown json node")

    def _json_var(self, node: JsonVar) -> JsonValue:
        """Embed a context value by type; ``$default`` replaces a null or absent value.

        :param node: The ``$var`` node.
        :returns: The value (a context sub-tree is embedded as data, never evaluated).
        :raises TemplateError: When the value is absent and there is no default.
        """
        value = self._lookup(node.var)
        if value is _MISSING or value is None:
            if node.has_default:
                fallback = _thaw(node.default)
                self._budget.charge(_size(fallback))
                return fallback
            if value is _MISSING:
                raise TemplateError(f"variable {_echo_name(node.var)} is not present in the render context")
            return None
        self._budget.charge(_size(value))
        return value


def _check_extensions(template: Template, extensions: Sequence[str]):
    """Check every extension the template requires is loaded (spec §2, §10).

    :param template: The template.
    :param extensions: Names of the loaded extensions.
    :raises TemplateError: When a required extension is missing.
    """
    if isinstance(extensions, str) or not all(isinstance(name, str) for name in extensions):
        raise TemplateError("extensions must be a sequence of extension names")
    loaded = frozenset(extensions)
    missing = [name for name in template.requires_extensions if name not in loaded]
    if missing:
        listed = ", ".join(neutralize(name[:_MAX_NAME_ECHO]) for name in missing[:5])
        raise TemplateError(f"template requires extension(s) that are not loaded: {listed}")


def render_template(
    template: Template,
    context: Mapping[str, JsonValue],
    *,
    extensions: Sequence[str] = (),
) -> str:
    """Render a validated template against a JSON-shaped context (Task 02 contract).

    :param template: A :class:`~docsentinel.telemetry.loader.Template` from
        :func:`~docsentinel.telemetry.loader.load_template` or
        :func:`~docsentinel.telemetry.loader.validate_template`.
    :param context: The context tree, e.g. from
        :meth:`~docsentinel.telemetry.model.ReportModel.build`; it is read, never mutated.
    :param extensions: Names of the loaded extensions (spec §9; none exist yet).
    :returns: The rendered report; identical bytes for identical inputs.
    :raises TemplateError: For a non-template, a missing required extension, a
        context that is not JSON-shaped, an absent variable, a filter given the wrong
        kind of value, or a render past the M13 caps. Messages never echo context data.
    """
    if not isinstance(template, Template):
        raise TemplateError("render_template needs a validated Template")
    _check_extensions(template, extensions)
    _check_context(context)
    renderer = _Renderer(MappingProxyType(context))
    try:
        if template.type == "text":
            return renderer.text(template)
        if template.type == "json":
            return renderer.json(template)
    except RecursionError:
        raise TemplateError("template nesting is too deep to render") from None
    raise TemplateError("unknown template type")


__all__ = ["MAX_ITERATIONS", "MAX_OUTPUT_CHARS", "TemplateError", "render_template"]
