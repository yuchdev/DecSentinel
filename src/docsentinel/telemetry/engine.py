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
  to the bytes of ``json.dumps(indent, ensure_ascii=True, sort_keys)``, streamed
  piece by piece (R7). ``ensure_ascii`` is forced ``True`` whatever the template
  object says (threat model M8).
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
  stops rendering with a :class:`TemplateError`. Output is never truncated. Each
  piece of a line or ``$str`` is charged as it is appended, a ``json``/``join``
  filter is refused before it materializes a result past the remaining budget, and
  sub-tree sizes are memoized and bounded, so the cap fires early rather than after
  a huge value is built (R1); an ``append`` loop extends a segment list, never
  re-copies the line (R2); a cyclic context is rejected (R3). Work that emits
  nothing is bounded too (R5): every node visited, condition evaluated, loop item
  and filter call costs one step against :data:`MAX_STEPS` (an ``in`` condition
  one more per operand), and every string a filter builds is charged to
  :data:`MAX_WORK_CHARS` even when a later filter (``len``) discards it, so false
  ``when`` conditions, loops over empty lists, ``$if``/``$omit_if`` and
  ``json|len`` cannot keep a render busy while staying under the output caps.
  JSON output is serialized as a stream and every chunk is charged against
  :data:`MAX_OUTPUT_CHARS` as it is produced, so ``indent`` and nesting cannot
  build an indented document far past the cap before it is refused (R7). Each
  container inside a ``$default`` costs one step, and a ``$default`` is copied
  once per node, not once per loop item.
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
* **Extension filters** (threat model 0007-extensions M9, M10) -- an
  ``ext.<name>.<filter>`` call is looked up only in the per-render registry passed
  as ``extensions`` (never in the core filter table). Each call costs one step, its
  container input is charged to :data:`MAX_WORK_CHARS` before it is frozen, and its
  result -- an exact JSON scalar, checked by
  :class:`~docsentinel.telemetry.extensions.BoundFilter` -- is charged too; any
  failure is a bounded :class:`TemplateError`.
* **Extension data scope** (M12) -- before rendering, every ``ext`` object of the
  context is cut to the template's ``requires_extensions`` (and dropped when it
  lists none) by :func:`~docsentinel.telemetry.extensions.scope_extension_data`, so
  a whole-object sink such as ``{doc|json}`` never emits another extension's data.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from json.encoder import encode_basestring_ascii
from types import MappingProxyType
from typing import Any, Final, Optional, Union

from docsentinel.telemetry.extensions import (
    EXT_FILTER_PREFIX,
    BoundFilter,
    LoadedExtensions,
    check_template,
    missing_extensions_message,
    scope_extension_data,
)
from docsentinel.telemetry.filters import JSON_FILTER, TemplateError, apply_filter, neutralize, to_text
from docsentinel.telemetry.loader import (
    PLACEMENT_APPEND,
    PLACEMENT_BLOCK,
    PLACEMENT_ONE_LINE,
    TYPE_JSON,
    TYPE_TEXT,
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

#: Cap on render steps (M13, R5): one per text/json node visited, condition node
#: evaluated, loop item and filter call, whether or not anything is emitted. A
#: 358-document scan with 5000 findings costs at most about 120k steps under a
#: severity-routing ``github`` template (16x margin; 20000 findings about 480k), while
#: a hostile template stops within a few seconds (about 2.5 us per step).
MAX_STEPS: Final[int] = 2_000_000

#: Cap on characters built by filters across one render (M13, R5), charged even
#: when a later filter such as ``len`` discards the string.
MAX_WORK_CHARS: Final[int] = 4 * MAX_OUTPUT_CHARS

#: Largest transient chunk the streaming json serializer may build in one C call
#: (R7). A sub-tree whose worst-case encoding could pass this is walked node by node.
_FAST_CHUNK_CHARS: Final[int] = 1024 * 1024

#: Worst-case encoded characters per lower-bound character of :func:`_size` (R7): a
#: float prints up to 24 characters where :func:`_size` counts one.
_WORST_EXPANSION: Final[int] = 24

#: Serialized pieces collected before they are joined into one batch (R7).
_FLUSH_PIECES: Final[int] = 1024

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

    Walks iteratively (depth-first with explicit leave markers), so depth cannot
    overflow the stack. A container reached twice through different parents (shared
    sub-trees such as ``documents_with_problems``) is checked once; a container met
    again while it is still on the current path is a cycle and is rejected (R3).

    :param context: The render context.
    :raises TemplateError: When the root is not a ``dict``, or any node is not an
        exact ``dict``/``list``/``str``/``int``/``bool``/``None`` or finite ``float``,
        a key is not a string, or the tree holds a cycle. The offending value is
        never echoed.
    """
    if type(context) is not dict:
        raise TemplateError("the render context must be a JSON object")
    done: set[int] = set()
    on_path: set[int] = set()
    stack: list[tuple[object, bool]] = [(context, False)]
    while stack:
        value, leaving = stack.pop()
        if leaving:
            on_path.discard(id(value))
            done.add(id(value))
            continue
        kind = type(value)
        if kind is dict or kind is list:
            marker = id(value)
            if marker in on_path:
                raise TemplateError("the render context holds a reference cycle")
            if marker in done:
                continue
            on_path.add(marker)
            stack.append((value, True))
            if kind is dict:
                for key, item in value.items():
                    if type(key) is not str:
                        raise TemplateError("the render context has a non-string object key")
                    stack.append((item, False))
            else:
                stack.extend((item, False) for item in value)
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
    """Iteration, step, work and output-size budget of one render call (M13, R5)."""

    __slots__ = ("chars", "iterations", "steps", "work")

    def __init__(self):
        """Start an empty budget."""
        self.chars = 0
        self.iterations = 0
        self.steps = 0
        self.work = 0

    def step(self, count: int = 1):
        """Count ``count`` render steps, whether or not they emit anything (R5).

        :param count: Steps about to be taken.
        :raises TemplateError: When :data:`MAX_STEPS` is passed.
        """
        self.steps += count
        if self.steps > MAX_STEPS:
            raise TemplateError(f"rendering stopped: template work larger than {MAX_STEPS} steps")

    def build(self, count: int):
        """Count ``count`` characters built by a filter, even if later discarded (R5).

        :param count: Characters of the filter result.
        :raises TemplateError: When :data:`MAX_WORK_CHARS` is passed.
        """
        self.work += count
        if self.work > MAX_WORK_CHARS:
            raise TemplateError(f"rendering stopped: filters built more than {MAX_WORK_CHARS} characters")

    def iterate(self):
        """Count one loop item (also one step).

        :raises TemplateError: When :data:`MAX_ITERATIONS` or :data:`MAX_STEPS` is passed.
        """
        self.step()
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

    def remaining(self) -> int:
        """Return how many characters may still be emitted.

        :returns: ``MAX_OUTPUT_CHARS`` minus the characters charged so far (at least 0).
        """
        return max(MAX_OUTPUT_CHARS - self.chars, 0)

    def reserve(self, estimate: int):
        """Refuse work whose result would already pass the cap, without charging it (R1).

        Used before a filter materializes a large string, so the cap fires before
        the memory is allocated rather than after.

        :param estimate: A lower bound on the characters about to be produced.
        :raises TemplateError: When ``estimate`` exceeds :meth:`remaining`, or would
            pass :data:`MAX_WORK_CHARS` (R5).
        """
        if estimate > self.remaining():
            raise TemplateError(f"rendering stopped: output larger than {MAX_OUTPUT_CHARS} characters")
        if self.work + estimate > MAX_WORK_CHARS:
            raise TemplateError(f"rendering stopped: filters built more than {MAX_WORK_CHARS} characters")


def _scalar_size(value: JsonValue) -> int:
    """Return a lower bound on the compact JSON length of a non-container value.

    :param value: A scalar.
    :returns: ``len + 2`` for a string (its quotes), else 1.
    """
    return len(value) + 2 if isinstance(value, str) else 1


def _size(value: JsonValue, limit: int, memo: dict[int, tuple[JsonValue, int]]) -> int:
    """Return a lower bound on the serialized size of a JSON value, bounded by ``limit``.

    Iterative post-order walk. Every container's size is memoized by ``id`` (the
    memo pins the object, so an ``id`` is never reused while cached), so a shared
    sub-tree is walked once however often it is referenced and a doubling DAG costs
    linear time. The walk stops as soon as any sub-tree reaches ``limit + 1``,
    since the whole value is then at least that large (R3). The bound never
    overestimates: brackets, commas, quotes and ``":"`` are counted at their
    compact minimum and every scalar as at least one character.

    :param value: A context sub-tree or thawed template literal.
    :param limit: The remaining output budget.
    :param memo: Container sizes already computed in this render.
    :returns: The lower bound, saturated at ``limit + 1``.
    :raises TemplateError: When the value holds a reference cycle.
    """
    cap = limit + 1
    if not isinstance(value, (dict, list)):
        return min(_scalar_size(value), cap)
    pending: set[int] = set()
    stack: list[tuple[JsonValue, bool]] = [(value, False)]
    while stack:
        item, leaving = stack.pop()
        marker = id(item)
        if not leaving:
            if marker in memo:
                continue
            if marker in pending:
                raise TemplateError("the render context holds a reference cycle")
            pending.add(marker)
            stack.append((item, True))
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, False) for child in children if isinstance(child, (dict, list)))
            continue
        pending.discard(marker)
        total = 2 + len(item)
        if isinstance(item, dict):
            total += sum(len(key) + 3 for key in item)
            children = item.values()
        else:
            children = item
        for child in children:
            total += memo[id(child)][1] if isinstance(child, (dict, list)) else _scalar_size(child)
            if total >= cap:
                break
        memo[marker] = (item, min(total, cap))
        if total >= cap:
            return cap
    return min(memo[id(value)][1], cap)


def _containers(value: Any) -> int:
    """Return how many containers (lists, tuples, mappings) a template literal holds (R7).

    :param value: A literal from the parsed template, frozen or thawed.
    :returns: The container count, the value itself included.
    """
    count = 0
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            count += 1
            stack.extend(item.values())
        elif isinstance(item, (tuple, list)):
            count += 1
            stack.extend(item)
    return count


def _float_text(value: float) -> str:
    """Return the ``json.dumps`` spelling of a float.

    :param value: The float.
    :returns: ``NaN``/``Infinity``/``-Infinity`` or ``float.__repr__``.
    """
    if value != value:
        return "NaN"
    if value == math.inf:
        return "Infinity"
    if value == -math.inf:
        return "-Infinity"
    return float.__repr__(value)


class _JsonStream:
    """Streaming json serializer that charges every chunk against a cap (R7).

    The output is byte-identical to ``json.dumps(value, indent=indent,
    ensure_ascii=True, sort_keys=sort_keys)``, but it is produced piece by piece
    with an explicit stack, and each piece is counted as it is produced. The
    serializer stops with a :class:`TemplateError` as soon as the total passes the
    cap, so neither ``indent`` nor nesting can make it build more than the cap plus
    one bounded chunk. A small sub-tree (worst case at most
    :data:`_FAST_CHUNK_CHARS`) is encoded in one ``json.dumps`` call for speed:
    any sub-tree without ``indent``, and a container of scalars only with
    ``indent`` (its separator then carries the line break and padding).
    """

    __slots__ = ("_batches", "_indent", "_item_sep", "_limit", "_memo", "_pads", "_pieces", "_sort_keys", "_total")

    def __init__(
        self,
        indent: Optional[int],
        sort_keys: bool,
        limit: int,
        memo: Optional[dict[int, tuple[JsonValue, int]]] = None,
    ):
        """Prepare an empty stream.

        :param indent: ``None`` or the indent width (0..8).
        :param sort_keys: Whether object keys are sorted.
        :param limit: The cap on serialized characters.
        :param memo: A :func:`_size` memo to reuse, such as the one of the render
            that built the value, so embedded sub-trees are not measured twice. Its
            entries are exact lower bounds: a saturated entry only arises in a render
            that has already stopped with a :class:`TemplateError`.
        """
        self._indent = indent
        self._sort_keys = sort_keys
        self._limit = limit
        self._item_sep = ", " if indent is None else ","
        self._pads: list[str] = []
        self._pieces: list[str] = []
        self._batches: list[str] = []
        self._total = 0
        self._memo: dict[int, tuple[JsonValue, int]] = {} if memo is None else memo

    def _emit(self, text: str):
        """Append one piece, charging it against the cap.

        :param text: The serialized piece.
        :raises TemplateError: When the total passes the cap.
        """
        self._total += len(text)
        if self._total > self._limit:
            raise TemplateError(f"rendering stopped: output larger than {self._limit} characters")
        self._pieces.append(text)
        if len(self._pieces) >= _FLUSH_PIECES:
            self._batches.append("".join(self._pieces))
            self._pieces.clear()

    def _pad(self, level: int) -> str:
        """Return the line break and indentation of ``level`` (``indent`` is set).

        :param level: The nesting level.
        :returns: ``"\\n"`` followed by ``indent * level`` spaces.
        """
        pads = self._pads
        while len(pads) <= level:
            pads.append("\n" + " " * (self._indent * len(pads)))
        return pads[level]

    def _fast(self, value: JsonValue, level: int) -> Optional[str]:
        """Encode a small container in one call, or return ``None`` to walk it.

        :param value: A non-empty list or dict.
        :param level: Its nesting level.
        :returns: Its exact serialization, or ``None`` when its worst case could pass
            :data:`_FAST_CHUNK_CHARS` or (with ``indent``) it holds a container.
        """
        bound = _FAST_CHUNK_CHARS // _WORST_EXPANSION
        if self._indent is None:
            if 2 * len(value) > bound or _size(value, bound, self._memo) > bound:
                return None
            return json.dumps(value, ensure_ascii=True, sort_keys=self._sort_keys)
        children = value.values() if type(value) is dict else value
        if any(isinstance(child, (dict, list, tuple)) for child in children):
            return None
        inner = self._pad(level + 1)
        if len(value) * (len(inner) + 1) > _FAST_CHUNK_CHARS or _size(value, bound, self._memo) > bound:
            return None
        body = json.dumps(value, ensure_ascii=True, sort_keys=self._sort_keys, separators=("," + inner, ": "))
        return body[0] + inner + body[1:-1] + self._pad(level) + body[-1]

    def _value(self, value: JsonValue, level: int, stack: list[list[Any]], prefix: str):
        """Emit ``prefix`` and a scalar, or open a container frame on ``stack``.

        :param value: The JSON value.
        :param level: Its nesting level.
        :param stack: Open container frames ``[iterator, is_dict, level, first]``.
        :param prefix: Separator, padding and key text emitted before the value.
        :raises TypeError: For a value that is not JSON data.
        """
        if isinstance(value, str):
            self._emit(prefix + encode_basestring_ascii(value))
        elif value is None:
            self._emit(prefix + "null")
        elif value is True:
            self._emit(prefix + "true")
        elif value is False:
            self._emit(prefix + "false")
        elif isinstance(value, int):
            self._emit(prefix + int.__repr__(value))
        elif isinstance(value, float):
            self._emit(prefix + _float_text(value))
        elif isinstance(value, (list, tuple, dict)):
            is_dict = isinstance(value, dict)
            if not value:
                self._emit(prefix + ("{}" if is_dict else "[]"))
                return
            whole = self._fast(value, level) if type(value) in (list, dict) else None
            if whole is not None:
                self._emit(prefix + whole)
                return
            self._emit(prefix + ("{" if is_dict else "["))
            members = (sorted(value.items()) if self._sort_keys else value.items()) if is_dict else value
            stack.append([iter(members), is_dict, level + 1, True])
        else:
            raise TypeError("value is not JSON serializable")

    def serialize(self, value: JsonValue) -> str:
        """Serialize ``value`` in full, or stop at the cap.

        :param value: The evaluated json body.
        :returns: The serialized document.
        :raises TemplateError: When the output passes the cap.
        :raises TypeError: For a value or key that is not JSON data.
        :raises ValueError: For an int too long to print.
        """
        stack: list[list[Any]] = []
        self._value(value, 0, stack, "")
        while stack:
            frame = stack[-1]
            items, is_dict, level, first = frame
            item = next(items, _MISSING)
            if item is _MISSING:
                stack.pop()
                closer = "}" if is_dict else "]"
                self._emit(closer if self._indent is None else self._pad(level - 1) + closer)
                continue
            prefix = "" if first else self._item_sep
            frame[3] = False
            if self._indent is not None:
                prefix += self._pad(level)
            if is_dict:
                key, item = item
                if type(key) is not str:
                    raise TypeError("keys must be str")
                prefix += encode_basestring_ascii(key) + ": "
            self._value(item, level, stack, prefix)
        return "".join([*self._batches, *self._pieces])


class _Lines:
    """Text output lines whose last (open) line is kept as a list of segments (R2).

    An ``append`` loop extends the open line by adding one segment, so many appends
    cost linear time; the segments are joined once, when the next line starts or
    when :meth:`finish` is called.
    """

    __slots__ = ("_closed", "_open")

    def __init__(self):
        """Start with no lines."""
        self._closed: list[str] = []
        self._open: Optional[list[str]] = None

    def has_line(self) -> bool:
        """Return whether any line was started.

        :returns: ``True`` once :meth:`start` or :meth:`extend` was called.
        """
        return self._open is not None

    def start(self, text: str):
        """Close the open line, if any, and open a new one holding ``text``.

        :param text: The first segment of the new line.
        """
        if self._open is not None:
            self._closed.append("".join(self._open))
        self._open = [text]

    def extend(self, text: str):
        """Add ``text`` to the open line, or open the first line with it.

        :param text: The segment.
        """
        if self._open is None:
            self._open = [text]
        else:
            self._open.append(text)

    def finish(self) -> list[str]:
        """Return every line, the open one joined.

        :returns: The output lines in order.
        """
        if self._open is None:
            return list(self._closed)
        return [*self._closed, "".join(self._open)]


class _Renderer:
    """One render pass over a fixed context; loop aliases are bound in place."""

    def __init__(self, context: Mapping[str, JsonValue], extension_filters: Mapping[str, BoundFilter]):
        """Bind the context and the per-render extension filter registry.

        :param context: The checked, JSON-shaped context.
        :param extension_filters: Full name -> bound extension filter (M9).
        """
        self._context = context
        self._extension_filters = extension_filters
        self._aliases: dict[str, JsonValue] = {}
        self._budget = _Budget()
        self._sizes: dict[int, tuple[JsonValue, int]] = {}
        self._defaults: dict[int, tuple[JsonVar, JsonValue, int]] = {}

    def _bounded_size(self, value: JsonValue) -> int:
        """Return :func:`_size` of ``value`` against the remaining budget.

        :param value: A JSON value.
        :returns: A lower bound on its serialized length, at most remaining + 1.
        """
        return _size(value, self._budget.remaining(), self._sizes)

    def _estimate(self, name: str, value: JsonValue, args: tuple[str, ...]) -> int:
        """Return a lower bound on the length a materializing filter would produce (R1).

        :param name: The filter name.
        :param value: Its input.
        :param args: Its literal arguments.
        :returns: The bound for ``json`` and ``join``; 0 for any other filter, whose
            output is bounded by its (already present) scalar input.
        """
        if name == JSON_FILTER:
            return self._bounded_size(value)
        if name == "join" and type(value) is list and args and isinstance(args[0], str):
            limit = self._budget.remaining() + 1
            total = len(args[0]) * max(len(value) - 1, 0)
            for item in value:
                if total >= limit:
                    break
                total += len(item) if isinstance(item, str) else 1
            return total
        return 0

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
        self._budget.step()
        for call in ref.filters:
            self._budget.step()
            try:
                if call.name.startswith(EXT_FILTER_PREFIX):
                    value = self._extension_filter(call.name, value, call.args)
                else:
                    self._budget.reserve(self._estimate(call.name, value, call.args))
                    value = apply_filter(call.name, value, call.args)
            except TemplateError as exc:
                raise TemplateError(f"variable {_echo_name(ref)}: {exc}") from None
            if isinstance(value, str):
                self._budget.build(len(value))
        return value

    def _extension_filter(self, name: str, value: JsonValue, args: tuple[str, ...]) -> JsonValue:
        """Apply one registered extension filter (M10).

        :param name: The full ``ext.<name>.<filter>`` name.
        :param value: Its input.
        :param args: Its literal arguments.
        :returns: The exact JSON scalar it returned.
        :raises TemplateError: When the filter is not registered, fails, or returns
            anything but a JSON scalar.
        """
        bound = self._extension_filters.get(name)
        if bound is None:
            raise TemplateError("extension filter is not registered by a loaded extension")
        if isinstance(value, (dict, list)):
            self._budget.build(_size(value, MAX_WORK_CHARS, self._sizes))
        return bound(value, args)

    def _interpolate(self, text: Interpolation) -> str:
        """Render an interpolation in a single pass (M14), charging each piece (R1).

        Every literal and substituted piece is charged against the output budget as
        it is appended, so one long line or ``$str`` stops at the cap instead of
        being built in full first. Callers must not charge the result again.

        :param text: The parsed text.
        :returns: Literals and substituted values concatenated; values are never
            re-scanned for ``{...}``.
        """
        pieces: list[str] = []
        for part in text.parts:
            if isinstance(part, str):
                piece = part
            else:
                value = self._value(part)
                try:
                    piece = to_text(value)
                except TemplateError as exc:
                    raise TemplateError(f"variable {_echo_name(part)}: {exc}") from None
            self._budget.charge(len(piece))
            pieces.append(piece)
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
        self._budget.step()
        if isinstance(condition, Compare):
            if condition.op == "in":
                self._budget.step(len(condition.operand))
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
        buffer = _Lines()
        self._nodes(template.lines, buffer)
        lines = buffer.finish()
        for line in lines:
            if neutralize(line) != line:
                raise TemplateError("a rendered line holds a control or format character from an unfiltered value")
        rendered = output.join.join(lines)
        if output.trailing_newline and lines:
            rendered += output.join
        return rendered

    def _nodes(self, nodes: Sequence[TextNode], lines: _Lines):
        """Render text nodes into ``lines``.

        :param nodes: The nodes.
        :param lines: The output line buffer, extended in place.
        """
        for node in nodes:
            self._budget.step()
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

    def _emit(self, lines: _Lines, line: str):
        """Start one output line, charging its line break.

        :param lines: The output line buffer.
        :param line: The new line; its characters were charged by :meth:`_interpolate`.
        """
        self._budget.charge(1)
        lines.start(line)

    def _loop(self, node: LoopNode, lines: _Lines):
        """Render a loop in its placement.

        :param node: The loop node (its ``when`` already holds).
        :param lines: The output line buffer.
        """
        items = self._items(node.over)
        if node.placement == PLACEMENT_BLOCK:
            try:
                for item in items:
                    self._budget.iterate()
                    self._aliases[node.alias] = item
                    self._nodes(node.body, lines)
            finally:
                self._aliases.pop(node.alias, None)
            return
        if node.placement not in (PLACEMENT_ONE_LINE, PLACEMENT_APPEND) or node.text is None:
            raise TemplateError("unknown loop placement")
        if not items:
            return
        pieces: list[str] = []
        self._budget.charge(len(node.prefix) + len(node.suffix))
        try:
            for position, item in enumerate(items):
                self._budget.iterate()
                self._aliases[node.alias] = item
                separator = node.separator if position else ""
                self._budget.charge(len(separator))
                pieces.append(separator)
                pieces.append(self._interpolate(node.text))
        finally:
            self._aliases.pop(node.alias, None)
        segment = node.prefix + "".join(pieces) + node.suffix
        if node.placement == PLACEMENT_APPEND and lines.has_line():
            lines.extend(segment)
        else:
            self._budget.charge(1)
            lines.start(segment)

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
        stream = _JsonStream(output.indent, output.sort_keys, MAX_OUTPUT_CHARS, self._sizes)
        try:
            return stream.serialize(body)
        except (TypeError, ValueError, RecursionError):
            raise TemplateError("the rendered json value could not be serialized") from None

    def _evaluate(self, node: JsonNode) -> JsonValue:
        """Evaluate one json template node; operators come from template nodes only (M14).

        :param node: The parsed node.
        :returns: The JSON value.
        """
        self._budget.step()
        if isinstance(node, JsonLiteral):
            self._budget.charge(self._bounded_size(node.value))
            return node.value
        if isinstance(node, JsonArray):
            self._budget.charge(2 + max(len(node.items) - 1, 0))
            return [self._evaluate(item) for item in node.items]
        if isinstance(node, JsonObject):
            result: dict[str, JsonValue] = {}
            self._budget.charge(2)
            for member in node.members:
                if member.omit_if is not None and self._holds(member.omit_if):
                    continue
                self._budget.charge(len(member.key) + 1 + (1 if result else 0))
                result[member.key] = self._evaluate(member.value)
            return result
        if isinstance(node, JsonVar):
            return self._json_var(node)
        if isinstance(node, JsonFor):
            values: list[JsonValue] = []
            items = self._items(node.over)
            try:
                for item in items:
                    self._budget.iterate()
                    self._aliases[node.alias] = item
                    values.append(self._evaluate(node.each))
            finally:
                self._aliases.pop(node.alias, None)
            return values
        if isinstance(node, JsonIf):
            if self._holds(node.condition):
                return self._evaluate(node.then)
            return None if node.otherwise is None else self._evaluate(node.otherwise)
        if isinstance(node, JsonStr):
            return self._interpolate(node.text)
        raise TemplateError("unknown json node")

    def _default(self, node: JsonVar) -> tuple[JsonValue, int]:
        """Return the thawed ``$default`` of a node and its container count, once per node (R7).

        Every use shares one thawed copy, so a ``$default`` inside a loop neither
        allocates nor pins (in the size memo) a fresh copy per item; the shared value
        is only read, never mutated.

        :param node: A ``$var`` node with a default.
        :returns: The thawed default and how many containers it holds.
        """
        cached = self._defaults.get(id(node))
        if cached is None:
            fallback = _thaw(node.default)
            cached = (node, fallback, _containers(fallback))
            self._defaults[id(node)] = cached
        return cached[1], cached[2]

    def _json_var(self, node: JsonVar) -> JsonValue:
        """Embed a context value by type; ``$default`` replaces a null or absent value.

        :param node: The ``$var`` node.
        :returns: The value (a context sub-tree is embedded as data, never evaluated).
        :raises TemplateError: When the value is absent and there is no default.
        """
        value = self._lookup(node.var)
        if value is _MISSING or value is None:
            if node.has_default:
                fallback, containers = self._default(node)
                self._budget.step(containers)
                self._budget.charge(self._bounded_size(fallback))
                return fallback
            if value is _MISSING:
                raise TemplateError(f"variable {_echo_name(node.var)} is not present in the render context")
            return None
        self._budget.charge(self._bounded_size(value))
        return value


def _check_extensions(
    template: Template, extensions: Union[LoadedExtensions, Sequence[str]]
) -> Mapping[str, BoundFilter]:
    """Check every extension the template requires is loaded (spec §2, §10; M30, M31).

    :param template: The template.
    :param extensions: The loaded registry, or bare names of loaded extensions (a
        name list carries no filters, so a template using an extension filter needs
        the registry).
    :returns: The registry's extension filters (empty for a name list).
    :raises TemplateError: When a required extension or a used extension filter is
        missing.
    """
    if isinstance(extensions, LoadedExtensions):
        check_template(template, extensions)
        return extensions.filters
    if isinstance(extensions, str) or not all(isinstance(name, str) for name in extensions):
        raise TemplateError("extensions must be a sequence of extension names")
    loaded = frozenset(extensions)
    missing = [name for name in template.requires_extensions if name not in loaded]
    if missing:
        raise TemplateError(missing_extensions_message(missing))
    if template.extension_filters:
        raise TemplateError("template uses extension filters; pass the loaded extension registry")
    return MappingProxyType({})


def render_template(
    template: Template,
    context: Mapping[str, JsonValue],
    *,
    extensions: Union[LoadedExtensions, Sequence[str]] = (),
) -> str:
    """Render a validated template against a JSON-shaped context (Task 02 contract).

    :param template: A :class:`~docsentinel.telemetry.loader.Template` from
        :func:`~docsentinel.telemetry.loader.load_template` or
        :func:`~docsentinel.telemetry.loader.validate_template`.
    :param context: The context tree, e.g. from
        :meth:`~docsentinel.telemetry.model.ReportModel.build`; it is read, never mutated.
    :param extensions: The loaded extension registry from
        :func:`~docsentinel.telemetry.extensions.resolve_extensions` (names and
        filters of the same registry), or bare names of loaded extensions.
    :returns: The rendered report; identical bytes for identical inputs.
    :raises TemplateError: For a non-template, a missing required extension, a
        context that is not JSON-shaped, an absent variable, a filter given the wrong
        kind of value, a context holding a reference cycle or a value that cannot be
        rendered (such as an int too long to print, R3), or a render past the M13
        caps (output, loop items, steps or filter-built characters, R5). Messages never echo context data.
    """
    if not isinstance(template, Template):
        raise TemplateError("render_template needs a validated Template")
    extension_filters = _check_extensions(template, extensions)
    try:
        context = scope_extension_data(context, template.requires_extensions)
        _check_context(context)
        renderer = _Renderer(MappingProxyType(context), extension_filters)
        if template.type == TYPE_TEXT:
            return renderer.text(template)
        if template.type == TYPE_JSON:
            return renderer.json(template)
    except RecursionError:
        raise TemplateError("template nesting is too deep to render") from None
    except (ValueError, TypeError, OverflowError):
        raise TemplateError("the render context holds a value that cannot be rendered") from None
    raise TemplateError("unknown template type")


__all__ = ["MAX_ITERATIONS", "MAX_OUTPUT_CHARS", "MAX_STEPS", "MAX_WORK_CHARS", "TemplateError", "render_template"]
