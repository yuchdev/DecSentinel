"""Report template loader and validator (Milestone 0007 Story 02.0 Task 01).

:func:`load_template` turns a template source -- a packaged name, a path, or an
already-parsed mapping -- into an immutable, fully validated :class:`Template`.
Every failure raises :class:`TemplateError` with a bounded, neutralized message
naming the JSON path of the offending node (for example ``lines[7].over``). The
contract is ``docs/specs/report-template-format.md``; the context schema every
variable is checked against is :data:`docsentinel.telemetry.model.CONTEXT_SCHEMA`.
Rendering is Task 02 and lives elsewhere; this module never renders.

Security contract (``docs/security/threat-model-0007-template-engine-2026-10-31.md``).
A config-named template is authored by whoever controls the scanned checkout, so
its every byte is hostile input. Mitigations implemented here:

* **M1/M2 -- trust propagation.** A list element inherits the list's trust tag, and
  a container whose tag is ``None`` is untrusted as soon as any descendant is
  untrusted (a ``None`` tag with no members is untrusted too: fail closed).
* **M3 -- scalars only.** A dict, or a list not reduced by ``join``/``len``/``json``,
  in a text position is a load-time error, so ``str()`` of a container is never output.
* **M4-M6 -- sink order and context.** In a ``text`` template the filter chain of an
  untrusted variable must *end* with a sink filter for the declared
  ``output.sink``: ``neutralize``/``json``/``gha_property``/``gha_data`` under
  ``terminal``, only ``gha_property``/``gha_data`` under ``github``. In a ``github``
  line that starts with ``::``, every variable (trusted ones included) before the
  second ``::`` (the property segment) must end with ``gha_property``, and an
  untrusted one after it with ``gha_data``; an ``append`` loop continues an unknown
  line, so all its variables need ``gha_property``. Under ``github`` every emitted
  line carrying a variable (``line`` nodes, inline loops including ``append``) must
  start with literal text that, after leading whitespace is trimmed, is neither empty
  nor a lone ``:`` -- so a finding message or path can never begin a line and become
  a live workflow command. Because the runner's legacy parser matches ``##[``
  anywhere in a line that is not a well-formed command (T2-R1), an untrusted
  variable may only sit on a line opening with a literal ``::error``/``warning``/
  ``notice``/``debug``/``group`` (then a space or ``::``) that holds a literal second
  ``::``; plain lines and ``append`` loops may carry only trusted variables, and no
  variable may directly follow a literal ending in ``#``. A ``terminal`` template may
  not start a line with ``::`` (leading whitespace ignored), so a workflow-command
  template cannot omit its sink.
* **M7/M8 -- literal hygiene.** No template string (key or value) may contain a code
  point the ``neutralize`` table escapes, CR/LF included; ``output.join`` may only be
  ``"\\n"``. ``output.indent`` is ``null`` or an int in 0..8 and ``ensure_ascii`` must
  be ``true``.
* **M9-M11 -- file gate.** A name matches :data:`NAME_PATTERN`; anything else is a
  path. Packaged names resolve first and cannot be shadowed. A config-named file and
  its directory pass the DS115 containment gate (``is_ds116_owned`` ->
  ``resolve_local_reference`` ``RESOLVED`` -> ``escapes_via_symlink``) before any
  open; no second resolver is added. Every file is ``stat``-ed (regular, at most
  :data:`MAX_TEMPLATE_BYTES`) before it is opened ``O_NONBLOCK`` (and ``O_NOFOLLOW``
  for config-named files), re-checked with ``fstat``, read ``MAX + 1`` bytes and
  rejected (never truncated) when larger, then strictly UTF-8 decoded with no BOM.
* **M12 -- parse bombs.** Duplicate keys, ``NaN``/``Infinity`` and non-finite floats
  are rejected while parsing; ``RecursionError``/``ValueError`` become a bounded
  error. Raw nesting and value count are checked iteratively before any recursion;
  template nesting is at most :data:`MAX_NESTING`, template nodes at most
  :data:`MAX_NODES`, list indexes at most six digits, filter arguments quoted
  literals of at most :data:`MAX_FILTER_ARG` characters parsed without ``eval``.
* **M13 (depth part)** -- loop nesting (``loop`` and ``$for``) is at most
  :data:`MAX_LOOP_NESTING`.
* **M14 (load-time part)** -- dotted paths are checked against the schema only (no
  attribute names, so ``{doc.__class__}``/``{doc.keys}`` are unknown variables), and
  an unknown ``$``-key in a ``json`` template is an error, not a literal.
* **M16 -- safe errors.** Every echoed fragment is neutralized and bounded to 80
  characters, the whole message is neutralized and bounded again in
  :class:`TemplateError`, only configured values (never a resolved absolute path)
  are echoed, and no exception ``repr`` is ever included.
* **M17 -- immutability.** The parsed form holds only frozen dataclasses, tuples,
  ``frozenset`` and ``MappingProxyType``; only packaged templates are cached, keyed
  by resolved resource path, ``mtime_ns`` and size.

Extension data and filters (``docs/security/threat-model-0007-extensions-2026-11-03.md``):

* **M11** -- ``ext`` (run, ``doc.ext``, ``p.ext``) resolves as an object whose
  members are only the names in the template's ``requires_extensions``; every deeper
  segment has the value kind ``any``, always untrusted, inherited by every
  descendant and list element. ``ext.<name>`` itself is a container (it cannot be
  emitted in text); an ``any`` value passes where a scalar or list is expected and
  is checked at render time.
* **M12** -- referencing ``ext.<n>...`` or a filter ``ext.<n>.<f>`` without listing
  ``<n>`` in ``requires_extensions`` is a load-time error.
* **M7/M8** -- an ``ext.<n>.<f>`` filter is never a sink, and the output of any
  chain that contains one is untrusted whatever its input, so the chain must still
  end with a core sink and obey every ``github`` rule. Its arity and input kind are
  recorded in :attr:`Template.extension_filters` and checked against the loaded
  registry by :func:`docsentinel.telemetry.extensions.check_template` before the
  scan; extension filters never enter :data:`FILTERS`.

``neutralize``, :class:`TemplateError` and :data:`MAX_MESSAGE` come from
:mod:`docsentinel.telemetry.filters` (Task 02), the stdlib-only bottom layer, and are
re-exported here so ``loader.TemplateError`` keeps working. This module is
deliberately not re-exported from ``docsentinel.telemetry`` (``reporting`` imports
that package, so a re-export would be an import cycle).
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Final, Optional, Union

from docsentinel.detectors.path_boundaries import escapes_via_symlink, is_ds116_owned
from docsentinel.markdown_blocks import ReferenceStatus, resolve_local_reference
from docsentinel.telemetry.filters import MAX_MESSAGE as MAX_MESSAGE  # re-exported (M16 bound)
from docsentinel.telemetry.filters import TemplateError
from docsentinel.telemetry.filters import neutralize as neutralize_text
from docsentinel.telemetry.model import CONTEXT_SCHEMA, UNTRUSTED, Variable

#: The one supported template format version.
TEMPLATE_VERSION: Final[int] = 1

#: Hard cap on template file bytes (Task 01 rule 1).
MAX_TEMPLATE_BYTES: Final[int] = 256 * 1024

#: Maximum template node/condition nesting (M12).
MAX_NESTING: Final[int] = 32

#: Maximum template nodes (text nodes, conditions and json values) (M12).
MAX_NODES: Final[int] = 10_000

#: Maximum loop (``loop``/``$for``) nesting (M13).
MAX_LOOP_NESTING: Final[int] = 4

#: Maximum characters of one quoted filter argument (M12).
MAX_FILTER_ARG: Final[int] = 256

#: Maximum characters of one echoed fragment (M16).
MAX_ECHO: Final[int] = 80

#: Packaged-or-directory template name (M9); any other source is a path.
NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")

#: Directory of the packaged templates (Story 03.0 ships ``text``/``github``/``json``).
PACKAGED_TEMPLATES_DIR: Final[Path] = Path(__file__).resolve().parent / "templates"

#: The two template ``type`` values (spec §2).
TYPE_TEXT: Final[str] = "text"
TYPE_JSON: Final[str] = "json"

#: Template used when no format is named (``render()`` and ``docsentinel scan``).
DEFAULT_TEMPLATE: Final[str] = "text"

#: Most templates :func:`available_templates` accepts from ``report_templates_dir``;
#: a directory holding more fails closed instead of being listed partially.
MAX_DIRECTORY_TEMPLATES: Final[int] = 1024

#: Most directory entries of any kind :func:`available_templates` visits in
#: ``report_templates_dir``; a larger directory fails closed instead of being walked
#: in full on every scan (CWE-400).
MAX_DIRECTORY_ENTRIES: Final[int] = 4096

#: Recognised ``output.sink`` values of a ``text`` template (M5).
SINK_TERMINAL: Final[str] = "terminal"
SINK_GITHUB: Final[str] = "github"
SINKS: Final[frozenset[str]] = frozenset({SINK_TERMINAL, SINK_GITHUB})

#: ``loop.placement`` values (spec §4).
PLACEMENT_BLOCK: Final[str] = "block"
PLACEMENT_ONE_LINE: Final[str] = "one-line"
PLACEMENT_APPEND: Final[str] = "append"
PLACEMENTS: Final[frozenset[str]] = frozenset({PLACEMENT_BLOCK, PLACEMENT_ONE_LINE, PLACEMENT_APPEND})

#: The closed condition operators (spec §4, Task 01 rule 5).
COMPARE_OPERATORS: Final[frozenset[str]] = frozenset({"eq", "ne", "in", "gt", "lt", "truthy", "falsy"})
COMBINATORS: Final[frozenset[str]] = frozenset({"all", "any", "not"})

_MAX_NAME = 64
_MAX_RAW_DEPTH = 100
_MAX_RAW_VALUES = 50_000
_MAX_PATH_SEGMENTS = 16
_MAX_SCHEMA_VERSION = 1000
_MAX_INDENT = 8
_MAX_IN_OPERANDS = 256

_ALIAS_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,63}")
_EXTENSION_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SEGMENT_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_INDEX_PATTERN = re.compile(r"[0-9]{1,6}")
_FILTER_NAME_PATTERN = re.compile(r"[a-z_][a-z0-9_]{0,63}(?:\.[a-z_][a-z0-9_]{0,63}){0,3}")
#: A well-formed workflow command opener (T2-R1): ASCII spaces only (a strict subset
#: of what the runner's ``TrimStart`` removes), ``::``, a literal command name from a
#: closed allowlist, then a literal space or the second ``::``.
_GHA_COMMAND_PATTERN = re.compile(r" *::(?:error|warning|notice|debug|group)(?: |::)")

_UTF8_BOM = b"\xef\xbb\xbf"

#: Value kinds tracked through a filter chain; ``any`` is extension data (M11).
_SCALAR = "scalar"
_LIST = "list"
_DICT = "dict"
_ANY = "any"

#: Schema type descriptors of extension data (M11): the ``ext`` object, one
#: extension's subtree, and any value below it.
_TYPE_EXT = "ext"
_TYPE_EXT_MEMBER = "ext_member"
_TYPE_ANY = "any"

#: Prefix of an extension filter name, ``ext.<extension>.<filter>`` (spec §7).
_EXT_FILTER_PREFIX = "ext."
_EXT_FILTER_LEAF_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _echo(value: str) -> str:
    """Return a bounded, neutralized echo of an author-controlled string (M16).

    :param value: The raw fragment.
    :returns: At most :data:`MAX_ECHO` source characters, neutralized, with ``...``
        when truncated.
    """
    bounded = neutralize_text(value[:MAX_ECHO])
    return f"{bounded}..." if len(value) > MAX_ECHO else bounded


def _echo_path(where: str) -> str:
    """Return a bounded, neutralized JSON path, keeping its most specific tail.

    :param where: The JSON path of the offending node.
    :returns: The echoed path, ``<template>`` for the root.
    """
    if not where:
        return "<template>"
    if len(where) > MAX_ECHO:
        where = "..." + where[-(MAX_ECHO - 3) :]
    return neutralize_text(where)


def _echo_names(names: frozenset[str]) -> str:
    """Return a bounded, sorted, comma-joined echo of variable names.

    :param names: The names to list.
    :returns: At most five echoed names, then a ``... N more`` tail.
    """
    ordered = sorted(names)
    listed = ", ".join(_echo(name) for name in ordered[:5])
    return f"{listed}, ... {len(ordered) - 5} more" if len(ordered) > 5 else listed


# --------------------------------------------------------------------------- parsed form


@dataclass(frozen=True)
class FilterCall:
    """One filter application in a variable expression.

    :ivar name: The filter name from :data:`FILTERS`.
    :ivar args: The literal string arguments (at most one in v1).
    """

    name: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class VarRef:
    """A validated variable reference.

    :ivar name: The dotted path exactly as written (``doc.path``); this is the name
        ``variables_used`` lists.
    :ivar path: The traversal steps: ``str`` for a dict key, ``int`` for a list index.
    :ivar filters: The filter chain, applied left to right.
    """

    name: str
    path: tuple[Union[str, int], ...]
    filters: tuple[FilterCall, ...] = ()


@dataclass(frozen=True)
class Interpolation:
    """A parsed ``text``/``$str`` string: literal runs and variable references.

    :ivar parts: Literal ``str`` runs (braces already unescaped) and :class:`VarRef`.
    """

    parts: tuple[Union[str, VarRef], ...]

    @property
    def variables(self) -> frozenset[str]:
        """The immutable set of referenced variable names.

        Includes the ``name`` of every ``VarRef`` part, without duplicates.
        """
        return frozenset(part.name for part in self.parts if isinstance(part, VarRef))


@dataclass(frozen=True)
class Compare:
    """A comparison condition ``{"var": ..., <op>: operand}``.

    :ivar var: The compared variable (no filters).
    :ivar op: One of :data:`COMPARE_OPERATORS`.
    :ivar operand: The literal operand (a tuple for ``in``; ``True`` for truthy/falsy).
    """

    var: VarRef
    op: str
    operand: Any


@dataclass(frozen=True)
class AllOf:
    """``{"all": [...]}`` -- every condition holds.

    :ivar conditions: The non-empty condition tuple.
    """

    conditions: tuple[Condition, ...]


@dataclass(frozen=True)
class AnyOf:
    """``{"any": [...]}`` -- at least one condition holds.

    :ivar conditions: The non-empty condition tuple.
    """

    conditions: tuple[Condition, ...]


@dataclass(frozen=True)
class Not:
    """``{"not": <cond>}`` -- the condition does not hold.

    :ivar condition: The negated condition.
    """

    condition: Condition


Condition = Union[Compare, AllOf, AnyOf, Not]


@dataclass(frozen=True)
class LineNode:
    """A ``line`` node: one output line.

    :ivar text: The parsed line text.
    :ivar variables_used: The declared variable set (equal to ``text.variables``).
    :ivar when: Optional guard condition.
    """

    text: Interpolation
    variables_used: frozenset[str]
    when: Optional[Condition] = None


@dataclass(frozen=True)
class LoopNode:
    """A ``loop`` node iterating a context list.

    :ivar over: The iterated list variable.
    :ivar alias: The loop-scoped element name introduced by ``as``.
    :ivar placement: One of :data:`PLACEMENTS`.
    :ivar when: Optional guard condition, evaluated in the enclosing scope.
    :ivar text: The per-item text of an inline (``one-line``/``append``) loop.
    :ivar separator: Literal separator between inline items.
    :ivar prefix: Literal emitted before a non-empty inline list.
    :ivar suffix: Literal emitted after a non-empty inline list.
    :ivar variables_used: Declared variable set of ``text`` (inline loops).
    :ivar body: Child nodes of a ``block`` loop.
    """

    over: VarRef
    alias: str
    placement: str
    when: Optional[Condition] = None
    text: Optional[Interpolation] = None
    separator: str = ""
    prefix: str = ""
    suffix: str = ""
    variables_used: frozenset[str] = frozenset()
    body: tuple[TextNode, ...] = ()


@dataclass(frozen=True)
class GroupNode:
    """A ``group`` node: a conditional run of nodes with no loop.

    :ivar when: The guard condition.
    :ivar body: The child nodes.
    """

    when: Condition
    body: tuple[TextNode, ...]


TextNode = Union[LineNode, LoopNode, GroupNode]


@dataclass(frozen=True)
class JsonLiteral:
    """A literal JSON scalar emitted as-is.

    :ivar value: ``str``/``int``/``float``/``bool``/``None``.
    """

    value: Union[str, int, float, bool, None]


@dataclass(frozen=True)
class JsonArray:
    """A literal JSON array whose items may be operators.

    :ivar items: The item nodes.
    """

    items: tuple[JsonNode, ...]


@dataclass(frozen=True)
class JsonMember:
    """One member of a literal JSON object.

    :ivar key: The literal key.
    :ivar value: The member value node.
    :ivar omit_if: When set, the member is dropped while this condition holds.
    """

    key: str
    value: JsonNode
    omit_if: Optional[Condition] = None


@dataclass(frozen=True)
class JsonObject:
    """A literal JSON object whose member values may be operators.

    :ivar members: The members in template order.
    """

    members: tuple[JsonMember, ...]


@dataclass(frozen=True)
class JsonVar:
    """``{"$var": path}`` with optional ``"$default"``.

    :ivar var: The referenced variable (no filters).
    :ivar has_default: Whether ``$default`` was given.
    :ivar default: The frozen literal fallback for a ``None`` value.
    """

    var: VarRef
    has_default: bool = False
    default: Any = None


@dataclass(frozen=True)
class JsonFor:
    """``{"$for": path, "as": alias, "each": value}``.

    :ivar over: The iterated list variable.
    :ivar alias: The loop-scoped element name.
    :ivar each: The value node evaluated per element.
    """

    over: VarRef
    alias: str
    each: JsonNode


@dataclass(frozen=True)
class JsonIf:
    """``{"$if": cond, "then": value, "else": value}``.

    :ivar condition: The condition.
    :ivar then: The value when it holds.
    :ivar otherwise: The value when it does not (``None`` yields ``null``).
    """

    condition: Condition
    then: JsonNode
    otherwise: Optional[JsonNode] = None


@dataclass(frozen=True)
class JsonStr:
    """``{"$str": "..."}`` -- an interpolated string.

    :ivar text: The parsed string.
    """

    text: Interpolation


JsonNode = Union[JsonLiteral, JsonArray, JsonObject, JsonVar, JsonFor, JsonIf, JsonStr]


@dataclass(frozen=True)
class TextOutput:
    """``output`` settings of a ``text`` template.

    :ivar join: The line joiner; only ``"\\n"`` is accepted (M7).
    :ivar trailing_newline: Whether the rendered text ends with ``join``.
    :ivar sink: The declared sink context (M5), one of :data:`SINKS`.
    """

    join: str = "\n"
    trailing_newline: bool = False
    sink: str = SINK_TERMINAL


@dataclass(frozen=True)
class JsonOutput:
    """``output`` settings of a ``json`` template.

    :ivar indent: ``None`` or an int in 0..8 (M8).
    :ivar ensure_ascii: Always ``True`` in v1 (M8).
    :ivar sort_keys: Whether object keys are sorted on serialization.
    """

    indent: Optional[int] = None
    ensure_ascii: bool = True
    sort_keys: bool = False


@dataclass(frozen=True)
class Template:
    """A validated, immutable report template.

    :ivar template_version: The format version (``1``).
    :ivar name: The kebab-case template name.
    :ivar type: ``"text"`` or ``"json"``.
    :ivar description: Free-form description, ``""`` when absent.
    :ivar requires_extensions: Extension names the renderer entry must find loaded.
    :ivar output: :class:`TextOutput` or :class:`JsonOutput`.
    :ivar lines: Top-level nodes of a ``text`` template (``()`` for ``json``).
    :ivar body: Body node of a ``json`` template (``None`` for ``text``).
    :ivar schema_version: Declared ``schema_version`` of a ``json`` template.
    :ivar origin: ``packaged``, ``directory``, ``path`` or ``mapping``; lets a caller
        note a non-packaged template in use.
    :ivar source: The source as configured or named (never a resolved absolute path).
    :ivar extension_filters: Every distinct extension filter use as
        ``(name, argument count, input kind)``, in first-use order; bound to the
        loaded registry before the scan (M9, M30).
    """

    template_version: int
    name: str
    type: str
    description: str
    requires_extensions: tuple[str, ...]
    output: Union[TextOutput, JsonOutput]
    lines: tuple[TextNode, ...] = ()
    body: Optional[JsonNode] = None
    schema_version: Optional[int] = None
    origin: str = "mapping"
    source: str = "<mapping>"
    extension_filters: tuple[tuple[str, int, str], ...] = ()


# --------------------------------------------------------------------------- filter table


@dataclass(frozen=True)
class FilterSpec:
    """Load-time signature of one filter (implementations are Task 02's).

    :ivar arity: Number of quoted literal arguments.
    :ivar accepts: Input kinds (``scalar``/``list``/``dict``).
    :ivar sinks: Sink contexts in which the filter counts as a sink (M4-M6).
    :ivar scalar_elements: Whether a list input must have scalar elements (``join``).
    """

    arity: int
    accepts: frozenset[str]
    sinks: frozenset[str] = frozenset()
    scalar_elements: bool = False


_ANY_KIND = frozenset({_SCALAR, _LIST, _DICT})

#: The closed filter table of spec §7 as load-time signatures; every filter returns
#: a scalar. Task 02 implements the functions and must keep this table in parity.
FILTERS: Final[Mapping[str, FilterSpec]] = MappingProxyType(
    {
        "neutralize": FilterSpec(0, frozenset({_SCALAR}), frozenset({SINK_TERMINAL})),
        "gha_property": FilterSpec(0, frozenset({_SCALAR}), SINKS),
        "gha_data": FilterSpec(0, frozenset({_SCALAR}), SINKS),
        "json": FilterSpec(0, _ANY_KIND, frozenset({SINK_TERMINAL})),
        "join": FilterSpec(1, frozenset({_LIST}), scalar_elements=True),
        "len": FilterSpec(0, _ANY_KIND),
        "lower": FilterSpec(0, frozenset({_SCALAR})),
        "upper": FilterSpec(0, frozenset({_SCALAR})),
        "default": FilterSpec(1, frozenset({_SCALAR})),
    }
)


# --------------------------------------------------------------------------- schema helpers


def _kind(var: Variable) -> str:
    """Return the value kind of a schema variable.

    :param var: The schema entry.
    :returns: ``list``, ``dict``, ``any`` (extension data below ``ext.<name>``) or ``scalar``.
    """
    if var.type == _TYPE_ANY:
        return _ANY
    if var.type in (_TYPE_EXT, _TYPE_EXT_MEMBER):
        return _DICT
    if var.type.startswith("list["):
        return _LIST
    if var.type.startswith("dict[") or var.type == "object":
        return _DICT
    return _SCALAR


def _element(var: Variable) -> Variable:
    """Return the element schema of a list variable; it inherits the list's trust (M1).

    :param var: A list schema entry (or an ``any`` value iterated at render time).
    :returns: The element schema.
    """
    if var.type == _TYPE_ANY:
        return Variable(_TYPE_ANY, UNTRUSTED)
    if var.fields:
        return Variable("object", var.trust, var.fields)
    return Variable(var.type[len("list[") : -1], var.trust)


def _untrusted(var: Variable) -> bool:
    """Return whether a variable must be treated as untrusted (M2).

    :param var: The schema entry.
    :returns: ``True`` for an untrusted tag, or a ``None`` tag with an untrusted
        descendant or no members at all (fail closed).
    """
    if var.trust == UNTRUSTED:
        return True
    if var.trust is None:
        return not var.fields or any(_untrusted(member) for member in var.fields.values())
    return False


# --------------------------------------------------------------------------- JSON parsing


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` rejecting duplicate keys (M12).

    :param pairs: The decoded key/value pairs of one object.
    :returns: The object.
    :raises TemplateError: On a duplicate key.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TemplateError(f"duplicate object key: {_echo(key)}")
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    """``parse_constant`` rejecting ``NaN``/``Infinity``/``-Infinity`` (M12).

    :param token: The constant token.
    :raises TemplateError: Always.
    """
    raise TemplateError(f"non-finite number is not allowed: {_echo(token)}")


def _finite_float(token: str) -> float:
    """``parse_float`` rejecting values that overflow to infinity (M12).

    :param token: The float literal.
    :returns: The finite float.
    :raises TemplateError: When the value is not finite.
    """
    value = float(token)
    if not math.isfinite(value):
        raise TemplateError("non-finite number is not allowed")
    return value


def _parse_json(text: str, label: str) -> Any:
    """Parse template JSON with every M12 parse-time guard.

    :param text: The decoded template text.
    :param label: The echoed source label.
    :returns: The decoded JSON value.
    :raises TemplateError: On any parse failure, bounded and without the raw text.
    """
    try:
        return json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant, parse_float=_finite_float
        )
    except TemplateError as exc:
        raise TemplateError(f"template {label}: {exc}") from None
    except RecursionError:
        raise TemplateError(f"template {label}: nesting is too deep to parse") from None
    except json.JSONDecodeError as exc:
        raise TemplateError(f"template {label}: invalid JSON at line {exc.lineno} column {exc.colno}") from None
    except ValueError:
        raise TemplateError(f"template {label}: invalid JSON number") from None


def _is_neutral(value: str) -> bool:
    """Return whether ``value`` holds no code point the ``neutralize`` table escapes (M7).

    :param value: A template string.
    :returns: ``True`` when neutralization leaves it unchanged.
    """
    return neutralize_text(value) == value


def _precheck(raw: Any, label: str):
    """Iteratively check raw nesting, size, value types and literal hygiene (M7, M12).

    Runs before any recursion, so a deeply nested or huge tree cannot overflow the
    stack of the recursive validator.

    :param raw: The decoded template tree.
    :param label: The echoed source label.
    :raises TemplateError: On excess depth or values, a non-JSON value, a
        non-finite float, a non-string key, or a string holding a control, bidi,
        zero-width, separator or surrogate code point.
    """
    stack: list[tuple[Any, int, str, str]] = [(raw, 0, "", "root")]
    count = 0
    while stack:
        value, depth, where, tag = stack.pop()
        count += 1
        if count > _MAX_RAW_VALUES:
            raise TemplateError(f"template {label}: more than {_MAX_RAW_VALUES} JSON values")
        if depth > _MAX_RAW_DEPTH:
            raise TemplateError(f"template {label}: {_echo_path(where)}: JSON nesting deeper than {_MAX_RAW_DEPTH}")
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TemplateError(f"template {label}: {_echo_path(where)}: object keys must be strings")
                child = f"{where}.{key}" if where else key
                if not _is_neutral(key):
                    raise TemplateError(f"template {label}: {_echo_path(child)}: key contains a control character")
                child_tag = ("output" if key == "output" else "") if tag == "root" else ""
                if tag == "output" and key == "join":
                    child_tag = "join"
                stack.append((item, depth + 1, child, child_tag))
        elif isinstance(value, (list, tuple)):
            for position, item in enumerate(value):
                stack.append((item, depth + 1, f"{where}[{position}]", ""))
        elif isinstance(value, str):
            if not (tag == "join" and value == "\n") and not _is_neutral(value):
                raise TemplateError(
                    f"template {label}: {_echo_path(where)}: string contains a control, bidi, zero-width, "
                    "separator or surrogate character"
                )
        elif type(value) is float:
            if not math.isfinite(value):
                raise TemplateError(f"template {label}: {_echo_path(where)}: non-finite number is not allowed")
        elif value is not None and type(value) not in (bool, int):
            raise TemplateError(f"template {label}: {_echo_path(where)}: value is not JSON data")


def _freeze_literal(value: Any) -> Any:
    """Return an immutable copy of a literal JSON value (M17).

    :param value: A prechecked JSON value.
    :returns: Scalars unchanged, lists as tuples, objects as ``MappingProxyType``.
    """
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_literal(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_literal(item) for item in value)
    return value


# --------------------------------------------------------------------------- validator


Scope = Mapping[str, Variable]


class _Validator:
    """Recursive validator turning a prechecked raw tree into a :class:`Template`."""

    def __init__(self, label: str):
        """Initialise the validator.

        :param label: The echoed source label used in every error.
        """
        self._label = label
        self._nodes = 0
        self._type = ""
        self._sink = SINK_TERMINAL
        self._requires: frozenset[str] = frozenset()
        self._extension_filters: dict[tuple[str, int, str], None] = {}

    # ---- errors and generic shape checks

    def fail(self, where: str, reason: str) -> TemplateError:
        """Build a :class:`TemplateError` for a JSON path.

        :param where: The JSON path of the offending node.
        :param reason: The reason; hostile fragments must already be echoed.
        :returns: The error to raise.
        """
        return TemplateError(f"template {self._label}: {_echo_path(where)}: {reason}")

    def _tick(self, where: str, depth: int):
        """Count one template node and enforce the node and nesting bounds (M12).

        :param where: The node's JSON path.
        :param depth: The node's nesting depth.
        """
        self._nodes += 1
        if self._nodes > MAX_NODES:
            raise self.fail(where, f"template has more than {MAX_NODES} nodes")
        if depth > MAX_NESTING:
            raise self.fail(where, f"nesting deeper than {MAX_NESTING}")

    def _object(self, raw: Any, where: str, allowed: frozenset[str], required: frozenset[str]) -> Mapping[str, Any]:
        """Check that ``raw`` is an object with no unknown and no missing keys.

        :param raw: The raw value.
        :param where: Its JSON path.
        :param allowed: Allowed keys.
        :param required: Required keys.
        :returns: The object.
        """
        if not isinstance(raw, dict):
            raise self.fail(where, "expected an object")
        unknown = frozenset(raw) - allowed
        if unknown:
            raise self.fail(where, f"unknown key(s): {_echo_names(unknown)}")
        missing = required - frozenset(raw)
        if missing:
            raise self.fail(where, f"missing key(s): {_echo_names(missing)}")
        return raw

    def _string(self, raw: Any, where: str) -> str:
        """Return ``raw`` when it is a string.

        :param raw: The raw value.
        :param where: Its JSON path.
        :returns: The string.
        """
        if not isinstance(raw, str):
            raise self.fail(where, "expected a string")
        return raw

    def _bool(self, raw: Any, where: str) -> bool:
        """Return ``raw`` when it is a boolean.

        :param raw: The raw value.
        :param where: Its JSON path.
        :returns: The boolean.
        """
        if type(raw) is not bool:
            raise self.fail(where, "expected true or false")
        return raw

    # ---- envelope

    def template(self, raw: Any, *, origin: str, source: str) -> Template:
        """Validate the whole template.

        :param raw: The prechecked raw tree.
        :param origin: The :attr:`Template.origin` value.
        :param source: The :attr:`Template.source` value.
        :returns: The immutable template.
        """
        if not isinstance(raw, dict):
            raise self.fail("", "a template must be a JSON object")
        version = raw.get("template_version")
        if type(version) is not int or version != TEMPLATE_VERSION:
            raise self.fail("template_version", f"unsupported template version (expected {TEMPLATE_VERSION})")
        kind = raw.get("type")
        if kind not in ("text", "json"):
            raise self.fail("type", 'type must be "text" or "json"')
        self._type = kind
        common = frozenset({"template_version", "name", "type", "description", "requires_extensions"})
        if kind == "text":
            obj = self._object(raw, "", common | {"output", "lines"}, frozenset({"name", "lines"}))
        else:
            obj = self._object(raw, "", common | {"schema_version", "output", "body"}, frozenset({"name", "body"}))
        name = self._string(obj["name"], "name")
        if len(name) > _MAX_NAME or NAME_PATTERN.fullmatch(name) is None:
            raise self.fail("name", "name must be kebab-case ([a-z0-9] runs joined by '-')")
        description = self._string(obj.get("description", ""), "description")
        requires = self._extensions(obj.get("requires_extensions", []))
        self._requires = frozenset(requires)
        if kind == "text":
            output = self._text_output(obj.get("output", {}))
            self._sink = output.sink
            lines = self._text_nodes(obj["lines"], "lines", CONTEXT_SCHEMA, 1, 0)
            return Template(
                TEMPLATE_VERSION,
                name,
                kind,
                description,
                requires,
                output,
                lines,
                origin=origin,
                source=source,
                extension_filters=tuple(self._extension_filters),
            )
        schema_version = obj.get("schema_version", 1)
        if type(schema_version) is not int or not 1 <= schema_version <= _MAX_SCHEMA_VERSION:
            raise self.fail("schema_version", f"schema_version must be an integer in 1..{_MAX_SCHEMA_VERSION}")
        json_output = self._json_output(obj.get("output", {}))
        body = self._json_value(obj["body"], "body", CONTEXT_SCHEMA, 1, 0)
        return Template(
            TEMPLATE_VERSION,
            name,
            kind,
            description,
            requires,
            json_output,
            body=body,
            schema_version=schema_version,
            origin=origin,
            source=source,
            extension_filters=tuple(self._extension_filters),
        )

    def _extensions(self, raw: Any) -> tuple[str, ...]:
        """Validate ``requires_extensions`` (Task 01 rule 7; checked against loaded ones later).

        :param raw: The raw list.
        :returns: The extension names.
        """
        if not isinstance(raw, list):
            raise self.fail("requires_extensions", "expected a list of extension names")
        names: list[str] = []
        for position, item in enumerate(raw):
            where = f"requires_extensions[{position}]"
            value = self._string(item, where)
            if _EXTENSION_PATTERN.fullmatch(value) is None:
                raise self.fail(where, f"invalid extension name: {_echo(value)}")
            if value in names:
                raise self.fail(where, f"duplicate extension name: {_echo(value)}")
            names.append(value)
        return tuple(names)

    def _text_output(self, raw: Any) -> TextOutput:
        """Validate ``output`` of a ``text`` template (M5, M7).

        :param raw: The raw object.
        :returns: The output settings.
        """
        obj = self._object(raw, "output", frozenset({"join", "trailing_newline", "sink"}), frozenset())
        join = obj.get("join", "\n")
        if join != "\n":
            raise self.fail("output.join", 'output.join may only be "\\n"')
        trailing = self._bool(obj.get("trailing_newline", False), "output.trailing_newline")
        sink = obj.get("sink", SINK_TERMINAL)
        if sink not in SINKS:
            raise self.fail("output.sink", 'output.sink must be "terminal" or "github"')
        return TextOutput(join="\n", trailing_newline=trailing, sink=sink)

    def _json_output(self, raw: Any) -> JsonOutput:
        """Validate ``output`` of a ``json`` template (M8).

        :param raw: The raw object.
        :returns: The output settings.
        """
        obj = self._object(raw, "output", frozenset({"indent", "ensure_ascii", "sort_keys"}), frozenset())
        indent = obj.get("indent")
        if indent is not None and (type(indent) is not int or not 0 <= indent <= _MAX_INDENT):
            raise self.fail("output.indent", f"output.indent must be null or an integer in 0..{_MAX_INDENT}")
        if obj.get("ensure_ascii", True) is not True:
            raise self.fail("output.ensure_ascii", "output.ensure_ascii must be true")
        sort_keys = self._bool(obj.get("sort_keys", False), "output.sort_keys")
        return JsonOutput(indent=indent, ensure_ascii=True, sort_keys=sort_keys)

    # ---- variables

    def _parse_path(self, raw: str, where: str) -> tuple[str, tuple[Union[str, int], ...]]:
        """Parse a dotted variable path (M12, M14).

        :param raw: The path text, e.g. ``doc.problems.0.message``.
        :param where: The JSON path for errors.
        :returns: ``(name, steps)`` with list indexes as ``int``.
        """
        segments = raw.split(".")
        if len(segments) > _MAX_PATH_SEGMENTS:
            raise self.fail(where, f"variable path has more than {_MAX_PATH_SEGMENTS} segments: {_echo(raw)}")
        steps: list[Union[str, int]] = []
        for position, segment in enumerate(segments):
            if _SEGMENT_PATTERN.fullmatch(segment):
                steps.append(segment)
            elif position > 0 and _INDEX_PATTERN.fullmatch(segment):
                steps.append(int(segment))
            else:
                raise self.fail(where, f"invalid variable path: {_echo(raw)}")
        return raw, tuple(steps)

    def _resolve(self, ref: VarRef, scope: Scope, where: str) -> Variable:
        """Resolve a reference against the schema and loop scope (Task 01 rule 3).

        :param ref: The reference.
        :param scope: Visible names: :data:`CONTEXT_SCHEMA` plus enclosing aliases.
        :param where: The JSON path for errors.
        :returns: The schema entry of the referenced value.
        """
        head = ref.path[0]
        current = scope.get(head) if isinstance(head, str) else None
        if current is None:
            raise self.fail(where, f"unknown variable: {_echo(ref.name)}")
        for step in ref.path[1:]:
            kind = _kind(current)
            if current.type == _TYPE_EXT:
                current = self._extension_member(ref, step, where)
            elif current.type in (_TYPE_EXT_MEMBER, _TYPE_ANY) and (isinstance(step, str) or current.type == _TYPE_ANY):
                current = Variable(_TYPE_ANY, UNTRUSTED)
            elif kind == _LIST and isinstance(step, int):
                current = _element(current)
            elif kind == _DICT and isinstance(step, str) and current.fields:
                member = current.fields.get(step)
                if member is None:
                    raise self.fail(where, f"unknown variable: {_echo(ref.name)}")
                current = member
            elif kind == _DICT and isinstance(step, str) and current.type.startswith("dict["):
                value_type = current.type[len("dict[") : -1].split(",", 1)[-1]
                current = Variable(value_type, current.trust)
            else:
                raise self.fail(where, f"unknown variable: {_echo(ref.name)}")
        return current

    def _extension_member(self, ref: VarRef, step: Union[str, int], where: str) -> Variable:
        """Resolve ``ext.<name>``: only a name listed in ``requires_extensions`` (M11, M12).

        :param ref: The reference, for errors.
        :param step: The segment after ``ext``.
        :param where: The JSON path for errors.
        :returns: The untrusted schema entry of that extension's subtree.
        """
        if not isinstance(step, str) or _EXTENSION_PATTERN.fullmatch(step) is None:
            raise self.fail(where, f"unknown variable: {_echo(ref.name)}")
        if step not in self._requires:
            raise self.fail(where, f"{_echo(ref.name)} needs extension {_echo(step)} listed in requires_extensions")
        return Variable(_TYPE_EXT_MEMBER, UNTRUSTED)

    def _extension_filter(self, call: FilterCall, kind: str, where: str):
        """Check an ``ext.<name>.<filter>`` call and record its use (M7-M9, M12).

        :param call: The filter call.
        :param kind: The value kind it receives.
        :param where: The JSON path for errors.
        """
        segments = call.name.split(".")
        if (
            len(segments) != 3
            or _EXTENSION_PATTERN.fullmatch(segments[1]) is None
            or _EXT_FILTER_LEAF_PATTERN.fullmatch(segments[2]) is None
        ):
            raise self.fail(where, f"unknown filter: {_echo(call.name)}")
        if segments[1] not in self._requires:
            raise self.fail(
                where, f"filter {_echo(call.name)} needs extension {_echo(segments[1])} listed in requires_extensions"
            )
        self._extension_filters.setdefault((call.name, len(call.args), kind), None)

    def _plain_ref(self, raw: Any, where: str, scope: Scope) -> tuple[VarRef, Variable]:
        """Parse and resolve a filter-free variable (``over``, ``var``, ``$var``, ``$for``).

        :param raw: The raw path value.
        :param where: Its JSON path.
        :param scope: Visible names.
        :returns: The reference and its schema entry.
        """
        name, steps = self._parse_path(self._string(raw, where), where)
        ref = VarRef(name, steps)
        return ref, self._resolve(ref, scope, where)

    def _alias(self, raw: Any, where: str, scope: Scope) -> str:
        """Validate a loop alias: identifier, not shadowing a core or enclosing name.

        :param raw: The raw ``as`` value.
        :param where: Its JSON path.
        :param scope: Visible names.
        :returns: The alias.
        """
        alias = self._string(raw, where)
        if _ALIAS_PATTERN.fullmatch(alias) is None:
            raise self.fail(where, f"invalid loop alias: {_echo(alias)}")
        if alias in scope or alias == "ext":
            raise self.fail(where, f"loop alias shadows an existing name: {_echo(alias)}")
        return alias

    def _list_var(self, raw: Any, where: str, scope: Scope) -> tuple[VarRef, Variable]:
        """Resolve a loop's iterated variable, which must be a list.

        :param raw: The raw ``over``/``$for`` value.
        :param where: Its JSON path.
        :param scope: Visible names.
        :returns: The reference and its element schema.
        """
        ref, var = self._plain_ref(raw, where, scope)
        if _kind(var) not in (_LIST, _ANY):
            raise self.fail(where, f"loop variable is not a list: {_echo(ref.name)}")
        return ref, _element(var)

    # ---- interpolation

    def _interpolation(self, raw: Any, where: str) -> Interpolation:
        """Parse ``{var|filter(arg)}`` syntax with ``{{``/``}}`` escapes (spec §3).

        :param raw: The raw string.
        :param where: Its JSON path.
        :returns: The parsed interpolation (variables not yet resolved).
        """
        text = self._string(raw, where)
        parts: list[Union[str, VarRef]] = []
        buffer: list[str] = []
        position = 0
        while position < len(text):
            char = text[position]
            if char == "{" and text.startswith("{{", position):
                buffer.append("{")
                position += 2
            elif char == "}" and text.startswith("}}", position):
                buffer.append("}")
                position += 2
            elif char == "}":
                raise self.fail(where, "unmatched '}' (write '}}' for a literal brace)")
            elif char == "{":
                if buffer:
                    parts.append("".join(buffer))
                    buffer = []
                ref, position = self._expression(text, position + 1, where)
                parts.append(ref)
            else:
                buffer.append(char)
                position += 1
        if buffer:
            parts.append("".join(buffer))
        return Interpolation(tuple(parts))

    def _expression(self, text: str, start: int, where: str) -> tuple[VarRef, int]:
        """Parse one ``path|filter|filter("arg")`` expression after its ``{``.

        :param text: The whole string.
        :param start: Index just after ``{``.
        :param where: The JSON path for errors.
        :returns: The reference and the index just after the closing ``}``.
        """
        end = start
        while end < len(text) and text[end] not in "|}":
            end += 1
        if end >= len(text):
            raise self.fail(where, "unterminated '{' (write '{{' for a literal brace)")
        name, steps = self._parse_path(text[start:end], where)
        filters: list[FilterCall] = []
        position = end
        while text[position] == "|":
            position += 1
            name_end = position
            while name_end < len(text) and (text[name_end].isalnum() or text[name_end] in "_."):
                name_end += 1
            filter_name = text[position:name_end]
            if _FILTER_NAME_PATTERN.fullmatch(filter_name) is None:
                raise self.fail(where, f"invalid filter name in {_echo(name)}")
            position = name_end
            args: tuple[str, ...] = ()
            if position < len(text) and text[position] == "(":
                argument, position = self._argument(text, position + 1, where)
                args = (argument,)
            filters.append(FilterCall(filter_name, args))
            if position >= len(text):
                raise self.fail(where, "unterminated '{' (write '{{' for a literal brace)")
            if text[position] not in "|}":
                raise self.fail(where, f"invalid variable expression for {_echo(name)}")
        return VarRef(name, steps, tuple(filters)), position + 1

    def _argument(self, text: str, start: int, where: str) -> tuple[str, int]:
        """Parse one quoted filter argument and its closing ``)`` (M12; no ``eval``).

        :param text: The whole string.
        :param start: Index just after ``(``.
        :param where: The JSON path for errors.
        :returns: The argument and the index just after ``)``.
        """
        if start >= len(text) or text[start] not in "\"'":
            raise self.fail(where, "a filter argument must be a quoted string literal")
        quote = text[start]
        close = text.find(quote, start + 1)
        if close < 0:
            raise self.fail(where, "unterminated filter argument")
        argument = text[start + 1 : close]
        if len(argument) > MAX_FILTER_ARG:
            raise self.fail(where, f"filter argument longer than {MAX_FILTER_ARG} characters")
        if close + 1 >= len(text) or text[close + 1] != ")":
            raise self.fail(where, "a filter takes exactly one quoted argument followed by ')'")
        return argument, close + 2

    def _check_ref(
        self,
        ref: VarRef,
        scope: Scope,
        where: str,
        *,
        property_segment: bool,
        command_line: bool = True,
        data_segment: bool = False,
    ):
        """Check one emitted reference: filters, M3 scalar rule and M4-M6 trust rule.

        :param ref: The reference.
        :param scope: Visible names.
        :param where: The JSON path for errors.
        :param property_segment: Whether it sits in a GitHub command property segment.
        :param command_line: ``False`` when, under the ``github`` sink, it sits on a
            line not proven to be a well-formed workflow command, so it must be trusted.
        :param data_segment: Whether it sits after the second ``::`` of a well-formed
            command, so an untrusted value must end with ``gha_data``.
        """
        var = self._resolve(ref, scope, where)
        kind = _kind(var)
        element_kind = _kind(_element(var)) if kind == _LIST else None
        # M8: the output of a chain holding an extension filter is untrusted.
        tainted = False
        for call in ref.filters:
            if call.name.startswith(_EXT_FILTER_PREFIX):
                self._extension_filter(call, kind, where)
                tainted = True
                kind = _SCALAR
                element_kind = None
                continue
            spec = FILTERS.get(call.name)
            if spec is None:
                raise self.fail(where, f"unknown filter: {_echo(call.name)}")
            if len(call.args) != spec.arity:
                raise self.fail(where, f"filter {call.name} takes {spec.arity} argument(s)")
            # An ``any`` value (M11) is checked by the filter at render time.
            if kind != _ANY and (kind not in spec.accepts or (spec.scalar_elements and element_kind != _SCALAR)):
                raise self.fail(where, f"filter {call.name} cannot take the {kind} value of {_echo(ref.name)}")
            kind = _SCALAR
            element_kind = None
        if kind not in (_SCALAR, _ANY):
            raise self.fail(where, f"{_echo(ref.name)} is a {kind}; reduce it with join, len or json before output")
        if self._type != "text":
            return
        last = ref.filters[-1].name if ref.filters else ""
        # Every variable in a command property segment, trusted ones included (a
        # trusted ``model`` id may carry ``:``), must be escaped for that segment.
        if property_segment and last != "gha_property":
            raise self.fail(where, f"variable {_echo(ref.name)} in a command property needs gha_property")
        if not tainted and not _untrusted(var):
            return
        if not last or last not in FILTERS or self._sink not in FILTERS[last].sinks:
            raise self.fail(
                where,
                f"untrusted variable {_echo(ref.name)} must end its filter chain with a {self._sink} sink filter",
            )
        # T2-R1: the runner's legacy parser matches ``##[`` anywhere in a line that
        # is not a well-formed command, and the gha_* filters keep ``#[]``.
        if not command_line:
            raise self.fail(
                where,
                f"untrusted variable {_echo(ref.name)} under output.sink github is only allowed "
                "in a well-formed workflow command line",
            )
        if data_segment and last != "gha_data":
            raise self.fail(where, f"variable {_echo(ref.name)} in command data needs gha_data")

    def _emitted_text(
        self,
        raw: Any,
        where: str,
        scope: Scope,
        *,
        line_prefix: Optional[str] = None,
        separator: Optional[str] = None,
        append: bool = False,
    ) -> Interpolation:
        """Parse and check an emitted string (line/loop ``text`` or ``$str``).

        Under ``output.sink: github`` (threat model T2/T2-R1):

        * an emitted line that carries a variable must start with literal text that
          cannot become ``::``: GitHub trims leading whitespace before matching a
          workflow command, so a line led by a variable (or by only whitespace or a
          lone ``:``) could become a live command such as ``::stop-commands::``;
        * an untrusted variable may only sit on a well-formed command line: the line
          opens with a literal ``::<name>`` from the closed allowlist (``error``,
          ``warning``, ``notice``, ``debug``, ``group``) followed by a literal space or
          ``::``, and holds a literal second ``::``. Any other line falls through to the
          runner's legacy parser, which matches ``##[`` anywhere and which the
          ``gha_*`` filters do not escape. An ``append`` loop cannot prove which line
          it continues, so it may carry only trusted variables;
        * every variable before the second ``::`` (and every ``append`` variable) needs
          ``gha_property``, an untrusted one after it needs ``gha_data``;
        * no variable may directly follow a literal ending in ``#``, so a value can
          never complete ``##[``.

        :param raw: The raw string.
        :param where: Its JSON path.
        :param scope: Visible names.
        :param line_prefix: Literal emitted before ``raw`` at the start of an output
            line (``""`` for a ``line`` node, the loop ``prefix`` for an inline loop),
            or ``None`` when ``raw`` never starts a line (``$str``).
        :param separator: The inline loop ``separator`` when ``raw`` is a per-item text
            (repeated on one line), else ``None``. Each item's segment is judged by
            counting ``::`` from ``line_prefix`` through the item's own literals.
        :param append: Whether ``raw`` continues an unknown previous line, so under
            the ``github`` sink every variable is treated as a property segment and
            must be trusted.
        :returns: The parsed interpolation.
        """
        interpolation = self._interpolation(raw, where)
        parts = interpolation.parts
        if line_prefix is None or self._type != "text":
            for part in parts:
                if not isinstance(part, str):
                    self._check_ref(part, scope, where, property_segment=False)
            return interpolation
        first = parts[0] if parts and isinstance(parts[0], str) else ""
        lead = (line_prefix + first).lstrip()
        command = lead.startswith("::")
        if command and self._sink != SINK_GITHUB:
            raise self.fail(where, 'a line starting with "::" requires output.sink "github"')
        github = self._sink == SINK_GITHUB
        has_variables = any(not isinstance(part, str) for part in parts)
        if github and has_variables and lead in ("", ":"):
            raise self.fail(where, 'under output.sink "github" an emitted line must start with literal text')
        if github:
            self._reject_hash_join(parts, where, line_prefix, separator)
        literal_markers = line_prefix.count("::") + sum(part.count("::") for part in parts if isinstance(part, str))
        well_formed = (
            not append and literal_markers >= 2 and _GHA_COMMAND_PATTERN.match(line_prefix + first) is not None
        )
        # Counted per item from the prefix: an inline item is judged as if it were
        # the first on the line; later items only ever land in the data segment.
        markers = line_prefix.count("::")
        for part in parts:
            if isinstance(part, str):
                markers += part.count("::")
                continue
            self._check_ref(
                part,
                scope,
                where,
                property_segment=github if append else command and markers < 2,
                command_line=not github or well_formed,
                data_segment=github and well_formed and markers >= 2,
            )
        return interpolation

    def _reject_hash_join(
        self, parts: tuple[Union[str, VarRef], ...], where: str, line_prefix: str, separator: Optional[str]
    ):
        """Reject a variable directly after a literal ending in ``#`` (T2-R1).

        A value led by ``[`` would otherwise complete the legacy ``##[`` command
        marker. For an inline loop the join between items (the item's trailing
        literal plus ``separator``) is checked as well.

        :param parts: The parsed text parts.
        :param where: Its JSON path.
        :param line_prefix: Literal emitted before the first part.
        :param separator: The inline loop separator, or ``None`` when not repeated.
        """
        preceding: list[str] = []
        previous = line_prefix
        for part in parts:
            if isinstance(part, str):
                previous = part
                continue
            preceding.append(previous)
            previous = ""
        if separator is not None and parts and not isinstance(parts[0], str):
            preceding.append((parts[-1] if isinstance(parts[-1], str) else "") + separator)
        if any(text.endswith("#") for text in preceding):
            raise self.fail(where, 'under output.sink "github" a variable may not follow a literal ending in "#"')

    def _variables_used(self, raw: Any, where: str, interpolation: Interpolation) -> frozenset[str]:
        """Check ``variables_used`` equals the referenced set, both directions (rule 4).

        :param raw: The raw declaration.
        :param where: Its JSON path.
        :param interpolation: The node's parsed text.
        :returns: The declared set.
        """
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise self.fail(where, "variables_used must be a list of variable names")
        declared = frozenset(raw)
        if len(declared) != len(raw):
            raise self.fail(where, "variables_used lists a variable twice")
        referenced = interpolation.variables
        if declared - referenced:
            raise self.fail(where, f"declared but not used: {_echo_names(declared - referenced)}")
        if referenced - declared:
            raise self.fail(where, f"used but not declared: {_echo_names(referenced - declared)}")
        return declared

    # ---- conditions

    def _condition(self, raw: Any, where: str, scope: Scope, depth: int) -> Condition:
        """Validate a ``when``/``$if``/``$omit_if`` condition (closed grammar, rule 5).

        :param raw: The raw condition.
        :param where: Its JSON path.
        :param scope: Visible names.
        :param depth: Nesting depth.
        :returns: The condition.
        """
        self._tick(where, depth)
        if not isinstance(raw, dict):
            raise self.fail(where, "a condition must be an object")
        if "var" not in raw:
            if len(raw) != 1 or next(iter(raw)) not in COMBINATORS:
                raise self.fail(where, "a condition is {var, <op>} or one of all/any/not")
            ((combinator, operand),) = raw.items()
            if combinator == "not":
                return Not(self._condition(operand, f"{where}.not", scope, depth + 1))
            if not isinstance(operand, list) or not operand:
                raise self.fail(f"{where}.{combinator}", f"{combinator} takes a non-empty list of conditions")
            items = tuple(
                self._condition(item, f"{where}.{combinator}[{position}]", scope, depth + 1)
                for position, item in enumerate(operand)
            )
            return AllOf(items) if combinator == "all" else AnyOf(items)
        ops = frozenset(raw) - {"var"}
        if len(ops) != 1 or not ops <= COMPARE_OPERATORS:
            raise self.fail(where, f"unknown or missing condition operator: {_echo_names(ops)}")
        (op,) = ops
        ref, var = self._plain_ref(raw["var"], f"{where}.var", scope)
        operand = raw[op]
        at = f"{where}.{op}"
        if op in ("truthy", "falsy"):
            if operand is not True:
                raise self.fail(at, f"{op} takes the value true")
            return Compare(ref, op, True)
        if _kind(var) not in (_SCALAR, _ANY):
            raise self.fail(at, f"{op} needs a scalar variable; {_echo(ref.name)} is a {_kind(var)}")
        if op in ("gt", "lt"):
            if type(operand) not in (int, float):
                raise self.fail(at, f"{op} takes a number")
        elif op == "in":
            if not isinstance(operand, list) or len(operand) > _MAX_IN_OPERANDS:
                raise self.fail(at, f"in takes a list of at most {_MAX_IN_OPERANDS} scalars")
            if any(isinstance(item, (dict, list)) for item in operand):
                raise self.fail(at, "in takes a list of scalars")
            operand = tuple(operand)
        elif isinstance(operand, (dict, list)):
            raise self.fail(at, f"{op} takes a scalar")
        return Compare(ref, op, operand)

    # ---- text nodes

    def _text_nodes(self, raw: Any, where: str, scope: Scope, depth: int, loops: int) -> tuple[TextNode, ...]:
        """Validate a list of text nodes.

        :param raw: The raw list.
        :param where: Its JSON path.
        :param scope: Visible names.
        :param depth: Nesting depth of the nodes.
        :param loops: Enclosing loop count.
        :returns: The nodes.
        """
        if not isinstance(raw, list):
            raise self.fail(where, "expected a list of nodes")
        return tuple(
            self._text_node(item, f"{where}[{position}]", scope, depth, loops) for position, item in enumerate(raw)
        )

    def _text_node(self, raw: Any, where: str, scope: Scope, depth: int, loops: int) -> TextNode:
        """Validate one ``line``/``loop``/``group`` node.

        :param raw: The raw node.
        :param where: Its JSON path.
        :param scope: Visible names.
        :param depth: Nesting depth.
        :param loops: Enclosing loop count.
        :returns: The node.
        """
        self._tick(where, depth)
        node_type = raw.get("type") if isinstance(raw, dict) else None
        if node_type == "line":
            obj = self._object(
                raw, where, frozenset({"type", "text", "variables_used", "when"}), frozenset({"text", "variables_used"})
            )
            when = self._when(obj, where, scope, depth)
            text = self._emitted_text(obj["text"], f"{where}.text", scope, line_prefix="")
            used = self._variables_used(obj["variables_used"], f"{where}.variables_used", text)
            return LineNode(text, used, when)
        if node_type == "group":
            obj = self._object(raw, where, frozenset({"type", "when", "body"}), frozenset({"when", "body"}))
            when = self._condition(obj["when"], f"{where}.when", scope, depth + 1)
            return GroupNode(when, self._text_nodes(obj["body"], f"{where}.body", scope, depth + 1, loops))
        if node_type == "loop":
            return self._loop(raw, where, scope, depth, loops)
        raise self.fail(f"{where}.type", 'node type must be "line", "loop" or "group"')

    def _when(self, obj: Mapping[str, Any], where: str, scope: Scope, depth: int) -> Optional[Condition]:
        """Validate an optional ``when`` key.

        :param obj: The node object.
        :param where: The node's JSON path.
        :param scope: Visible names.
        :param depth: The node's depth.
        :returns: The condition or ``None``.
        """
        if "when" not in obj:
            return None
        return self._condition(obj["when"], f"{where}.when", scope, depth + 1)

    def _loop(self, raw: Mapping[str, Any], where: str, scope: Scope, depth: int, loops: int) -> LoopNode:
        """Validate a ``loop`` node (spec §4 placements, M13 nesting).

        :param raw: The raw node.
        :param where: Its JSON path.
        :param scope: Visible names.
        :param depth: Nesting depth.
        :param loops: Enclosing loop count.
        :returns: The node.
        """
        placement = raw.get("placement", PLACEMENT_BLOCK)
        if placement not in PLACEMENTS:
            raise self.fail(f"{where}.placement", 'placement must be "block", "one-line" or "append"')
        common = frozenset({"type", "over", "as", "placement", "when"})
        if placement == PLACEMENT_BLOCK:
            obj = self._object(raw, where, common | {"body"}, frozenset({"over", "as", "body"}))
        else:
            inline = common | {"text", "separator", "prefix", "suffix", "variables_used"}
            obj = self._object(raw, where, inline, frozenset({"over", "as", "text", "variables_used"}))
        if loops + 1 > MAX_LOOP_NESTING:
            raise self.fail(where, f"loops nest deeper than {MAX_LOOP_NESTING}")
        when = self._when(obj, where, scope, depth)
        over, element = self._list_var(obj["over"], f"{where}.over", scope)
        alias = self._alias(obj["as"], f"{where}.as", scope)
        inner: Scope = MappingProxyType({**scope, alias: element})
        if placement == PLACEMENT_BLOCK:
            body = self._text_nodes(obj["body"], f"{where}.body", inner, depth + 1, loops + 1)
            return LoopNode(over, alias, placement, when, body=body)
        separator = self._string(obj.get("separator", ""), f"{where}.separator")
        prefix = self._string(obj.get("prefix", ""), f"{where}.prefix")
        suffix = self._string(obj.get("suffix", ""), f"{where}.suffix")
        # An ``append`` result starts a line when no (or an empty) line precedes it,
        # so both inline placements get the line-start checks (T2, M5).
        text = self._emitted_text(
            obj["text"],
            f"{where}.text",
            inner,
            line_prefix=prefix,
            separator=separator,
            append=placement == PLACEMENT_APPEND,
        )
        used = self._variables_used(obj["variables_used"], f"{where}.variables_used", text)
        return LoopNode(over, alias, placement, when, text, separator, prefix, suffix, used)

    # ---- json values

    def _json_value(self, raw: Any, where: str, scope: Scope, depth: int, loops: int) -> JsonNode:
        """Validate one ``json`` template value (spec §5).

        :param raw: The raw value.
        :param where: Its JSON path.
        :param scope: Visible names.
        :param depth: Nesting depth.
        :param loops: Enclosing ``$for`` count.
        :returns: The node.
        """
        self._tick(where, depth)
        if isinstance(raw, list):
            return JsonArray(
                tuple(
                    self._json_value(item, f"{where}[{position}]", scope, depth + 1, loops)
                    for position, item in enumerate(raw)
                )
            )
        if not isinstance(raw, dict):
            return JsonLiteral(raw)
        if any(key.startswith("$") for key in raw):
            return self._json_operator(raw, where, scope, depth, loops)
        members: list[JsonMember] = []
        for key, value in raw.items():
            at = f"{where}.{key}"
            if isinstance(value, dict) and "$omit_if" in value:
                omit = self._object(value, at, frozenset({"$omit_if", "value"}), frozenset({"$omit_if", "value"}))
                condition = self._condition(omit["$omit_if"], f"{at}.$omit_if", scope, depth + 1)
                inner = self._json_value(omit["value"], f"{at}.value", scope, depth + 1, loops)
                members.append(JsonMember(key, inner, condition))
            else:
                members.append(JsonMember(key, self._json_value(value, at, scope, depth + 1, loops)))
        return JsonObject(tuple(members))

    def _json_operator(self, raw: Mapping[str, Any], where: str, scope: Scope, depth: int, loops: int) -> JsonNode:
        """Validate a ``$``-operator object; an unknown ``$`` key is an error (M14).

        :param raw: The raw operator object.
        :param where: Its JSON path.
        :param scope: Visible names.
        :param depth: Nesting depth.
        :param loops: Enclosing ``$for`` count.
        :returns: The operator node.
        """
        if "$var" in raw:
            obj = self._object(raw, where, frozenset({"$var", "$default"}), frozenset({"$var"}))
            ref, _ = self._plain_ref(obj["$var"], f"{where}.$var", scope)
            if "$default" not in obj:
                return JsonVar(ref)
            default = obj["$default"]
            self._reject_operator_keys(default, f"{where}.$default")
            return JsonVar(ref, True, _freeze_literal(default))
        if "$for" in raw:
            obj = self._object(raw, where, frozenset({"$for", "as", "each"}), frozenset({"$for", "as", "each"}))
            if loops + 1 > MAX_LOOP_NESTING:
                raise self.fail(where, f"loops nest deeper than {MAX_LOOP_NESTING}")
            over, element = self._list_var(obj["$for"], f"{where}.$for", scope)
            alias = self._alias(obj["as"], f"{where}.as", scope)
            inner: Scope = MappingProxyType({**scope, alias: element})
            return JsonFor(over, alias, self._json_value(obj["each"], f"{where}.each", inner, depth + 1, loops + 1))
        if "$if" in raw:
            obj = self._object(raw, where, frozenset({"$if", "then", "else"}), frozenset({"$if", "then"}))
            condition = self._condition(obj["$if"], f"{where}.$if", scope, depth + 1)
            then = self._json_value(obj["then"], f"{where}.then", scope, depth + 1, loops)
            otherwise = None
            if "else" in obj:
                otherwise = self._json_value(obj["else"], f"{where}.else", scope, depth + 1, loops)
            return JsonIf(condition, then, otherwise)
        if "$str" in raw:
            obj = self._object(raw, where, frozenset({"$str"}), frozenset({"$str"}))
            return JsonStr(self._emitted_text(obj["$str"], f"{where}.$str", scope))
        if "$omit_if" in raw:
            raise self.fail(where, "$omit_if is only valid as the value of an object member")
        unknown = frozenset(key for key in raw if key.startswith("$"))
        raise self.fail(where, f"unknown operator: {_echo_names(unknown)}")

    def _reject_operator_keys(self, raw: Any, where: str):
        """Reject ``$`` keys inside a literal ``$default`` value (M14).

        :param raw: The literal (prechecked, so bounded in depth).
        :param where: Its JSON path.
        """
        if isinstance(raw, dict):
            for key, value in raw.items():
                if key.startswith("$"):
                    raise self.fail(where, f"operator key inside a literal default: {_echo(key)}")
                self._reject_operator_keys(value, f"{where}.{key}")
        elif isinstance(raw, list):
            for position, value in enumerate(raw):
                self._reject_operator_keys(value, f"{where}[{position}]")


def validate_template(raw: Any, *, origin: str = "mapping", source: str = "<mapping>") -> Template:
    """Validate an already-decoded template tree.

    :param raw: The decoded template (``dict``), e.g. from a test.
    :param origin: The :attr:`Template.origin` to record.
    :param source: The source label to record and echo.
    :returns: The immutable template.
    :raises TemplateError: On any validation failure.
    """
    label = _echo(source)
    _precheck(raw, label)
    try:
        return _Validator(label).template(raw, origin=origin, source=source)
    except RecursionError:
        raise TemplateError(f"template {label}: nesting is too deep to validate") from None


# --------------------------------------------------------------------------- file gate


def _read_gated(path: Path, label: str, *, nofollow: bool) -> str:
    """Read a template file through the regular-file/size/encoding gate (M11).

    :param path: The file to read.
    :param label: The echoed configured label (never the resolved path).
    :param nofollow: Refuse a symlink as the final component (config-named files).
    :returns: The decoded text.
    :raises TemplateError: When the file is missing, unreadable, not regular,
        oversized, has a BOM, or is not UTF-8.
    """
    try:
        info = os.stat(path)
    except OSError:
        raise TemplateError(f"template {label}: could not be read") from None
    if not stat.S_ISREG(info.st_mode):
        raise TemplateError(f"template {label}: not a regular file")
    if info.st_size > MAX_TEMPLATE_BYTES:
        raise TemplateError(f"template {label}: larger than {MAX_TEMPLATE_BYTES} bytes")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if nofollow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise TemplateError(f"template {label}: could not be read") from None
    try:
        stream = os.fdopen(descriptor, "rb")
    except OSError:
        os.close(descriptor)
        raise TemplateError(f"template {label}: could not be read") from None
    try:
        with stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise TemplateError(f"template {label}: not a regular file")
            if opened.st_size > MAX_TEMPLATE_BYTES:
                raise TemplateError(f"template {label}: larger than {MAX_TEMPLATE_BYTES} bytes")
            data = stream.read(MAX_TEMPLATE_BYTES + 1)
    except OSError:
        raise TemplateError(f"template {label}: could not be read") from None
    if len(data) > MAX_TEMPLATE_BYTES:
        raise TemplateError(f"template {label}: larger than {MAX_TEMPLATE_BYTES} bytes")
    if data.startswith(_UTF8_BOM):
        raise TemplateError(f"template {label}: a UTF-8 byte order mark is not allowed")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise TemplateError(f"template {label}: not valid UTF-8") from None


def _check_contained(root: Path, configured: str, what: str):
    """Apply the DS115 containment gate to a config-named path before any open (M10).

    :param root: The canonical scan root.
    :param configured: The path exactly as configured, relative to the root.
    :param what: Short description for the error (``report_templates_dir`` ...).
    :raises TemplateError: When the path is DS116-owned, not ``RESOLVED`` in-root, or
        escapes through a symlink. Only the configured value is echoed.
    """
    refused = TemplateError(f"{what} escapes the scan root: {_echo(configured)}")
    if is_ds116_owned(root, ".", configured):
        raise refused
    reference = resolve_local_reference(root, ".", configured)
    if reference.status is not ReferenceStatus.RESOLVED or reference.path is None:
        raise refused
    if escapes_via_symlink(root, root / configured):
        raise refused


@lru_cache(maxsize=32)
def _load_packaged_cached(resource: str, mtime_ns: int, size: int, name: str) -> Template:
    """Load and validate one packaged template, cached by resource identity (M17).

    :param resource: The resolved packaged resource path.
    :param mtime_ns: Its modification time, part of the cache key.
    :param size: Its size, part of the cache key.
    :param name: The requested name (must equal the template ``name``).
    :returns: The immutable template.
    """
    text = _read_gated(Path(resource), _echo(name), nofollow=False)
    return _finish(text, origin="packaged", source=name, expected_name=name)


def _finish(text: str, *, origin: str, source: str, expected_name: Optional[str]) -> Template:
    """Parse and validate template text, checking the name equals the file stem.

    :param text: The decoded template text.
    :param origin: The :attr:`Template.origin`.
    :param source: The configured source label.
    :param expected_name: The stem the template ``name`` must equal, if any.
    :returns: The immutable template.
    """
    raw = _parse_json(text, _echo(source))
    template = validate_template(raw, origin=origin, source=source)
    if expected_name is not None and template.name != expected_name:
        raise TemplateError(f"template {_echo(source)}: name must equal the file stem {_echo(expected_name)}")
    return template


def _load_by_name(name: str, root: Optional[Path], templates_dir: Optional[str]) -> Template:
    """Resolve a template name: packaged first, then ``report_templates_dir`` (M9, M10).

    :param name: A name matching :data:`NAME_PATTERN`.
    :param root: The scan root, required for ``templates_dir``.
    :param templates_dir: The configured ``report_templates_dir``, or ``None``.
    :returns: The template.
    """
    packaged = PACKAGED_TEMPLATES_DIR / f"{name}.json"
    try:
        info = os.stat(packaged)
    except FileNotFoundError:
        info = None
    except OSError:
        raise TemplateError(f"packaged template {_echo(name)} could not be read") from None
    if info is not None:
        return _load_packaged_cached(str(packaged), info.st_mtime_ns, info.st_size, name)
    if not templates_dir:
        raise TemplateError(f"unknown template: {_echo(name)}")
    if not isinstance(templates_dir, str):
        raise TemplateError("report_templates_dir must be a string")
    if root is None:
        raise TemplateError("report_templates_dir needs a scan root")
    canonical = Path(root).resolve()
    configured = str(PurePosixPath(templates_dir) / f"{name}.json")
    _check_contained(canonical, templates_dir, "report_templates_dir")
    _check_contained(canonical, configured, "report template")
    candidate = canonical / configured
    if not os.path.lexists(candidate):
        raise TemplateError(f"unknown template: {_echo(name)}")
    return _finish(
        _read_gated(candidate, _echo(configured), nofollow=True),
        origin="directory",
        source=configured,
        expected_name=name,
    )


def load_template(
    source: Union[str, os.PathLike[str], Mapping[str, Any]],
    *,
    root: Optional[Path] = None,
    templates_dir: Optional[str] = None,
    from_config: bool = False,
) -> Template:
    """Load and validate a report template (Task 01 contract).

    Resolution: a :class:`~collections.abc.Mapping` is validated directly; a ``str``
    matching :data:`NAME_PATTERN` is a **name**, resolved first among the packaged
    templates and then under ``templates_dir`` (a packaged name can never be
    shadowed); any other source is a **path**. A path named in configuration
    (``from_config=True``) is root-contained and opened without following a final
    symlink; a command-line path is trusted like any argv path and gets only the
    regular-file/size/encoding gate.

    :param source: A template name, a path, or an already-decoded template mapping.
    :param root: The scan root; required for ``templates_dir`` and ``from_config``.
    :param templates_dir: The configured ``report_templates_dir`` (relative to ``root``).
    :param from_config: Whether a path ``source`` comes from configuration.
    :returns: The immutable, validated template.
    :raises TemplateError: On any resolution, read, parse or validation failure.
    """
    if isinstance(source, Mapping):
        return validate_template(dict(source))
    if isinstance(source, str) and len(source) <= _MAX_NAME and NAME_PATTERN.fullmatch(source):
        return _load_by_name(source, root, templates_dir)
    configured = os.fspath(source)
    if not isinstance(configured, str):
        raise TemplateError("a template path must be text")
    label = _echo(configured)
    if not from_config:
        return _finish(
            _read_gated(Path(configured), label, nofollow=False), origin="path", source=configured, expected_name=None
        )
    if root is None:
        raise TemplateError("a configured template path needs a scan root")
    canonical = Path(root).resolve()
    _check_contained(canonical, configured, "report template")
    return _finish(
        _read_gated(canonical / configured, label, nofollow=True), origin="path", source=configured, expected_name=None
    )


def _is_template_name(value: object) -> bool:
    """Return whether ``value`` is a template name rather than a path (M9).

    :param value: Candidate name.
    :returns: ``True`` for a string of at most 64 characters matching :data:`NAME_PATTERN`.
    """
    return isinstance(value, str) and len(value) <= _MAX_NAME and NAME_PATTERN.fullmatch(value) is not None


def load_named_template(name: str, *, root: Optional[Path] = None, templates_dir: Optional[str] = None) -> Template:
    """Load a template by name only; a path-shaped value is refused, never opened.

    Used where the caller supplies a *format name* (``render(format=...)``,
    ``docsentinel scan --format``): unlike :func:`load_template`, a value that is not
    a name is an unknown template rather than a file path to read.

    :param name: The template name (packaged first, then ``templates_dir``).
    :param root: The scan root, required for ``templates_dir``.
    :param templates_dir: The configured ``report_templates_dir``, or ``None``.
    :returns: The immutable, validated template.
    :raises TemplateError: For a non-name, an unknown name, or any load failure.
    """
    if not _is_template_name(name):
        shown = _echo(name) if isinstance(name, str) else "<not text>"
        raise TemplateError(f"unknown template: {shown}")
    return _load_by_name(name, root, templates_dir)


def packaged_template_names() -> tuple[str, ...]:
    """Return the names of the packaged templates, sorted.

    :returns: Every ``templates/<name>.json`` stem that is a valid template name.
    """
    names = (entry.stem for entry in PACKAGED_TEMPLATES_DIR.glob("*.json") if entry.is_file())
    return tuple(sorted(name for name in names if _is_template_name(name)))


def available_templates(root: Optional[Path] = None, templates_dir: Optional[str] = None) -> tuple[str, ...]:
    """Return every template name a scan can select with ``--format``, sorted.

    The packaged names are always listed. With ``templates_dir`` the directory passes
    the same containment gate as a template load (M10) and is listed without
    following symlinks; only regular ``<name>.json`` files with a valid name count,
    and a name already packaged is not repeated (packaged names cannot be shadowed).
    Files are not opened or validated here; a selected template is validated when
    loaded. At most :data:`MAX_DIRECTORY_ENTRIES` entries of any kind are visited,
    so a directory crowded with non-template files cannot make every scan walk it
    in full.

    :param root: The scan root, required for ``templates_dir``.
    :param templates_dir: The configured ``report_templates_dir``, or ``None``.
    :returns: The sorted, de-duplicated template names.
    :raises TemplateError: When ``templates_dir`` is not a string, escapes the root,
        cannot be listed, holds more than :data:`MAX_DIRECTORY_TEMPLATES` templates,
        or holds more than :data:`MAX_DIRECTORY_ENTRIES` entries.
    """
    packaged = packaged_template_names()
    if not templates_dir:
        return packaged
    if not isinstance(templates_dir, str):
        raise TemplateError("report_templates_dir must be a string")
    if root is None:
        raise TemplateError("report_templates_dir needs a scan root")
    canonical = Path(root).resolve()
    _check_contained(canonical, templates_dir, "report_templates_dir")
    found: set[str] = set()
    try:
        with os.scandir(canonical / templates_dir) as entries:
            for visited, entry in enumerate(entries, start=1):
                if visited > MAX_DIRECTORY_ENTRIES:
                    raise TemplateError(f"report_templates_dir holds more than {MAX_DIRECTORY_ENTRIES} entries")
                stem, suffix = os.path.splitext(entry.name)
                if suffix != ".json" or not _is_template_name(stem) or not entry.is_file(follow_symlinks=False):
                    continue
                found.add(stem)
                if len(found) > MAX_DIRECTORY_TEMPLATES:
                    raise TemplateError(f"report_templates_dir holds more than {MAX_DIRECTORY_TEMPLATES} templates")
    except OSError:
        raise TemplateError(f"report_templates_dir could not be listed: {_echo(templates_dir)}") from None
    return tuple(sorted(found.union(packaged)))
