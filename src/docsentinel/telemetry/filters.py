"""Closed filter table of the report template language (spec §7, Story 02.0 Task 02).

This is the lowest layer of the template engine: it imports only the standard
library, so :mod:`docsentinel.reporting`, :mod:`docsentinel.telemetry.loader` and
:mod:`docsentinel.telemetry.engine` can all depend on it without an import cycle.

It holds:

* the control/bidi/zero-width/separator/surrogate neutralization tables, moved
  verbatim from :mod:`docsentinel.reporting` (``_build_control_table``,
  ``_neutralize_controls``, ``_escape_property``, ``_escape_data``) and exposed as
  :func:`neutralize`, :func:`gha_property` and :func:`gha_data`. The originals in
  ``reporting.py`` stay until Story 03.0 deletes them; parity tests pin both to the
  same output. ``reporting.neutralize_text`` is this module's :func:`neutralize`;
* :class:`TemplateError`, defined here because its message is neutralized on
  construction and this module must not import the loader (the loader re-exports
  it, so ``loader.TemplateError`` is the same class);
* :func:`apply_filter`, the runtime side of the loader's load-time signature table
  :data:`docsentinel.telemetry.loader.FILTERS`. :data:`FILTER_NAMES` must equal that
  table's keys (a test pins the parity).

Every filter is pure and total over JSON-shaped values: a value of the wrong kind
raises :class:`TemplateError`, never a bare ``TypeError``, and no filter performs
I/O, reads the environment or the clock.

Accepted residual risk (threat model T11): :func:`neutralize` does not escape ``\\``,
so text that literally contains ``\\x1b`` renders like a neutralized ESC. It spoofs
the display but injects nothing, and the move keeps that behaviour byte-identical.
"""

import json
import math
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, Final

#: Upper bound on a :class:`TemplateError` message after neutralization.
MAX_MESSAGE: Final[int] = 512

JsonValue = Any


def _escaped(code_point: int) -> str:
    """Return a visible backslash escape for a single code point.

    :param code_point: The Unicode code point to render.
    :returns: ``\\xHH`` for a byte-range code point, ``\\uHHHH`` for the basic
        multilingual plane, otherwise ``\\UHHHHHHHH`` -- all ASCII-printable.
    """
    if code_point <= 0xFF:
        return f"\\x{code_point:02x}"
    if code_point <= 0xFFFF:
        return f"\\u{code_point:04x}"
    return f"\\U{code_point:08x}"


def _build_control_table(*, keep_crlf: bool) -> dict[int, str]:
    """Build a :meth:`str.translate` table neutralising unsafe control code points.

    The neutralised set is: the C0 controls ``U+0000``-``U+001F`` (NUL, BEL, TAB,
    the ESC that starts an ANSI sequence, and CR/LF that could forge a log line),
    DEL (``U+007F``), the C1 controls ``U+0080``-``U+009F``, the bidirectional
    formatting controls (``U+061C``, ``U+200E``-``U+200F``, ``U+202A``-``U+202E``,
    ``U+2066``-``U+2069``) that enable Trojan-Source display reordering, and the
    zero-width format characters (``U+200B``-``U+200D``, ``U+FEFF``) that can hide
    text, the line and paragraph separators ``U+2028``/``U+2029``, and lone surrogates
    (``U+D800``-``U+DFFF``, produced by ``surrogateescape`` for undecodable POSIX
    names, which would otherwise make the output un-encodable). Ordinary Unicode
    letters, digits and punctuation are not in the table and pass through unchanged,
    so ASCII-printable input is byte-identical.

    :param keep_crlf: When ``True``, omit CR and LF from the table so the caller's
        GitHub property/data escaper can keep encoding them as ``%0D``/``%0A``;
        the text sink passes ``False`` so CR/LF are neutralised like any control.
    :returns: A mapping from code point to its backslash-escaped replacement.
    """
    code_points: set[int] = set(range(0x00, 0x20)) | {0x7F} | set(range(0x80, 0xA0))
    code_points |= {0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF}
    code_points |= set(range(0x202A, 0x202F))  # LRE RLE PDF LRO RLO
    code_points |= {0x2066, 0x2067, 0x2068, 0x2069}  # LRI RLI FSI PDI
    code_points |= {0x2028, 0x2029}  # LINE SEPARATOR, PARAGRAPH SEPARATOR
    code_points |= set(range(0xD800, 0xE000))  # lone surrogates (surrogateescape of undecodable names)
    if keep_crlf:
        code_points -= {0x0D, 0x0A}
    return {code_point: _escaped(code_point) for code_point in code_points}


#: Full table used by the human-readable text sink (CR/LF neutralised too).
_TEXT_CONTROL_TABLE: dict[int, str] = _build_control_table(keep_crlf=False)
#: Table used by the GitHub sink, which keeps CR/LF for its own ``%0D``/``%0A``
#: percent escaping; every other control/format code point is still neutralised.
_GITHUB_CONTROL_TABLE: dict[int, str] = _build_control_table(keep_crlf=True)


def _neutralize_controls(value: str, *, keep_crlf: bool = False) -> str:
    """Replace unsafe control and bidi/zero-width format code points with escapes.

    :param value: An untrusted path or message string from scanned content.
    :param keep_crlf: Pass ``True`` from the GitHub sink so CR/LF survive for its
        ``%0D``/``%0A`` property/data escaping; the text sink uses ``False``.
    :returns: ``value`` with every neutralised code point rendered as a visible
        ASCII backslash escape; ASCII-printable input is returned byte-identical.
    """
    return value.translate(_GITHUB_CONTROL_TABLE if keep_crlf else _TEXT_CONTROL_TABLE)


def _escape_property(value: str) -> str:
    """Escape a GitHub Actions workflow command property value.

    Control and bidi/zero-width code points are neutralised first (CR/LF excepted,
    as this function percent-encodes them next), then the GitHub property delimiters
    ``%``, CR, LF, ``:`` and ``,`` are percent-encoded per the runner contract.
    """
    neutral = _neutralize_controls(value, keep_crlf=True)
    return neutral.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _escape_data(value: str) -> str:
    """Escape a GitHub Actions workflow command message.

    Control and bidi/zero-width code points are neutralised first (CR/LF excepted),
    then ``%``, CR and LF are percent-encoded per the runner contract.
    """
    neutral = _neutralize_controls(value, keep_crlf=True)
    return neutral.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


class TemplateError(Exception):
    """An unreadable, oversized, unparseable, invalid or unrenderable report template (spec §10).

    The message is neutralized and bounded on construction, so ``str()`` of the
    error is safe to print by any caller, not only the CLI (M16).
    """

    def __init__(self, message: str):
        """Initialise the error with a neutralized, bounded message.

        :param message: The diagnostic; hostile fragments must already be echoed.
        """
        safe = _neutralize_controls(message)
        if len(safe) > MAX_MESSAGE:
            safe = safe[: MAX_MESSAGE - 3] + "..."
        super().__init__(safe)


def _require_text(value: object, name: str) -> str:
    """Return ``value`` when it is a ``str``.

    :param value: The filter input.
    :param name: The filter name for the error.
    :returns: The string.
    :raises TemplateError: When ``value`` is not a string.
    """
    if not isinstance(value, str):
        raise TemplateError(f"filter {name} needs a string, got {_kind_name(value)}")
    return value


def neutralize(value: str) -> str:
    """Return ``value`` with unsafe control, format and surrogate code points escaped.

    The text sink filter (spec §7), and the public ``reporting.neutralize_text``:
    C0/C1/DEL, CR/LF, bidi controls, zero-width characters, line/paragraph
    separators and lone surrogates become visible ASCII backslash escapes.

    :param value: Text that may embed untrusted path or content characters.
    :returns: The text with every unsafe code point rendered as a visible escape.
    :raises TemplateError: When ``value`` is not a string.
    """
    return _neutralize_controls(_require_text(value, "neutralize"))


def gha_property(value: str) -> str:
    """Escape a GitHub Actions workflow command property value (spec §7).

    :param value: The raw property text.
    :returns: ``neutralize`` (CR/LF kept), then ``%``, CR, LF, ``:`` and ``,``
        percent-encoded.
    :raises TemplateError: When ``value`` is not a string.
    """
    return _escape_property(_require_text(value, "gha_property"))


def gha_data(value: str) -> str:
    """Escape a GitHub Actions workflow command message (spec §7).

    :param value: The raw message text.
    :returns: ``neutralize`` (CR/LF kept), then ``%``, CR and LF percent-encoded.
    :raises TemplateError: When ``value`` is not a string.
    """
    return _escape_data(_require_text(value, "gha_data"))


# --------------------------------------------------------------------------- template filters


def _kind_name(value: object) -> str:
    """Return a short, data-free name for a value's kind (never its content).

    :param value: Any value.
    :returns: ``list``, ``object``, ``string``, ``number``, ``boolean``, ``null`` or
        ``non-JSON value``.
    """
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if value is None:
        return "null"
    return "non-JSON value"


def is_scalar(value: object) -> bool:
    """Return whether ``value`` is a JSON scalar (``str``/``int``/finite ``float``/``bool``/``None``).

    :param value: Any value.
    :returns: ``True`` for a JSON scalar.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return True
    return type(value) is float and math.isfinite(value)


def to_text(value: JsonValue) -> str:
    """Render a JSON scalar as emitted text.

    Strings are returned unchanged; every other scalar uses its JSON spelling
    (``null``, ``true``/``false``, decimal numbers), so a ``None`` is visible as
    ``null`` rather than silently empty.

    :param value: A JSON scalar.
    :returns: Its text.
    :raises TemplateError: When ``value`` is a container or not JSON data.
    """
    if isinstance(value, str):
        return value
    if not is_scalar(value):
        raise TemplateError(f"a {_kind_name(value)} cannot be emitted as text; reduce it with join, len or json")
    return json.dumps(value)


def _scalar_text(value: JsonValue, name: str) -> str:
    """Return the text of a scalar filter input.

    :param value: The filter input.
    :param name: The filter name for the error.
    :returns: Its text.
    :raises TemplateError: When ``value`` is not a JSON scalar.
    """
    if not is_scalar(value):
        raise TemplateError(f"filter {name} needs a scalar, got {_kind_name(value)}")
    return to_text(value)


def _filter_neutralize(value: JsonValue) -> str:
    """``neutralize`` filter: scalar text with unsafe code points escaped."""
    return neutralize(_scalar_text(value, "neutralize"))


def _filter_gha_property(value: JsonValue) -> str:
    """``gha_property`` filter: scalar text escaped for a workflow command property."""
    return gha_property(_scalar_text(value, "gha_property"))


def _filter_gha_data(value: JsonValue) -> str:
    """``gha_data`` filter: scalar text escaped for a workflow command message."""
    return gha_data(_scalar_text(value, "gha_data"))


def _filter_json(value: JsonValue) -> str:
    """``json`` filter: ASCII-safe ``json.dumps`` of any JSON value.

    :raises TemplateError: When the value is not serializable JSON data.
    """
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise TemplateError(f"filter json cannot serialize a {_kind_name(value)}") from None


def _filter_join(value: JsonValue, separator: str) -> str:
    """``join(sep)`` filter: a list of scalars joined by ``separator``.

    :raises TemplateError: When the value is not a list of scalars.
    """
    if not isinstance(value, list):
        raise TemplateError(f"filter join needs a list, got {_kind_name(value)}")
    if not all(is_scalar(item) for item in value):
        raise TemplateError("filter join needs a list of scalars")
    return separator.join(to_text(item) for item in value)


def _filter_len(value: JsonValue) -> int:
    """``len`` filter: length of a list, object or string.

    :raises TemplateError: For a number, boolean or null.
    """
    if not isinstance(value, (list, dict, str)):
        raise TemplateError(f"filter len needs a list, object or string, got {_kind_name(value)}")
    return len(value)


def _filter_lower(value: JsonValue) -> str:
    """``lower`` filter: lower-cased scalar text."""
    return _scalar_text(value, "lower").lower()


def _filter_upper(value: JsonValue) -> str:
    """``upper`` filter: upper-cased scalar text."""
    return _scalar_text(value, "upper").upper()


def _filter_default(value: JsonValue, fallback: str) -> JsonValue:
    """``default(x)`` filter: ``fallback`` when the value is null, else the value.

    :raises TemplateError: When the value is not a scalar.
    """
    if not is_scalar(value):
        raise TemplateError(f"filter default needs a scalar, got {_kind_name(value)}")
    return fallback if value is None else value


#: Runtime filter functions, keyed like :data:`docsentinel.telemetry.loader.FILTERS`.
_FUNCTIONS: Final[Mapping[str, Callable[..., JsonValue]]] = MappingProxyType(
    {
        "neutralize": _filter_neutralize,
        "gha_property": _filter_gha_property,
        "gha_data": _filter_gha_data,
        "json": _filter_json,
        "join": _filter_join,
        "len": _filter_len,
        "lower": _filter_lower,
        "upper": _filter_upper,
        "default": _filter_default,
    }
)

#: The closed set of filter names implemented at render time (spec §7).
FILTER_NAMES: Final[frozenset[str]] = frozenset(_FUNCTIONS)


def apply_filter(name: str, value: JsonValue, args: tuple[str, ...] = ()) -> JsonValue:
    """Apply one filter from the closed table.

    :param name: The filter name; must be in :data:`FILTER_NAMES`.
    :param value: The JSON-shaped input.
    :param args: The literal string arguments the loader parsed.
    :returns: The filter result (a ``str``, or an ``int`` for ``len``, or the
        unchanged scalar for ``default``).
    :raises TemplateError: For an unknown filter, a wrong argument count, or an input
        of the wrong kind.
    """
    function = _FUNCTIONS.get(name)
    if function is None:
        raise TemplateError("unknown filter")
    expected = 1 if name in ("join", "default") else 0
    if len(args) != expected or not all(isinstance(arg, str) for arg in args):
        raise TemplateError(f"filter {name} takes {expected} string argument(s)")
    return function(value, *args)
