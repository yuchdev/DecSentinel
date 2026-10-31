"""Text and machine-readable representations of a scan.

A finding's ``path`` and ``message`` -- and a document's ``path`` -- originate in
scanned repository content (file names and detector-echoed source excerpts), which
is untrusted input. The text and GitHub-annotation sinks write those strings to a
terminal, a CI log, or the GitHub Actions workflow-command stream, so any raw
control byte they carry (an ANSI escape, a line feed forging a second log line, a
bidirectional override reordering displayed text) would reach the reader verbatim.
:func:`_neutralize_controls` replaces those code points with a visible backslash
escape before either human-facing sink renders them; the JSON sink is already safe
because :func:`json.dumps` defaults to ``ensure_ascii=True`` and escapes every
control and non-ASCII code point. Neutralisation is a *rendering* concern only:
baseline fingerprints (see :mod:`docsentinel.baseline`) hash the raw
:class:`~docsentinel.models.Finding` fields, never this escaped output, so they are
unaffected. Ordinary Unicode letters are left intact and ASCII-printable input is
byte-identical after translation.
"""

import json
from dataclasses import asdict

from docsentinel.models import ScanResult
from docsentinel.telemetry.filters import neutralize as _neutralize
from docsentinel.telemetry.model import ADVISORY_BANNER  # re-exported for existing callers


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
    names, which would otherwise make the output un-encodable). Ordinary Unicode letters, digits and punctuation are not in the table and
    pass through unchanged, so ASCII-printable input is byte-identical.

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


def neutralize_text(value: str) -> str:
    """Return ``value`` with unsafe control, format and surrogate code points escaped.

    Public entry point for output paths outside the report renderers (for example the
    command-line error lines), so untrusted text such as a scanned path inside an
    exception message never reaches a terminal or log with raw control bytes.
    Delegates to :func:`docsentinel.telemetry.filters.neutralize`, the moved copy of
    :func:`_neutralize_controls` (Story 02.0 Task 02); the local original stays for
    :func:`render` until the Story 03.0 cut-over deletes it.

    :param value: Text that may embed untrusted path or content characters.
    :returns: The text with every unsafe code point rendered as a visible escape.
    """
    return _neutralize(value)


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


def _gha_level(severity: str) -> str:
    """Map finding severity to a GitHub Actions workflow command level."""
    if severity == "error":
        return "error"
    return "warning"


def _render_github(result: ScanResult) -> str:
    """Render scan findings as GitHub Actions workflow command annotations."""
    lines: list[str] = []
    for finding in result.findings:
        level = _gha_level(finding.severity)
        escaped_file = _escape_property(finding.path)
        location = f"file={escaped_file},line={finding.line}" if finding.line is not None else f"file={escaped_file}"
        escaped_message = _escape_data(finding.message)
        lines.append(f"::{level} {location}::{escaped_message}")
    return "\n".join(lines)


#: ``ScanResult`` fields added after JSON schema v1 (Milestone 0007); the v1 JSON
#: sink drops them so its output stays byte-identical. They reach reports through
#: :class:`~docsentinel.telemetry.model.ReportModel` instead.
_V1_EXCLUDED_RESULT_KEYS: tuple[str, ...] = ("rules_evaluated", "opt_in_off")
#: ``Finding`` enrichment fields added after JSON schema v1, dropped likewise.
_V1_EXCLUDED_FINDING_KEYS: tuple[str, ...] = ("column", "value", "type")


def _schema_v1_dict(result: ScanResult) -> dict[str, object]:
    """Return ``asdict(result)`` restricted to the JSON schema v1 keys.

    :param result: Completed scan to serialize.
    :returns: The v1 mapping, without any post-v1 ``ScanResult``/``Finding`` field.
    """
    data = asdict(result)
    for key in _V1_EXCLUDED_RESULT_KEYS:
        data.pop(key, None)
    for finding in data["findings"]:
        for key in _V1_EXCLUDED_FINDING_KEYS:
            finding.pop(key, None)
    return data


def render(result: ScanResult, format: str = "text") -> str:
    """Render a scan result into text, JSON, or GitHub annotation output format.

    Parameters
    ----------
    result : ScanResult
        Completed scan to render.
    format : str
        One of ``text``, ``json`` or ``github``.

    Returns
    -------
    str
        The rendered report.

    Raises
    ------
    ValueError
        If ``format`` is not a supported output format.
    """
    if format == "json":
        data = _schema_v1_dict(result)
        if result.profile == "deep" and result.findings:
            data["advisory"] = ADVISORY_BANNER
        return json.dumps(data, indent=2)
    if format == "github":
        return _render_github(result)
    if format != "text":
        raise ValueError(f"Unsupported format: {format}")
    lines = [
        f"Schema version: {result.schema_version}",
        f"Profile: {result.profile}",
        f"Documents: {len(result.documents)}",
        "Enabled rules: " + json.dumps(result.enabled_rules),
        result.notice,
    ]
    if result.profile == "deep" and result.findings:
        lines.append(ADVISORY_BANNER)
    lines.extend(f"  {_neutralize_controls(document.path)} ({document.bytes} bytes)" for document in result.documents)
    lines.extend(f"Pending: {reason}" for reason in result.pending)
    lines.extend(
        f"{finding.severity}: {_neutralize_controls(finding.path)}: {_neutralize_controls(finding.message)}"
        for finding in result.findings
    )
    return "\n".join(lines)
