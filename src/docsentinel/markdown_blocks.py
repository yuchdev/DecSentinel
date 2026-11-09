"""Shared, standard-library-only Markdown block scanner.

This module provides a single, reusable tokenizer for the narrow GFM subset
that DocSentinel's fast detectors depend on. It exists so that multiple fast
checks do not reimplement incompatible fence, heading, and inline masking.

The scanner is deterministic, runs in time proportional to the source length
for ordinary input, and performs no file, network, or subprocess I/O. It uses
only the Python standard library, regardless of which optional extras are
installed, so importing it never pulls in ``standard`` or ``deep`` dependencies.

Offsets reported by every token are **character** offsets (Python ``str``
indices) into the input text exactly as supplied, expressed as half-open
ranges ``[start_offset, end_offset)``. Line numbers are **one-based** physical
line numbers counting ``\\n``, ``\\r\\n``, and ``\\r`` terminators; a missing
final newline does not create a phantom trailing line.

See ``docs/dev/markdown_dialect.md`` for the supported dialect and the
intentional gaps (this module does not claim CommonMark or full GFM
conformance).
"""

import bisect
import enum
import html as _html
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

__all__ = [
    "MarkdownSpan",
    "Heading",
    "Fence",
    "Comment",
    "InlineCode",
    "ReferenceDefinition",
    "ReferenceUse",
    "LocalReference",
    "Image",
    "HtmlAnchor",
    "TableRow",
    "MarkdownBlockIndex",
    "ReferenceStatus",
    "ResolvedReference",
    "scan_markdown",
    "split_physical_lines",
    "slugify",
    "normalize_label",
    "resolve_local_reference",
]

_LINE_SPLIT = re.compile(r"\r\n|\r|\n")
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_ATX_RE = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_SETEXT_RE = re.compile(r"^ {0,3}(=+|-+)\s*$")
# Inline links/images (``[text](target)``, ``![alt](target)``), reference uses
# (``[text][label]``), and the HTML anchor/image attribute searches are all
# extracted by hand-rolled single-pass scanners below rather than by one regex
# per ``[`` or ``<tag`` start. A greedy ``[^\]]*``/``[^>]*?`` regex rescans the
# rest of the line from every candidate start, which is quadratic on an
# adversarial line such as ``"[" * N``; the scanners here are linear in the
# line length. The opener and attribute halves of the HTML searches are kept as
# small anchored regexes that cannot backtrack across the whole line.
_HTML_ANCHOR_OPEN_RE = re.compile(r"<a\s+", re.I)
_HTML_ANCHOR_ATTR_RE = re.compile(r'(?:id|name)=["\']([^"\']+)["\']', re.I)
# Like ``_HTML_ANCHOR_ATTR_RE`` but also captures the attribute kind so explicit
# anchor tokens can record whether the identity came from ``id`` or ``name``.
_HTML_ANCHOR_KIND_ATTR_RE = re.compile(r'(id|name)=["\']([^"\']+)["\']', re.I)
_HTML_IMG_OPEN_RE = re.compile(r"<(?:img|source)\s+", re.I)
_HTML_IMG_ATTR_RE = re.compile(r'src=["\']([^"\']+)["\']', re.I)
# ``href`` on an ``<a>`` tag and ``srcset`` on an ``<img>``/``<source>`` tag are
# live local references a renderer resolves, so DS116 must see them (the opener
# patterns above are reused). ``srcset`` is a comma-separated candidate list; the
# first whitespace-delimited token of each candidate is its URL.
_HTML_HREF_ATTR_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
_HTML_SRCSET_ATTR_RE = re.compile(r'srcset=["\']([^"\']+)["\']', re.I)
_REF_DEF_RE = re.compile(r"^ {0,3}(?:>\s?)*\[([^\]]+)\]:\s*(\S+)")
_DELIM_CELL_RE = re.compile(r"^:?-+:?$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_WINDOWS_RE = re.compile(r"^[A-Za-z]:[\\/]|^\\\\")


@dataclass(frozen=True)
class MarkdownSpan:
    """A half-open source range for a scanned token.

    :ivar path: POSIX-style relative document path the span belongs to.
    :ivar start_line: One-based line where the token starts.
    :ivar end_line: One-based line where the token ends (inclusive).
    :ivar start_offset: Inclusive character offset of the token start.
    :ivar end_offset: Exclusive character offset of the token end.
    """

    path: str
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int


@dataclass(frozen=True)
class Heading:
    """An ATX or setext heading.

    :ivar level: Heading level, 1 through 6.
    :ivar text: Raw heading text with surrounding whitespace stripped.
    :ivar slug: GitHub-style anchor slug, carrying the duplicate suffix.
    :ivar base_slug: Slug before any duplicate suffix was applied.
    :ivar style: ``"atx"`` or ``"setext"``.
    :ivar span: Source range of the heading.
    """

    level: int
    text: str
    slug: str
    base_slug: str
    style: str
    span: MarkdownSpan


@dataclass(frozen=True)
class Fence:
    """A fenced code block delimiter pair.

    :ivar marker: Fence character, ``"`"`` or ``"~"``.
    :ivar length: Number of marker characters in the opening delimiter.
    :ivar info_string: Trimmed info string following the opening delimiter.
    :ivar closed: Whether a valid closing delimiter was found.
    :ivar body_nonempty: Whether the fenced body has non-blank content.
    :ivar opener_line: One-based line of the opening delimiter.
    :ivar closer_line: One-based line of the closing delimiter, if closed.
    :ivar span: Source range covering opener through closer (or end of file).
    :ivar reason: Parser-capability reason when the fence is malformed.
    """

    marker: str
    length: int
    info_string: str
    closed: bool
    body_nonempty: bool
    opener_line: int
    closer_line: Optional[int]
    span: MarkdownSpan
    reason: Optional[str] = None


@dataclass(frozen=True)
class Comment:
    """An HTML comment found outside fenced code.

    :ivar text: Raw comment text including the delimiters.
    :ivar closed: Whether a closing ``-->`` was found.
    :ivar span: Source range of the comment.
    """

    text: str
    closed: bool
    span: MarkdownSpan


@dataclass(frozen=True)
class InlineCode:
    """An inline code span delimited by a backtick run on a single line.

    :ivar text: Content between the backtick runs.
    :ivar backticks: Number of backticks in the delimiter run.
    :ivar span: Source range of the span including delimiters.
    """

    text: str
    backticks: int
    span: MarkdownSpan


@dataclass(frozen=True)
class ReferenceDefinition:
    """A reference-style link definition (``[label]: target``).

    :ivar label: Normalized reference label.
    :ivar raw_label: Label exactly as written.
    :ivar target: Target text following the label.
    :ivar span: Source range of the definition line.
    """

    label: str
    raw_label: str
    target: str
    span: MarkdownSpan


@dataclass(frozen=True)
class ReferenceUse:
    """A reference-style link use (``[text][label]`` or ``[label][]``).

    :ivar label: Normalized reference label being used.
    :ivar raw_label: Label exactly as written (text for collapsed uses).
    :ivar span: Source range of the use.
    """

    label: str
    raw_label: str
    span: MarkdownSpan


@dataclass(frozen=True)
class LocalReference:
    """An inline link or image target.

    :ivar raw_target: Target text exactly as written.
    :ivar category: One of ``"ordinary"`` or ``"image"``; ``"nav"`` and
        ``"code_span"`` are reserved for policy detectors.
    :ivar path_component: Target with any URL fragment removed.
    :ivar fragment: URL fragment after ``#``, without the leading ``#``.
    :ivar span: Source range of the link.
    :ivar html: Whether the reference came from an HTML ``<a href>`` tag rather
        than Markdown ``[text](target)`` syntax. Purely additive (defaulted) so
        existing consumers stay byte-compatible; ``DS113`` reads it to limit its
        link-shaped asset checks to HTML ``href`` targets and leave ordinary
        Markdown links to ``DS101``.
    """

    raw_target: str
    category: str
    path_component: str
    fragment: str
    span: MarkdownSpan
    html: bool = False


@dataclass(frozen=True)
class Image:
    """A Markdown image or a basic HTML ``img``/``source`` tag.

    :ivar raw_target: Image source exactly as written.
    :ivar alt: Alt text for Markdown images; empty for HTML tags.
    :ivar html: Whether the image came from an HTML tag.
    :ivar span: Source range of the image.
    :ivar attribute: The HTML attribute the target came from -- ``"src"`` for an
        ``<img src>``/``<source src>`` tag or ``"srcset"`` for a ``srcset``
        candidate -- and ``""`` for a Markdown ``![alt](target)`` image. This is
        purely additive (defaulted) so existing consumers that read only
        :attr:`raw_target`/:attr:`html` stay byte-compatible; ``DS113`` reads it to
        honour the ``check_srcset`` toggle independently of ``check_html_asset_tags``.
    """

    raw_target: str
    alt: str
    html: bool
    span: MarkdownSpan
    attribute: str = ""


@dataclass(frozen=True)
class HtmlAnchor:
    """An explicit anchor from an HTML ``<a>`` tag outside masked regions.

    Unlike :attr:`MarkdownBlockIndex.html_anchors`, which records bare anchor
    strings from every non-fenced line (including inline code and HTML comments
    for DS101 backward compatibility), explicit-anchor tokens are extracted only
    from text that is not fenced, not inside an HTML comment, and not inside an
    inline-code span, and they carry the attribute kind, raw spelling, and a
    source position. The raw value is preserved verbatim and never lowercased,
    matching HTML ``id``/``name`` case semantics.

    :ivar attribute: The source attribute, ``"id"`` or ``"name"``.
    :ivar value: The anchor identifier exactly as written.
    :ivar line: One-based line of the ``<a>`` tag.
    :ivar span: Source range from the ``<a`` opener through the attribute value.
    """

    attribute: str
    value: str
    line: int
    span: MarkdownSpan


@dataclass(frozen=True)
class TableRow:
    """A single row of a GFM-style pipe table.

    :ivar cells: Trimmed cell contents in column order.
    :ivar is_delimiter: Whether the row is the header delimiter row.
    :ivar span: Source range of the row line.
    """

    cells: tuple[str, ...]
    is_delimiter: bool
    span: MarkdownSpan


@dataclass(frozen=True)
class MarkdownBlockIndex:
    """An immutable index of tokens scanned from one Markdown document.

    :ivar path: POSIX-style relative path of the scanned document.
    :ivar headings: Headings in source order.
    :ivar fences: Fenced code block delimiter pairs in source order.
    :ivar comments: HTML comments outside fenced code, in source order.
    :ivar inline_code: Inline code spans outside fenced code, in source order.
    :ivar reference_definitions: Reference-style link definitions.
    :ivar reference_uses: Reference-style link uses.
    :ivar local_references: Inline link and image targets.
    :ivar images: Markdown and basic HTML images.
    :ivar table_rows: Rows of detected GFM pipe tables.
    :ivar html_anchors: Explicit ``id``/``name`` anchor strings from HTML ``<a>``
        tags on every non-fenced line, including inline code and comments; kept
        for DS101 backward compatibility.
    :ivar explicit_anchors: Explicit ``<a>`` anchors with attribute kind, raw
        spelling, and source position, extracted only from non-fenced,
        non-comment, non-inline-code text.
    """

    path: str
    headings: tuple[Heading, ...] = ()
    fences: tuple[Fence, ...] = ()
    comments: tuple[Comment, ...] = ()
    inline_code: tuple[InlineCode, ...] = ()
    reference_definitions: tuple[ReferenceDefinition, ...] = ()
    reference_uses: tuple[ReferenceUse, ...] = ()
    local_references: tuple[LocalReference, ...] = ()
    images: tuple[Image, ...] = ()
    table_rows: tuple[TableRow, ...] = ()
    html_anchors: tuple[str, ...] = field(default=())
    explicit_anchors: tuple[HtmlAnchor, ...] = ()

    def anchor_names(self) -> frozenset[str]:
        """Return heading slugs and explicit HTML anchors for this document.

        This mirrors the anchor set that DS101 resolves ``#fragment`` links
        against: heading slugs (with duplicate suffixes) plus HTML ``id``/
        ``name`` anchors.

        :returns: The frozen set of resolvable in-document anchor names.
        """
        names = {heading.slug for heading in self.headings}
        names.update(self.html_anchors)
        return frozenset(names)


class ReferenceStatus(enum.Enum):
    """Outcome of resolving a local Markdown reference.

    :cvar RESOLVED: Target is a safe path inside the root (it need not exist).
    :cvar EXTERNAL: Target is a URL scheme, protocol-relative URL, or data URI.
    :cvar OUTSIDE_ROOT: Target lexically escapes the scan root.
    :cvar UNSUPPORTED: Target cannot be interpreted safely in this dialect.
    """

    RESOLVED = "resolved"
    EXTERNAL = "external"
    OUTSIDE_ROOT = "outside_root"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class ResolvedReference:
    """The tagged result of :func:`resolve_local_reference`.

    :ivar status: The :class:`ReferenceStatus` for the reference.
    :ivar path: Candidate filesystem path inside the root when
        :attr:`status` is ``RESOLVED``; ``None`` otherwise. The path is not
        guaranteed to exist and has not been opened.
    :ivar fragment: URL fragment after ``#``, without the leading ``#``.
    :ivar reason: Additive, defaulted sub-category for an ``UNSUPPORTED``
        result, letting a consumer such as ``DS116`` separate the *unsafe*
        reasons (``"drive"``, ``"unc"``, ``"backslash"``, ``"control"``) from
        the *safe* ones (``"template"``, ``"glob"``). Empty for every other
        status. This field is purely additive: it defaults to ``""`` so every
        existing three-argument construction and every ``DS101``-``DS117``
        consumer that reads only :attr:`status`/:attr:`path`/:attr:`fragment`
        stays byte-compatible.
    :ivar boundary: Additive, defaulted containment boundary for a ``RESOLVED``
        :attr:`path`: the link root for a site-root-absolute (``/``) target, the
        scan root for every other target, ``None`` for other statuses. Consumers
        pass it to the symlink-out checks of ``path_boundaries`` instead of the
        scan root. It is excluded from equality (``compare=False``), so existing
        three-argument comparisons are unchanged.
    """

    status: ReferenceStatus
    path: Optional[Path]
    fragment: str
    reason: str = ""
    boundary: Optional[Path] = field(default=None, compare=False)


def slugify(heading_text: str) -> str:
    """Return the GitHub-style anchor slug for heading text.

    This matches the slug algorithm used by DS101: lowercase, drop characters
    that are not word characters, whitespace, or hyphens, then replace runs of
    whitespace with single hyphens.

    :param heading_text: Raw heading text.
    :returns: The anchor slug.
    """
    text = heading_text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"\s", "-", text)
    return text


def normalize_label(label: str) -> str:
    """Return the normalized form of a reference label.

    Labels are NFC-normalized, stripped, internally whitespace-collapsed, and
    case-folded so that references that differ only by Unicode form or case
    match the same definition.

    :param label: Raw reference label.
    :returns: The normalized label.
    """
    normalized = unicodedata.normalize("NFC", label).strip()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.casefold()


def _iter_lines(text: str) -> list[tuple[int, str, int, int]]:
    """Split text into physical lines preserving source offsets.

    :param text: Source text exactly as read.
    :returns: A list of ``(line_number, content, start_offset, end_offset)``
        tuples, where ``content`` excludes the line terminator and the offsets
        are half-open character offsets of ``content``.
    """
    lines: list[tuple[int, str, int, int]] = []
    pos = 0
    line_number = 1
    for match in _LINE_SPLIT.finditer(text):
        lines.append((line_number, text[pos : match.start()], pos, match.start()))
        pos = match.end()
        line_number += 1
    if pos < len(text) or not text:
        lines.append((line_number, text[pos:], pos, len(text)))
    return lines


def split_physical_lines(text: str) -> list[str]:
    """Return physical line contents using the scanner's line numbering.

    Unlike :meth:`str.splitlines`, which also breaks on ``\\v``, ``\\f``,
    ``\\x1c``-``\\x1e``, ``\\x85``, ``\\u2028``, and ``\\u2029``, this splits only
    on ``\\r\\n``, ``\\r``, and ``\\n`` so that the one-based index of each
    returned line matches the ``start_line`` the scanner assigns to tokens.
    Callers that must align line ranges with scanned spans should use this
    helper rather than :meth:`str.splitlines`.

    :param text: Source text exactly as read.
    :returns: Line contents in order, each without its terminator; the
        one-based line number of a line is its list index plus one.
    """
    return [content for _, content, _, _ in _iter_lines(text)]


def backtick_runs(content: str) -> list[tuple[int, int]]:
    """Return every maximal backtick run in ``content`` as ``(start, length)``.

    The line is scanned exactly once, so collecting the runs is linear in the
    source length regardless of how the backticks are distributed.

    :param content: One line of text without its terminator.
    :returns: ``(start_offset, run_length)`` pairs in ascending start order.
    """
    runs: list[tuple[int, int]] = []
    index = 0
    length = len(content)
    while index < length:
        if content[index] != "`":
            index += 1
            continue
        end = index + 1
        while end < length and content[end] == "`":
            end += 1
        runs.append((index, end - index))
        index = end
    return runs


def backtick_runs_by_length(content: str) -> dict[int, list[int]]:
    """Return a mapping of backtick-run length to its ascending start offsets.

    This is the shared index used to close a code span in amortised constant or
    logarithmic time: the closer of an opener of length ``L`` is the first run of
    exactly length ``L`` after it, found by :func:`first_backtick_run_at_or_after`
    with :func:`bisect.bisect_left` rather than by rescanning the remainder of the
    line from every opener (which is quadratic on a line of unmatched runs of
    strictly increasing length such as ``x`x``x```x...``).

    :param content: One line of text without its terminator.
    :returns: A mapping ``{run_length: [start_offset, ...]}`` with ascending
        starts per length.
    """
    by_length: dict[int, list[int]] = {}
    for start, length in backtick_runs(content):
        by_length.setdefault(length, []).append(start)
    return by_length


def first_backtick_run_at_or_after(by_length: dict[int, list[int]], run_length: int, position: int) -> int:
    """Return the start of the first run of exactly ``run_length`` at or after ``position``.

    :param by_length: A mapping from :func:`backtick_runs_by_length`.
    :param run_length: The exact backtick-run length a closer must have.
    :param position: The lowest start offset a matching run may have.
    :returns: The matching run's start offset, or ``-1`` when none exists.
    """
    starts = by_length.get(run_length)
    if starts is None:
        return -1
    index = bisect.bisect_left(starts, position)
    if index < len(starts):
        return starts[index]
    return -1


def find_code_spans(content: str) -> list[tuple[int, int, int]]:
    """Find single-line inline code spans in amortised linear time.

    A span opens on a run of backticks and closes on the next run of the **same**
    length; runs of a different length between them are swallowed, and an opener
    with no later matching run is left unmatched. Rather than rescan the line from
    every opener, the runs are collected once and each opener's closer is located
    by a logarithmic lookup in the shared length index, so a line of unmatched
    runs of strictly increasing length stays linear instead of quadratic.

    :param content: One line of text without its terminator.
    :returns: ``(start, end, run_length)`` tuples in source order, where the span
        covers ``[start, end)`` and its backtick runs are ``run_length`` long.
    """
    runs = backtick_runs(content)
    if not runs:
        return []
    by_length: dict[int, list[int]] = {}
    for start, length in runs:
        by_length.setdefault(length, []).append(start)
    run_starts = [start for start, _ in runs]
    spans: list[tuple[int, int, int]] = []
    index = 0
    total = len(runs)
    while index < total:
        start, run = runs[index]
        close_start = first_backtick_run_at_or_after(by_length, run, start + run)
        if close_start == -1:
            index += 1
            continue
        spans.append((start, close_start + run, run))
        index = bisect.bisect_left(run_starts, close_start) + 1
    return spans


def _find_inline_code(content: str) -> list[tuple[int, int, int, str]]:
    """Find single-line inline code spans, carrying each span's inner text.

    A thin wrapper over :func:`find_code_spans` that reattaches the inner text
    ``content[start + run : end - run]`` the scanner's callers expect.

    :param content: One line of text without its terminator.
    :returns: ``(start, end, backticks, inner_text)`` tuples in order.
    """
    return [(start, end, run, content[start + run : end - run]) for start, end, run in find_code_spans(content)]


def _strip_angle_brackets(destination: str) -> str:
    """Return a link/refdef destination with a CommonMark ``<...>`` wrapper removed.

    CommonMark lets a destination be written as ``<dest>``; the angle brackets are
    delimiters, not part of the path, and a valid wrapped destination contains no
    unescaped ``<``. A string that is not a wrapped destination is returned
    unchanged, so an ordinary ``../x`` is untouched. The check is O(len) and never
    rescans, so a long destination stays linear.

    :param destination: The destination exactly as written (after the first token
        split for inline links, or the ``\\S+`` target for a reference definition).
    :returns: The inner destination when wrapped in ``<...>``, else ``destination``.
    """
    inner = destination.strip()
    if len(inner) >= 2 and inner[0] == "<" and inner[-1] == ">" and "<" not in inner[1:-1]:
        return inner[1:-1]
    return destination


def _srcset_urls(value: str) -> list[str]:
    """Return the candidate URLs of an HTML ``srcset`` attribute value.

    A ``srcset`` is a comma-separated list of candidates, each ``url [descriptor]``.
    This follows the WHATWG srcset parsing algorithm closely enough for reference
    extraction: a candidate's URL is a maximal run of **non-whitespace** characters,
    and the comma that separates two candidates is the descriptor-delimiting comma
    *after* that run, never a comma inside the URL run itself. A naive
    ``value.split(",")`` corrupts a ``data:`` URI -- ``data:image/png;base64,AAAA``
    carries an internal comma, so the split manufactures a spurious ``AAAA``
    candidate that then classifies as an in-root relative path (the HIGH srcset /
    data-URI finding in the DS113 threat model). Collecting the URL as a
    whitespace-delimited run keeps a whole ``data:`` URI as a single candidate.

    The scan is a single left-to-right pass that only ever advances its cursor, so
    a long ``srcset`` or one with many candidates stays O(len). Descriptor
    parentheses are balanced only so a comma inside a ``(...)`` descriptor does not
    split a candidate early; the descriptor text itself is discarded.

    :param value: The raw ``srcset`` attribute value.
    :returns: The candidate URLs in source order, skipping empty candidates.
    """
    urls: list[str] = []
    index = 0
    length = len(value)
    while index < length:
        while index < length and (value[index].isspace() or value[index] == ","):
            index += 1
        if index >= length:
            break
        url_start = index
        while index < length and not value[index].isspace():
            index += 1
        url = value[url_start:index]
        # A URL ending in commas is a candidate with no descriptor (WHATWG); the
        # trailing commas are the separator, not part of the path.
        if url.endswith(","):
            stripped = url.rstrip(",")
            if stripped:
                urls.append(stripped)
            continue
        if url:
            urls.append(url)
        # Skip this candidate's descriptor up to the first comma at paren depth 0.
        depth = 0
        while index < length:
            char = value[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(depth - 1, 0)
            elif char == "," and depth == 0:
                index += 1
                break
            index += 1
    return urls


def _find_inline_links(content: str) -> list[tuple[int, int, bool, str, str]]:
    """Find inline links and images with a linear single-pass scan.

    A single left-to-right pass maintains a stack of open ``[`` positions, so a
    ``]`` closes the *matching* bracket rather than the former regex's first ``]``.
    This lets link text hold a nested image or link -- ``[![alt](inner.png)](dest)``
    now yields both the inner image and the **outer** destination, which the former
    ``[^\\]]*`` text could never reach. An optional leading ``!`` makes the bracket
    an image. The pass stays linear: every character is visited once, each ``]``
    does at most one forward ``find(")")`` that advances the cursor past the match,
    and a ``"[" * N`` or ``"](" * N`` flood never rescans. The destination is still
    the first ``)`` after ``(``; a nested-parenthesis destination such as
    ``x(y)z.md`` remains a known gap (see the module dialect doc).

    :param content: One line of text without its terminator.
    :returns: ``(start, end, is_image, text, target)`` tuples in source order,
        where ``start``/``end`` are the half-open match offsets into ``content``.
    """
    results: list[tuple[int, int, bool, str, str]] = []
    length = len(content)
    stack: list[tuple[int, bool]] = []
    index = 0
    while index < length:
        char = content[index]
        if char == "[":
            is_image = index > 0 and content[index - 1] == "!"
            stack.append((index - 1 if is_image else index, is_image))
            index += 1
            continue
        if char == "]" and stack:
            start, is_image = stack.pop()
            if index + 1 < length and content[index + 1] == "(":
                paren_open = index + 1
                close_paren = content.find(")", paren_open + 1)
                if close_paren == -1:
                    # No closing paren remains, so no further link can complete.
                    break
                text_start = start + (2 if is_image else 1)
                results.append(
                    (start, close_paren + 1, is_image, content[text_start:index], content[paren_open + 1 : close_paren])
                )
                index = close_paren + 1
                continue
        index += 1
    results.sort(key=lambda match: match[0])
    return results


def _find_reference_uses(content: str) -> list[tuple[int, int, str, str]]:
    """Find reference-style link uses with a linear single-pass scan.

    This reproduces the former ``\\[([^\\]]+)\\]\\[([^\\]]*)\\]`` regex exactly
    (a non-empty first label, then a possibly empty second label) without
    rescanning from every ``[``, keeping adversarial input linear.

    :param content: One line of text without its terminator.
    :returns: ``(start, end, first_label, second_label)`` tuples in source
        order, where the offsets are half-open match offsets into ``content``.
    """
    results: list[tuple[int, int, str, str]] = []
    length = len(content)
    index = 0
    while index < length:
        if content[index] != "[":
            index += 1
            continue
        first_close = content.find("]", index + 1)
        if first_close == -1:
            break
        if first_close == index + 1:
            # Empty first label cannot satisfy ``[^\]]+``; move past this ``[``.
            index += 1
            continue
        if first_close + 1 < length and content[first_close + 1] == "[":
            second_close = content.find("]", first_close + 2)
            if second_close == -1:
                break
            results.append(
                (index, second_close + 1, content[index + 1 : first_close], content[first_close + 2 : second_close])
            )
            index = second_close + 1
        else:
            index = first_close + 1
    return results


def _find_tagged_attributes(
    content: str, open_re: re.Pattern[str], attr_re: re.Pattern[str]
) -> list[tuple[int, int, str]]:
    """Extract an HTML tag attribute value with a linear scan.

    This reproduces a ``<tag\\s+[^>]*?attr=["']([^"']+)["']`` regex without the
    lazy ``[^>]*?`` that rescans the remainder of the line from every ``<tag``
    opener. Tag openers are matched by the cheap anchored ``open_re`` and the
    attribute values are matched once by ``attr_re``; the two are joined with a
    monotonic pointer, so a line of ``"<a " * N`` stays linear. For each opener
    the earliest attribute whose match begins within the opener's tag (before
    its ``>``) is used, matching the lazy regex, and matches are non-overlapping.

    :param content: One line of text without its terminator.
    :param open_re: Anchored opener pattern such as ``<a\\s+``.
    :param attr_re: Attribute pattern with the value as group 1.
    :returns: ``(start, end, value)`` tuples in source order.
    """
    attributes = list(attr_re.finditer(content))
    if not attributes:
        return []
    results: list[tuple[int, int, str]] = []
    length = len(content)
    attr_count = len(attributes)
    attr_index = 0
    resume = 0
    # The tag closer is tracked with a single forward-only cursor rather than a
    # fresh ``find('>')`` per opener. Opener matches are non-overlapping and in
    # increasing order, so ``whitespace_end`` is monotonic; advancing the cursor
    # only forward makes the total closer search O(len(content)) instead of
    # O(openers * len(content)) on a line whose ``>`` is far away or absent.
    gt_cursor = content.find(">")
    for opener in open_re.finditer(content):
        if opener.start() < resume:
            # Consumed inside a previous (non-overlapping) match.
            continue
        whitespace_end = opener.end()
        while gt_cursor != -1 and gt_cursor < whitespace_end:
            gt_cursor = content.find(">", gt_cursor + 1)
        boundary = length if gt_cursor == -1 else gt_cursor
        while attr_index < attr_count and attributes[attr_index].start() < whitespace_end:
            attr_index += 1
        if attr_index < attr_count and attributes[attr_index].start() <= boundary:
            attribute = attributes[attr_index]
            results.append((opener.start(), attribute.end(), attribute.group(1)))
            resume = attribute.end()
    return results


def _find_html_anchor_attributes(content: str) -> list[tuple[str, str, int, int]]:
    """Extract the first ``id``/``name`` attribute of each ``<a>`` tag, with its kind.

    This mirrors the linear, non-overlapping join in :func:`_find_tagged_attributes`
    (cheap anchored openers, attribute values matched once, a monotonic pointer
    linking the two) so a line of ``"<a " * N`` or ``"<a id=" * N`` stays linear
    instead of rescanning the remainder from every opener. Attributes may appear
    in either order and either quote style; the earliest ``id``/``name`` within a
    tag wins, matching the bare :func:`_find_tagged_attributes` extraction used
    for :attr:`MarkdownBlockIndex.html_anchors`.

    :param content: One line of text without its terminator; masked regions
        (comments, inline code) should already be blanked by the caller.
    :returns: ``(attribute, value, start, end)`` tuples in source order, where
        ``attribute`` is lowercased to ``"id"`` or ``"name"``, ``value`` is the
        raw spelling, and the offsets span the opener through the attribute end.
    """
    attributes = list(_HTML_ANCHOR_KIND_ATTR_RE.finditer(content))
    if not attributes:
        return []
    results: list[tuple[str, str, int, int]] = []
    length = len(content)
    attr_count = len(attributes)
    attr_index = 0
    resume = 0
    # See :func:`_find_tagged_attributes`: the ``>`` closer is tracked with a
    # single forward-only cursor so an unterminated or far-closing tag on one
    # line stays O(len(content)) in total rather than O(openers * len(content)).
    gt_cursor = content.find(">")
    for opener in _HTML_ANCHOR_OPEN_RE.finditer(content):
        if opener.start() < resume:
            # Consumed inside a previous (non-overlapping) match.
            continue
        whitespace_end = opener.end()
        while gt_cursor != -1 and gt_cursor < whitespace_end:
            gt_cursor = content.find(">", gt_cursor + 1)
        boundary = length if gt_cursor == -1 else gt_cursor
        while attr_index < attr_count and attributes[attr_index].start() < whitespace_end:
            attr_index += 1
        if attr_index < attr_count and attributes[attr_index].start() <= boundary:
            attribute = attributes[attr_index]
            results.append((attribute.group(1).lower(), attribute.group(2), opener.start(), attribute.end()))
            resume = attribute.end()
    return results


def _mask_line(
    content: str,
    line_start: int,
    inline_spans: list[tuple[int, int, int, str]],
    comment_ranges: list[tuple[int, int]],
    comment_cursor: int,
) -> tuple[str, int]:
    """Return ``content`` with inline-code and comment columns blanked to spaces.

    Blanking preserves offsets so explicit-anchor spans computed on the masked
    line still map back to the original source. Inline-code ranges are local to
    the line; comment ranges are global character offsets intersected with this
    line's extent. When nothing overlaps, the original string is returned so the
    common case allocates nothing.

    ``comment_ranges`` is sorted by start offset and the ranges are
    non-overlapping, and ``scan_markdown`` calls this with monotonically
    increasing ``line_start``. The returned cursor is the index of the first
    comment range that may still overlap a *later* line; passing it back in on
    the next call keeps the total comment work ``O(lines + overlaps)`` instead of
    ``O(lines x comments)`` -- a comment-per-line flood is linear, not quadratic.

    :param content: One line of text without its terminator.
    :param line_start: Character offset of ``content`` in the full source.
    :param inline_spans: Inline-code spans from :func:`_find_inline_code`.
    :param comment_ranges: Global ``(start, end)`` comment offset ranges, sorted
        by start offset and non-overlapping.
    :param comment_cursor: Index of the first comment range not yet fully behind
        the current line; obtained from the previous call (``0`` for the first).
    :returns: A ``(masked_line, next_comment_cursor)`` tuple.
    """
    length = len(content)
    line_end = line_start + length
    chars: Optional[list[str]] = None
    for start, end, _, _ in inline_spans:
        if chars is None:
            chars = list(content)
        chars[start:end] = " " * (end - start)
    count = len(comment_ranges)
    # Drop comments that end at or before this line; later lines start even
    # further right, so they can never overlap again.
    while comment_cursor < count and comment_ranges[comment_cursor][1] <= line_start:
        comment_cursor += 1
    scan = comment_cursor
    while scan < count and comment_ranges[scan][0] < line_end:
        range_start, range_end = comment_ranges[scan]
        low = range_start - line_start if range_start > line_start else 0
        high = range_end - line_start if range_end < line_end else length
        if low < high:
            if chars is None:
                chars = list(content)
            chars[low:high] = " " * (high - low)
        scan += 1
    return (content if chars is None else "".join(chars)), comment_cursor


def _split_table_cells(content: str) -> tuple[str, ...]:
    """Split a pipe-table row into trimmed cells, honoring escaped pipes.

    :param content: One table row line without its terminator.
    :returns: The trimmed cells with leading and trailing border cells dropped.
    """
    cells: list[str] = []
    buffer: list[str] = []
    index = 0
    length = len(content)
    while index < length:
        char = content[index]
        if char == "\\" and index + 1 < length:
            buffer.append(content[index : index + 2])
            index += 2
            continue
        if char == "|":
            cells.append("".join(buffer))
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    cells.append("".join(buffer))
    if cells and cells[0].strip() == "":
        cells = cells[1:]
    if cells and cells[-1].strip() == "":
        cells = cells[:-1]
    return tuple(cell.strip() for cell in cells)


def _is_delimiter_row(content: str) -> bool:
    """Return whether a line is a GFM table header delimiter row.

    :param content: One line of text without its terminator.
    :returns: ``True`` for rows such as ``---|:--:|--``.
    """
    if "-" not in content or "|" not in content:
        return False
    cells = _split_table_cells(content)
    return bool(cells) and all(_DELIM_CELL_RE.match(cell) for cell in cells)


def _scan_fences(path: str, lines: list[tuple[int, str, int, int]]) -> tuple[tuple[Fence, ...], list[bool]]:
    """Scan fenced code blocks and mark fenced lines.

    Unmatched openers are reported conservatively as malformed fences that run
    to end of file so other rules never parse their swallowed body as active
    Markdown. A closing candidate that carries an info string or a shorter or
    different marker is not treated as a closer.

    :param path: POSIX-style relative document path.
    :param lines: The materialized source lines.
    :returns: A tuple of fences and a per-line boolean of whether the line is
        part of a fenced block (including its delimiters).
    """
    fences: list[Fence] = []
    fenced = [False] * len(lines)
    in_fence = False
    marker = ""
    marker_length = 0
    info_string = ""
    opener_line = 0
    opener_offset = 0
    body_nonempty = False

    for index, (line_number, content, start, end) in enumerate(lines):
        match = _FENCE_RE.match(content)
        if not in_fence:
            if match:
                in_fence = True
                marker = match.group(1)[0]
                marker_length = len(match.group(1))
                info_string = match.group(2).strip()
                opener_line = line_number
                opener_offset = start
                body_nonempty = False
                fenced[index] = True
            continue

        fenced[index] = True
        is_closer = (
            match is not None
            and match.group(1)[0] == marker
            and len(match.group(1)) >= marker_length
            and match.group(2).strip() == ""
        )
        if is_closer:
            span = MarkdownSpan(path, opener_line, line_number, opener_offset, end)
            fences.append(
                Fence(
                    marker=marker,
                    length=marker_length,
                    info_string=info_string,
                    closed=True,
                    body_nonempty=body_nonempty,
                    opener_line=opener_line,
                    closer_line=line_number,
                    span=span,
                )
            )
            in_fence = False
        elif content.strip():
            body_nonempty = True

    if in_fence:
        last_number, _, _, last_end = lines[-1]
        span = MarkdownSpan(path, opener_line, last_number, opener_offset, last_end)
        fences.append(
            Fence(
                marker=marker,
                length=marker_length,
                info_string=info_string,
                closed=False,
                body_nonempty=body_nonempty,
                opener_line=opener_line,
                closer_line=None,
                span=span,
                reason="unclosed fence: no matching closing delimiter",
            )
        )

    return tuple(fences), fenced


def _comment_mask(text: str, lines: list[tuple[int, str, int, int]], fenced: list[bool]) -> str:
    """Return ``text`` with fenced lines and inline-code spans blanked to spaces.

    Offsets are preserved (every blanked character becomes a single space), so a
    ``<!--``/``-->`` delimiter found in the result is at the same offset it has in
    ``text`` yet a delimiter that sits inside a fenced block or an inline code span
    is invisible. This mirrors CommonMark, where a code span is literal text and
    can never open or close an HTML comment, and runs in time proportional to the
    source size (:func:`_find_inline_code` is amortised linear per line).

    :param text: Source text exactly as read.
    :param lines: The materialized source lines.
    :param fenced: Per-line fenced flags from :func:`_scan_fences`.
    :returns: The masked copy of ``text``, equal in length and offsets.
    """
    masked = list(text)
    for index, (_line_number, content, start, _end) in enumerate(lines):
        if fenced[index]:
            for offset in range(start, start + len(content)):
                masked[offset] = " "
            continue
        for code_start, code_end, _backticks, _inner in _find_inline_code(content):
            for offset in range(start + code_start, start + code_end):
                masked[offset] = " "
    return "".join(masked)


def _all_occurrences(masked: str, needle: str) -> list[int]:
    """Return every start offset of ``needle`` in ``masked`` in ascending order.

    :param masked: The masked text to scan.
    :param needle: The literal substring to locate.
    :returns: Ascending start offsets; overlapping matches are all reported.
    """
    positions: list[int] = []
    found = masked.find(needle)
    while found != -1:
        positions.append(found)
        found = masked.find(needle, found + 1)
    return positions


def _scan_comments(
    path: str, text: str, lines: list[tuple[int, str, int, int]], fenced: list[bool]
) -> tuple[Comment, ...]:
    """Scan HTML comments outside fenced code and inline code spans.

    Masking follows CommonMark so the scanner only hides what a renderer hides
    (standing requirement 16 of the DS116 threat model). Fenced lines and inline
    code spans are blanked first, then each remaining ``<!--`` opener is classified:

    * A **line-start** opener (at most three spaces of indentation, nothing else
      before it) begins an HTML-block comment that runs to the first ``-->`` or, if
      none follows, to end of file (the historical behaviour, kept intact).
    * A **mid-line** opener is an inline raw-HTML comment only when a ``-->`` closes
      it **within the same paragraph** (before the next blank line); otherwise the
      literal ``<!--`` masks nothing, exactly as CommonMark renders it as text. This
      closes the detector-evasion hole where an unclosed mid-line or in-code-span
      ``<!--`` hid every later reference to end of document.

    The scan is linear: closer positions, opener positions and paragraph (blank
    line) boundaries are each precomputed once and resolved with :func:`bisect`, so
    a paragraph carrying many unclosed openers costs ``O(n log n)`` rather than the
    quadratic ``search -->`` from every opener.

    :param path: POSIX-style relative document path.
    :param text: Source text exactly as read.
    :param lines: The materialized source lines.
    :param fenced: Per-line fenced flags from :func:`_scan_fences`.
    :returns: Comments in source order, including a single trailing unclosed
        comment only when a line-start opener has no closer.
    """
    line_starts = [line[2] for line in lines]

    def line_of(offset: int) -> int:
        """Return the one-based line number for a character offset.

        :param offset: A character offset into ``text``.
        :returns: The one-based line number containing ``offset``.
        """
        return bisect.bisect_right(line_starts, offset)

    masked = _comment_mask(text, lines, fenced)
    opener_positions = _all_occurrences(masked, "<!--")
    closer_positions = _all_occurrences(masked, "-->")
    blank_line_starts = [start for _number, content, start, _end in lines if content.strip() == ""]

    comments: list[Comment] = []
    consumed_until = 0
    for open_index in opener_positions:
        if open_index < consumed_until:
            continue
        line_start = line_starts[line_of(open_index) - 1]
        # Classify the opener as a line-start HTML block (<=3 spaces of indent,
        # nothing else before it) in O(1): never slice the whole prefix, which on a
        # single huge line of many comments would be O(len) per comment and so
        # quadratic overall. At most three leading characters are inspected.
        indent = open_index - line_start
        is_block = indent <= 3 and all(text[line_start + offset] == " " for offset in range(indent))

        if is_block:
            bound = len(text)
        else:
            blank_index = bisect.bisect_right(blank_line_starts, open_index)
            bound = blank_line_starts[blank_index] if blank_index < len(blank_line_starts) else len(text)

        closer_index = bisect.bisect_left(closer_positions, open_index + 4)
        close_index = closer_positions[closer_index] if closer_index < len(closer_positions) else -1

        if close_index == -1 or close_index >= bound:
            if is_block:
                span = MarkdownSpan(path, line_of(open_index), line_of(len(text) - 1), open_index, len(text))
                comments.append(Comment(text=text[open_index:], closed=False, span=span))
                break
            continue

        end_index = close_index + 3
        span = MarkdownSpan(path, line_of(open_index), line_of(end_index - 1), open_index, end_index)
        comments.append(Comment(text=text[open_index:end_index], closed=True, span=span))
        consumed_until = end_index
    return comments


def _slug_with_suffix(text: str, seen: dict[str, int]) -> tuple[str, str]:
    """Return the duplicate-suffixed slug for a heading, updating ``seen``.

    This reproduces DS101's duplicate-anchor behavior: the first occurrence of
    a base slug is used verbatim and later occurrences gain a ``-N`` suffix.

    :param text: Raw heading text.
    :param seen: Mutable map of base slug to prior occurrence count.
    :returns: A ``(slug, base_slug)`` tuple.
    """
    base = slugify(text)
    count = seen.get(base, 0)
    slug = base if count == 0 else f"{base}-{count}"
    seen[base] = count + 1
    return slug, base


def scan_markdown(text: str, path: str = "") -> MarkdownBlockIndex:
    """Scan Markdown text into an immutable token index.

    The scan is single-origin and deterministic: every token carries character
    offsets and one-based line numbers into ``text`` exactly as supplied, and
    no file, network, or subprocess I/O occurs.

    :param text: The Markdown source text.
    :param path: POSIX-style relative path recorded in token spans.
    :returns: The :class:`MarkdownBlockIndex` for the document.
    """
    lines = _iter_lines(text)
    fences, fenced = _scan_fences(path, lines)
    # Comments are scanned up front so their character ranges can mask explicit
    # anchor extraction on every line they cover, including multi-line comments.
    comments = _scan_comments(path, text, lines, fenced)
    comment_ranges = [(comment.span.start_offset, comment.span.end_offset) for comment in comments]

    headings: list[Heading] = []
    inline_code: list[InlineCode] = []
    reference_definitions: list[ReferenceDefinition] = []
    reference_uses: list[ReferenceUse] = []
    local_references: list[LocalReference] = []
    images: list[Image] = []
    html_anchors: list[str] = []
    explicit_anchors: list[HtmlAnchor] = []
    seen_slugs: dict[str, int] = {}
    previous_paragraph: Optional[tuple[int, str, int, int]] = None
    comment_cursor = 0

    for index, (line_number, content, start, end) in enumerate(lines):
        if fenced[index]:
            previous_paragraph = None
            continue

        inline_spans = _find_inline_code(content)
        html_anchors.extend(
            value for _, _, value in _find_tagged_attributes(content, _HTML_ANCHOR_OPEN_RE, _HTML_ANCHOR_ATTR_RE)
        )
        masked, comment_cursor = _mask_line(content, start, inline_spans, comment_ranges, comment_cursor)
        for attribute, value, anchor_start, anchor_end in _find_html_anchor_attributes(masked):
            span = MarkdownSpan(path, line_number, line_number, start + anchor_start, start + anchor_end)
            explicit_anchors.append(HtmlAnchor(attribute=attribute, value=value, line=line_number, span=span))
        for tag_start, tag_end, value in _find_tagged_attributes(content, _HTML_IMG_OPEN_RE, _HTML_IMG_ATTR_RE):
            span = MarkdownSpan(path, line_number, line_number, start + tag_start, start + tag_end)
            images.append(Image(raw_target=value, alt="", html=True, span=span, attribute="src"))
        for tag_start, tag_end, value in _find_tagged_attributes(content, _HTML_IMG_OPEN_RE, _HTML_SRCSET_ATTR_RE):
            span = MarkdownSpan(path, line_number, line_number, start + tag_start, start + tag_end)
            for candidate_url in _srcset_urls(value):
                images.append(Image(raw_target=candidate_url, alt="", html=True, span=span, attribute="srcset"))
        for tag_start, tag_end, value in _find_tagged_attributes(content, _HTML_ANCHOR_OPEN_RE, _HTML_HREF_ATTR_RE):
            href = _strip_angle_brackets(value)
            href_path, _, href_fragment = href.partition("#")
            span = MarkdownSpan(path, line_number, line_number, start + tag_start, start + tag_end)
            local_references.append(
                LocalReference(
                    raw_target=href,
                    category="ordinary",
                    path_component=href_path,
                    fragment=href_fragment,
                    span=span,
                    html=True,
                )
            )

        atx_match = _ATX_RE.match(content)
        setext_match = _SETEXT_RE.match(content)

        if atx_match:
            text_value = atx_match.group(2)
            slug, base = _slug_with_suffix(text_value, seen_slugs)
            span = MarkdownSpan(path, line_number, line_number, start, end)
            headings.append(
                Heading(
                    level=len(atx_match.group(1)),
                    text=text_value,
                    slug=slug,
                    base_slug=base,
                    style="atx",
                    span=span,
                )
            )
            previous_paragraph = None
        elif setext_match and previous_paragraph is not None:
            prev_number, prev_content, prev_start, _ = previous_paragraph
            text_value = prev_content.strip()
            slug, base = _slug_with_suffix(text_value, seen_slugs)
            span = MarkdownSpan(path, prev_number, line_number, prev_start, end)
            headings.append(
                Heading(
                    level=1 if setext_match.group(1)[0] == "=" else 2,
                    text=text_value,
                    slug=slug,
                    base_slug=base,
                    style="setext",
                    span=span,
                )
            )
            previous_paragraph = None
        elif content.strip() == "" or setext_match:
            previous_paragraph = None
        else:
            previous_paragraph = (line_number, content, start, end)

        for code_start, code_end, backticks, inner in inline_spans:
            span = MarkdownSpan(path, line_number, line_number, start + code_start, start + code_end)
            inline_code.append(InlineCode(text=inner, backticks=backticks, span=span))

        definition = _REF_DEF_RE.match(content)
        if definition:
            span = MarkdownSpan(path, line_number, line_number, start, end)
            reference_definitions.append(
                ReferenceDefinition(
                    label=normalize_label(definition.group(1)),
                    raw_label=definition.group(1),
                    target=_strip_angle_brackets(definition.group(2)),
                    span=span,
                )
            )
        else:
            for link_start, link_end, is_image, link_text, raw_destination in _find_inline_links(content):
                raw_target = _strip_angle_brackets(raw_destination)
                path_component, _, fragment = raw_target.partition("#")
                span = MarkdownSpan(path, line_number, line_number, start + link_start, start + link_end)
                if is_image:
                    images.append(Image(raw_target=raw_target, alt=link_text, html=False, span=span))
                    category = "image"
                else:
                    category = "ordinary"
                local_references.append(
                    LocalReference(
                        raw_target=raw_target,
                        category=category,
                        path_component=path_component,
                        fragment=fragment,
                        span=span,
                    )
                )
            for use_start, use_end, first_label, second_label in _find_reference_uses(content):
                raw_label = second_label if second_label else first_label
                span = MarkdownSpan(path, line_number, line_number, start + use_start, start + use_end)
                reference_uses.append(ReferenceUse(label=normalize_label(raw_label), raw_label=raw_label, span=span))

    table_rows = _scan_tables(path, lines, fenced)

    return MarkdownBlockIndex(
        path=path,
        headings=tuple(headings),
        fences=fences,
        comments=comments,
        inline_code=tuple(inline_code),
        reference_definitions=tuple(reference_definitions),
        reference_uses=tuple(reference_uses),
        local_references=tuple(local_references),
        images=tuple(images),
        table_rows=table_rows,
        html_anchors=tuple(html_anchors),
        explicit_anchors=tuple(explicit_anchors),
    )


def _scan_tables(path: str, lines: list[tuple[int, str, int, int]], fenced: list[bool]) -> tuple[TableRow, ...]:
    """Scan GFM-style pipe tables over non-fenced lines.

    A table starts at a header line that contains a pipe and is immediately
    followed by a delimiter row, and continues through consecutive pipe rows.

    :param path: POSIX-style relative document path.
    :param lines: The materialized source lines.
    :param fenced: Per-line fenced flags from :func:`_scan_fences`.
    :returns: Table rows in source order.
    """
    rows: list[TableRow] = []
    index = 0
    count = len(lines)
    while index < count:
        line_number, content, start, end = lines[index]
        if (
            not fenced[index]
            and "|" in content
            and not _is_delimiter_row(content)
            and index + 1 < count
            and not fenced[index + 1]
            and _is_delimiter_row(lines[index + 1][1])
        ):
            rows.append(
                TableRow(
                    cells=_split_table_cells(content),
                    is_delimiter=False,
                    span=MarkdownSpan(path, line_number, line_number, start, end),
                )
            )
            delim_number, delim_content, delim_start, delim_end = lines[index + 1]
            rows.append(
                TableRow(
                    cells=_split_table_cells(delim_content),
                    is_delimiter=True,
                    span=MarkdownSpan(path, delim_number, delim_number, delim_start, delim_end),
                )
            )
            index += 2
            while index < count and not fenced[index] and "|" in lines[index][1] and lines[index][1].strip():
                body_number, body_content, body_start, body_end = lines[index]
                rows.append(
                    TableRow(
                        cells=_split_table_cells(body_content),
                        is_delimiter=False,
                        span=MarkdownSpan(path, body_number, body_number, body_start, body_end),
                    )
                )
                index += 1
            continue
        index += 1
    return tuple(rows)


def _normalize_relative(relative: str) -> Optional[tuple[str, ...]]:
    """Lexically normalize a POSIX relative path, detecting root escapes.

    :param relative: A ``/``-separated relative path.
    :returns: The normalized path parts, or ``None`` if the path escapes above
        its base using ``..``.
    """
    parts: list[str] = []
    for part in relative.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return tuple(parts)


def resolve_local_reference(
    root: Path, document_path: str, raw_target: str, *, link_root: Optional[Path] = None
) -> ResolvedReference:
    """Resolve a Markdown reference target against a scan root.

    This resolver is lexical only: it never opens a target, follows a symlink,
    or touches the filesystem, so it is safe to run during tokenization and on
    untrusted document content. A missing path is still ``RESOLVED`` (existence
    is another rule's concern); only a lexical ``..`` escape is ``OUTSIDE_ROOT``.
    Symlink-based escapes require filesystem checks and are intentionally out of
    scope here.

    To match what a CommonMark renderer resolves, the target is first unwrapped of
    a ``<...>`` angle-bracket destination, then HTML entities and numeric character
    references are decoded once (``html.unescape``), then percent-encoding is
    decoded once (``unquote``). Both decodes are linear and run exactly once, so
    ``&amp;`` stays an in-root literal while ``&#46;&#46;/`` and ``..%2f..%2f``
    classify as the escapes a renderer would make live; ``%252e%252e`` stays
    literal (no double-decode).

    A site-root-absolute target (a leading ``/``) is joined onto ``link_root``
    rather than onto the scan root, and its ``..`` normalisation is bounded by
    ``link_root``: ``/../x`` past the link root is ``OUTSIDE_ROOT``, while ``/src/x``
    inside the link root is ``RESOLVED`` even when it lies outside the scan root.
    Relative targets always resolve against the referring document inside ``root``.

    :param root: The resolved scan root directory.
    :param document_path: POSIX-style relative path of the referring document.
    :param raw_target: The link target exactly as written.
    :param link_root: Base for ``/`` targets, the scan root or an ancestor of it
        (see :func:`docsentinel.link_root.resolve_link_root`); ``None`` uses
        ``root``, the historical behaviour, as configured-path callers must.
    :returns: A tagged :class:`ResolvedReference`.
    """
    # Decode HTML entities once, up front, exactly as a renderer does, so a numeric
    # character reference such as ``&#46;`` (whose ``#`` would otherwise be mistaken
    # for a fragment delimiter) and a named one such as ``&period;`` both collapse to
    # their real characters before the fragment is split off. ``html.unescape`` is
    # linear and runs exactly once.
    target = _html.unescape(_strip_angle_brackets(raw_target).strip())
    path_part, _, fragment = target.partition("#")

    if path_part == "":
        if target.startswith("#"):
            return ResolvedReference(ReferenceStatus.RESOLVED, root / document_path, fragment, boundary=root)
        return ResolvedReference(ReferenceStatus.UNSUPPORTED, None, fragment)

    # Decode percent-encoding once more, so encoded and literal forms classify
    # identically and ``..%2f..%2f`` cannot slip past as an in-root literal. The lone
    # ``unquote`` never double-decodes, so ``%252e%252e`` stays literal.
    decoded = unquote(path_part)

    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in decoded):
        return ResolvedReference(ReferenceStatus.UNSUPPORTED, None, fragment, reason="control")

    if _WINDOWS_RE.match(decoded):
        return ResolvedReference(
            ReferenceStatus.UNSUPPORTED, None, fragment, reason="unc" if decoded.startswith("\\\\") else "drive"
        )
    if "\\" in decoded:
        return ResolvedReference(ReferenceStatus.UNSUPPORTED, None, fragment, reason="backslash")

    if decoded.startswith("//") or _SCHEME_RE.match(decoded):
        return ResolvedReference(ReferenceStatus.EXTERNAL, None, fragment)

    if "{" in decoded or "}" in decoded:
        return ResolvedReference(ReferenceStatus.UNSUPPORTED, None, fragment, reason="template")
    if "*" in decoded or "?" in decoded:
        return ResolvedReference(ReferenceStatus.UNSUPPORTED, None, fragment, reason="glob")

    if decoded.startswith("/"):
        # Site-root-absolute: joined onto (and bounded by) the link root.
        base = link_root if link_root is not None else root
        combined = decoded.lstrip("/")
    else:
        base = root
        document_dir = str(Path(document_path).parent).replace("\\", "/")
        combined = decoded if document_dir in ("", ".") else f"{document_dir}/{decoded}"

    parts = _normalize_relative(combined)
    if parts is None:
        return ResolvedReference(ReferenceStatus.OUTSIDE_ROOT, None, fragment)
    return ResolvedReference(ReferenceStatus.RESOLVED, base.joinpath(*parts), fragment, boundary=base)
