"""Detect declared documentation navigation integrity problems (``DS112``).

This fast, standard-library-only analyzer reports contract violations inside a
small set of **user-configured navigation index** Markdown documents. When
``navigation_indexes`` names one or more indexes, ``DS112`` extracts the local
links that constitute declared navigation (the links on *navigation list items*)
and reports three things, all **inside the scan root only**:

* a ``navigation_required`` document that no navigation link points at;
* a navigation target linked more than once (``navigation_unique_targets``); and
* a navigation link whose local destination does not exist
  (``navigation_check_missing``).

A missing, unreadable, non-regular, out-of-root, or non-discovered configured
index is a **config/readiness error** (:class:`~docsentinel.config.ConfigError`),
never a silent clean result and never a :class:`~docsentinel.models.Finding`.

**"Appear exactly once" is two orthogonal checks, not one.** Story 09.0's README
summarises the contract as "required targets appear exactly once ... and duplicates
are reported once each at the later link". ``DS112`` realises that phrasing as the
*union* of two independent sub-checks rather than a single coupled rule, which is
the shape the config options and the Task 02 fixtures require:

* **presence** -- ``navigation_required`` reports a required document that no
  navigation link points at (``missing_required_nav_item``); it does not care how
  many times a listed target appears; and
* **uniqueness** -- ``navigation_unique_targets`` (default **on**) reports a
  navigation target linked more than once, once at the *later* link
  (``duplicate_navigation_target``, ``duplicate_with_fragments``).

Because ``navigation_unique_targets`` defaults on, a required target listed twice is
still reported once (as a duplicate), so the observable "exactly once" behaviour
holds under the shipped defaults; the two concerns stay separately toggleable. No
fixture requires a required target to be flagged *specifically for being required
and duplicated*, so the decomposition satisfies the matrix with no coupled
"required-appears-twice" check.

It reuses the shared, purely lexical resolver
:func:`docsentinel.markdown_blocks.resolve_local_reference` and the shared Markdown
scanner; it adds no second path resolver and runs no regex over unmasked source.

Security contract (see
``docs/security/threat-model-ds112-navigation-integrity-2026-10-23.md`` and the
DS116/DS113 precedents). Unlike DS113/DS116, ``DS112`` is driven by
**attacker-controlled configuration** as well as content: in CI/pre-commit a PR
author chooses which files ``navigation_indexes`` opens. The DS116/DS113 floor
applies unchanged and the following DS112-specific controls are added:

* **Config-injection containment (R2).** An index is opened **only** when it is a
  member of the engine-supplied ``documents`` (discovery has already proven it is
  an in-root, non-symlink, regular, include-matched ``.md`` file). Because an
  injected :class:`~docsentinel.config.Config` bypasses ``load_config``
  validation, the open is also defended lexically with
  :func:`~docsentinel.detectors.path_boundaries.is_ds116_owned`, by resolver
  containment, by :func:`~docsentinel.detectors.path_boundaries.escapes_via_symlink`,
  and by ``os.stat`` + :func:`stat.S_ISREG`; the read is bounded to
  :data:`_MAX_INDEX_BYTES`. A FIFO/device/socket/directory/symlink-out/outside/
  non-``.md`` configured index is never opened.
* **No filesystem access outside the root (R4/R6).** Every navigation target is
  routed through :func:`resolve_local_reference` and
  :func:`~docsentinel.detectors.path_boundaries.is_ds116_owned` first. A target
  that escapes lexically (``OUTSIDE_ROOT`` / DS116-owned) is reported **purely
  lexically with zero filesystem access** as an escape finding (R4; an intentional
  overlap with DS116, which reports it at ``error``). The missing-destination
  probe (R6) is ``os.stat`` only (never ``open``), run only on a ``RESOLVED``,
  in-root, non-``is_ds116_owned``, non-symlink-escaping target, one ``stat`` per
  distinct resolved path (memoised).
* **Fail-closed readiness error (R3).** A missing/unreadable/non-regular/out-of-root
  /non-discovered configured index raises :class:`~docsentinel.config.ConfigError`,
  which the engine propagates to CLI exit ``2`` (``Scan failed: ...``) and to a
  raised exception for the Python API / pytest. It is never a warning-severity
  finding and never a silent skip; no new exit code and no JSON schema v1 change.
* **Bounded, repr-escaped echo.** Every finding message and every readiness
  ``ConfigError`` echo only the author's raw target or the configured index path,
  bounded to :data:`_MAX_ECHO` characters and ``unicode_escape``-escaped, so no
  control byte, ``ESC`` sequence, or non-ASCII byte reaches the report sinks or
  the ``Scan failed:`` line; the resolved absolute path is never echoed.
* **Linear cost.** Navigation targets are resolved once per link (O(links)); the
  ``navigation_required`` check is set membership over the union of resolved
  targets (O(links + required), never O(required x links)); duplicate detection is
  a per-index set; the list-marker scan is a single bounded linear pass over the
  masked text with no catastrophic regex; the index read is bounded; and the
  missing-destination ``stat`` is memoised.

Rulings recorded (threat model R1-R8):

* **R1 -- navigation scope.** The shared scanner does not model lists, so ``DS112``
  derives navigation-list membership itself, line-by-line **over the scanner's
  masked text** (fenced code, inline code, and HTML comments blanked), with a
  bounded linear marker test (``-``/``*``/``+`` or ordered ``N.``/``N)`` with 0-3
  spaces of indentation), exactly as DS108 derives its reference view and DS117 its
  table rows over masked text. Only inline links and full/collapsed reference uses
  whose start line is a navigation list item are navigation; prose links outside
  lists and links inside fenced/inline-code/comment regions are not. No regex over
  unmasked source.
* **R2 -- index read discipline and membership** (above). A configured index that
  exists but is excluded by ``include``/``exclude`` is absent from ``documents`` and
  is therefore the R3 readiness error (an internally inconsistent configuration),
  not a silent skip.
* **R3 -- readiness error surface** (above).
* **R4 -- escaping nav target** (above): a DS112 finding emitted lexically, with
  the documented intentional DS116 overlap.
* **R5 -- target identity / normalization.** Navigation links and
  ``navigation_required`` entries are compared as canonical **root-anchored,
  fragment-stripped** paths produced by :func:`resolve_local_reference` (reusing its
  single entity+percent decode and ``<...>`` unwrap). Navigation links resolve
  relative to the **index location**, not the process cwd; duplicate identity
  ignores the fragment. String comparison is exact (case-sensitive); the existence
  probe's case behaviour is the host filesystem's and is documented.
* **R6 -- missing-destination discipline** (above). This overlaps DS101's
  dangling-link check by design; ``DS112`` does not depend on DS107 and does its own
  normalized resolution.
* **R7 -- reference-style vs shortcut nav items.** Full ``[text][label]`` and
  collapsed ``[label][]`` navigation items are resolved by joining
  ``reference_uses`` to ``reference_definitions`` by normalized label. **Shortcut**
  ``[label]`` navigation items are a documented shared-scanner gap (the scanner does
  not populate ``reference_uses`` for shortcuts) and are an accepted ``DS112`` false
  negative, not patched with an ad-hoc regex.
* **R8 -- opt-in accounting.** The opt-in gate is ``navigation_indexes`` only;
  ``navigation_check_missing``/``navigation_unique_targets``/``navigation_required``
  are sub-options, not part of the gate, so ``DS112`` is genuinely evaluated whenever
  indexes are configured even if the sub-checks are off. Empty ``navigation_indexes``
  makes ``DS112`` not-applicable and it is named (not counted) in the engine notice,
  mirroring DS110.

**DS112 is a best-effort structural guard, not a complete navigation-integrity
control.** It inherits every shared-scanner false negative (multi-line and
nested-parenthesis destinations, multi-line HTML tags, unquoted attributes,
shortcut references; see ``docs/dev/markdown_dialect.md``) plus the self-derived
list-membership heuristic (list items indented beyond three spaces, and list items
nested inside block quotes or indented code, are not recognised) and the
platform-dependent case behaviour of the existence probe.

``DS112`` is registered as an import side effect of this module (Story 09.0
Task 02): the :class:`~docsentinel.rules.Rule` is passed through ``register_rule``
and :func:`detect` is wired into ``ANALYZERS`` at the end of the module, exactly as
DS108/DS110/DS113 were sequenced, so the Milestone 0005 fixture catalog enforces
every committed ``tests/assets/ds112/*`` scenario. Because the opt-in gate is
``navigation_indexes`` (empty by default), the rule is inert on an unconfigured
repo and is honestly reported as not-applicable in the engine notice.
"""

from __future__ import annotations

import os
import re
import stat
from bisect import bisect_right
from pathlib import Path
from typing import Optional

from docsentinel import models, rules
from docsentinel.config import Config, ConfigError
from docsentinel.detectors.path_boundaries import escapes_via_symlink, is_ds116_owned
from docsentinel.link_root import link_root_for
from docsentinel.markdown_blocks import (
    MarkdownBlockIndex,
    ReferenceStatus,
    resolve_local_reference,
    scan_markdown,
    split_physical_lines,
)

#: Stable metadata for ``DS112``, registered as a ``fast``-profile opt-in policy
#: rule alongside its committed ``tests/assets/ds112/*`` fixtures (Story 09.0
#: Task 02). The ``opt_in_option`` names the config list that switches the policy
#: on, exactly as ``DS110`` uses ``require_fence_languages``; with
#: ``navigation_indexes`` empty the rule is inert, the engine notice names it, and
#: it is not counted among the evaluated rules.
DS112 = rules.register_rule(
    rules.Rule(
        code="DS112",
        profile="fast",
        title="Declared documentation navigation integrity",
        description=(
            "A configured navigation index omits a required target, links a target more than once, "
            "or points at a missing or escaping local destination."
        ),
        severity="warning",
        opt_in_option="navigation_indexes",
    )
)

#: Maximum characters of an author's raw target or a configured index path echoed
#: into a finding or readiness-error message.
_MAX_ECHO = 80

#: Upper bound on characters read from a configured navigation index. A discovered
#: regular ``.md`` file is only size-``stat``-ed by discovery, never opened, so a
#: multi-gigabyte in-root file configured as an index must not be read whole; the
#: read is bounded here. An index larger than this is truncated (a best-effort
#: limitation), never blocking the scan or exhausting memory.
_MAX_INDEX_BYTES = 5_000_000

#: A navigation list item: a bullet (``-``/``*``/``+``) or ordered (``N.``/``N)``)
#: marker with 0-3 spaces of indentation, requiring whitespace or end-of-line after
#: the marker (CommonMark requires a space after a list marker). The ordinal is
#: bounded to nine digits so the single linear pass carries no catastrophic regex.
_LIST_MARKER_RE = re.compile(r"^ {0,3}(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)")

#: Fixed diagnostic text per violation kind; the bounded, escaped target or path is
#: appended by the caller.
_ESCAPE_TEXT = "navigation target escapes the documentation root"
_DUPLICATE_TEXT = "navigation target is linked more than once"
_MISSING_TEXT = "navigation target does not exist"
_REQUIRED_TEXT = "required navigation target is not listed in the configured navigation"


def _echo(raw_value: str) -> str:
    """Return a bounded, repr-escaped echo of an author-controlled string.

    The value is bounded to :data:`_MAX_ECHO` characters, then escaped with
    ``unicode_escape`` so control bytes, ``ESC`` sequences, and non-ASCII bytes
    render as printable ``\\xNN``/``\\uNNNN`` forms before the string reaches any
    report sink or the ``Scan failed:`` line, mirroring the bounded echo used by
    ``DS116``/``DS113``. The resolved absolute path is never echoed.

    :param raw_value: The raw target or configured index path exactly as written.
    :returns: The bounded, escaped echo with a trailing ``...`` when truncated.
    """
    bounded = raw_value[:_MAX_ECHO]
    escaped = bounded.encode("unicode_escape").decode("ascii")
    return f"{escaped}..." if len(raw_value) > _MAX_ECHO else escaped


def _finding(path: str, message: str, line: Optional[int]) -> models.Finding:
    """Return a ``DS112`` finding at a navigation index location.

    :param path: POSIX-style relative path of the configured index.
    :param message: Smallest meaningful diagnostic message.
    :param line: One-based source line, or ``None`` when no span represents it
        (for an unlisted required target).
    :returns: A :class:`~docsentinel.models.Finding` at ``DS112`` severity.
    """
    return models.Finding(rule=DS112.code, path=path, message=message, severity=DS112.severity, line=line)


def _masked_lines(text: str, index: MarkdownBlockIndex) -> list[str]:
    """Return physical lines with fenced, comment, and inline-code spans blanked.

    Every character inside a fenced code block, an HTML comment, or an inline-code
    span is replaced with a space while line terminators are preserved, so the
    returned lines keep their original one-based numbering yet no list marker inside
    a region a CommonMark renderer hides is recognised as navigation (R1). Each span
    is visited once, so the mask is built in time proportional to the source length.

    :param text: The Markdown source text exactly as read.
    :param index: The scanned block index supplying fence, comment, and inline-code
        spans.
    :returns: The masked physical lines, where line ``n`` is index ``n - 1``.
    """
    masked = list(text)
    total = len(masked)

    def blank(start: int, end: int):
        """Blank a half-open offset range to spaces, keeping line terminators.

        :param start: Inclusive start offset.
        :param end: Exclusive end offset.
        """
        for position in range(start, min(end, total)):
            character = masked[position]
            if character != "\n" and character != "\r":
                masked[position] = " "

    for fence in index.fences:
        blank(fence.span.start_offset, fence.span.end_offset)
    for comment in index.comments:
        blank(comment.span.start_offset, comment.span.end_offset)
    for code in index.inline_code:
        blank(code.span.start_offset, code.span.end_offset)
    return split_physical_lines("".join(masked))


def _navigation_list_lines(text: str, index: MarkdownBlockIndex) -> frozenset[int]:
    """Return the one-based line numbers that are navigation list items.

    A line is a navigation list item when its **masked** content matches
    :data:`_LIST_MARKER_RE`; the mask ensures a marker inside a fence, inline code,
    or an HTML comment never counts (R1). This is a single linear pass.

    :param text: The Markdown source text exactly as read.
    :param index: The scanned block index.
    :returns: The set of navigation list-item line numbers.
    """
    masked = _masked_lines(text, index)
    return frozenset(number for number, content in enumerate(masked, start=1) if _LIST_MARKER_RE.match(content))


def _masked_offset_ranges(index: MarkdownBlockIndex) -> tuple[list[int], list[int]]:
    """Return disjoint, sorted offset ranges a CommonMark renderer hides.

    The shared scanner emits link and reference tokens from the raw line even when
    they sit inside an inline-code span or an HTML comment (it only skips *fenced*
    lines), so a link such as ``- `[x](y.md)``` would otherwise be treated as
    navigation. DS112 therefore drops any token whose start offset falls inside an
    inline-code span, an HTML comment, or a fenced block, masking only what the
    renderer hides (R1), exactly as DS113 does. The ranges are coalesced once so a
    membership test is a single :func:`bisect_right`.

    :param index: The scanned block index.
    :returns: A ``(starts, ends)`` pair of aligned, ascending, disjoint ranges.
    """
    raw: list[tuple[int, int]] = []
    for fence in index.fences:
        raw.append((fence.span.start_offset, fence.span.end_offset))
    for comment in index.comments:
        raw.append((comment.span.start_offset, comment.span.end_offset))
    for code in index.inline_code:
        raw.append((code.span.start_offset, code.span.end_offset))
    raw.sort()
    starts: list[int] = []
    ends: list[int] = []
    for start, end in raw:
        if starts and start <= ends[-1]:
            ends[-1] = max(ends[-1], end)
        else:
            starts.append(start)
            ends.append(end)
    return starts, ends


def _offset_masked(starts: list[int], ends: list[int], offset: int) -> bool:
    """Return whether a source offset falls inside any masked (hidden) range.

    :param starts: Ascending, disjoint range start offsets.
    :param ends: Range end offsets aligned with ``starts``.
    :param offset: The candidate token's start offset.
    :returns: ``True`` when the offset is inside a hidden range.
    """
    position = bisect_right(starts, offset) - 1
    return position >= 0 and offset < ends[position]


def _navigation_links(index: MarkdownBlockIndex, list_lines: frozenset[int]) -> list[tuple[int, int, str]]:
    """Return the navigation link targets drawn from navigation list items.

    Navigation comes from two shared-scanner token sources, each restricted to a
    navigation list line and to text a CommonMark renderer makes live: inline/HTML
    ``ordinary`` link targets (``index.local_references`` excluding images, which are
    DS113's concern), and full/collapsed reference uses (``index.reference_uses``)
    joined to their definitions (``index.reference_definitions``) by normalized label.
    A token whose start offset lies inside an inline-code span, an HTML comment, or a
    fence is dropped (R1). Shortcut references never reach ``reference_uses`` (a
    documented scanner gap, R7) and are not navigation here.

    :param index: The scanned block index.
    :param list_lines: The navigation list-item line numbers from
        :func:`_navigation_list_lines`.
    :returns: ``(start_offset, start_line, raw_target)`` tuples in no particular
        order; the caller sorts them into source order.
    """
    starts, ends = _masked_offset_ranges(index)
    links: list[tuple[int, int, str]] = []
    for reference in index.local_references:
        if reference.category == "image":
            continue
        if reference.span.start_line in list_lines and not _offset_masked(starts, ends, reference.span.start_offset):
            links.append((reference.span.start_offset, reference.span.start_line, reference.raw_target))

    definitions: dict[str, str] = {}
    for definition in index.reference_definitions:
        definitions.setdefault(definition.label, definition.target)
    for use in index.reference_uses:
        if use.span.start_line not in list_lines:
            continue
        if _offset_masked(starts, ends, use.span.start_offset):
            continue
        target = definitions.get(use.label)
        if target is not None:
            links.append((use.span.start_offset, use.span.start_line, target))
    return links


def _resolved_identity(path: Path, root: Path) -> str:
    """Return the canonical root-anchored POSIX identity of a resolved path.

    A ``RESOLVED`` candidate is always built as ``root`` joined with its normalized
    parts, so it is contained in ``root``; the identity is its fragment-stripped,
    root-relative POSIX form, the key used for the required and duplicate checks (R5).

    :param path: The resolver's ``RESOLVED`` in-root candidate path.
    :param root: The canonical scan root.
    :returns: The root-relative POSIX identity (for example ``docs/guide.md``).
    """
    return os.path.relpath(os.fspath(path), os.fspath(root)).replace(os.sep, "/")


def _destination_missing(candidate: Path, cache: dict[str, bool]) -> bool:
    """Return whether a resolved in-root navigation destination does not exist.

    The candidate is already lexically confirmed in-root and confirmed not to escape
    through a symlink by the caller, so the single following ``os.stat`` stays inside
    the root (R6). Existence is decided with ``os.stat`` only -- content is never
    opened -- so a FIFO/device/socket resolves without blocking. At most one ``stat``
    runs per distinct resolved path (memoised in ``cache``).

    :param candidate: The resolved in-root candidate path.
    :param cache: Per-scan memo mapping a resolved path string to its missing flag.
    :returns: ``True`` when the destination does not exist (or is inaccessible).
    """
    key = os.path.normpath(os.fspath(candidate))
    if key in cache:
        return cache[key]
    try:
        os.stat(candidate)
    except OSError:
        # A nonexistent or inaccessible in-root destination both read as missing;
        # os.stat never opens content, so this cannot block on a special file.
        missing = True
    else:
        missing = False
    cache[key] = missing
    return missing


def _analyze_index(
    text: str,
    index_path: str,
    root: Path,
    settings: Config,
    stat_cache: dict[str, bool],
    link_root: Optional[Path] = None,
) -> tuple[list[models.Finding], set[str]]:
    """Analyze one navigation index, returning its findings and resolved identities.

    This is the shared core behind :func:`check_text` and :func:`detect`. It derives
    navigation list membership over the masked text (R1), then for each navigation
    link reports an escape (R4), a duplicate target (``navigation_unique_targets``),
    and a missing destination (``navigation_check_missing``, R6), collecting the
    canonical identity (R5) of every in-root navigation target for the caller's
    ``navigation_required`` aggregation.

    :param text: The index document's Markdown text.
    :param index_path: POSIX-style relative path of the index, used as the resolver
        base so navigation links resolve relative to the index location (R5).
    :param root: The canonical scan root.
    :param settings: Effective configuration supplying the sub-check toggles.
    :param stat_cache: Memo for the missing-destination probe, shared across indexes.
    :param link_root: Base and containment boundary for ``/`` navigation targets;
        ``None`` uses ``root``. A ``/`` target inside the link root but outside the
        scan root is a legitimate repository link, not an escape.
    :returns: ``(findings, identities)`` where ``identities`` is the set of resolved
        root-relative navigation target identities in this index.
    """
    index = scan_markdown(text, index_path)
    list_lines = _navigation_list_lines(text, index)

    findings: list[models.Finding] = []
    identities: set[str] = set()
    seen_identity: set[str] = set()
    seen_key: set[tuple[Optional[int], str]] = set()

    def record(line: Optional[int], message: str):
        """Append a finding, collapsing a duplicate ``(line, message)`` pair.

        :param line: One-based source line, or ``None``.
        :param message: The finding message.
        """
        key = (line, message)
        if key in seen_key:
            return
        seen_key.add(key)
        findings.append(_finding(index_path, message, line))

    for _offset, line, raw_target in sorted(_navigation_links(index, list_lines)):
        target = raw_target.strip()
        if not target or target.startswith("#"):
            # An empty target or a fragment-only link to the same document is not an
            # extra navigation document target.
            continue
        if is_ds116_owned(root, index_path, target, link_root=link_root):
            # Lexical root escape or unsafe category: reported with zero filesystem
            # access (R4); DS116 independently reports it at error severity.
            record(line, f"{_ESCAPE_TEXT}: {_echo(target)}")
            continue
        reference = resolve_local_reference(root, index_path, target, link_root=link_root)
        if reference.status is ReferenceStatus.OUTSIDE_ROOT:
            record(line, f"{_ESCAPE_TEXT}: {_echo(target)}")
            continue
        if reference.status is not ReferenceStatus.RESOLVED or reference.path is None:
            # EXTERNAL (URL/data URI/protocol-relative) links are permitted but not a
            # local target; safe UNSUPPORTED (template/glob) is not navigation either.
            continue
        identity = _resolved_identity(reference.path, root)
        is_duplicate = identity in seen_identity
        seen_identity.add(identity)
        identities.add(identity)
        if settings.navigation_unique_targets and is_duplicate:
            record(line, f"{_DUPLICATE_TEXT}: {_echo(target)}")
        # An in-root symlink pointing outside the root is DS116's concern and is
        # never stat-ed; otherwise probe existence with a single memoised os.stat.
        if (
            settings.navigation_check_missing
            and not escapes_via_symlink(reference.boundary if reference.boundary is not None else root, reference.path)
            and _destination_missing(reference.path, stat_cache)
        ):
            record(line, f"{_MISSING_TEXT}: {_echo(target)}")

    return findings, identities


def check_text(text: str, index_path: str, root: Path, config: Optional[Config] = None) -> tuple[models.Finding, ...]:
    """Return the per-index ``DS112`` findings for one navigation index's ``text``.

    This is the pure recognition entry point used by unit tests with inline source
    strings; :func:`detect` layers the engine-supplied document membership, the
    readiness error, and the cross-index ``navigation_required`` aggregation over it.
    It reports the escape (R4), duplicate (``navigation_unique_targets``), and
    missing-destination (``navigation_check_missing``, R6) violations found within
    this single index; the ``navigation_required`` contract spans every configured
    index and so belongs to :func:`detect`.

    :param text: The index document's Markdown text exactly as read.
    :param index_path: POSIX-style relative path recorded on each finding and used as
        the resolver base (navigation links resolve relative to the index location).
    :param root: The canonical scan root used for containment and the existence probe.
    :param config: Effective settings, or ``None`` for defaults.
    :returns: Findings in source order, one per offending navigation link.
    :raises ConfigError: When ``link_root`` is invalid for this scan root.
    """
    settings = config if config is not None else Config()
    findings, _identities = _analyze_index(text, index_path, root, settings, {}, link_root_for(root, settings))
    return tuple(findings)


def _read_index(path: Path) -> str:
    """Read bounded UTF-8 text from a navigation index path.

    At most :data:`_MAX_INDEX_BYTES` characters are read so a huge in-root regular
    file configured as an index can never exhaust memory; a larger index is
    truncated (a documented best-effort limitation). The file has already been proven
    a regular in-root file by the caller before this open.

    :param path: Absolute path to the configured index document.
    :returns: The decoded index text, bounded to :data:`_MAX_INDEX_BYTES` characters.
    """
    with path.open(encoding="utf-8") as stream:
        return stream.read(_MAX_INDEX_BYTES)


def _require_readable_index(root: Path, index_path: str, document_identities: frozenset[str]):
    """Validate a configured index is a safe, discovered in-root regular ``.md`` file.

    A configured index is read only when it is a member of the discovered documents
    (R2); because an injected :class:`~docsentinel.config.Config` bypasses
    ``load_config`` validation, the membership check is backed by lexical containment
    (:func:`is_ds116_owned` and resolver containment), a non-following symlink check
    (:func:`escapes_via_symlink`), and ``os.stat`` + :func:`stat.S_ISREG`. Any failure
    raises :class:`~docsentinel.config.ConfigError` (R3); the message echoes only the
    bounded, repr-escaped configured path, never a resolved absolute path.

    :param root: The canonical scan root.
    :param index_path: The configured index path exactly as written in the config.
    :param document_identities: Canonical identities of every discovered document.
    :raises ConfigError: When the index is out-of-root, not discovered, not a regular
        file, or unreadable.
    """
    if is_ds116_owned(root, ".", index_path):
        raise ConfigError(f"configured navigation index escapes the documentation root: {_echo(index_path)}")
    reference = resolve_local_reference(root, ".", index_path)
    if reference.status is not ReferenceStatus.RESOLVED or reference.path is None:
        raise ConfigError(f"configured navigation index escapes the documentation root: {_echo(index_path)}")
    if _resolved_identity(reference.path, root) not in document_identities:
        raise ConfigError(f"configured navigation index is not a scanned document: {_echo(index_path)}")
    candidate = root / index_path
    if escapes_via_symlink(root, candidate):
        raise ConfigError(f"configured navigation index escapes the documentation root: {_echo(index_path)}")
    try:
        info = os.stat(candidate)
    except OSError as exc:
        # Unreadable or absent in-root index: fail closed rather than scan nothing.
        raise ConfigError(f"configured navigation index could not be read: {_echo(index_path)}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigError(f"configured navigation index is not a regular file: {_echo(index_path)}")


def _required_identity(root: Path, required: str) -> Optional[str]:
    """Return the canonical identity of a ``navigation_required`` entry, or ``None``.

    Required entries are root-relative; they are normalized to the same
    root-anchored, fragment-stripped identity space as navigation links (R5) so
    ``./guide.md`` and ``guide.md`` compare equal. A required entry that does not
    resolve inside the root (only reachable through an injected ``Config``) yields
    ``None`` and can never be satisfied, so it is reported as unlisted.

    :param root: The canonical scan root.
    :param required: A ``navigation_required`` entry exactly as configured.
    :returns: The root-relative POSIX identity, or ``None`` when it does not resolve.
    """
    reference = resolve_local_reference(root, ".", required)
    if reference.status is not ReferenceStatus.RESOLVED or reference.path is None:
        return None
    return _resolved_identity(reference.path, root)


def detect(
    root: Path,
    documents: tuple[models.Document, ...],
    config: Optional[Config] = None,
    *,
    link_root: Optional[Path] = None,
) -> tuple[models.Finding, ...]:
    """Return ``DS112`` findings across the configured navigation indexes.

    The opt-in gate is ``navigation_indexes`` only (R8): with it empty the policy is
    not applicable and no findings are produced (the engine notice names ``DS112``).
    The trusted scan root is canonicalised exactly once here with the single
    permitted :func:`os.path.realpath`; the current working directory never enters
    resolution. Each configured index is validated and read defensively (R2/R3),
    analyzed (R1/R4/R5/R6), then the ``navigation_required`` contract is checked as
    set membership over the union of resolved navigation target identities
    (O(links + required), never O(required x links)).

    :param root: The scan root directory (trusted).
    :param documents: Discovered documents, in scan order; the membership gate for
        which configured indexes may be opened.
    :param config: Effective settings; the engine passes this, and direct callers
        may omit it to use defaults.
    :param link_root: The engine-validated base for ``/`` targets; ``None`` falls back
        to :func:`~docsentinel.link_root.link_root_for`, which accepts only values
        meaning the scan root.
    :returns: Findings across every configured index, with the unlisted-required
        findings last.
    :raises ConfigError: When ``link_root`` is invalid for this scan root, or when a
        configured index is missing, unreadable, non-regular,
        out-of-root, or not a discovered document.
    """
    settings = config if config is not None else Config()
    if not settings.navigation_indexes:
        return ()
    canonical = Path(os.path.realpath(root))
    base = link_root if link_root is not None else link_root_for(canonical, settings)

    document_identities = frozenset(
        _resolved_identity(reference.path, canonical)
        for reference in (resolve_local_reference(canonical, ".", document.path) for document in documents)
        if reference.status is ReferenceStatus.RESOLVED and reference.path is not None
    )

    findings: list[models.Finding] = []
    identities: set[str] = set()
    stat_cache: dict[str, bool] = {}
    for index_path in settings.navigation_indexes:
        _require_readable_index(canonical, index_path, document_identities)
        try:
            text = _read_index(canonical / index_path)
        except (OSError, UnicodeDecodeError) as exc:
            # A non-UTF-8 or mid-read-failing index must fail closed with the documented readiness error.
            raise ConfigError(f"configured navigation index could not be read: {_echo(index_path)}") from exc
        index_findings, index_identities = _analyze_index(text, index_path, canonical, settings, stat_cache, base)
        findings.extend(index_findings)
        identities.update(index_identities)

    if settings.navigation_required:
        primary = settings.navigation_indexes[0]
        for required in settings.navigation_required:
            identity = _required_identity(canonical, required)
            if identity is None or identity not in identities:
                findings.append(_finding(primary, f"{_REQUIRED_TEXT}: {_echo(required)}", None))

    return tuple(findings)


rules.ANALYZERS[DS112.code] = detect
