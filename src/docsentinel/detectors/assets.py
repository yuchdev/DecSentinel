"""Detect missing local media and document assets (``DS113``).

This fast, standard-library-only analyzer reports local **asset** references whose
target does not exist, is not a regular file, or cannot be used as an asset,
**inside the scan root only**. It resolves Markdown images (``![alt](target)``),
HTML ``<img src>``/``<source src>`` tags and ``<source srcset>``/``<img srcset>``
candidates, HTML ``<a href>`` link targets, and reference-style image/link
definitions to local paths, then checks existence and regular-file status with
``os.stat``/``stat.S_ISREG`` -- it **never opens or reads asset content**.

It reuses the shared, purely lexical resolver
:func:`docsentinel.markdown_blocks.resolve_local_reference` and the shared Markdown
scanner; it adds no second path resolver and runs no regex over unmasked source.

Security contract (see
``docs/security/threat-model-ds113-missing-assets-2026-10-23.md`` and the DS116
precedent). The DS116 standing requirements apply as a floor and are not relaxed:

* **No filesystem access outside the root (R2).** Before any filesystem call a
  target is routed through :func:`~docsentinel.detectors.path_boundaries.is_ds116_owned`
  and the shared resolver; the analyzer acts **only** on a ``RESOLVED`` in-root
  candidate, and then only when
  :func:`~docsentinel.detectors.path_boundaries.escapes_via_symlink` is false on it.
  ``EXTERNAL`` targets (URL schemes, protocol-relative ``//host``, ``data:`` URIs),
  safe ``UNSUPPORTED`` targets (``template``, ``glob``), fragment-only targets, and
  every DS116-owned unsafe category (``OUTSIDE_ROOT``, ``drive``, ``unc``,
  ``backslash``, ``control``) or in-root-symlink-out candidate are skipped with
  **no** ``stat``. An escaped or symlink-out missing asset is DS116's finding, never
  DS113's.
* **Never open or read content (special-files, R3).** Existence and file type are
  decided with ``os.stat`` + :func:`stat.S_ISREG` only -- never ``open``, ``read``,
  ``imghdr``, or any content sniff. A committed FIFO, device, socket, or directory
  at an asset path is reported as a non-regular-file finding **without** being
  opened, so it can neither block the scan nor read unbounded data. An in-root
  symlink whose (lexically in-root) target is a regular file is a **valid** asset;
  a symlink whose target escapes the root is DS116's, not a DS113 "missing" finding.
* **``srcset`` / ``data:`` URI splitting (fixed).** The shared
  :func:`docsentinel.markdown_blocks._srcset_urls` now collects each candidate URL as
  a whitespace-delimited run, so a ``data:`` URI's internal comma can never
  manufacture a spurious in-root filesystem probe.
* **Bounded, repr-escaped echo.** A finding message echoes only the author's raw
  target, bounded to :data:`_MAX_ECHO` characters and ``unicode_escape``-escaped so
  no control byte, ``ESC`` sequence, or non-ASCII byte reaches the report sinks; the
  resolved absolute path and the specific non-regular file *type* are never
  disclosed (only "missing" / "not a regular file").
* **Linear cost.** Resolution and classification reuse the shared scanner and are
  O(total bytes); at most **one** ``stat`` is performed per distinct resolved
  in-root path (memoised within a document), duplicate ``(line, message)`` findings
  are collapsed, and the containment gate runs before any ``stat`` so escaped floods
  cost no I/O.

Rulings recorded (threat model R1-R5):

* **R1** -- a reference *definition's* target is checked only when its decoded
  extension is in ``asset_extensions`` **and** the definition is actually used
  (its normalized label appears among the reference uses), so DS113 neither steps
  on DS101's link territory nor flags an unused definition (DS108's concern).
* **R2** -- DS116-owned and escaped references are never ``stat``-ed (above).
* **R3** -- an in-root symlink to an in-root regular file is valid; an existing
  non-regular in-root path (directory, FIFO, device, socket) is a finding reported
  without opening it.
* **R4** -- the shared scanner does not model backslash escapes outside table
  cells, so ``\\![alt](x.png)`` is still seen as an image (a possible over-detection,
  never a hidden escape). This is accepted rather than diverging from the scanner.
* **R5** -- Markdown ``![]()`` and HTML ``<img>``/``<source>`` images are checked
  **regardless** of extension (an image is an asset by syntax); ``asset_extensions``
  (matched case-insensitively) gates only link-shaped references (HTML ``<a href>``
  and reference definitions), so DS113 does not probe every ordinary ``.md`` link.

**DS113 is a best-effort structural guard, not a complete asset-integrity or
containment control.** It inherits every shared-scanner false negative (multi-line
or nested-parenthesis destinations, multi-line HTML tags, unquoted attributes;
see ``docs/dev/markdown_dialect.md``). Existence is decided by the host
filesystem's case policy, so a case-mismatched reference such as ``Logo.PNG`` to a
committed ``logo.png`` is **platform-dependent** (present on case-insensitive macOS
or Windows, missing on a case-sensitive Linux CI runner); DS113 does not add a
per-directory case check. A residual symlink-swap TOCTOU exists exactly as in
DS101/DS103: the non-following :func:`escapes_via_symlink` gate runs before the
following ``os.stat``; DS113 never opens content, so it has no exploitable use
window of its own.

``DS113`` is **registered** by this module (Story 10.0 Task 02) as an always-active,
default-on fast rule at ``error`` severity: it calls ``register_rule`` on its
:class:`~docsentinel.rules.Rule` and wires :func:`detect` into ``ANALYZERS``, so the
Milestone 0005 fixture catalog now enforces every committed ``tests/assets/ds113/*``
scenario.
"""

from __future__ import annotations

import os
import stat
from bisect import bisect_right
from pathlib import Path
from typing import Optional

from docsentinel import models, rules
from docsentinel.config import Config
from docsentinel.detectors.path_boundaries import escapes_via_symlink, is_ds116_owned
from docsentinel.link_root import link_root_for
from docsentinel.markdown_blocks import MarkdownBlockIndex, ReferenceStatus, resolve_local_reference, scan_markdown

#: Stable metadata for ``DS113``, registered as an always-active, default-on fast
#: rule at ``error`` severity (Story 10.0 Task 02). It carries no ``opt_in_option``;
#: the ``missing_asset_policy`` knob downgrades or silences it without changing the
#: Rule metadata severity. The ``ANALYZERS`` wiring at the end of the module runs
#: :func:`detect` in the fast profile alongside the committed ``tests/assets/ds113/*``
#: fixtures.
DS113 = rules.register_rule(
    rules.Rule(
        code="DS113",
        profile="fast",
        title="Missing local media and document assets",
        description="A local media or document asset referenced by the docs does not exist as a regular file.",
        severity="error",
    )
)

#: Maximum characters of the author's raw target echoed into a finding message.
_MAX_ECHO = 80

#: Classification reasons for a resolved in-root asset path.
_MISSING = "missing"
_NOT_REGULAR = "not_regular"

#: Fixed diagnostic text per reason; the bounded, escaped raw target is appended.
_REASON_TEXT = {
    _MISSING: "missing asset",
    _NOT_REGULAR: "asset is not a regular file",
}


def _echo(raw_target: str) -> str:
    """Return a bounded, repr-escaped echo of the author's raw target.

    The target is bounded to :data:`_MAX_ECHO` characters, then escaped with
    ``unicode_escape`` so control bytes, ``ESC`` sequences, and non-ASCII bytes
    render as printable ``\\xNN``/``\\uNNNN`` forms before the string reaches any
    report sink, mirroring the bounded echo used by ``DS116``. The resolved path is
    never echoed.

    :param raw_target: The reference target exactly as written.
    :returns: The bounded, escaped echo with a trailing ``...`` when truncated.
    """
    bounded = raw_target[:_MAX_ECHO]
    escaped = bounded.encode("unicode_escape").decode("ascii")
    return f"{escaped}..." if len(raw_target) > _MAX_ECHO else escaped


def _first_token(raw_target: str) -> str:
    """Return the first whitespace-delimited token of a raw reference target.

    A Markdown image destination may carry a trailing title the shared scanner does
    not parse; taking the first token isolates the path exactly as ``DS101`` and
    ``DS116`` do. HTML attribute values and reference-definition targets are already
    single tokens, so this is a no-op for them.

    :param raw_target: The target text exactly as written.
    :returns: The first whitespace-delimited token, or ``""`` when blank.
    """
    parts = raw_target.split()
    return parts[0] if parts else ""


def _asset_extensions(settings: Config) -> frozenset[str]:
    """Return the configured asset extensions, lower-cased and without leading dots.

    Matching is case-insensitive (threat-model requirement 8), so the scope
    decision never adds a second case trap on top of the platform-dependent
    filesystem case policy.

    :param settings: Effective configuration.
    :returns: The normalized extension set (for example ``{"png", "pdf"}``).
    """
    return frozenset(extension.lower().lstrip(".") for extension in settings.asset_extensions)


def _has_asset_extension(candidate: Path, extensions: frozenset[str]) -> bool:
    """Return whether a resolved path's suffix is a configured asset extension.

    :param candidate: The resolved in-root candidate path.
    :param extensions: The normalized extension set from :func:`_asset_extensions`.
    :returns: ``True`` when the path's lower-cased suffix is in ``extensions``.
    """
    return candidate.suffix.lower().lstrip(".") in extensions


def _coalesced_masked_ranges(index: MarkdownBlockIndex) -> tuple[list[int], list[int]]:
    """Return disjoint, sorted offset ranges a CommonMark renderer hides.

    Inline code spans and HTML comments both hide images, links, and reference
    definitions in CommonMark, yet the shared scanner extracts image and link
    tokens from the raw line (it only skips *fenced* lines). DS113 therefore drops
    any candidate whose start offset falls inside an inline-code span or HTML
    comment, masking only what the renderer hides (threat-model requirement 7). The
    two range sets are merged and coalesced once into disjoint intervals so a
    membership test is a single :func:`bisect_right`, keeping a comment- or
    code-span flood linear.

    :param index: The scanned block index.
    :returns: A ``(starts, ends)`` pair of aligned, ascending, disjoint ranges.
    """
    raw: list[tuple[int, int]] = []
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


def _is_masked(starts: list[int], ends: list[int], offset: int) -> bool:
    """Return whether a source offset falls inside any masked (hidden) range.

    :param starts: Ascending, disjoint range start offsets.
    :param ends: Range end offsets aligned with ``starts``.
    :param offset: The candidate token's start offset.
    :returns: ``True`` when the offset is inside a hidden range.
    """
    index = bisect_right(starts, offset) - 1
    return index >= 0 and offset < ends[index]


def _classify_path(root: Path, candidate: Path, cache: dict[str, Optional[str]]) -> Optional[str]:
    """Return the missing/non-regular reason for a resolved in-root path, or ``None``.

    The path is already lexically confirmed in-root by the caller (via the shared
    resolver) and confirmed not to escape through a symlink (via
    :func:`escapes_via_symlink`), so the single following ``os.stat`` stays inside
    the root. Existence and type are decided with ``os.stat`` + :func:`stat.S_ISREG`
    only; content is never opened, so a FIFO/device/socket is classified without
    blocking. At most one ``stat`` runs per distinct resolved path (memoised in
    ``cache``).

    :param root: The canonical scan root (unused beyond documentation of intent;
        containment is already established by the caller).
    :param candidate: The resolved in-root candidate path.
    :param cache: Per-document memo mapping a resolved path string to its reason.
    :returns: :data:`_MISSING`, :data:`_NOT_REGULAR`, or ``None`` when the path is a
        usable regular file.
    """
    key = os.path.normpath(os.fspath(candidate))
    if key in cache:
        return cache[key]
    try:
        info = os.stat(candidate)
    except OSError:
        # A missing file, a broken in-root symlink, or an inaccessible in-root path
        # all read as "missing"; os.stat never opens content, so this cannot block.
        reason: Optional[str] = _MISSING
    else:
        reason = None if stat.S_ISREG(info.st_mode) else _NOT_REGULAR
    cache[key] = reason
    return reason


def _collect_candidates(index: MarkdownBlockIndex, settings: Config) -> list[tuple[int, int, str, bool]]:
    """Return the asset references to validate, honouring the ``check_*`` toggles.

    Images are collected regardless of extension (R5); HTML ``<a href>`` links and
    used reference definitions carrying an asset extension are the link-shaped
    references gated by ``asset_extensions`` (R1/R5, applied by the caller after
    resolution). Each candidate carries whether the extension gate applies.

    :param index: The scanned block index.
    :param settings: Effective configuration supplying the ``check_*`` toggles.
    :returns: ``(start_offset, start_line, raw_target, extension_gated)`` tuples.
    """
    candidates: list[tuple[int, int, str, bool]] = []
    for image in index.images:
        if image.attribute == "srcset":
            if not (settings.check_html_asset_tags and settings.check_srcset):
                continue
        elif image.html:
            if not settings.check_html_asset_tags:
                continue
        elif not settings.check_markdown_images:
            continue
        candidates.append((image.span.start_offset, image.span.start_line, _first_token(image.raw_target), False))

    if settings.check_html_asset_tags:
        for reference in index.local_references:
            if reference.html:
                candidates.append(
                    (reference.span.start_offset, reference.span.start_line, _first_token(reference.raw_target), True)
                )

    used_labels = {use.label for use in index.reference_uses}
    for definition in index.reference_definitions:
        if definition.label in used_labels:
            candidates.append(
                (definition.span.start_offset, definition.span.start_line, _first_token(definition.target), True)
            )
    return candidates


def check_text(
    text: str,
    document_path: str,
    root: Path,
    config: Optional[Config] = None,
    *,
    link_root: Optional[Path] = None,
) -> tuple[models.Finding, ...]:
    """Return ``DS113`` findings for one document's Markdown ``text``.

    Like ``DS116``, ``DS113`` needs the scan ``root`` to decide containment, so the
    root is a required argument. The analyzer validates Markdown images, HTML
    ``<img>``/``<source>`` ``src``/``srcset`` targets, HTML ``<a href>`` link
    targets, and used reference-definition targets; targets inside fenced code,
    inline code, or HTML comments are treated as examples and skipped. One finding
    is emitted per offending reference at its one-based source line, in stable
    source order, with duplicate ``(line, message)`` pairs collapsed.

    With ``missing_asset_policy = "off"`` no findings are produced and no filesystem
    access occurs. Severity is ``"warning"`` under ``missing_asset_policy = "warn"``
    and ``"error"`` (the rule default, blocking) otherwise; the
    :class:`~docsentinel.rules.Rule` metadata severity stays ``error`` regardless.

    :param text: The Markdown source text exactly as read.
    :param document_path: POSIX-style relative path recorded on each finding.
    :param root: The canonical scan root used for containment.
    :param config: Effective settings, or ``None`` for defaults.
    :param link_root: Precomputed base and containment boundary for ``/`` targets,
        or ``None`` to resolve it from ``config`` with ``link_root_for``.
    :returns: Findings in source order, one per offending reference.
    :raises ConfigError: When ``link_root`` must be resolved here and is invalid.
    """
    settings = config if config is not None else Config()
    if settings.missing_asset_policy == "off":
        return ()
    severity = "warning" if settings.missing_asset_policy == "warn" else DS113.severity
    base = link_root if link_root is not None else link_root_for(root, settings)

    index = scan_markdown(text, document_path)
    extensions = _asset_extensions(settings)
    starts, ends = _coalesced_masked_ranges(index)
    candidates = _collect_candidates(index, settings)

    findings: list[models.Finding] = []
    seen: set[tuple[int, str]] = set()
    cache: dict[str, Optional[str]] = {}
    for offset, line, raw_target, extension_gated in sorted(candidates):
        target = _first_token(raw_target)
        if not target or target.startswith("#"):
            # Empty or fragment-only references are not local assets.
            continue
        if _is_masked(starts, ends, offset):
            continue
        # Containment gate (lexical, no filesystem access): DS116 owns every unsafe
        # category, so DS113 must neither resolve nor stat it (R2).
        if is_ds116_owned(root, document_path, target, link_root=base):
            continue
        reference = resolve_local_reference(root, document_path, target, link_root=base)
        if reference.status is not ReferenceStatus.RESOLVED or reference.path is None:
            # EXTERNAL (URL/data URI/protocol-relative), template, glob, or an
            # empty target: not a local asset DS113 owns.
            continue
        if extension_gated and not _has_asset_extension(reference.path, extensions):
            # A link-shaped reference without an asset extension is DS101's/prose's
            # territory, not DS113's (R5).
            continue
        boundary = reference.boundary if reference.boundary is not None else root
        if escapes_via_symlink(boundary, reference.path):
            # An in-root symlink pointing outside the root is DS116's finding (R2);
            # never stat it.
            continue
        reason = _classify_path(root, reference.path, cache)
        if reason is None:
            continue
        message = f"{_REASON_TEXT[reason]}: {_echo(target)}"
        key = (line, message)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            models.Finding(rule=DS113.code, path=document_path, message=message, severity=severity, line=line)
        )
    return tuple(findings)


def _read_text(path: Path) -> str:
    """Read UTF-8 text from a path.

    :param path: Absolute path to the Markdown document.
    :returns: The decoded document text.
    """
    with path.open(encoding="utf-8") as stream:
        return stream.read()


def detect(
    root: Path,
    documents: tuple[models.Document, ...],
    config: Optional[Config] = None,
    *,
    link_root: Optional[Path] = None,
) -> tuple[models.Finding, ...]:
    """Return ``DS113`` findings for Markdown documents in their supplied order.

    The trusted scan root is canonicalised exactly once here with the single
    permitted :func:`os.path.realpath`; every containment comparison uses that
    canonical root, and the current working directory never enters resolution.

    :param root: The scan root directory (trusted).
    :param documents: Discovered documents to inspect, in scan order.
    :param config: Effective settings; the engine passes this, and direct callers
        may omit it to use defaults.
    :param link_root: The engine-validated base for ``/`` targets; ``None`` falls back
        to :func:`~docsentinel.link_root.link_root_for`, which accepts only values
        meaning the scan root.
    :returns: Findings across all documents in document then source order.
    :raises ConfigError: When ``link_root`` is invalid for this scan root.
    """
    settings = config if config is not None else Config()
    if settings.missing_asset_policy == "off":
        return ()
    canonical = Path(os.path.realpath(root))
    base = link_root if link_root is not None else link_root_for(canonical, settings)
    findings: list[models.Finding] = []
    for document in documents:
        if not document.path.endswith(".md"):
            continue
        text = _read_text(canonical / document.path)
        findings.extend(check_text(text, document.path, canonical, settings, link_root=base))
    return tuple(findings)


rules.ANALYZERS[DS113.code] = detect
