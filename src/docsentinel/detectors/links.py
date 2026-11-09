"""Detect dangling Markdown links and anchors."""

import os
import re
from pathlib import Path
from typing import Optional

from docsentinel import models, rules
from docsentinel.config import Config
from docsentinel.detectors.path_boundaries import contained_path, is_ds116_owned
from docsentinel.link_root import link_root_for

DS101 = rules.register_rule(
    rules.Rule(
        code="DS101",
        profile="fast",
        title="Dangling link or anchor",
        description="A Markdown link or #anchor target does not resolve.",
        severity="error",
    )
)

_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
_CODE_SPAN_RE = re.compile(r"`+[^`]*`+")
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_HEADING_RE = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_HTML_ANCHOR_RE = re.compile(r'<a\s+[^>]*?(?:id|name)=["\']([^"\']+)["\']', re.I)

#: Most characters read from a linked Markdown file *outside the scan root* (reached
#: through the link root) to collect its anchors, matching the DS115 mapping cap. A
#: larger file, or one that is not UTF-8, skips the anchor check instead of stalling
#: or failing the scan (the link itself still resolves). In-root targets keep the
#: historical read, whose errors propagate.
_MAX_ANCHOR_SOURCE_CHARS = 1_000_000


def _read_lines(path: Path) -> list[str]:
    """Read UTF-8 text from a path as logical lines."""
    with path.open(encoding="utf-8") as stream:
        return stream.read().splitlines()


def slugify(heading_text: str) -> str:
    """Return the GitHub-style anchor slug for heading text."""
    text = heading_text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"\s", "-", text)
    return text


def heading_anchors(path: Path) -> set[str]:
    """Return heading slugs and explicit HTML anchors found in a Markdown file."""
    return _anchors_from_lines(_read_lines(path))


def _anchors_from_lines(lines: list[str]) -> set[str]:
    """Return heading slugs and explicit HTML anchors found in Markdown lines.

    :param lines: The document's logical lines.
    :returns: The anchor set.
    """
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    fence_marker: Optional[str] = None

    for line in lines:
        fence = _FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)[0]
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker == fence_marker:
                in_fence, fence_marker = False, None
            continue
        if in_fence:
            continue
        anchors.update(_HTML_ANCHOR_RE.findall(line))
        heading = _HEADING_RE.match(line)
        if not heading:
            continue
        base = slugify(heading.group(2))
        count = seen.get(base, 0)
        anchors.add(base if count == 0 else f"{base}-{count}")
        seen[base] = count + 1
    return anchors


def _linked_anchors(path: Path) -> Optional[set[str]]:
    """Return the anchors of a linked Markdown file, or ``None`` to skip the anchor check.

    The read is bounded to :data:`_MAX_ANCHOR_SOURCE_CHARS`; an oversized, non-UTF-8 or
    unreadable file yields ``None`` rather than a truncated (and so misleading) anchor
    set or a scan failure.

    :param path: The resolved, existing linked file.
    :returns: Its anchor set, or ``None`` when it cannot be read within the bound.
    """
    text: Optional[str]
    try:
        with path.open(encoding="utf-8") as stream:
            text = stream.read(_MAX_ANCHOR_SOURCE_CHARS + 1)
    except (OSError, UnicodeDecodeError):
        # An unreadable or non-UTF-8 linked file: its anchors are unknown, so the
        # caller skips the anchor check rather than failing the whole scan.
        text = None
    if text is None or len(text) > _MAX_ANCHOR_SOURCE_CHARS:
        return None
    return _anchors_from_lines(text.splitlines())


def _is_skippable(target: str) -> bool:
    """Return whether a target should not be resolved as a local file."""
    if not target:
        return True
    if target.startswith("//"):
        return True
    if "{" in target or "}" in target:
        return True
    if "*" in target or "?" in target:
        return True
    if target.startswith("#"):
        return False
    return bool(_SCHEME_RE.match(target))


def _resolve(target_path: str, source: Path, root: Path, link_root: Optional[Path] = None) -> Path:
    """Resolve a link file part relative to the link root (``/`` targets) or source document."""
    if target_path.startswith("/"):
        return ((link_root or root) / target_path.lstrip("/")).resolve()
    return (source.parent / target_path).resolve()


def _lexical_target(target_path: str, source: Path, root: Path, link_root: Optional[Path] = None) -> Path:
    """Join a link file part to its base **without** resolving symlinks or ``..``.

    This mirrors :func:`_resolve`'s join rules but omits ``Path.resolve`` (which
    follows symlinks out of root and was the existence oracle fixed in Story 11.0).
    The ``..``-bearing result is lexically equivalent to the old resolved path for
    every in-root, non-symlink target, so ``exists`` returns the same answer; the
    path is handed to :func:`~docsentinel.detectors.path_boundaries.escapes_via_symlink`
    first so a root escape or an in-root symlink pointing outside is never stat-ed.

    A site-root-absolute (``/``) target is joined onto ``link_root``, the repository
    base GitHub resolves ``/`` against; ``None`` keeps the historical scan-root join.

    :param target_path: The link file part (fragment already removed).
    :param source: The absolute path of the referring document.
    :param root: The scan root directory.
    :param link_root: Base for ``/`` targets, or ``None`` for ``root``.
    :returns: The unresolved join of the target against its base.
    """
    if target_path.startswith("/"):
        return (link_root or root) / target_path.lstrip("/")
    return source.parent / target_path


def _strip_code_spans(raw_line: str) -> tuple[str, list[int]]:
    """Remove inline code spans and map each kept character to its raw-line offset.

    The returned text is exactly ``_CODE_SPAN_RE.sub("", raw_line)`` (so link
    matching is unchanged); the offset list lets a match position in it be reported
    as a column of the original line.

    :param raw_line: One source line.
    :returns: The stripped line and, per stripped character, its 0-based raw offset.
    """
    kept: list[str] = []
    offsets: list[int] = []
    cursor = 0
    for span in _CODE_SPAN_RE.finditer(raw_line):
        kept.append(raw_line[cursor : span.start()])
        offsets.extend(range(cursor, span.start()))
        cursor = span.end()
    kept.append(raw_line[cursor:])
    offsets.extend(range(cursor, len(raw_line)))
    return "".join(kept), offsets


def check_document(
    root: Path, document: models.Document, *, link_root: Optional[Path] = None
) -> tuple[models.Finding, ...]:
    """Return dangling link and anchor findings for one Markdown document.

    :param root: The scan root directory.
    :param document: The document to inspect.
    :param link_root: Precomputed base for ``/`` targets; ``None`` uses the default
        config's lexical link root (the scan root).
    :returns: Findings in source order.
    """
    base = link_root if link_root is not None else link_root_for(Path(os.path.realpath(root)), Config())
    source = root / document.path
    findings: list[models.Finding] = []
    in_fence = False
    fence_marker: Optional[str] = None
    anchor_cache: dict[Path, set[str]] = {}

    for line_number, raw_line in enumerate(_read_lines(source), 1):
        fence = _FENCE_RE.match(raw_line)
        if fence:
            marker = fence.group(1)[0]
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker == fence_marker:
                in_fence, fence_marker = False, None
            continue
        if in_fence:
            continue

        line, offsets = _strip_code_spans(raw_line)
        for link in _LINK_RE.finditer(line):
            raw_target = link.group(1)
            target_parts = raw_target.split()
            target = target_parts[0] if target_parts else ""
            if _is_skippable(target):
                continue
            # 1-based column of the target in the original (unstripped) line.
            column = offsets[link.start(1) + len(raw_target) - len(raw_target.lstrip())] + 1

            # Security skip (lexical, no filesystem access): a target that escapes
            # the root or is an unsafe DS116-owned category (drive/UNC/backslash/
            # control) is handed to DS116 so DS101 never stats a path outside the
            # scan root (the existence oracle fixed in Story 11.0). Every other
            # target keeps DS101's exact legacy behavior below.
            if is_ds116_owned(root, document.path, target, link_root=base):
                continue

            file_part, _, anchor = target.partition("#")
            if file_part == "":
                anchors = anchor_cache.setdefault(source, heading_anchors(source))
                if anchor and anchor not in anchors:
                    findings.append(
                        models.Finding(
                            rule=DS101.code,
                            path=document.path,
                            message=f"missing anchor '#{anchor}' in this file",
                            severity=DS101.severity,
                            line=line_number,
                            column=column,
                            value=target,
                            type="dangling anchor",
                        )
                    )
                continue

            candidate = _lexical_target(file_part, source, root, base)
            # Never follow an in-root symlink whose target escapes the root, and
            # never stat a lexical escape; DS116 owns both. The returned path has
            # symlinks and ``..`` safely resolved before any filesystem operation.
            # A ``/`` target is contained by the link root instead of the scan root.
            boundary = base if file_part.startswith("/") else root
            resolved = contained_path(boundary, candidate)
            if resolved is None:
                continue
            if not resolved.exists():
                findings.append(
                    models.Finding(
                        rule=DS101.code,
                        path=document.path,
                        message=f"dangling link -> {target}",
                        severity=DS101.severity,
                        line=line_number,
                        column=column,
                        value=target,
                        type="dangling link",
                    )
                )
                continue
            if anchor and resolved.is_file() and resolved.suffix == ".md":
                if resolved not in anchor_cache:
                    if resolved.is_relative_to(root):
                        # In-root target: read exactly as before (errors propagate).
                        anchor_cache[resolved] = heading_anchors(resolved)
                    else:
                        # Outside the scan root, reached through the link root: a
                        # bounded read that skips an oversized or undecodable file.
                        linked = _linked_anchors(resolved)
                        if linked is None:
                            continue
                        anchor_cache[resolved] = linked
                anchors = anchor_cache[resolved]
                if anchor not in anchors:
                    findings.append(
                        models.Finding(
                            rule=DS101.code,
                            path=document.path,
                            message=f"missing anchor '#{anchor}' in {file_part}",
                            severity=DS101.severity,
                            line=line_number,
                            column=column,
                            value=target,
                            type="dangling anchor",
                        )
                    )
    return tuple(findings)


def detect(
    root: Path,
    documents: tuple[models.Document, ...],
    config: Optional[Config] = None,
    *,
    link_root: Optional[Path] = None,
) -> tuple[models.Finding, ...]:
    """Return DS101 findings for Markdown documents in their supplied order.

    :param root: The scan root directory.
    :param documents: Documents to inspect in their supplied order.
    :param config: Effective settings supplying ``link_root``; ``None`` uses defaults.
    :param link_root: The engine-validated base for ``/`` targets; ``None`` falls back
        to :func:`~docsentinel.link_root.link_root_for`, which accepts only values
        meaning the scan root.
    :returns: Findings across all documents in document then source order.
    :raises ConfigError: When ``link_root`` is invalid for this scan root.
    """
    settings = config if config is not None else Config()
    base = link_root if link_root is not None else link_root_for(Path(os.path.realpath(root)), settings)
    return tuple(
        finding
        for document in documents
        if document.path.endswith(".md")
        for finding in check_document(root, document, link_root=base)
    )


rules.ANALYZERS[DS101.code] = detect
