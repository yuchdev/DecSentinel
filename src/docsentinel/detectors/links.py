"""Detect dangling Markdown links and anchors."""

import re
from pathlib import Path
from typing import Optional

from docsentinel import models, rules
from docsentinel.detectors.path_boundaries import contained_path, is_ds116_owned

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
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    fence_marker: Optional[str] = None

    for line in _read_lines(path):
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


def _resolve(target_path: str, source: Path, root: Path) -> Path:
    """Resolve a link file part relative to the scan root or source document."""
    if target_path.startswith("/"):
        return (root / target_path.lstrip("/")).resolve()
    return (source.parent / target_path).resolve()


def _lexical_target(target_path: str, source: Path, root: Path) -> Path:
    """Join a link file part to its base **without** resolving symlinks or ``..``.

    This mirrors :func:`_resolve`'s join rules but omits ``Path.resolve`` (which
    follows symlinks out of root and was the existence oracle fixed in Story 11.0).
    The ``..``-bearing result is lexically equivalent to the old resolved path for
    every in-root, non-symlink target, so ``exists`` returns the same answer; the
    path is handed to :func:`~docsentinel.detectors.path_boundaries.escapes_via_symlink`
    first so a root escape or an in-root symlink pointing outside is never stat-ed.

    :param target_path: The link file part (fragment already removed).
    :param source: The absolute path of the referring document.
    :param root: The scan root directory.
    :returns: The unresolved join of the target against its base.
    """
    if target_path.startswith("/"):
        return root / target_path.lstrip("/")
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


def check_document(root: Path, document: models.Document) -> tuple[models.Finding, ...]:
    """Return dangling link and anchor findings for one Markdown document."""
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
            if is_ds116_owned(root, document.path, target):
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

            candidate = _lexical_target(file_part, source, root)
            # Never follow an in-root symlink whose target escapes the root, and
            # never stat a lexical escape; DS116 owns both. The returned path has
            # symlinks and ``..`` safely resolved before any filesystem operation.
            resolved = contained_path(root, candidate)
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
                anchors = anchor_cache.setdefault(resolved, heading_anchors(resolved))
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


def detect(root: Path, documents: tuple[models.Document, ...]) -> tuple[models.Finding, ...]:
    """Return DS101 findings for Markdown documents in their supplied order."""
    return tuple(
        finding for document in documents if document.path.endswith(".md") for finding in check_document(root, document)
    )


rules.ANALYZERS[DS101.code] = detect
