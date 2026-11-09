"""Detect documentation references that escape the scan root (``DS116``).

This fast, standard-library-only analyzer reports references whose target leaves
the configured documentation root: lexical parent-directory escapes, percent-
encoded escapes, Windows drive/UNC/backslash paths, control bytes, and in-root
symlinks whose target points outside the root. It is a deterministic structural
check that reuses the shared, purely lexical resolver
:func:`docsentinel.markdown_blocks.resolve_local_reference` and the shared
Markdown scanner; it never adds a second path resolver.

Security contract (see ``docs/security/threat-model-ds116-path-boundaries-2026-10-22.md``):

* **No filesystem access outside the root.** A target is only touched on the
  filesystem once it is lexically confirmed inside the root. Lexical escapes and
  unsafe ``UNSUPPORTED`` targets are classified with zero filesystem calls.
* **Decode exactly once.** Percent-encoding is decoded a single time by the
  shared resolver and the remainder is treated literally, so ``%252e%252e`` stays
  in-root rather than double-decoding to ``..``. When ``decode_percent_paths`` is
  false the analyzer suppresses that single decode (by neutralising ``%`` before
  the resolver's own ``unquote``) yet still catches raw ``../`` traversal.
* **Residual-encoding defence (ruling G1).** After the single decode, a path
  component that still carries a percent-encoded dot or separator octet
  (``%2e``/``%2f``/``%5c``, any case) is reported; a lone ``%25`` such as
  ``100%25.md`` and other residual ``%xx`` stay clean. The analyzer never decodes
  twice.
* **Safe, non-following symlink containment (ruling G4).** Lexical containment is
  checked first; only for a lexically in-root target does the analyzer walk the
  normalised components with :func:`os.lstat`/:func:`os.readlink` on the in-root
  symlink objects, computing each symlink's target lexically. A symlink whose
  target escapes the root is a finding. No path outside the root is ever
  ``stat``-ed, opened, ``realpath``-ed, or ``resolve``-ed, and the walk is bounded
  (hop limit plus per-component loop detection) so it stays linear.
* **Bounded, repr-escaped echo.** A finding message echoes only the author's raw
  target, bounded to :data:`_MAX_ECHO` characters and repr-escaped so no control
  byte, ``ESC`` sequence, or non-ASCII byte reaches the report sinks; the resolved
  absolute path, the target's existence, and its file type are never disclosed.

Ruling G3 is honoured by the shared resolver: an absolute POSIX path such as
``/etc/passwd`` is reinterpreted root-relative (clean), consistent with the
root-relative ``/docs/guide.md`` allowance. "Root" for a ``/`` target means the
**link root** (``link_root``, see :mod:`docsentinel.link_root`): by default the
nearest ancestor holding ``.git``, else the scan root. A ``/`` target that stays
inside the link root is a legitimate repository reference and not an escape even
when it lies outside the scan root (``/src/foo.py`` while scanning ``docs/``);
``/../x`` past the link root is an escape, and the symlink-out walk for a ``/``
target uses the link root as its boundary. Relative targets keep the scan root as
their boundary. The current working directory never enters resolution; the
trusted scan root is canonicalised exactly once in :func:`detect`.

``DS116`` is an always-active ``fast``-profile rule: it registers its
:class:`~docsentinel.rules.Rule` and ``ANALYZERS`` entry as an import side effect
(Story 11.0 Task 02, together with the committed ``tests/assets/ds116/*``
fixtures the Milestone 0005 catalog is registration gated on). It registers
**without** an ``opt_in_option`` -- unlike the opt-in ``DS110``, ``DS116`` is on
by default at ``error`` severity.

The ownership split differs by reference kind (Story 11.0 code-span ruling):

* **Links, images, reference definitions, and HTML ``href``/``src``/``srcset``**
  are checked at full strictness: every unsafe category is a DS116 finding, and
  ``DS101`` delegates all of them to DS116 via :func:`is_ds116_owned` rather than
  resolving or ``stat``-ing an escaped link target.
* **Inline code spans** are documentation, not references, so DS116 reports only
  genuine traversal there -- a lexical root escape (including percent-encoded and
  residual-encoding forms) or an in-root symlink pointing outside. Drive, UNC,
  rooted-backslash, embedded-backslash, and control-looking code spans (and regex
  or escape spans such as ``\\n`` or ``DS\\d{3}``) are **not** DS116 findings; DS103
  resumes its exact pre-Story-11 behaviour for them and only skips the root-escape
  and symlink-out code spans that DS116 owns.

The shared scanner feeds DS116 the reference forms a CommonMark renderer makes
live, so the Story 11.0 close-gate sweep closed several evasions: HTML ``<a href>``
and ``<img>``/``<source>`` ``srcset`` attributes are extracted; a ``<...>``
angle-bracket destination is unwrapped; HTML entity and numeric character
references in a destination are decoded once (via the shared resolver); a nested
image-in-link-text exposes the **outer** destination; and a reference definition
inside a block quote is recognised.

**DS116 is not a complete containment control; it is a deterministic,
best-effort structural guard.** Known false negatives remain, pinned by tests and
documented in ``docs/dev/markdown_dialect.md``:

* **Multi-line references.** The shared scanner is line-based, so a link or
  reference definition whose destination is split across physical lines is not
  joined and escapes detection.
* **Nested-parenthesis destinations.** The destination ends at the first ``)``, so
  a CommonMark balanced-parenthesis destination such as ``x(y)z.md`` is truncated
  (a parsing approximation, not a guaranteed catch).
* **Time-of-check/time-of-use (TOCTOU).** The downstream existence checks in DS101
  and DS103 run after DS116's lexical gate; a symlink swapped between the gate and
  the check is a theoretical race. DS116 itself never opens or reads target
  content, so it has no exploitable use window; the residual race is acknowledged
  and not fixed here (there is no cheap, deterministic fix without a single
  atomic open DocSentinel deliberately avoids).
"""

from __future__ import annotations

import os
import re
import stat
from bisect import bisect_right
from collections import deque
from pathlib import Path
from typing import Optional
from urllib.parse import unquote

from docsentinel import models, rules
from docsentinel.config import Config
from docsentinel.link_root import link_root_for
from docsentinel.markdown_blocks import ReferenceStatus, resolve_local_reference, scan_markdown

#: Stable metadata for ``DS116``, registered as an always-active ``fast``-profile
#: rule (no ``opt_in_option`` -- on by default at ``error`` severity) alongside its
#: committed ``tests/assets/ds116/*`` fixtures (Story 11.0 Task 02).
DS116 = rules.register_rule(
    rules.Rule(
        code="DS116",
        profile="fast",
        title="Path traversal outside documentation root",
        description="A documentation reference escapes the configured scan root.",
        severity="error",
    )
)

#: Maximum characters of the author's raw target echoed into a finding message.
_MAX_ECHO = 80

#: Upper bound on symlink hops in a single containment walk; protects against a
#: crafted cycle or a pathologically deep chain while keeping the walk linear.
_MAX_SYMLINK_HOPS = 64

#: ``UNSUPPORTED`` sub-categories gated by ``windows_path_policy``.
_WINDOWS_REASONS = frozenset({"drive", "unc", "backslash"})

#: Categories DS116 reports for full references (links, images, reference
#: definitions, HTML ``src``/``href``) but **not** for inline code spans. Per the
#: Story 11.0 ruling a drive/UNC/backslash/control code span is a documented literal
#: example, so DS116 leaves it to DS103's legacy behaviour; DS116 code spans report
#: only genuine traversal (root escape, residual encoding, in-root symlink-out).
_CODE_SPAN_EXEMPT_REASONS = _WINDOWS_REASONS | {"control"}

#: Residual percent-encoded dot (``%2e``) or separator (``%2f``/``%5c``) octets
#: that survive a single decode -- the ruling G1 "suspicious residual" signal.
_RESIDUAL_ENCODING_RE = re.compile(r"%(?:2e|2f|5c)", re.IGNORECASE)

#: Fixed diagnostic text per violation category; the echoed raw target is
#: appended by :func:`_build_message`.
_REASON_TEXT = {
    "escape": "reference escapes the documentation root",
    "residual": "reference keeps percent-encoded path separators after one decode",
    "drive": "reference uses a Windows drive-letter path",
    "unc": "reference uses a UNC network path",
    "backslash": "reference uses backslash path separators",
    "control": "reference contains control characters",
    "symlink": "reference resolves through a symlink that escapes the documentation root",
}

# Path-like recognition for explicit code spans, mirroring DS103's shape rules so
# the two agree on what counts as a path (versions and bare extensions are not).
_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9]{1,5}$")
_VERSION_RE = re.compile(r"v?\d+(\.\d+){1,3}")
_BARE_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9]{1,4}")


def _first_token(raw_target: str) -> str:
    """Return the first whitespace-delimited token of a raw reference target.

    Markdown link destinations and reference-definition targets may carry a
    trailing title the shared scanner does not parse; taking the first token
    isolates the actual path exactly as ``DS101`` does.

    :param raw_target: The target text exactly as written.
    :returns: The first whitespace-delimited token, or ``""`` when blank.
    """
    parts = raw_target.split()
    return parts[0] if parts else ""


def _looks_path_like(candidate: str) -> bool:
    """Return whether an inline code span should be treated as a path reference.

    A single-token span counts as a path only when it carries a forward-slash
    separator or a file extension, excluding command flags, shell syntax, version
    strings, and bare extensions. Per the Story 11.0 code-span ruling a backslash is
    deliberately **not** a path signal here: regex and escape spans such as ``\\n``,
    ``\\|``, ``\\b\\w+\\b`` or ``DS\\d{3}`` are documentation, not references, so DS116
    must not even consider them. A Windows drive span such as ``C:\\Windows\\win.ini``
    is still considered (it carries a ``.ini`` extension) but its drive/backslash
    category is suppressed for code spans in :func:`check_text`.

    :param candidate: The trimmed inline-code text.
    :returns: ``True`` when the span is path-like enough to validate.
    """
    if not candidate or any(character.isspace() for character in candidate):
        return False
    if candidate.startswith(("-", "$", ">")):
        return False
    if _VERSION_RE.fullmatch(candidate) or _BARE_EXTENSION_RE.fullmatch(candidate):
        return False
    return "/" in candidate or bool(_EXTENSION_RE.search(candidate))


def _within(candidate: str, root: str) -> bool:
    """Return whether a normalised path string is the root or lives under it.

    :param candidate: An already ``os.path.normpath``-ed absolute path string.
    :param root: The normalised absolute scan-root string.
    :returns: ``True`` when ``candidate`` is contained in ``root``.
    """
    if candidate == root:
        return True
    # Separator-aware: a root of ``/`` must stay ``/``, never become ``//``.
    prefix = root if root.endswith(os.sep) else root + os.sep
    return candidate.startswith(prefix)


def contained_path(root: Path, candidate: Path, *, max_hops: int = _MAX_SYMLINK_HOPS) -> Optional[Path]:
    """Return the validated in-root path, resolving symlinks before ``..`` components.

    Unlike normalising the candidate first, this walks the original component order.
    Symlink targets are expanded lexically and each resulting component is checked
    without following it, so a ``link/..`` sequence cannot hide an outside traversal.
    Missing components are preserved as lexical path components; callers may safely
    perform their existence check on the returned path.

    :param root: The trusted (already canonicalised) scan-root directory.
    :param candidate: An absolute candidate path, possibly containing ``..``.
    :param max_hops: Maximum symlink hops before failing closed.
    :returns: A normalized path inside root, or ``None`` if containment is unproven.
    """
    root_str = os.path.normpath(str(root))
    candidate_str = os.fspath(candidate)

    def relative_parts(path: str) -> Optional[list[str]]:
        """Return unnormalized path components relative to root when contained."""
        if path == root_str:
            return []
        prefix = root_str if root_str.endswith(os.sep) else root_str + os.sep
        if not path.startswith(prefix):
            return None
        return path[len(prefix) :].split(os.sep)

    components = relative_parts(candidate_str)
    if components is None:
        return None
    pending = deque(components)

    parts: list[str] = []
    hops = 0
    while pending:
        part = pending.popleft()
        if part in ("", os.curdir):
            continue
        if part == os.pardir:
            if not parts:
                return None
            parts.pop()
            continue

        current = Path(root_str).joinpath(*parts, part)
        try:
            info = os.lstat(current)
        except (FileNotFoundError, NotADirectoryError):
            parts.append(part)
            continue

        if not stat.S_ISLNK(info.st_mode):
            parts.append(part)
            continue

        hops += 1
        if hops > max_hops:
            return None
        target = os.readlink(current)

        if os.path.isabs(target):
            target_parts = relative_parts(target)
            if target_parts is None:
                return None
            parts.clear()
        else:
            target_parts = target.split(os.sep)
        pending.extendleft(reversed(target_parts))

    return Path(root_str).joinpath(*parts)


def escapes_via_symlink(root: Path, candidate: Path, *, max_hops: int = _MAX_SYMLINK_HOPS) -> bool:
    """Return whether a candidate path escapes the root lexically or through a symlink.

    This is the safe, non-following containment check (ruling G4). The candidate is
    first normalised lexically; if that normal form is not inside the root the path
    is an escape and the function returns at once with no filesystem access. Only
    for a lexically in-root candidate does the walk visit each component with
    :func:`os.lstat`; when a component is a symlink its target is read with
    :func:`os.readlink` and resolved **lexically** (never with ``realpath`` or
    ``resolve``). If that lexical target leaves the root the walk reports an escape
    without ever ``stat``-ing the outside object. All :func:`os.lstat` and
    :func:`os.readlink` calls touch only in-root objects, so no path outside the
    root is ever accessed. The walk is bounded by ``max_hops`` and by per-component
    loop detection, so it is linear in the in-root component count.

    :param root: The trusted (already canonicalised) scan-root directory.
    :param candidate: A candidate path to test for containment.
    :param max_hops: Maximum total symlink hops before the walk stops.
    :returns: ``True`` when the candidate escapes the root lexically or via a symlink.
    """
    root_str = os.path.normpath(str(root))
    candidate_str = os.path.normpath(str(candidate))
    if not _within(candidate_str, root_str):
        # Lexical escape (e.g. an unnormalised ``..`` chain that leaves the root);
        # DS116 owns it and no filesystem access is performed.
        return True
    relative = os.path.relpath(candidate_str, root_str)
    relative_parts: tuple[str, ...] = () if relative == os.curdir else Path(relative).parts

    current = Path(root_str)
    hops = 0
    for part in relative_parts:
        current = current / part
        seen: set[str] = set()
        while True:
            hops += 1
            if hops > max_hops:
                # Bounded: every object walked so far stayed in-root, so a hop
                # overflow (a long in-root chain or cycle) is not an escape.
                return False
            try:
                info = os.lstat(current)
            except OSError:
                # Missing or inaccessible in-root object: record with a sentinel
                # and stop following this component (nothing to resolve).
                info = None
            if info is None or not stat.S_ISLNK(info.st_mode):
                break
            key = os.fspath(current)
            if key in seen:
                return False
            seen.add(key)
            link_target = os.readlink(current)
            if os.path.isabs(link_target):
                resolved = os.path.normpath(link_target)
            else:
                resolved = os.path.normpath(os.path.join(os.path.dirname(key), link_target))
            if not _within(resolved, root_str):
                return True
            current = Path(resolved)
    return False


def is_ds116_owned(root: Path, document_path: str, raw_target: str, *, link_root: Optional[Path] = None) -> bool:
    """Return whether a target belongs to a DS116-owned *unsafe* category.

    This is the narrow security gate ``DS101`` consults for **link** targets so that
    the Story 11.0 oracle fix changes its public behavior only for the categories
    DS116 owns, never for ordinary templates, globs, external schemes, or in-root
    targets. ``DS103`` no longer calls it: per the code-span ruling DS103 skips only
    root-escape and symlink-out code spans (via :func:`escapes_via_symlink`) and
    reports drive/UNC/backslash/control spans with its legacy behaviour. The gate is
    purely lexical (it never touches the filesystem) and reports
    ``True`` only when the shared resolver classifies the decoded target as a root
    escape (``OUTSIDE_ROOT``) or as an *unsafe* ``UNSUPPORTED`` sub-category
    (``drive``, ``unc``, ``backslash``, ``control``). Safe ``UNSUPPORTED`` tags
    (``template``, ``glob``) and ``EXTERNAL``/``RESOLVED`` targets return ``False``
    so the caller runs its unchanged legacy logic. In-root symlink escapes are a
    separate concern handled by :func:`escapes_via_symlink` on the caller's own
    resolved path, because the resolver's decode-and-``#`` handling differs from
    the legacy per-detector resolution.

    :param root: The scan root directory.
    :param document_path: POSIX-style relative path of the referring document.
    :param raw_target: The reference target exactly as written.
    :param link_root: Base and boundary for ``/`` targets; ``None`` uses ``root``
        (configured-path callers must keep it ``None``).
    :returns: ``True`` when the target is an unsafe, DS116-owned category.
    """
    reference = resolve_local_reference(root, document_path, raw_target, link_root=link_root)
    if reference.status is ReferenceStatus.OUTSIDE_ROOT:
        return True
    return reference.status is ReferenceStatus.UNSUPPORTED and reference.reason in _WINDOWS_REASONS | {"control"}


def _classify(
    root: Path, document_path: str, raw_target: str, settings: Config, link_root: Optional[Path] = None
) -> Optional[str]:
    """Return the ``DS116`` violation category for one reference, or ``None``.

    The target is routed through the shared lexical resolver. When
    ``decode_percent_paths`` is false the resolver's single ``unquote`` is
    neutralised (every ``%`` becomes ``%25`` first, which ``unquote`` restores)
    so no decoding happens, yet raw ``../`` traversal is still caught.

    :param root: The canonical scan root.
    :param document_path: POSIX-style relative path of the referring document.
    :param raw_target: The reference target exactly as written.
    :param settings: Effective configuration.
    :param link_root: Base and boundary for ``/`` targets; ``None`` uses ``root``.
    :returns: A key of :data:`_REASON_TEXT`, or ``None`` when the reference is safe.
    """
    target = raw_target.strip()
    if not target:
        return None

    probe = target if settings.decode_percent_paths else target.replace("%", "%25")
    reference = resolve_local_reference(root, document_path, probe, link_root=link_root)
    status = reference.status

    if status is ReferenceStatus.EXTERNAL:
        return None
    if status is ReferenceStatus.OUTSIDE_ROOT:
        return "escape"
    if status is ReferenceStatus.UNSUPPORTED:
        if reference.reason == "control":
            return "control"
        if reference.reason in _WINDOWS_REASONS:
            return None if settings.windows_path_policy == "off" else reference.reason
        # Safe UNSUPPORTED: templates, globs, query strings, empty targets.
        return None

    # RESOLVED: lexically inside the root.
    if settings.decode_percent_paths and _RESIDUAL_ENCODING_RE.search(unquote(target.partition("#")[0])):
        return "residual"
    boundary = reference.boundary if reference.boundary is not None else root
    if reference.path is not None and escapes_via_symlink(boundary, reference.path):
        return "symlink"
    return None


def _echo(raw_target: str) -> str:
    """Return a bounded, repr-escaped echo of the author's raw target.

    The target is first bounded to :data:`_MAX_ECHO` characters, then escaped with
    ``unicode_escape`` so control bytes, ``ESC`` sequences, and non-ASCII bytes
    become printable ``\\xNN``/``\\uNNNN`` forms before the string reaches any
    report sink. The resolved path is never echoed.

    :param raw_target: The reference target exactly as written.
    :returns: The bounded, escaped echo with a trailing ``...`` when truncated.
    """
    bounded = raw_target[:_MAX_ECHO]
    escaped = bounded.encode("unicode_escape").decode("ascii")
    return f"{escaped}..." if len(raw_target) > _MAX_ECHO else escaped


def _build_message(reason: str, raw_target: str) -> str:
    """Return the smallest meaningful ``DS116`` message for a violation.

    :param reason: A key of :data:`_REASON_TEXT`.
    :param raw_target: The author's raw reference target.
    :returns: Fixed diagnostic text plus the bounded, escaped raw target.
    """
    return f"{_REASON_TEXT[reason]}: {_echo(raw_target)}"


def _comment_filter(comment_starts: list[int], comment_ends: list[int], offset: int) -> bool:
    """Return whether a source offset falls inside any HTML comment range.

    :param comment_starts: Sorted comment start offsets.
    :param comment_ends: Comment end offsets aligned with ``comment_starts``.
    :param offset: The token's start offset.
    :returns: ``True`` when the offset is inside a comment (an example to skip).
    """
    index = bisect_right(comment_starts, offset) - 1
    return index >= 0 and offset < comment_ends[index]


def check_text(
    text: str,
    document_path: str,
    root: Path,
    config: Optional[Config] = None,
    *,
    link_root: Optional[Path] = None,
) -> tuple[models.Finding, ...]:
    """Return ``DS116`` findings for one document's Markdown ``text``.

    Unlike the config-only ``check_text`` of other fast rules, ``DS116`` needs the
    scan ``root`` to decide containment, so the root is a required argument. The
    analyzer validates inline links, image sources (Markdown and HTML tags),
    reference-definition targets, and explicit path-like code spans; targets inside
    fenced code or HTML comments are treated as examples and skipped. One finding
    is emitted per offending reference at its one-based source line, in stable
    source order, with duplicate ``(line, message)`` pairs collapsed.

    With ``root_escape_policy = "off"`` no findings are produced. Severity is
    ``"warning"`` under ``root_escape_policy = "warn"`` and ``"error"`` (the rule
    default, blocking) otherwise; the :class:`~docsentinel.rules.Rule` metadata
    severity stays ``error`` regardless.

    :param text: The Markdown source text exactly as read.
    :param document_path: POSIX-style relative path recorded on each finding.
    :param root: The canonical scan root used for containment.
    :param config: Effective settings, or ``None`` for defaults.
    :param link_root: Precomputed base for ``/`` targets; ``None`` resolves it from
        ``config`` via :func:`~docsentinel.link_root.link_root_for`.
    :returns: Findings in source order, one per offending reference.
    :raises ConfigError: When ``link_root`` must be resolved here and is invalid.
    """
    settings = config if config is not None else Config()
    if settings.root_escape_policy == "off":
        return ()
    severity = "warning" if settings.root_escape_policy == "warn" else DS116.severity
    base = link_root if link_root is not None else link_root_for(root, settings)

    index = scan_markdown(text, document_path)
    comment_starts: list[int] = []
    comment_ends: list[int] = []
    for comment in index.comments:
        comment_starts.append(comment.span.start_offset)
        comment_ends.append(comment.span.end_offset)

    # Each candidate carries whether it is an inline code span, because the code-span
    # scope (Story 11.0 ruling) is narrower than the full-reference scope: a code span
    # reports only real traversal (root escape, residual encoding, in-root symlink-out),
    # never the drive/UNC/backslash/control categories that are documentation there.
    candidates: list[tuple[int, int, str, bool]] = []
    for reference in index.local_references:
        candidates.append(
            (reference.span.start_offset, reference.span.start_line, _first_token(reference.raw_target), False)
        )
    for image in index.images:
        if image.html:
            candidates.append((image.span.start_offset, image.span.start_line, _first_token(image.raw_target), False))
    for definition in index.reference_definitions:
        candidates.append(
            (definition.span.start_offset, definition.span.start_line, _first_token(definition.target), False)
        )
    for code in index.inline_code:
        candidate = code.text.strip()
        if _looks_path_like(candidate):
            candidates.append((code.span.start_offset, code.span.start_line, candidate, True))

    findings: list[models.Finding] = []
    seen: set[tuple[int, str]] = set()
    for offset, line, raw_target, is_code_span in sorted(candidates):
        if not raw_target or _comment_filter(comment_starts, comment_ends, offset):
            continue
        reason = _classify(root, document_path, raw_target, settings, base)
        if reason is None:
            continue
        if is_code_span and reason in _CODE_SPAN_EXEMPT_REASONS:
            # Drive/UNC/backslash/control inside a code span is a documented literal
            # example, not a reference; DS103 reports those with its legacy behaviour.
            continue
        message = _build_message(reason, raw_target)
        key = (line, message)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            models.Finding(rule=DS116.code, path=document_path, message=message, severity=severity, line=line)
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
    """Return ``DS116`` findings for Markdown documents in their supplied order.

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
    if settings.root_escape_policy == "off":
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


rules.ANALYZERS[DS116.code] = detect
