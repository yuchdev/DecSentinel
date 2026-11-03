"""``builtin:domain``: a path -> domain label for reports and fault events (Story 04.0 Task 02).

A document's domain (``docs``, ``agent``, ...) is assigned from its scan-root-relative
path by the ordered ``telemetry_domains`` table: the first entry whose glob matches
wins, and :data:`DEFAULT_DOMAIN` (``"docs"``) applies when none does. The label is
asserted by the scanned repository, not authenticated (threat model 0007-extensions
residual R5).

:func:`domain_for` is the **single** source of the label. The report model sets the
core ``doc.domain`` from it, :func:`docsentinel.telemetry.classify.classify` puts it on
every :class:`~docsentinel.telemetry.classify.Classification`, and the Milestone 0006
fault-event adapter calls it with the same effective ``Config``, so the report and the
event stream cannot disagree (M24).

Mitigations implemented here (``docs/security/threat-model-0007-extensions-2026-11-03.md``):

* **M20/M22** -- the table is re-validated (grammar and bounds) for an injected
  ``Config`` with :func:`docsentinel.config.validate_telemetry_domains`; anything
  invalid is a fail-closed ``ConfigError``.
* **M21** -- matching is a non-regex, segment-wise dynamic program over the ``/``
  segments of the glob and the path, ``O(glob segments x path segments x segment
  cost)``. The per-segment step is a two-pointer walk with single-star backtracking
  (the same algorithm as DS118's ``_glob_matches``). No ``re`` pattern is compiled
  from configured text and ``fnmatch`` is never used. Matching is case-sensitive
  over the path exactly as discovered: no NFC, no ``realpath``, no filesystem access.
* **M18** -- results are memoized per path, and the validated table is built once
  per ``Config``.
* **M23** -- array order is kept; first match wins.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final, Optional

from docsentinel.config import Config, validate_telemetry_domains, validate_telemetry_extensions

#: Domain of a document no ``telemetry_domains`` entry matches, and of every document
#: while ``builtin:domain`` is not loaded. Re-exported as
#: ``docsentinel.telemetry.classify.DEFAULT_DOMAIN``.
DEFAULT_DOMAIN: Final[str] = "docs"

#: The extension name and its selecting spec.
EXTENSION_NAME: Final[str] = "domain"
EXTENSION_SPEC: Final[str] = f"builtin:{EXTENSION_NAME}"

#: The glob segment that matches zero or more whole path segments.
_ANY_SEGMENTS: Final[str] = "**"

#: Bound on memoized paths per table; the memo is cleared when it is reached.
_MAX_MEMO: Final[int] = 1 << 20


def segment_matches(pattern: str, text: str) -> bool:
    """Return whether one path segment matches one glob segment (no regex).

    ``?`` matches exactly one character, ``*`` any (possibly empty) run of
    characters, everything else itself. Segments never contain ``/``, so neither
    wildcard can cross a separator. A linear two-pointer walk with single-star
    backtracking: ``O(len(pattern) x len(text))`` in the worst case, never
    exponential.

    :param pattern: A validated glob segment other than ``**``.
    :param text: A path segment.
    :returns: ``True`` when the whole segment matches the whole pattern.
    """
    pattern_length = len(pattern)
    text_length = len(text)
    pattern_index = 0
    text_index = 0
    star_index = -1
    star_text = 0
    while text_index < text_length:
        if pattern_index < pattern_length and pattern[pattern_index] in ("?", text[text_index]):
            pattern_index += 1
            text_index += 1
        elif pattern_index < pattern_length and pattern[pattern_index] == "*":
            star_index = pattern_index
            star_text = text_index
            pattern_index += 1
        elif star_index != -1:
            pattern_index = star_index + 1
            star_text += 1
            text_index = star_text
        else:
            return False
    while pattern_index < pattern_length and pattern[pattern_index] == "*":
        pattern_index += 1
    return pattern_index == pattern_length


def glob_matches(pattern: Sequence[str], path: Sequence[str]) -> bool:
    """Return whether a segmented path matches a segmented glob (M21).

    Bottom-up dynamic programming over suffixes: ``row[j]`` says whether the glob
    segments from ``i`` on match the path segments from ``j`` on. A ``**`` segment
    matches zero or more whole segments; any other glob segment matches exactly one
    path segment through :func:`segment_matches`, which is only called when the rest
    of the glob already matches the rest of the path.

    :param pattern: The validated glob segments.
    :param path: The path segments (``path.split("/")``).
    :returns: ``True`` when the whole path matches the whole glob.
    """
    size = len(path)
    following = [False] * size + [True]
    for segment in reversed(pattern):
        row = [False] * (size + 1)
        if segment == _ANY_SEGMENTS:
            row[size] = following[size]
            for index in range(size - 1, -1, -1):
                row[index] = following[index] or row[index + 1]
        else:
            for index in range(size - 1, -1, -1):
                row[index] = following[index + 1] and segment_matches(segment, path[index])
        following = row
    return following[0]


@dataclass(frozen=True)
class DomainTable:
    """The validated ``telemetry_domains`` table of one ``Config``.

    :ivar enabled: Whether ``builtin:domain`` is in the effective
        ``telemetry_extensions``; when it is not, :meth:`domain` always returns
        :data:`DEFAULT_DOMAIN`.
    :ivar entries: ``(glob segments, glob, domain)`` in configured order.
    """

    enabled: bool
    entries: tuple[tuple[tuple[str, ...], str, str], ...]
    _memo: dict[str, tuple[str, Optional[str]]] = field(default_factory=dict, compare=False, repr=False)

    def lookup(self, path: str) -> tuple[str, Optional[str]]:
        """Return the domain of ``path`` and the glob that chose it, ignoring :attr:`enabled`.

        Memoized per path (M18).

        :param path: The scan-root-relative POSIX path, exactly as discovered.
        :returns: ``(domain, glob)`` for the first matching entry, or
            ``(DEFAULT_DOMAIN, None)`` when none matches.
        """
        known = self._memo.get(path)
        if known is not None:
            return known
        found: tuple[str, Optional[str]] = (DEFAULT_DOMAIN, None)
        if self.entries:
            segments = path.split("/")
            for pattern, glob, domain in self.entries:
                if glob_matches(pattern, segments):
                    found = (domain, glob)
                    break
        if len(self._memo) >= _MAX_MEMO:
            self._memo.clear()
        self._memo[path] = found
        return found

    def domain(self, path: str) -> str:
        """Return the domain of ``path``: :data:`DEFAULT_DOMAIN` unless :attr:`enabled`.

        :param path: The scan-root-relative POSIX path.
        :returns: The domain label.
        """
        return self.lookup(path)[0] if self.enabled else DEFAULT_DOMAIN


def _build(config: Config) -> DomainTable:
    """Validate a ``Config``'s domain settings and build its table (M22).

    :param config: The effective configuration.
    :returns: The table.
    :raises ConfigError: For an invalid ``telemetry_domains`` or
        ``telemetry_extensions`` value.
    """
    extensions = validate_telemetry_extensions(config.telemetry_extensions)
    pairs = validate_telemetry_domains(config.telemetry_domains)
    entries = tuple((tuple(glob.split("/")), glob, domain) for glob, domain in pairs)
    return DomainTable(EXTENSION_SPEC in extensions, entries)


#: The last ``(config, table)`` built: a strong reference, so ``is`` identifies it.
_last: tuple[Optional[Config], Optional[DomainTable]] = (None, None)


def domain_table(config: Config) -> DomainTable:
    """Return the validated domain table of ``config``, built once per ``Config`` object.

    Batch callers (the report model, the fault-event adapter) call this once and
    then :meth:`DomainTable.domain` per path. The table is cached for the last
    ``Config`` object seen, so :func:`domain_for` stays cheap per call.

    :param config: The effective configuration.
    :returns: The table.
    :raises ConfigError: For an invalid ``telemetry_domains`` or
        ``telemetry_extensions`` value (an injected ``Config`` is re-checked).
    """
    global _last
    cached_config, cached_table = _last
    if cached_config is config and cached_table is not None:
        return cached_table
    table = _build(config)
    _last = (config, table)
    return table


def domain_for(path: str, config: Config) -> str:
    """Return the domain label of a document path (spec §9; M18, M20-M24).

    The single source of ``doc.domain``, ``Classification.domain`` and the Milestone
    0006 ``FaultEvent.domain``.

    :param path: The scan-root-relative POSIX path, exactly as discovered.
    :param config: The effective configuration (``--extension builtin:domain``
        merged into ``telemetry_extensions``).
    :returns: :data:`DEFAULT_DOMAIN` unless ``builtin:domain`` is in
        ``config.telemetry_extensions``; otherwise the domain of the first matching
        ``telemetry_domains`` entry, or :data:`DEFAULT_DOMAIN` when none matches.
    :raises ConfigError: For an invalid or out-of-bounds table in an injected
        ``Config``.
    """
    return domain_table(config).domain(path)


class DomainExtension:
    """The ``builtin:domain`` report extension.

    ``provide_document`` returns ``{"name": <domain>, "matched": <glob> | null}``
    under ``doc.ext.domain``; ``matched`` is ``null`` when the fallback applied.
    The core ``doc.domain`` is set by the report model from :func:`domain_for`,
    never from this hook (M24). Both values are untrusted in templates (M11).

    :ivar name: The extension name, ``domain``.
    """

    name: Final[str] = EXTENSION_NAME

    def __init__(self, config: Config):
        """Bind the validated domain table of the effective configuration.

        :param config: The configuration the extensions are resolved with.
        :raises ConfigError: For an invalid table in an injected ``Config``.
        """
        self._table = domain_table(config)

    def provide_document(self, doc: Mapping, model: Mapping) -> dict:
        """Return the document's domain and the glob that assigned it.

        :param doc: The frozen document mapping.
        :param model: The frozen run context (unused).
        :returns: ``{"name": str, "matched": Optional[str]}``.
        """
        name, matched = self._table.lookup(doc["path"])
        return {"name": name, "matched": matched}


def make(config: Config) -> DomainExtension:
    """Build the ``builtin:domain`` extension (the static-table factory).

    :param config: The effective configuration.
    :returns: The extension.
    """
    return DomainExtension(config)


__all__ = [
    "DEFAULT_DOMAIN",
    "DomainExtension",
    "DomainTable",
    "domain_for",
    "domain_table",
    "glob_matches",
    "make",
    "segment_matches",
]
