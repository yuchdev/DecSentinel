"""Configuration for local, deterministic scans."""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_CONFIG_OPTIONS = {
    "include",
    "exclude",
    "profile",
    "select",
    "ignore",
    "baseline",
    "max_grade_level",
    "duplicate_similarity",
    "min_information_score",
    "docsig_paths",
    # Standard-profile statistical size limits (DS201, DS202, DS203).
    "min_document_words",
    "min_paragraph_words",
    "min_paragraph_chars",
    "deep_confirm",
    # Story 02 — anchor identity and collisions (DS104).
    "anchor_collision_policy",
    "anchor_renderer",
    # Story 03 — heading hierarchy validation (DS105).
    "heading_level_policy",
    "first_heading_level",
    "multiple_h1_policy",
    "setext_heading_support",
    # Story 04 — contentless section detection (DS106).
    "empty_section_policy",
    "placeholder_content_policy",
    "image_content_counts",
    "empty_section_min_text_chars",
    # Story 05 — reference definition integrity (DS108).
    "unused_reference_definitions",
    "duplicate_reference_definitions",
    "reference_label_normalization",
    # Story 06 — fenced code boundary validation (DS109).
    "fence_dialect",
    "report_stray_closing_fence",
    # Story 07 — code fence language policy (DS110).
    "require_fence_languages",
    "allow_unlabelled_empty_fences",
    "allowed_fence_languages",
    # Story 08 — pipe table structural validation (DS117).
    "table_dialect",
    "table_strict_cells",
    "table_enable",
    # Story 09 — configured navigation integrity (DS112).
    "navigation_indexes",
    "navigation_required",
    "navigation_unique_targets",
    "navigation_check_missing",
    # Story 10 — missing local media assets (DS113).
    "asset_extensions",
    "check_html_asset_tags",
    "check_markdown_images",
    "check_srcset",
    "missing_asset_policy",
    # Story 11 — repository root path boundaries (DS116).
    "root_escape_policy",
    "decode_percent_paths",
    "windows_path_policy",
    # Story 12 — document identity uniqueness (DS114).
    "document_id_field",
    "document_id_scope",
    "document_id_case_sensitive",
    "document_id_required",
    # Story 13 — deprecated reference and terminology (DS115).
    "deprecated_references_file",
    "deprecated_check_prose",
    "deprecated_check_links",
    "deprecated_case_sensitive",
    # Story 14 — documentation path naming policy (DS118).
    "documentation_naming",
    "documentation_naming_allow",
    "documentation_naming_directories",
    "documentation_naming_prefix_patterns",
    # Milestone 0007 Story 03.0 — template-driven reporting.
    "report_templates_dir",
    "report_show_clean_documents",
    "report_include_run_meta",
    # Milestone 0007 Story 04.0 — report extensions (builtin-only in config).
    "telemetry_extensions",
}
# Standalone config file names accepted at the scan root: the preferred name first, then the alias.
STANDALONE_CONFIG_NAMES = ("docsentinel.toml", "doc_sentinel.toml")
_SELECTOR_PATTERN = re.compile(r"DS\d*")

#: A ``telemetry_extensions`` entry: ``builtin:`` plus an extension name matching
#: ``docsentinel.telemetry.extensions.EXTENSION_NAME_PATTERN`` (a test pins parity).
#: Configuration may name only builtin extensions (threat model 0007-extensions M1).
_BUILTIN_EXTENSION_SPEC_PATTERN = re.compile(r"builtin:[a-z][a-z0-9_]{0,63}")

#: Most ``telemetry_extensions`` entries accepted.
MAX_TELEMETRY_EXTENSIONS = 32

# A ``document_id_field`` (the frontmatter key DS114 reads) must be a simple,
# identifier-like key name, bounded in length so a pathological config value can
# never drive an unbounded key comparison in the detector.
_DOCUMENT_ID_FIELD_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,127}")

# Enum-valued options and their accepted vocabularies. Where a milestone
# specification fixes a single value (for example ``anchor_renderer`` or the
# dialect options), only that value is accepted until a story widens it.
_ENUM_OPTIONS: dict[str, frozenset[str]] = {
    "anchor_collision_policy": frozenset({"off", "explicit"}),
    "anchor_renderer": frozenset({"github"}),
    "heading_level_policy": frozenset({"off", "no-skips"}),
    "multiple_h1_policy": frozenset({"allow", "warn"}),
    "empty_section_policy": frozenset({"off", "leaf", "all"}),
    "placeholder_content_policy": frozenset({"ignore", "count"}),
    "duplicate_reference_definitions": frozenset({"off", "warn", "error"}),
    "reference_label_normalization": frozenset({"commonmark"}),
    "fence_dialect": frozenset({"gfm-subset"}),
    "table_dialect": frozenset({"gfm-subset"}),
    "missing_asset_policy": frozenset({"off", "warn", "error"}),
    "root_escape_policy": frozenset({"off", "warn", "error"}),
    "windows_path_policy": frozenset({"off", "portable"}),
    "document_id_scope": frozenset({"corpus", "directory"}),
    "documentation_naming": frozenset({"off", "kebab", "snake"}),
}

# Boolean-valued options, paired with the ``Config`` attribute defaults.
_BOOL_OPTIONS = (
    "setext_heading_support",
    "image_content_counts",
    "unused_reference_definitions",
    "report_stray_closing_fence",
    "require_fence_languages",
    "allow_unlabelled_empty_fences",
    "table_strict_cells",
    "table_enable",
    "navigation_unique_targets",
    "navigation_check_missing",
    "check_html_asset_tags",
    "check_markdown_images",
    "check_srcset",
    "decode_percent_paths",
    "document_id_case_sensitive",
    "document_id_required",
    "deprecated_check_prose",
    "deprecated_check_links",
    "deprecated_case_sensitive",
    "documentation_naming_directories",
    "report_show_clean_documents",
    "report_include_run_meta",
)

# Options holding a list of nonempty, non-path strings.
_STR_LIST_OPTIONS = (
    "allowed_fence_languages",
    "asset_extensions",
    "documentation_naming_allow",
    "documentation_naming_prefix_patterns",
)

# Options holding a list of nonempty relative paths that must stay under root.
_ROOT_PATH_LIST_OPTIONS = (
    "navigation_indexes",
    "navigation_required",
)


class ConfigError(ValueError):
    """An invalid or unreadable DocSentinel configuration."""


@dataclass(frozen=True)
class Config:
    """Immutable settings for a DocSentinel scan.

    .. note::

       :func:`load_config` validates every option (enum vocabularies, ranges,
       path containment) before constructing this dataclass. Constructing
       ``Config(...)`` directly, as a library caller may, bypasses that
       load-time validation: the field values are trusted as given, so callers
       that build a ``Config`` by hand are responsible for passing valid values.

    :ivar include: Glob patterns of Markdown documents to inventory.
    :ivar exclude: Glob/directory patterns removed from the inventory.
    :ivar profile: Active profile, one of ``fast``, ``standard``, ``deep``.
    :ivar select: Rule codes or prefixes to activate; empty selects all.
    :ivar ignore: Rule codes or prefixes to suppress; wins over ``select``.
    :ivar baseline: Path to a baseline JSON file, or ``None``.
    :ivar max_grade_level: Maximum acceptable readability grade for ``DS201``.
    :ivar duplicate_similarity: Cosine-similarity threshold for ``DS202``.
    :ivar min_information_score: Minimum information score for ``DS203``.
    :ivar docsig_paths: Python source roots scanned by ``DS204``.
    :ivar min_document_words: Minimum prose-word count before ``DS201`` scores a
        document. Documents with fewer prose words (after Markdown stripping) are
        skipped, so short notes are never penalised for readability. Integer
        ``>= 1``; the default ``50`` reproduces the historical built-in floor.
    :ivar min_paragraph_words: Minimum prose-word count for a paragraph to enter
        the ``DS202``/``DS203`` corpus. Paragraphs with fewer words are not
        analysed. Integer ``>= 1``; the default ``5`` reproduces the historical
        built-in floor.
    :ivar min_paragraph_chars: Minimum visible-character count for a paragraph to
        enter the ``DS202``/``DS203`` corpus. Paragraphs shorter than this are not
        analysed. A paragraph must clear **both** this and ``min_paragraph_words``.
        Integer ``>= 0``; the default ``30`` reproduces the historical built-in
        floor.
    :ivar deep_confirm: Whether the deep profile is explicitly confirmed.
    :ivar anchor_collision_policy: ``DS104`` collision policy.
    :ivar anchor_renderer: Renderer whose slugging ``DS104`` emulates.
    :ivar heading_level_policy: ``DS105`` heading-level policy.
    :ivar first_heading_level: Expected first heading level (1..6) for ``DS105``.
    :ivar multiple_h1_policy: Policy for repeated H1 headings.
    :ivar setext_heading_support: Whether setext headings participate in ``DS105``.
    :ivar empty_section_policy: ``DS106`` contentless-section policy.
    :ivar placeholder_content_policy: Whether HTML comments count as ``DS106`` content.
    :ivar image_content_counts: Whether an image counts as section content.
    :ivar empty_section_min_text_chars: ``DS106`` visible-text threshold. A section is
        flagged when its visible non-whitespace character count is ``<=`` this value,
        so a section must carry **strictly more** than ``empty_section_min_text_chars``
        visible characters to count as non-empty; the default ``0`` means any visible
        text at all is enough. Positive values are deferred to the ``DS203`` quality
        policy, so a caller who sets ``5`` should expect sections with exactly five
        visible characters to be flagged.
    :ivar unused_reference_definitions: Whether unused definitions warn (``DS108``).
    :ivar duplicate_reference_definitions: ``DS108`` duplicate-definition policy.
    :ivar reference_label_normalization: Reference-label normalization dialect.
    :ivar fence_dialect: Fenced-code dialect recognized by ``DS109``.
    :ivar report_stray_closing_fence: Whether unattached closers are reported.
    :ivar require_fence_languages: Whether ``DS110`` requires a fence language.
    :ivar allow_unlabelled_empty_fences: Whether empty fences may be unlabelled.
    :ivar allowed_fence_languages: Allowlist of fence languages; empty allows all.
    :ivar table_dialect: Pipe-table dialect recognized by ``DS117``.
    :ivar table_strict_cells: Whether ``DS117`` enforces consistent cell counts.
    :ivar table_enable: Whether the ``DS117`` table check runs.
    :ivar navigation_indexes: Navigation index documents inspected by ``DS112``.
    :ivar navigation_required: Documents required to appear in navigation.
    :ivar navigation_unique_targets: Whether navigation targets must be unique.
    :ivar navigation_check_missing: Whether missing navigation targets warn.
    :ivar asset_extensions: Media extensions ``DS113`` treats as local assets.
    :ivar check_html_asset_tags: Whether ``DS113`` inspects HTML media tags.
    :ivar check_markdown_images: Whether ``DS113`` inspects Markdown images.
    :ivar check_srcset: Whether ``DS113`` inspects ``srcset`` candidates.
    :ivar missing_asset_policy: ``DS113`` severity policy for a missing or
        non-regular local asset (``"off"``/``"warn"``/``"error"``), mirroring
        ``root_escape_policy``: ``"off"`` suppresses the rule with no filesystem
        access, ``"warn"`` downgrades each finding to ``warning`` severity, and
        ``"error"`` (the default, blocking) keeps the rule's ``error`` severity.
        The :class:`~docsentinel.rules.Rule` metadata severity stays ``error``
        regardless of this policy.
    :ivar root_escape_policy: ``DS116`` root-escape policy.
    :ivar decode_percent_paths: Whether percent-encoded paths are decoded once.
    :ivar windows_path_policy: ``DS116`` Windows path portability policy.
    :ivar document_id_field: Front-matter key carrying the document identity.
    :ivar document_id_scope: Scope within which identities must be unique.
    :ivar document_id_case_sensitive: Whether identity comparison is case-sensitive.
    :ivar document_id_required: Whether every document must declare an identity.
    :ivar deprecated_references_file: Mapping file of deprecated names, or empty.
    :ivar deprecated_check_prose: Whether ``DS115`` scans prose for deprecated names.
    :ivar deprecated_check_links: Whether ``DS115`` scans link targets.
    :ivar deprecated_case_sensitive: Whether deprecated matching is case-sensitive.
    :ivar documentation_naming: ``DS118`` naming policy (``off``/``kebab``/``snake``).
    :ivar documentation_naming_allow: Exempt file names for ``DS118``.
    :ivar documentation_naming_directories: Whether ``DS118`` checks directories.
    :ivar documentation_naming_prefix_patterns: Validated prefix exceptions.
    :ivar report_templates_dir: Directory, relative to the scan root, holding extra
        report templates selectable by name with ``--format``, or ``None``. Validated
        lexically here; the template loader re-applies the full containment gate
        (no symlink out of the root) before listing or opening anything in it.
    :ivar report_show_clean_documents: Whether the text report also lists documents
        without problems (``--show-clean-documents``).
    :ivar report_include_run_meta: Whether the report context carries the per-run
        ``run.generated_at``/``run.id`` values; off keeps reports deterministic.
    :ivar telemetry_extensions: Report extension specs, ``builtin:<name>`` only
        (threat model 0007-extensions M1): a ``python:`` spec is accepted only from
        the command line, never from configuration. The extension resolver
        re-checks an injected ``Config`` with :func:`validate_telemetry_extensions`.
    """

    include: tuple[str, ...] = ("*.md", "**/*.md")
    exclude: tuple[str, ...] = (".git", ".venv", "node_modules")
    profile: str = "fast"
    select: tuple[str, ...] = ()
    ignore: tuple[str, ...] = ()
    baseline: Optional[str] = None
    max_grade_level: float = 14.0
    duplicate_similarity: float = 0.85
    min_information_score: float = 0.15
    docsig_paths: tuple[str, ...] = ("src",)
    min_document_words: int = 50
    min_paragraph_words: int = 5
    min_paragraph_chars: int = 30
    deep_confirm: bool = False
    anchor_collision_policy: str = "explicit"
    anchor_renderer: str = "github"
    heading_level_policy: str = "no-skips"
    first_heading_level: int = 1
    multiple_h1_policy: str = "allow"
    setext_heading_support: bool = True
    empty_section_policy: str = "leaf"
    placeholder_content_policy: str = "ignore"
    image_content_counts: bool = True
    empty_section_min_text_chars: int = 0
    unused_reference_definitions: bool = False
    duplicate_reference_definitions: str = "warn"
    reference_label_normalization: str = "commonmark"
    fence_dialect: str = "gfm-subset"
    report_stray_closing_fence: bool = False
    require_fence_languages: bool = False
    allow_unlabelled_empty_fences: bool = True
    allowed_fence_languages: tuple[str, ...] = ()
    table_dialect: str = "gfm-subset"
    table_strict_cells: bool = True
    table_enable: bool = True
    navigation_indexes: tuple[str, ...] = ()
    navigation_required: tuple[str, ...] = ()
    navigation_unique_targets: bool = True
    navigation_check_missing: bool = True
    asset_extensions: tuple[str, ...] = ("png", "jpg", "jpeg", "svg", "webp", "gif", "pdf")
    check_html_asset_tags: bool = True
    check_markdown_images: bool = True
    check_srcset: bool = True
    missing_asset_policy: str = "error"
    root_escape_policy: str = "error"
    decode_percent_paths: bool = True
    windows_path_policy: str = "portable"
    document_id_field: str = "id"
    document_id_scope: str = "corpus"
    document_id_case_sensitive: bool = True
    document_id_required: bool = False
    deprecated_references_file: str = ""
    deprecated_check_prose: bool = True
    deprecated_check_links: bool = True
    deprecated_case_sensitive: bool = True
    documentation_naming: str = "off"
    documentation_naming_allow: tuple[str, ...] = ("README.md", "index.md")
    documentation_naming_directories: bool = True
    documentation_naming_prefix_patterns: tuple[str, ...] = ()
    report_templates_dir: Optional[str] = None
    report_show_clean_documents: bool = False
    report_include_run_meta: bool = False
    telemetry_extensions: tuple[str, ...] = ()


def validate_telemetry_extensions(value: object) -> tuple[str, ...]:
    """Return the validated ``telemetry_extensions`` entries, builtin specs only (M1).

    Every entry must be ``builtin:<name>``; any other entry, every ``python:`` spec
    included, is refused whatever the trust gate says, so a scanned repository's
    configuration can never choose code to execute. The rejected value is never
    echoed: it is repository-controlled.

    :param value: The configured list (a ``list`` from TOML, or the ``tuple`` of an
        injected :class:`Config`).
    :returns: The entries as a tuple, in configured order.
    :raises ConfigError: For a non-list, more than :data:`MAX_TELEMETRY_EXTENSIONS`
        entries, a non-``builtin:`` or malformed entry, or a duplicate entry.
    """
    if not isinstance(value, (list, tuple)):
        raise ConfigError("telemetry_extensions must be a list of builtin:<name> extension specs")
    if len(value) > MAX_TELEMETRY_EXTENSIONS:
        raise ConfigError(f"telemetry_extensions holds more than {MAX_TELEMETRY_EXTENSIONS} entries")
    seen: set[str] = set()
    for position, item in enumerate(value):
        if type(item) is not str or _BUILTIN_EXTENSION_SPEC_PATTERN.fullmatch(item) is None:
            raise ConfigError(
                f"telemetry_extensions[{position}] is not a builtin:<name> spec; configuration may name only "
                "builtin extensions"
            )
        if item in seen:
            raise ConfigError(f"telemetry_extensions[{position}] repeats an earlier entry")
        seen.add(item)
    return tuple(value)


def _require_bool(name: str, value: object) -> bool:
    """Return ``value`` when it is a real boolean, else raise ``ConfigError``.

    :param name: Option name used in the error message.
    :param value: Candidate value from the TOML table.
    :returns: The validated boolean.
    """
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false")
    return value


def _require_bounded_int(name: str, value: object, minimum: int) -> int:
    """Return ``value`` when it is an ``int`` at or above ``minimum``, else raise ``ConfigError``.

    Real booleans and floats (even integral ones such as ``5.0``) are rejected,
    matching the strictness of the other numeric options.

    :param name: Option name used in the error message.
    :param value: Candidate value from the TOML table.
    :param minimum: The smallest accepted integer value.
    :returns: The validated integer.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        requirement = "a non-negative integer" if minimum == 0 else f"an integer >= {minimum}"
        raise ConfigError(f"{name} must be {requirement}")
    return value


def _require_enum(name: str, value: object, allowed: frozenset[str]) -> str:
    """Return ``value`` when it is one of ``allowed``, else raise ``ConfigError``.

    :param name: Option name used in the error message.
    :param value: Candidate value from the TOML table.
    :param allowed: The accepted vocabulary for this option.
    :returns: The validated string.
    """
    if not isinstance(value, str) or value not in allowed:
        joined = ", ".join(sorted(allowed))
        raise ConfigError(f"{name} must be one of: {joined}")
    return value


def _require_str_list(name: str, value: object) -> tuple[str, ...]:
    """Return a tuple of nonempty strings, else raise ``ConfigError``.

    :param name: Option name used in the error message.
    :param value: Candidate value from the TOML table.
    :returns: The validated strings as a tuple.
    """
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError(f"{name} must be a list of nonempty strings")
    return tuple(value)


def _require_fence_language_list(name: str, value: object) -> tuple[str, ...]:
    """Return a tuple of single-token fence languages, else raise ``ConfigError``.

    A fence language is the first whitespace-delimited token of a fence info
    string, so an allowlist entry that itself contains whitespace (``"python
    bash"``, a leading space, or an embedded tab) could never match any single
    fence language and almost certainly signals a malformed config. Such entries
    are rejected; ordinary tokens with punctuation such as ``"c++"`` or
    ``"objective-c"`` remain valid.

    :param name: Option name used in the error message.
    :param value: Candidate value from the TOML table.
    :returns: The validated single-token languages as a tuple.
    """
    languages = _require_str_list(name, value)
    for language in languages:
        if any(character.isspace() for character in language):
            raise ConfigError(f"{name} entries must be single tokens without whitespace: {language!r}")
    return languages


def _is_within_root(path_part: str) -> bool:
    """Return whether a relative path stays lexically within the scan root.

    The check is lexical and performs no filesystem access: absolute paths,
    Windows drive/UNC paths, backslash separators, and ``..`` escapes above the
    root are rejected.

    :param path_part: A candidate ``/``-separated relative path.
    :returns: ``True`` when the path is root-relative and does not escape.
    """
    if path_part.startswith("/") or "\\" in path_part:
        return False
    if re.match(r"^[A-Za-z]:", path_part):
        return False
    depth = 0
    for part in path_part.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if depth == 0:
                return False
            depth -= 1
        else:
            depth += 1
    return True


def _require_root_path_list(name: str, value: object) -> tuple[str, ...]:
    """Return a tuple of root-relative paths, else raise ``ConfigError``.

    :param name: Option name used in the error message.
    :param value: Candidate value from the TOML table.
    :returns: The validated paths as a tuple.
    """
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError(f"{name} must be a list of nonempty paths under the scan root")
    for item in value:
        if not _is_within_root(item):
            raise ConfigError(f"{name} entries must stay within the scan root: {item}")
    return tuple(value)


def _load_toml_table(source: Path, *, wrapped: bool) -> dict[str, object]:
    """Load and validate options from a standalone or pyproject TOML table.

    :param source: The TOML file to read.
    :param wrapped: Whether to unwrap a ``[tool.doc_sentinel]`` table.
    :returns: The raw options mapping.
    """
    try:
        with source.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read {source}: {exc}") from exc

    options: object = data
    if wrapped:
        tool = data.get("tool")
        if not isinstance(tool, dict) or "doc_sentinel" not in tool:
            return {}
        options = tool["doc_sentinel"]
        if not isinstance(options, dict):
            raise ConfigError("Unknown config options: tool.doc_sentinel must be a table")

    unknown = set(options) - _CONFIG_OPTIONS
    if unknown:
        raise ConfigError(f"Unknown config options: {', '.join(sorted(unknown))}")
    return options


def load_config(root: Path, path: Optional[Path] = None) -> Config:
    """Load an explicit config or discover root-level DocSentinel settings.

    A standalone ``docsentinel.toml`` (or its alias ``doc_sentinel.toml``) wins
    over ``[tool.doc_sentinel]`` in ``pyproject.toml``; when none exists,
    defaults are returned. Both standalone names in one root is ambiguous and
    raises :class:`ConfigError`. An explicit ``path`` bypasses discovery. A :class:`Config` injected directly by a
    library caller is used verbatim by the engine and never consults files.

    :param root: The scan root directory used for discovery.
    :param path: An explicit config file, or ``None`` to discover one.
    :returns: The validated :class:`Config`.
    """
    if path is not None:
        source = path
        wrapped = source.name == "pyproject.toml"
    else:
        standalones = [root / name for name in STANDALONE_CONFIG_NAMES if (root / name).exists()]
        pyproject = root / "pyproject.toml"
        if len(standalones) > 1:
            names = " and ".join(path.name for path in standalones)
            raise ConfigError(f"found both {names} in {root}; keep only one")
        if standalones:
            source = standalones[0]
            wrapped = False
        elif pyproject.exists():
            source = pyproject
            wrapped = True
        else:
            return Config()

    options = _load_toml_table(source, wrapped=wrapped)
    defaults = Config()
    include = options.get("include", list(defaults.include))
    exclude = options.get("exclude", list(defaults.exclude))
    profile = options.get("profile", defaults.profile)
    select = options.get("select", list(defaults.select))
    ignore = options.get("ignore", list(defaults.ignore))
    baseline = options.get("baseline", defaults.baseline)
    max_grade_level = options.get("max_grade_level", defaults.max_grade_level)
    duplicate_similarity = options.get("duplicate_similarity", defaults.duplicate_similarity)
    min_information_score = options.get("min_information_score", defaults.min_information_score)
    docsig_paths = options.get("docsig_paths", list(defaults.docsig_paths))
    deep_confirm = options.get("deep_confirm", defaults.deep_confirm)
    for name, value in (("include", include), ("exclude", exclude)):
        if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
            raise ConfigError(f"{name} must be a list of nonempty patterns")
    if not isinstance(docsig_paths, list) or not all(isinstance(item, str) and item for item in docsig_paths):
        raise ConfigError("docsig_paths must be a list of nonempty paths")
    for name, value in (("select", select), ("ignore", ignore)):
        if not isinstance(value, list) or not all(
            isinstance(item, str) and _SELECTOR_PATTERN.fullmatch(item) for item in value
        ):
            raise ConfigError(f"{name} must be a list of DS rule codes or prefixes")
    if not isinstance(profile, str) or profile not in ("fast", "standard", "deep"):
        raise ConfigError("profile must be fast, standard, or deep")
    if baseline is not None and (not isinstance(baseline, str) or not baseline):
        raise ConfigError("baseline must be a nonempty string")
    if not isinstance(max_grade_level, (int, float)) or isinstance(max_grade_level, bool) or max_grade_level <= 0:
        raise ConfigError("max_grade_level must be a positive number")
    if (
        not isinstance(duplicate_similarity, (int, float))
        or isinstance(duplicate_similarity, bool)
        or not (0.0 <= float(duplicate_similarity) <= 1.0)
    ):
        raise ConfigError("duplicate_similarity must be a number between 0 and 1")
    if (
        not isinstance(min_information_score, (int, float))
        or isinstance(min_information_score, bool)
        or not (0.0 <= float(min_information_score) <= 1.0)
    ):
        raise ConfigError("min_information_score must be a number between 0 and 1")
    if not isinstance(deep_confirm, bool):
        raise ConfigError("deep_confirm must be true or false")

    extra = _load_extra_options(options, defaults)

    return Config(
        include=tuple(include),
        exclude=tuple(exclude),
        profile=profile,
        select=tuple(select),
        ignore=tuple(ignore),
        baseline=baseline,
        max_grade_level=float(max_grade_level),
        duplicate_similarity=float(duplicate_similarity),
        min_information_score=float(min_information_score),
        docsig_paths=tuple(docsig_paths),
        deep_confirm=deep_confirm,
        **extra,
    )


def _load_extra_options(options: dict[str, object], defaults: Config) -> dict[str, object]:
    """Validate the Story 02–14 and Milestone 0007 typed options into ``Config`` keyword arguments.

    :param options: The raw options mapping from the TOML table.
    :param defaults: A default :class:`Config` used to source field defaults.
    :returns: A mapping of validated keyword arguments for :class:`Config`.
    """
    extra: dict[str, object] = {}
    for name in _BOOL_OPTIONS:
        extra[name] = _require_bool(name, options.get(name, getattr(defaults, name)))
    for name, allowed in _ENUM_OPTIONS.items():
        extra[name] = _require_enum(name, options.get(name, getattr(defaults, name)), allowed)
    for name in _STR_LIST_OPTIONS:
        if name in options:
            validate = _require_fence_language_list if name == "allowed_fence_languages" else _require_str_list
            extra[name] = validate(name, options[name])
        else:
            extra[name] = getattr(defaults, name)
    for name in _ROOT_PATH_LIST_OPTIONS:
        if name in options:
            extra[name] = _require_root_path_list(name, options[name])
        else:
            extra[name] = getattr(defaults, name)

    first_heading_level = options.get("first_heading_level", defaults.first_heading_level)
    if (
        not isinstance(first_heading_level, int)
        or isinstance(first_heading_level, bool)
        or not (1 <= first_heading_level <= 6)
    ):
        raise ConfigError("first_heading_level must be an integer between 1 and 6")
    extra["first_heading_level"] = first_heading_level

    min_text_chars = options.get("empty_section_min_text_chars", defaults.empty_section_min_text_chars)
    if not isinstance(min_text_chars, int) or isinstance(min_text_chars, bool) or min_text_chars < 0:
        raise ConfigError("empty_section_min_text_chars must be a non-negative integer")
    extra["empty_section_min_text_chars"] = min_text_chars

    for name, minimum in (("min_document_words", 1), ("min_paragraph_words", 1), ("min_paragraph_chars", 0)):
        extra[name] = _require_bounded_int(name, options.get(name, getattr(defaults, name)), minimum)

    document_id_field = options.get("document_id_field", defaults.document_id_field)
    if not isinstance(document_id_field, str) or not document_id_field:
        raise ConfigError("document_id_field must be a nonempty string")
    if not _DOCUMENT_ID_FIELD_PATTERN.fullmatch(document_id_field):
        raise ConfigError(
            "document_id_field must be a simple key name: a letter or underscore "
            "followed by letters, digits, underscores or hyphens, at most 128 characters"
        )
    extra["document_id_field"] = document_id_field

    deprecated_file = options.get("deprecated_references_file", defaults.deprecated_references_file)
    if not isinstance(deprecated_file, str):
        raise ConfigError("deprecated_references_file must be a path string under the scan root")
    if deprecated_file and not _is_within_root(deprecated_file):
        raise ConfigError("deprecated_references_file must stay within the scan root")
    extra["deprecated_references_file"] = deprecated_file

    templates_dir = options.get("report_templates_dir", defaults.report_templates_dir)
    if templates_dir is not None:
        if not isinstance(templates_dir, str) or not templates_dir:
            raise ConfigError("report_templates_dir must be a nonempty directory path under the scan root")
        if not _is_within_root(templates_dir):
            raise ConfigError("report_templates_dir must stay within the scan root")
    extra["report_templates_dir"] = templates_dir

    extra["telemetry_extensions"] = validate_telemetry_extensions(
        options.get("telemetry_extensions", list(defaults.telemetry_extensions))
    )

    return extra
