"""Report extensions: API, loader and trust gate (Milestone 0007 Story 04.0 Task 01).

An extension adds data (and optionally filters) to the report context of
``docs/specs/report-template-format.md`` §9. It never touches the renderer. The
normative security contract is ``docs/security/threat-model-0007-extensions-2026-11-03.md``;
the mitigations implemented here are cited by number.

Selection and trust gate:

* **M1** -- ``Config.telemetry_extensions`` may hold only ``builtin:<name>`` specs;
  :func:`resolve_extensions` re-checks an injected ``Config`` with
  :func:`docsentinel.config.validate_telemetry_extensions` (``ConfigError``).
* **M2/M3** -- a ``python:<module>:<callable>`` spec comes only from the invoker
  (argv, or the library ``extensions=`` keyword) and only with the gate, an explicit
  ``allow_python`` flag. This module never reads the environment; only ``cli.py``
  does. The gate is checked inside :func:`load_python_target`, the single shared
  ``importlib`` helper (also the one the Milestone 0006 ``python:`` sink must use),
  before any ``import_module``, ``find_spec`` or ``sys.modules`` lookup. An AST
  tripwire test keeps it the only dynamic ``import_module`` call site.
* **M4** -- a refusal is always an :class:`ExtensionError` (or ``ConfigError``),
  never swallowed, on the report and the event path alike.
* **M5** -- the module and callable grammar is checked before any import, the
  callable is reached by ``getattr`` over validated segments only, and
  ``builtin:<name>`` resolves through the static table of
  :mod:`docsentinel.telemetry.builtin` (the name is never part of an import).
* **M6** -- the boundary is the scan root, its project roots (every ancestor
  holding a :data:`PROJECT_ROOT_MARKERS` entry, not only the nearest, so a marker
  planted under ``<checkout>/docs`` cannot drop the checkout) and the current
  directory. The scan root is anchored in every spelling the invoker supplied: the
  CLI passes the unresolved absolute argument (``origin_roots``) next to the
  resolved one, so a ``<checkout>/docs`` that is a symlink out of the checkout
  cannot drop the checkout (amended 2026-11-03, F1). Before any import, a
  ``sys.path`` entry (``''`` is the cwd) inside the boundary refuses every
  ``python:`` spec; the same ``sys.path`` check runs again after every factory,
  between each factory and its ``filters()`` hook, before every report hook, before
  every extension filter call (amended 2026-11-03, F2) and at every
  :class:`ModuleWatch` check, so an extension that adds the checkout to
  ``sys.path`` fails the run before a later import can resolve through it. Every dotted prefix of the module
  is resolved with ``importlib.util.find_spec`` (or read from an existing
  ``sys.modules`` entry) and refused when any origin or search location lies
  inside, or when it has no location and is not a builtin or frozen module. After
  the import, the factories, the report hooks and the render, a
  :class:`ModuleWatch` refuses (exit 2) when any module added to ``sys.modules``
  since the first ``python:`` import reports a location inside (best-effort
  detection of accidental imports).
  Exemption (amended 2026-11-03): a location whose absolute *and* canonical path
  are both under the running interpreter's own ``site-packages`` (``sysconfig``
  ``purelib``/``platlib``) is never refused, so a project-local ``.venv`` of the
  running interpreter works; ``PYTHONPATH`` entries, the user site, ``.pth``-added
  directories (an editable ``src/``) and any other virtual environment are not
  exempt. ``sys.path`` is never changed.

Data contract:

* **M13** -- an extension's ``name`` is read once; every hook is looked up once with
  ``getattr(obj, hook, None)``. Hooks receive a deep-frozen copy of the context
  (``MappingProxyType``/``tuple``), built once per render and never aliasing the
  rendered context.
* **M14-M16** -- each hook return is copied into fresh builtin objects by an
  iterative walk that refuses subclasses, cycles, depth over :data:`MAX_DEPTH`,
  containers over :data:`MAX_CONTAINER_ENTRIES`, keys over :data:`MAX_KEY_CHARS`,
  ints past ``2**53``, non-finite floats and lone surrogates, and stops as soon as
  its estimated serialized size passes the per-hook, per-extension or per-render cap.
* **M7-M10** -- extension filters are named ``ext.<own name>.<filter>``, are never
  sinks (any ``sink`` attribute is refused, tested by identity), live only in the per-render
  :class:`LoadedExtensions` registry (never in ``loader.FILTERS``), and at render
  time must return an exact JSON scalar; any failure is a bounded ``TemplateError``.
* **M25/M26** -- builtin names are reserved against ``python:`` extensions; names and
  specs are unique; returned trees are attached only under ``ext.<name>``.
* **M17/M27/M29** -- a hook's ``Exception`` or ``SystemExit`` becomes an
  :class:`ExtensionError` on the report path (only an exact ``KeyboardInterrupt``
  propagates; a subclass is wrapped like any other exception, amended 2026-11-03) and
  is swallowed with one warning per extension by :class:`EventHookGuard`. Messages
  echo only the spec or name, the hook, the exception ``__qualname__`` and at most
  200 characters of ``str(exc)``, each neutralized, capped at 512 characters.

* **M12** -- at render time :func:`scope_extension_data` hands a template only the
  ``ext`` members it lists in ``requires_extensions``.

Accepted residual risks (threat model R1-R4): an admitted ``python:`` extension is
full in-process code -- in particular, extensions run in selection order in one
process, so one extension can alter shared state (``sys.modules``, the frozen
model's backing dicts via ``gc``, module globals) that the next one sees (R1); a
hook that never returns is not stopped (decision D-C); the M6 origin check is
point-in-time, and :class:`ModuleWatch` is best-effort detection of accidental
imports, defeated by a planted module that rewrites its own location (R3).
"""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import math
import os
import re
import sys
import sysconfig
import types
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Literal, Optional, Protocol, Union, runtime_checkable

from docsentinel.config import Config, validate_telemetry_extensions
from docsentinel.telemetry import builtin
from docsentinel.telemetry.filters import MAX_MESSAGE, TemplateError, neutralize

#: Extension name grammar (spec §2, §9); equals the loader's ``_EXTENSION_PATTERN``.
EXTENSION_NAME_PATTERN: Final[str] = r"^[a-z][a-z0-9_]{0,63}$"

#: Spec prefixes (spec §9).
BUILTIN_PREFIX: Final[str] = "builtin:"
PYTHON_PREFIX: Final[str] = "python:"

#: Prefix of every extension filter name (spec §7).
EXT_FILTER_PREFIX: Final[str] = "ext."

#: The three data hooks, all optional (M13).
HOOK_RUN: Final[str] = "provide_run"
HOOK_DOCUMENT: Final[str] = "provide_document"
HOOK_PROBLEM: Final[str] = "provide_problem"
HOOK_FILTERS: Final[str] = "filters"

#: Value kinds an extension filter may declare (the loader's kinds).
FILTER_INPUT_KINDS: Final[frozenset[str]] = frozenset({"scalar", "list", "dict"})

#: Bounds of a ``python:`` spec (M5).
MAX_SPEC_CHARS: Final[int] = 256

#: Most extension specs per run (config plus argv).
MAX_EXTENSIONS: Final[int] = 32

#: Most filters one extension may register.
MAX_FILTERS: Final[int] = 64

#: Shape bounds of one hook return (M15).
MAX_DEPTH: Final[int] = 8
MAX_CONTAINER_ENTRIES: Final[int] = 10_000
MAX_KEY_CHARS: Final[int] = 256
MAX_INT: Final[int] = 2**53

#: Size caps on estimated serialized characters (M15, M16).
MAX_HOOK_CHARS: Final[int] = 1024 * 1024
MAX_EXTENSION_CHARS: Final[int] = 16 * 1024 * 1024
#: Equals ``engine.MAX_OUTPUT_CHARS`` (a test pins the parity; not imported to keep
#: this module below the engine in the import graph).
MAX_TOTAL_EXTENSION_CHARS: Final[int] = 64 * 1024 * 1024

#: Echo bounds of an error message (M27).
MAX_DETAIL_CHARS: Final[int] = 200
_MAX_QUALNAME = 64
_MAX_ECHO = 80
_MAX_SEARCH_LOCATIONS = 64
_MAX_ANCESTORS = 256

#: Entries whose presence marks a project root: every marked ancestor of the scan
#: root (inclusive) is an M6 anchor too (amended 2026-11-03: not only the nearest).
PROJECT_ROOT_MARKERS: Final[tuple[str, ...]] = (".git", "docsentinel.toml", "doc_sentinel.toml", "pyproject.toml")

_NAME_RE = re.compile(EXTENSION_NAME_PATTERN)
_FILTER_LEAF_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_MODULE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,15}")
_CALLABLE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){0,3}")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")

#: Where the extension contract is documented (M31 message).
_DOCS_HINT = "see docs/specs/report-template-format.md section 9"

JsonValue = Any
JsonScalar = Union[str, int, float, bool, None]


class ExtensionError(ValueError):
    """An extension refused, failed or returned invalid data (spec §10; CLI exit 2).

    The message is neutralized and bounded to 512 characters on construction, so
    ``str()`` of the error is safe to print by any caller (M27).
    """

    def __init__(self, message: str):
        """Initialise the error with a neutralized, bounded message.

        :param message: The diagnostic; hostile fragments must already be echoed.
        """
        safe = neutralize(message if isinstance(message, str) else "extension error")
        if len(safe) > MAX_MESSAGE:
            safe = safe[: MAX_MESSAGE - 3] + "..."
        super().__init__(safe)


@runtime_checkable
class Extension(Protocol):
    """Structural contract of a report extension (spec §9).

    Only ``name`` is mandatory. Every hook is optional: it is looked up once with
    ``getattr(obj, hook, None)``, must be callable when present, and a missing hook
    is a no-op. Hooks receive deep-frozen arguments and return a JSON-shaped
    ``dict`` (attached under ``ext.<name>``) or ``None``.

    :ivar name: Exact ``str`` matching :data:`EXTENSION_NAME_PATTERN`, read once.
    """

    name: str

    def provide_run(self, model: Mapping) -> Optional[Mapping]:
        """Return run-level data for ``ext.<name>``, or ``None``."""

    def provide_document(self, doc: Mapping, model: Mapping) -> Optional[Mapping]:
        """Return document data for ``doc.ext.<name>``, or ``None``."""

    def provide_problem(self, problem: Mapping, doc: Mapping, model: Mapping) -> Optional[Mapping]:
        """Return problem data for ``p.ext.<name>``, or ``None``."""

    def filters(self) -> Mapping[str, ExtensionFilter]:
        """Return the filters to register, keyed ``ext.<name>.<filter>`` (optional)."""


@dataclass(frozen=True)
class ExtensionFilter:
    """One filter an extension registers (spec §7). There is no ``sink`` field (M7).

    :ivar function: Called as ``function(value, *args)``; must return an exact
        ``str``/``int``/finite ``float``/``bool``/``None``.
    :ivar arity: Number of quoted literal arguments, ``0`` or ``1``.
    :ivar input_kinds: Accepted input kinds, a subset of :data:`FILTER_INPUT_KINDS`.
    """

    function: Callable[..., JsonScalar]
    arity: Literal[0, 1]
    input_kinds: frozenset[str]


# --------------------------------------------------------------------------- messages


def _echo(value: object, limit: int = _MAX_ECHO) -> str:
    """Return a bounded, neutralized echo of an invoker- or extension-chosen string.

    :param value: The fragment.
    :param limit: Characters kept before ``...``.
    :returns: The echo, or ``<not text>``.
    """
    if not isinstance(value, str):
        return "<not text>"
    text = str.__str__(value)
    bounded = neutralize(text[:limit])
    return f"{bounded}..." if len(text) > limit else bounded


def _qualname(exc: BaseException) -> str:
    """Return the bounded, neutralized ``__qualname__`` of an exception's class (M27).

    The read itself is guarded: a metaclass whose ``__qualname__`` raises (even
    ``SystemExit``) yields the fixed label ``<exception>`` instead of escaping.
    Only an exact ``KeyboardInterrupt`` propagates, as everywhere in this module; a
    subclass (which extension code can define and raise) is handled like any other
    exception.

    :param exc: The exception.
    :returns: The echo, or ``<exception>``.
    """
    try:
        qualname = getattr(type(exc), "__qualname__", None)
        return _echo(qualname, _MAX_QUALNAME) if isinstance(qualname, str) else "<exception>"
    except BaseException as exc:
        if type(exc) is KeyboardInterrupt:
            raise
        return "<exception>"


def _describe(exc: BaseException) -> str:
    """Return ``QualName: detail`` for an exception, bounded and neutralized (M27).

    Never ``repr(exc)`` or a traceback; a ``__str__`` that itself fails yields
    ``<unprintable>``, and a class name that cannot be read yields ``<exception>``.

    :param exc: The exception.
    :returns: The bounded description.
    """
    shown = _qualname(exc)
    try:
        detail = str(exc)
        text = _echo(detail, MAX_DETAIL_CHARS) if isinstance(detail, str) else ""
    except BaseException as exc:
        if type(exc) is KeyboardInterrupt:
            raise
        text = "<unprintable>"
    return f"{shown}: {text}" if text else shown


def _hook_failure(subject: str, hook: str, exc: BaseException) -> ExtensionError:
    """Build the report-path error for a failing hook (M17, M27).

    :param subject: The validated extension name or the configured spec.
    :param hook: The hook name.
    :param exc: The raised exception.
    :returns: The bounded error.
    """
    return ExtensionError(f"extension {_echo(subject)}: {hook} failed: {_describe(exc)}")


def missing_extensions_message(names: Sequence[str]) -> str:
    """Return the message for required extensions that are not loaded (M31).

    A builtin name suggests ``--extension builtin:<name>`` / ``telemetry_extensions``.
    Any other name says only that the invoker must supply an extension of that
    name; it never suggests the trust gate or a module path.

    :param names: The missing names, in template order.
    :returns: The neutralized message.
    """
    shown = list(names)[:5]
    parts = []
    for name in shown:
        echoed = _echo(name)
        if builtin.is_reserved_name(name):
            parts.append(f"{echoed} (enable it with --extension builtin:{echoed} or telemetry_extensions)")
        else:
            parts.append(f"{echoed} (an extension providing this name must be supplied by the invoker; {_DOCS_HINT})")
    more = f", ... {len(names) - 5} more" if len(names) > 5 else ""
    return f"template requires extension(s) that are not loaded: {'; '.join(parts)}{more}"


# --------------------------------------------------------------------------- spec grammar


@dataclass(frozen=True)
class _Spec:
    """A parsed extension spec.

    :ivar text: The spec as given.
    :ivar kind: ``builtin`` or ``python``.
    :ivar target: The builtin name, or the module path.
    :ivar attribute: The dotted callable path (``python`` only).
    """

    text: str
    kind: str
    target: str
    attribute: str = ""


def _parse_spec(spec: object) -> _Spec:
    """Parse ``builtin:<name>`` or ``python:<module>:<callable>`` (M5). Pure string work.

    :param spec: The spec.
    :returns: The parsed spec.
    :raises ExtensionError: For a non-string, an over-long or malformed spec, or an
        unknown prefix.
    """
    if type(spec) is not str:
        raise ExtensionError("an extension spec must be a string")
    if len(spec) > MAX_SPEC_CHARS:
        raise ExtensionError(f"extension spec longer than {MAX_SPEC_CHARS} characters: {_echo(spec)}")
    if spec.startswith(BUILTIN_PREFIX):
        name = spec[len(BUILTIN_PREFIX) :]
        if _NAME_RE.fullmatch(name) is None:
            raise ExtensionError(f"invalid builtin extension name: {_echo(spec)}")
        return _Spec(spec, "builtin", name)
    if spec.startswith(PYTHON_PREFIX):
        pieces = spec[len(PYTHON_PREFIX) :].split(":")
        if len(pieces) != 2:
            raise ExtensionError(f"a python extension spec is python:<module>:<callable>: {_echo(spec)}")
        module, attribute = pieces
        if _MODULE_RE.fullmatch(module) is None:
            raise ExtensionError(f"invalid module path in extension spec: {_echo(spec)}")
        if _CALLABLE_RE.fullmatch(attribute) is None:
            raise ExtensionError(f"invalid callable path in extension spec: {_echo(spec)}")
        return _Spec(spec, "python", module, attribute)
    raise ExtensionError(f"an extension spec is builtin:<name> or python:<module>:<callable>: {_echo(spec)}")


# --------------------------------------------------------------------------- origin check (M6)


def _spellings(text: str) -> tuple[str, ...]:
    """Return the absolute and the canonical spelling of a path, deduplicated.

    :param text: A path string.
    :returns: ``(abspath,)`` or ``(abspath, realpath)``.
    """
    return tuple(dict.fromkeys((os.path.abspath(text), os.path.realpath(text))))


def _has_project_marker(directory: str) -> bool:
    """Return whether ``directory`` holds one of :data:`PROJECT_ROOT_MARKERS`.

    Any entry counts (``lexists``: an empty file or a dangling link too). That is
    safe only because :func:`project_roots` keeps every marked ancestor: an extra
    marker can enlarge the boundary but never shrink it.

    :param directory: An absolute directory path.
    :returns: ``True`` when a marker exists.
    """
    return any(os.path.lexists(os.path.join(directory, marker)) for marker in PROJECT_ROOT_MARKERS)


def project_roots(root: Path) -> tuple[str, ...]:
    """Return the project roots of a scan root: every marked ancestor (M6, amended 2026-11-03).

    The scan root itself and then each parent, up to the filesystem root, is tested
    for a :data:`PROJECT_ROOT_MARKERS` entry; **every** match is a project root, not
    only the nearest. Both the absolute and the canonical spelling of ``root`` are
    walked. The scanned repository controls the markers below its own top, so a
    stray ``docs/.git`` (even an empty file or a dangling link), ``docs/pyproject.toml``
    or a scan root that is a link to ``docs/`` can add a directory but can never
    drop the checkout from the boundary. Scanning ``<checkout>/docs`` therefore
    always anchors the origin check at ``<checkout>``.

    This fails closed more often: a marker high up the tree (for example a
    ``~/.git`` dotfiles repository) puts everything below it, the user site and a
    user-installed interpreter included, inside the boundary, so ``python:``
    extensions are refused there.

    :param root: The scan root.
    :returns: The project root spellings found (empty when no ancestor is marked).
    :raises ExtensionError: When a spelling of ``root`` has more than
        :data:`_MAX_ANCESTORS` ancestors (fail closed rather than stop early).
    """
    found: list[str] = []
    for start in _spellings(os.fspath(root)):
        current = start
        for _ in range(_MAX_ANCESTORS):
            if _has_project_marker(current):
                found.append(current)
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        else:
            raise ExtensionError("python extensions are refused: the scan root path is implausibly deep")
    return tuple(dict.fromkeys(found))


def _own_site_packages() -> tuple[str, ...]:
    """Return the running interpreter's own ``site-packages`` directories (M6 exemption).

    Only ``sysconfig`` ``purelib``/``platlib`` of the running interpreter count, in
    both spellings. The user site, ``PYTHONPATH`` entries, ``.pth``-added
    directories and any other virtual environment are never included.

    :returns: Directory spellings.
    """
    found: list[str] = []
    for key in ("purelib", "platlib"):
        try:
            value = sysconfig.get_path(key)
        except (KeyError, ValueError, OSError):
            continue
        if isinstance(value, str) and value:
            found.extend(_spellings(value))
    return tuple(dict.fromkeys(found))


def _under(path: str, base: str) -> bool:
    """Return whether ``path`` equals or lies below ``base``, lexically.

    :param path: An absolute path.
    :param base: An absolute directory path.
    :returns: The containment decision.
    """
    try:
        return os.path.commonpath([path, base]) == base
    except ValueError:
        return False


@dataclass(frozen=True)
class _Boundary:
    """The M6 refusal boundary of one run.

    :ivar anchors: ``(path, stat or None)`` for every spelling of the scan root, its
        project root(s) and the current directory.
    :ivar sites: Spellings of the running interpreter's own ``site-packages``.
    """

    anchors: tuple[tuple[str, Optional[os.stat_result]], ...]
    sites: tuple[str, ...]

    @classmethod
    def of(cls, root: Path, cwd: Path, origin_roots: Sequence[Path] = ()) -> _Boundary:
        """Build the boundary for a scan root and a current directory.

        :param root: The scan root.
        :param cwd: The current directory.
        :param origin_roots: Further spellings of the scan root as the invoker wrote
            it (amended 2026-11-03, F1): each is an anchor and its marked ancestors
            are project roots too, so a resolved root that left the checkout through
            a symlink cannot drop the checkout from the boundary.
        :returns: The boundary.
        """
        extra = [os.fspath(origin) for origin in origin_roots]
        marked = [entry for start in (os.fspath(root), *extra) for entry in project_roots(Path(start))]
        anchors: dict[str, Optional[os.stat_result]] = {}
        for anchor in (os.fspath(root), os.fspath(cwd), *extra, *marked):
            for spelling in _spellings(anchor):
                if spelling in anchors:
                    continue
                try:
                    anchors[spelling] = os.stat(spelling)
                except OSError:
                    anchors[spelling] = None
        return cls(tuple(anchors.items()), _own_site_packages())

    def exempt(self, text: str) -> bool:
        """Return whether a location is in the running interpreter's own site-packages.

        Both the absolute and the canonical path must lie there, so an in-tree link
        out of ``site-packages`` is not exempt.

        :param text: An exact path string.
        :returns: The exemption decision.
        """
        absolute, real = os.path.abspath(text), os.path.realpath(text)
        return any(_under(absolute, site) for site in self.sites) and any(_under(real, site) for site in self.sites)

    def refuses(self, location: object) -> bool:
        """Return whether a module origin, search location or path entry is refused (M6).

        A location in the running interpreter's own ``site-packages`` is exempt.
        Otherwise both the location as written (so an in-root symlink to an outside
        file is still refused) and its canonical path are checked: lexically against
        every anchor spelling, then by walking their ancestors comparing
        device/inode with each anchor, so a case-insensitive filesystem or a second
        spelling of the root cannot hide containment. Fails closed: a location that
        cannot be resolved, or whose ancestor chain is implausibly long, counts as
        inside.

        :param location: A path string.
        :returns: ``True`` when the location is inside the scan root, its project
            root or the current directory and not exempt.
        """
        if not isinstance(location, str) or not location:
            return False
        text = str.__str__(location)
        try:
            if self.exempt(text):
                return False
            candidates = _spellings(text)
        except (OSError, ValueError):
            return True
        stats = [info for _, info in self.anchors if info is not None]
        for candidate in candidates:
            if any(_under(candidate, anchor) for anchor, _ in self.anchors):
                return True
            current = os.path.dirname(candidate)
            for _ in range(_MAX_ANCESTORS):
                try:
                    info = os.stat(current)
                except (OSError, ValueError):
                    info = None
                if info is not None and any(os.path.samestat(info, anchor) for anchor in stats):
                    return True
                parent = os.path.dirname(current)
                if parent == current:
                    break
                current = parent
            else:
                return True
        return False


#: The refusal message tail shared by every M6 refusal.
_INSIDE = "inside the scan root, its project root or the current directory"


def _check_import_path(boundary: _Boundary, cwd: Path):
    """Refuse when any ``sys.path`` entry resolves inside the boundary (M6).

    ``''`` and every relative entry are resolved both against the process working
    directory (what the import system uses) and against ``cwd``. Entries that are
    not ``str`` are skipped, as the path finder skips them.

    :param boundary: The run's boundary.
    :param cwd: The current directory given by the invoker.
    :raises ExtensionError: When an entry is inside, or ``sys.path`` cannot be read.
    """
    try:
        entries = [str.__str__(entry) for entry in list(sys.path) if isinstance(entry, str)]
    except BaseException as exc:
        if type(exc) is KeyboardInterrupt:
            raise
        raise ExtensionError("python extensions are refused: sys.path cannot be read") from None
    for entry in entries:
        candidates = [entry or os.curdir]
        if not os.path.isabs(entry):
            candidates.append(os.path.join(os.fspath(cwd), entry))
        if any(boundary.refuses(candidate) for candidate in candidates):
            raise ExtensionError(
                f"python extensions are refused: an import path (sys.path) entry is {_INSIDE}, so an imported "
                "module could come from the checkout; run the console script (not python -m) and do not put "
                "the checkout on PYTHONPATH"
            )


def _locations(values: object) -> list[object]:
    """Return a bounded list of search locations (fail closed past the bound).

    :param values: A ``submodule_search_locations``/``__path__`` value.
    :returns: Its entries.
    :raises ExtensionError: When it cannot be listed or holds too many entries.
    """
    if values is None:
        return []
    if isinstance(values, str):
        return [values]
    try:
        entries = []
        for entry in values:  # type: ignore[union-attr]
            entries.append(entry)
            if len(entries) > _MAX_SEARCH_LOCATIONS:
                raise ExtensionError("python extension refused: a package has too many search locations")
        return entries
    except ExtensionError:
        raise
    except BaseException as exc:
        if type(exc) is KeyboardInterrupt:
            raise
        raise ExtensionError("python extension refused: a package search path cannot be listed") from None


def _spec_locations(spec: object) -> list[object]:
    """Return the file locations of a module spec (origin when it has one, search paths).

    :param spec: A ``ModuleSpec``.
    :returns: Path strings to check.
    :raises ExtensionError: For an object that is not a ``ModuleSpec``.
    """
    if not isinstance(spec, importlib.machinery.ModuleSpec):
        raise ExtensionError("python extension refused: a module has no standard import spec")
    found: list[object] = []
    origin = spec.origin
    if isinstance(origin, str) and (spec.has_location or os.path.isabs(origin)):
        found.append(origin)
    found.extend(_locations(spec.submodule_search_locations))
    return found


#: ``ModuleSpec.origin`` values of modules that have no file by design (M6).
_FILELESS_ORIGINS: Final[frozenset[str]] = frozenset({"built-in", "frozen"})

#: The ``ModuleType.__dict__`` descriptor, so a module subclass cannot intercept the read.
_MODULE_DICT = types.ModuleType.__dict__["__dict__"]


def _module_locations(module: object) -> list[object]:
    """Return the file locations of an imported module, read from its ``__dict__`` only.

    The namespace is read through the ``ModuleType`` descriptor itself, so neither a
    module ``__getattr__`` nor a subclass ``__getattribute__`` runs.

    :param module: A ``sys.modules`` entry.
    :returns: Path strings to check.
    :raises ExtensionError: For an entry that is not a module object.
    """
    if not isinstance(module, types.ModuleType):
        raise ExtensionError("python extension refused: a sys.modules entry is not a module")
    namespace = _MODULE_DICT.__get__(module)
    found: list[object] = []
    spec = namespace.get("__spec__")
    if spec is not None:
        found.extend(_spec_locations(spec))
    found.append(namespace.get("__file__"))
    found.extend(_locations(namespace.get("__path__")))
    return found


def _is_fileless_by_design(module: object) -> bool:
    """Return whether a module is a builtin or frozen one (no file location by design).

    :param module: A module object or a ``ModuleSpec``.
    :returns: The decision.
    """
    spec = module if isinstance(module, importlib.machinery.ModuleSpec) else None
    if spec is None and isinstance(module, types.ModuleType):
        spec = _MODULE_DICT.__get__(module).get("__spec__")
    if not isinstance(spec, importlib.machinery.ModuleSpec):
        return False
    origin = spec.origin
    return type(origin) is str and origin in _FILELESS_ORIGINS


def _has_location(locations: list[object]) -> bool:
    """Return whether any non-empty path string is among ``locations``.

    :param locations: From :func:`_spec_locations` or :func:`_module_locations`.
    :returns: The decision.
    """
    return any(isinstance(location, str) and location for location in locations)


def _refuse_module(module: str, boundary: _Boundary, locations: list[object], subject: object):
    """Refuse a module whose locations are inside, or that has no location at all (M6).

    :param module: The module path, for the message.
    :param boundary: The run's boundary.
    :param locations: The module's locations.
    :param subject: The spec or module object, for the builtin/frozen exemption.
    :raises ExtensionError: When refused.
    """
    if any(boundary.refuses(location) for location in locations):
        raise ExtensionError(f"python extension module {_echo(module)} is refused: it resolves {_INSIDE}")
    if not _has_location(locations) and not _is_fileless_by_design(subject):
        raise ExtensionError(
            f"python extension module {_echo(module)} is refused: it has no file location and is not a builtin "
            "or frozen module"
        )


def _check_origins(module: str, boundary: _Boundary):
    """Refuse a module when any dotted prefix resolves inside the boundary (M6).

    Prefixes are checked outermost first, so a parent package is checked before
    ``find_spec`` of a child imports it. A prefix with no file location at all is
    refused unless it is a builtin or frozen module.

    :param module: The validated module path.
    :param boundary: The run's boundary.
    :raises ExtensionError: When a prefix is missing, not standard, locationless or inside.
    """
    parts = module.split(".")
    for count in range(1, len(parts) + 1):
        prefix = ".".join(parts[:count])
        loaded = sys.modules.get(prefix)
        subject: object
        if loaded is not None:
            locations = _module_locations(loaded)
            subject = loaded
        else:
            try:
                spec = importlib.util.find_spec(prefix)
            except BaseException as exc:
                if type(exc) is KeyboardInterrupt:
                    raise
                raise ExtensionError(
                    f"python extension module {_echo(module)} could not be located: {_qualname(exc)}"
                ) from None
            if spec is None:
                raise ExtensionError(f"python extension module {_echo(module)} was not found")
            locations = _spec_locations(spec)
            subject = spec
        _refuse_module(module, boundary, locations, subject)


class ModuleWatch:
    """Guard ``sys.path`` and watch ``sys.modules`` during a run (M6).

    Two layers. **Prevention:** :meth:`check_path` re-runs the ``sys.path`` check of
    :func:`load_python_target`, so an extension that put the checkout (the scan
    root, a project root or the current directory) on ``sys.path`` -- at import
    time, in its factory or in a hook -- fails the run (exit 2) before a later
    import can resolve through that entry. It runs at the start of every
    :meth:`check`, after every factory, before every ``filters()`` hook, before
    every report hook and before every extension filter call.

    **Detection:** a snapshot of ``sys.modules`` is taken before the first
    ``python:`` import; :meth:`check` compares the current ``sys.modules`` with it
    and refuses when an added or replaced entry reports a location inside the
    boundary (the running interpreter's own ``site-packages`` is exempt). This is
    best-effort detection of accidental imports, after the fact (the module has
    already run), and it is defeated by a planted module that rewrites its own
    location (``__file__``/``__spec__``), by an import whose ``sys.modules`` entry is
    deleted again, and by code run without a ``sys.modules`` entry at all
    (``spec_from_file_location`` + ``exec_module``, ``runpy.run_path``). Those need the
    extension's own cooperation (threat model R1/R3). Entries that are not modules,
    or that carry no location, are skipped. Accepted entries are remembered, so each
    new entry is inspected once.
    """

    def __init__(self, boundary: _Boundary, cwd: Path):
        """Snapshot ``sys.modules``.

        :param boundary: The run's boundary.
        :param cwd: The current directory given by the invoker (for relative
            ``sys.path`` entries).
        """
        self._boundary = boundary
        self._cwd = cwd
        self._seen: dict[str, object] = dict(sys.modules)
        self._accepted_path: Optional[tuple[object, ...]] = None

    @classmethod
    def start(cls, root: Path, cwd: Path, origin_roots: Sequence[Path] = ()) -> ModuleWatch:
        """Start a watch for a scan root and a current directory.

        :param root: The scan root.
        :param cwd: The current directory.
        :param origin_roots: Further spellings of the scan root (see :meth:`_Boundary.of`).
        :returns: The watch.
        """
        return cls(_Boundary.of(root, cwd, origin_roots), cwd)

    def changed(self) -> bool:
        """Return whether ``sys.modules`` changed size since the last snapshot.

        A cheap hint only: a replaced entry keeps the size, so no security decision
        is taken on it (:meth:`check` runs unconditionally at every call site).

        :returns: ``True`` when its size differs from the last snapshot.
        """
        return len(sys.modules) != len(self._seen)

    def _path_key(self) -> Optional[tuple[object, ...]]:
        """Return the process cwd and the ``sys.path`` entries, or ``None`` when unreadable.

        :returns: The key the last accepted ``sys.path`` check is remembered by.
        """
        try:
            return (os.getcwd(), *(str.__str__(entry) for entry in list(sys.path) if isinstance(entry, str)))
        except BaseException as exc:
            if type(exc) is KeyboardInterrupt:
                raise
            return None

    def check_path(self):
        """Refuse when a ``sys.path`` entry now lies inside the boundary (M6, prevention).

        The full check runs only when ``sys.path`` or the process cwd differs from
        the last accepted state, so calling this before every hook stays cheap. An
        unreadable state is always checked (and fails closed).

        :raises ExtensionError: When an entry is inside, or ``sys.path`` cannot be read.
        """
        key = self._path_key()
        if key is not None and key == self._accepted_path:
            return
        _check_import_path(self._boundary, self._cwd)
        self._accepted_path = key

    def check(self):
        """Refuse when a module added or replaced since the snapshot lies inside, or ``sys.path`` does (M6).

        The ``sys.modules`` comparison runs first, so a module already imported from
        the checkout is named; then :meth:`check_path`. Neither part imports
        anything, so their order inside this call does not matter for prevention.

        :raises ExtensionError: Naming the module (never its path), or ``sys.path``.
        """
        self._check_modules()
        self.check_path()

    def _check_modules(self):
        """Refuse when a module added or replaced since the snapshot reports a location inside.

        :raises ExtensionError: Naming the module (never its path).
        """
        current = dict(sys.modules)
        for name, module in current.items():
            if self._seen.get(name, _MISSING_MODULE) is module:
                continue
            try:
                inside = isinstance(module, types.ModuleType) and any(
                    self._boundary.refuses(location) for location in _module_locations(module)
                )
            except BaseException as exc:
                if type(exc) is KeyboardInterrupt:
                    raise
                inside = True
            if inside:
                raise ExtensionError(
                    f"python extension refused: module {_echo(name)} was imported during the run and resolves {_INSIDE}"
                )
        self._seen = current


#: Marks a ``sys.modules`` name absent from a snapshot.
_MISSING_MODULE: Final[object] = object()


def _origin_paths(origin_roots: object) -> tuple[Path, ...]:
    """Validate the extra scan-root spellings of the M6 boundary (amended 2026-11-03).

    :param origin_roots: A sequence of ``str``/``os.PathLike`` paths (not one path).
    :returns: Absolute paths, lexically normalized and never resolved, so a symlink
        the invoker named stays the spelling that is anchored.
    :raises ExtensionError: For a single path, a non-sequence, too many entries or an
        entry that is not a path.
    """
    if isinstance(origin_roots, (str, bytes, os.PathLike)) or not isinstance(origin_roots, Sequence):
        raise ExtensionError("origin_roots must be a sequence of paths")
    if len(origin_roots) > _MAX_SEARCH_LOCATIONS:
        raise ExtensionError("too many origin_roots")
    found: list[Path] = []
    for entry in origin_roots:
        if not isinstance(entry, (str, os.PathLike)):
            raise ExtensionError("origin_roots must be a sequence of paths")
        text = os.fspath(entry)
        if not isinstance(text, str) or not text:
            raise ExtensionError("origin_roots must be a sequence of paths")
        found.append(Path(os.path.abspath(text)))
    return tuple(found)


def load_python_target(
    spec: str, *, allow_python: bool, root: Path, cwd: Path, origin_roots: Sequence[Path] = ()
) -> object:
    """Resolve a ``python:<module>:<callable>`` spec to its callable (M2, M3, M5, M6).

    The single shared ``importlib`` helper (Milestone 0007 extensions and the
    Milestone 0006 ``python:`` sink). Order: the gate, before any import machinery
    is touched; the grammar; the ``sys.path`` check; the origin check of every
    dotted prefix; then the one ``import_module`` call; then the origin check again
    on the imported module and on every module the import added to ``sys.modules``;
    then ``getattr`` over the validated callable segments.

    :param spec: The spec, as given by the invoker.
    :param allow_python: The invoker's explicit gate decision; anything but ``True``
        refuses. There is deliberately no default.
    :param root: The scan root; a module inside it or inside its project root is refused.
    :param cwd: The current directory; a module inside it is refused.
    :param origin_roots: Further spellings of the scan root as the invoker wrote it
        (unresolved), anchored like ``root`` (M6, amended 2026-11-03).
    :returns: The resolved callable (not yet called).
    :raises ExtensionError: When refused by the gate, the grammar, the ``sys.path``
        check or the origin check, or when the import or attribute lookup fails, or
        the target is not callable. Nothing is executed for a spec refused before
        the import.
    """
    if allow_python is not True:
        raise ExtensionError(
            f"python extension {_echo(spec)} is refused: python: extensions run arbitrary code and need the "
            "invoker's explicit opt-in (--allow-python-extensions, or allow_python_extensions=True)"
        )
    parsed = _parse_spec(spec)
    if parsed.kind != "python":
        raise ExtensionError(f"not a python extension spec: {_echo(spec)}")
    boundary = _Boundary.of(root, cwd, _origin_paths(origin_roots))
    _check_import_path(boundary, cwd)
    _check_origins(parsed.target, boundary)
    watch = ModuleWatch(boundary, cwd)
    try:
        module = importlib.import_module(parsed.target)
    except BaseException as exc:
        if type(exc) is KeyboardInterrupt:
            raise
        raise ExtensionError(
            f"python extension module {_echo(parsed.target)} could not be imported: {_qualname(exc)}"
        ) from None
    _refuse_module(parsed.target, boundary, _module_locations(module), module)
    watch.check()
    target: object = module
    for segment in parsed.attribute.split("."):
        try:
            target = getattr(target, segment)
        except BaseException as exc:
            if type(exc) is KeyboardInterrupt:
                raise
            raise ExtensionError(f"python extension {_echo(spec)}: callable not found") from None
    if not callable(target):
        raise ExtensionError(f"python extension {_echo(spec)}: target is not callable")
    return target


# --------------------------------------------------------------------------- loaded registry


@dataclass(frozen=True)
class BoundFilter:
    """An admitted extension filter in the per-render registry (M9, M10).

    :ivar name: The full name ``ext.<extension>.<filter>``.
    :ivar extension: The owning extension name.
    :ivar function: The validated callable.
    :ivar arity: ``0`` or ``1``.
    :ivar input_kinds: Accepted input kinds.
    :ivar guard: Called before every call of ``function``; bound by the registry to
        :meth:`ModuleWatch.check_path` when a ``python:`` extension is loaded, so a
        filter that put the checkout on ``sys.path`` fails the render before the
        next filter call can import through it (M6, amended 2026-11-03, F2).
    """

    name: str
    extension: str
    function: Callable[..., JsonScalar]
    arity: int
    input_kinds: frozenset[str]
    guard: Optional[Callable[[], None]] = field(default=None, compare=False, repr=False)

    def __call__(self, value: JsonValue, args: tuple[str, ...]) -> JsonScalar:
        """Apply the filter at render time (M10).

        A container input is passed as a deep-frozen copy. The result must be an
        exact JSON scalar; anything else, and any exception (an exact
        ``KeyboardInterrupt`` aside; a subclass is wrapped), is a bounded
        :class:`~docsentinel.telemetry.filters.TemplateError`. The :attr:`guard`
        runs first, outside that wrapping: its :class:`ExtensionError` propagates
        and is never turned into a filter failure.

        :param value: The JSON input.
        :param args: The literal arguments.
        :returns: The scalar result.
        :raises TemplateError: On a wrong argument count or input kind, a raising
            filter or a non-scalar result.
        :raises ExtensionError: When the guard refuses (a ``sys.path`` entry inside
            the M6 boundary).
        """
        if len(args) != self.arity:
            raise TemplateError(f"filter {_echo(self.name)} takes {self.arity} argument(s)")
        kind = _value_kind(value)
        if kind not in self.input_kinds:
            raise TemplateError(f"filter {_echo(self.name)} cannot take a {kind} value")
        argument = freeze(value) if kind != "scalar" else value
        if self.guard is not None:
            self.guard()
        try:
            result = self.function(argument, *args)
        except BaseException as exc:
            if type(exc) is KeyboardInterrupt:
                raise
            raise TemplateError(f"filter {_echo(self.name)} failed: {_describe(exc)}") from None
        if not _is_exact_scalar(result):
            raise TemplateError(f"filter {_echo(self.name)} must return a JSON scalar")
        return result


@dataclass(frozen=True)
class LoadedExtension:
    """One admitted extension with its hooks looked up once (M13).

    :ivar spec: The spec it was selected by (``<object>`` for :func:`admit_extensions`).
    :ivar name: The validated name, read once.
    :ivar builtin: Whether it came from the builtin table.
    :ivar provide_run: The run hook, or ``None``.
    :ivar provide_document: The document hook, or ``None``.
    :ivar provide_problem: The problem hook, or ``None``.
    """

    spec: str
    name: str
    builtin: bool
    provide_run: Optional[Callable[..., Any]] = None
    provide_document: Optional[Callable[..., Any]] = None
    provide_problem: Optional[Callable[..., Any]] = None


@dataclass(frozen=True)
class LoadedExtensions:
    """The validated, immutable extension registry of one render (M9, M30).

    :ivar extensions: The admitted extensions, in selection order.
    :ivar filters: Full filter name -> :class:`BoundFilter`.
    :ivar watch: The :class:`ModuleWatch` started before the first ``python:``
        import, or ``None`` when no ``python:`` extension is loaded.
    """

    extensions: tuple[LoadedExtension, ...] = ()
    filters: Mapping[str, BoundFilter] = field(default_factory=lambda: MappingProxyType({}))
    watch: Optional[ModuleWatch] = field(default=None, compare=False, repr=False)

    def check_modules(self):
        """Refuse when a ``python:`` extension's run imported a module from the checkout (M6).

        Called after the factories, before and after the report hooks and after
        rendering (the filters); a no-op without ``python:`` extensions.

        :raises ExtensionError: When a module added since the first ``python:``
            import resolves inside the scan root, its project root or the cwd, or
            a ``sys.path`` entry now does.
        """
        if self.watch is not None:
            self.watch.check()

    def check_import_path(self):
        """Refuse when a ``sys.path`` entry now lies inside the boundary (M6, prevention).

        Called before every report and event hook, so an entry one hook (or
        extension) added fails the run before the next hook can import through it.
        Cheap when ``sys.path`` is unchanged; a no-op without ``python:`` extensions.

        :raises ExtensionError: When an entry is inside, or ``sys.path`` cannot be read.
        """
        if self.watch is not None:
            self.watch.check_path()

    @property
    def names(self) -> tuple[str, ...]:
        """Return the loaded extension names, in order.

        :returns: The names ``requires_extensions`` is checked against.
        """
        return tuple(extension.name for extension in self.extensions)

    @property
    def builtin_specs(self) -> tuple[str, ...]:
        """Return the ``builtin:`` specs, in order, for the effective ``Config`` (M25).

        :returns: The builtin specs.
        """
        return tuple(extension.spec for extension in self.extensions if extension.builtin)

    def __bool__(self) -> bool:
        """Return whether any extension is loaded."""
        return bool(self.extensions)

    def __len__(self) -> int:
        """Return the number of loaded extensions."""
        return len(self.extensions)


#: The empty registry.
NO_EXTENSIONS: Final[LoadedExtensions] = LoadedExtensions()


def _lookup(obj: object, attribute: str, subject: str) -> Any:
    """Read one attribute of an extension object once, wrapping failures.

    :param obj: The extension object.
    :param attribute: The attribute name.
    :param subject: The spec or name for errors.
    :returns: The attribute, or ``None`` when absent.
    :raises ExtensionError: When the lookup raises.
    """
    try:
        return getattr(obj, attribute, None)
    except BaseException as exc:
        if type(exc) is KeyboardInterrupt:
            raise
        raise ExtensionError(f"extension {_echo(subject)}: reading {attribute} failed: {_describe(exc)}") from None


def _admit_filters(raw: object, name: str) -> dict[str, BoundFilter]:
    """Validate the mapping a ``filters()`` hook returned (M7, M9).

    :param raw: The returned value.
    :param name: The owning extension name.
    :returns: Full name -> bound filter.
    :raises ExtensionError: For anything but an exact ``dict`` (a
        ``MappingProxyType`` may wrap a custom mapping whose methods run code), too
        many filters, a foreign or malformed name, a non-:class:`ExtensionFilter`, any
        ``sink`` attribute at all (tested by identity, never by truthiness), or a bad
        function/arity/input-kind declaration.
    """
    if type(raw) is not dict:
        raise ExtensionError(f"extension {name}: filters() must return a dict")
    items = list(raw.items())  # type: ignore[union-attr]
    if len(items) > MAX_FILTERS:
        raise ExtensionError(f"extension {name}: more than {MAX_FILTERS} filters")
    prefix = f"{EXT_FILTER_PREFIX}{name}."
    admitted: dict[str, BoundFilter] = {}
    for key, value in items:
        if type(key) is not str or not key.startswith(prefix) or _FILTER_LEAF_RE.fullmatch(key[len(prefix) :]) is None:
            raise ExtensionError(f"extension {name}: filter name {_echo(key)} must be {prefix}<filter>")
        if type(value) is not ExtensionFilter:
            raise ExtensionError(f"extension {name}: filter {_echo(key)} must be an ExtensionFilter")
        if _lookup(value, "sink", name) is not None:
            raise ExtensionError(
                f"extension {name}: filter {_echo(key)} declares a sink attribute; extension filters are never sinks"
            )
        function, arity, kinds = value.function, value.arity, value.input_kinds
        if not callable(function):
            raise ExtensionError(f"extension {name}: filter {_echo(key)} function is not callable")
        if type(arity) is not int or arity not in (0, 1):
            raise ExtensionError(f"extension {name}: filter {_echo(key)} arity must be 0 or 1")
        if (
            type(kinds) is not frozenset
            or not kinds
            or not all(type(kind) is str for kind in kinds)
            or not kinds <= FILTER_INPUT_KINDS
        ):
            raise ExtensionError(
                f"extension {name}: filter {_echo(key)} input_kinds must be a non-empty frozenset of scalar/list/dict"
            )
        admitted[key] = BoundFilter(key, name, function, arity, kinds)
    return admitted


def _admit(
    obj: object, *, spec: str, is_builtin: bool, expected: Optional[str] = None
) -> tuple[LoadedExtension, dict[str, BoundFilter]]:
    """Validate one extension object: name read once, hooks looked up once (M13, M25).

    :param obj: The extension object.
    :param spec: Its spec (echoed in errors until the name is validated).
    :param is_builtin: Whether it came from the builtin table.
    :param expected: The builtin table name it must carry, if any.
    :returns: The admitted extension and its filters.
    :raises ExtensionError: For an invalid or reserved name, a non-callable hook, or
        invalid filters.
    """
    name = _lookup(obj, "name", spec)
    if type(name) is not str or _NAME_RE.fullmatch(name) is None:
        raise ExtensionError(f"extension {_echo(spec)}: name must be a str matching {EXTENSION_NAME_PATTERN}")
    if expected is not None and name != expected:
        raise ExtensionError(f"builtin extension {_echo(spec)} reports a different name")
    if not is_builtin and builtin.is_reserved_name(name):
        raise ExtensionError(f"extension {_echo(spec)}: name {name} is reserved for a builtin extension")
    hooks: dict[str, Optional[Callable[..., Any]]] = {}
    for hook in (HOOK_RUN, HOOK_DOCUMENT, HOOK_PROBLEM, HOOK_FILTERS):
        value = _lookup(obj, hook, name)
        if value is not None and not callable(value):
            raise ExtensionError(f"extension {name}: {hook} must be callable")
        hooks[hook] = value
    filters: dict[str, BoundFilter] = {}
    if hooks[HOOK_FILTERS] is not None:
        filters = _admit_filters(_call(name, HOOK_FILTERS, hooks[HOOK_FILTERS]), name)
    loaded = LoadedExtension(spec, name, is_builtin, hooks[HOOK_RUN], hooks[HOOK_DOCUMENT], hooks[HOOK_PROBLEM])
    return loaded, filters


def _registry(
    admitted: Sequence[tuple[LoadedExtension, dict[str, BoundFilter]]], watch: Optional[ModuleWatch] = None
) -> LoadedExtensions:
    """Build the immutable registry, refusing duplicate names (M25).

    :param admitted: Admitted extensions with their filters.
    :param watch: The run's module watch, when a ``python:`` extension is loaded.
    :returns: The registry.
    :raises ExtensionError: When two extensions share a name.
    """
    names: set[str] = set()
    filters: dict[str, BoundFilter] = {}
    for extension, own in admitted:
        if extension.name in names:
            raise ExtensionError(f"two extensions are named {extension.name}")
        names.add(extension.name)
        filters.update(own)
    if watch is not None:
        filters = {key: replace(bound, guard=watch.check_path) for key, bound in filters.items()}
    return LoadedExtensions(tuple(extension for extension, _ in admitted), MappingProxyType(filters), watch)


def admit_extensions(objects: Sequence[object]) -> LoadedExtensions:
    """Admit extension objects a library caller already holds (no import, no gate).

    The caller has already executed the code that built these objects, so no trust
    decision is taken here; the data contract still applies and builtin names stay
    reserved (M25).

    :param objects: Extension objects.
    :returns: The registry.
    :raises ExtensionError: For too many objects, or any invalid object.
    """
    if isinstance(objects, (str, bytes)) or not isinstance(objects, Sequence):
        raise ExtensionError("extensions must be a sequence of extension objects")
    if len(objects) > MAX_EXTENSIONS:
        raise ExtensionError(f"more than {MAX_EXTENSIONS} extensions")
    return _registry([_admit(obj, spec="<object>", is_builtin=False) for obj in objects])


def resolve_extensions(
    specs: Sequence[str] = (),
    *,
    config: Config,
    allow_python: bool,
    root: Path,
    cwd: Path,
    origin_roots: Sequence[Path] = (),
) -> LoadedExtensions:
    """Select, gate, import and validate the extensions of one run (M1-M6, M13, M25, M30).

    Specs are taken in order: ``config.telemetry_extensions`` first (re-checked:
    builtin only), then ``specs`` (the invoker's argv-equivalent list). Every spec
    is parsed and the gate is checked for every ``python:`` spec before any
    extension is resolved, so a refusal executes nothing. After every factory (and
    its ``filters()`` hook) the :class:`ModuleWatch` checks ``sys.path`` and
    ``sys.modules`` again, so a factory that adds the checkout to ``sys.path`` fails
    the run before the next extension is imported or any hook runs (M6). The same
    check also runs between each factory and its ``filters()`` hook, and every
    registered extension filter checks ``sys.path`` before each call (amended
    2026-11-03, F2).

    :param specs: Invoker-supplied specs (``--extension``).
    :param config: The effective configuration.
    :param allow_python: The invoker's explicit gate decision (no default).
    :param root: The scan root, for the M6 origin check.
    :param cwd: The current directory, for the M6 origin check.
    :param origin_roots: Further spellings of the scan root, as the invoker wrote it
        (absolute but unresolved; the CLI passes ``os.path.abspath`` of its argument,
        or its parent for a file). Each is anchored with its marked ancestors, so a
        root that is a symlink out of the checkout cannot drop the checkout from the
        boundary (M6, amended 2026-11-03).
    :returns: The registry.
    :raises ConfigError: When ``config.telemetry_extensions`` holds a non-builtin entry.
    :raises ExtensionError: For a malformed, unknown, duplicate or refused spec, a
        failing factory, or an invalid extension.
    """
    configured = validate_telemetry_extensions(config.telemetry_extensions)
    if isinstance(specs, (str, bytes)) or not isinstance(specs, Sequence):
        raise ExtensionError("extensions must be a sequence of extension specs")
    origins = _origin_paths(origin_roots)
    ordered = (*configured, *specs)
    if len(ordered) > MAX_EXTENSIONS:
        raise ExtensionError(f"more than {MAX_EXTENSIONS} extensions")
    parsed: list[_Spec] = []
    seen: set[str] = set()
    for spec in ordered:
        item = _parse_spec(spec)
        if item.text in seen:
            raise ExtensionError(f"extension spec given twice: {_echo(item.text)}")
        seen.add(item.text)
        parsed.append(item)
    if allow_python is not True and any(item.kind == "python" for item in parsed):
        first = next(item for item in parsed if item.kind == "python")
        load_python_target(first.text, allow_python=False, root=root, cwd=cwd, origin_roots=origins)
    for item in parsed:
        if item.kind == "builtin" and builtin.builtin_factory(item.target) is None:
            raise ExtensionError(f"unknown builtin extension: {_echo(item.text)}")
    watch = ModuleWatch.start(root, cwd, origins) if any(item.kind == "python" for item in parsed) else None
    admitted = []
    for item in parsed:
        if item.kind == "builtin":
            factory = builtin.builtin_factory(item.target)
            instance = _call(item.text, "factory", factory)
        else:
            target = load_python_target(item.text, allow_python=allow_python, root=root, cwd=cwd, origin_roots=origins)
            instance = _call(item.text, "factory", target)
        if watch is not None:
            # F2: sys.path (and sys.modules) before filters() runs inside _admit.
            watch.check()
        admitted.append(
            _admit(
                instance,
                spec=item.text,
                is_builtin=item.kind == "builtin",
                expected=item.target if item.kind == "builtin" else None,
            )
        )
        if watch is not None:
            watch.check()
    return _registry(admitted, watch)


# --------------------------------------------------------------------------- template binding (M12, M30)


def check_template(template: Any, loaded: LoadedExtensions):
    """Check a validated template against the loaded registry; never loads anything (M30).

    :param template: A :class:`~docsentinel.telemetry.loader.Template`.
    :param loaded: The registry.
    :raises TemplateError: When a required extension is not loaded (M31 message), or
        a used extension filter is not registered or is used with the wrong arity
        or input kind.
    """
    names = frozenset(loaded.names)
    missing = [name for name in template.requires_extensions if name not in names]
    if missing:
        raise TemplateError(missing_extensions_message(missing))
    for name, argument_count, kind in template.extension_filters:
        bound = loaded.filters.get(name)
        if bound is None:
            raise TemplateError(f"template uses filter {_echo(name)}, which no loaded extension registers")
        if argument_count != bound.arity:
            raise TemplateError(f"filter {_echo(name)} takes {bound.arity} argument(s)")
        if kind != "any" and kind not in bound.input_kinds:
            raise TemplateError(f"filter {_echo(name)} cannot take a {kind} value")


#: Context keys holding a list of documents, each with ``ext`` and ``problems``.
_DOCUMENT_LISTS: Final[tuple[str, ...]] = ("documents", "documents_with_problems")

#: Context key of the flat problem list, each entry with ``ext``.
_FLAT_PROBLEMS: Final[str] = "findings"

#: The extension namespace key at every level.
_EXT_KEY: Final[str] = "ext"


def _scoped(entry: object, allowed: frozenset[str]) -> object:
    """Return a shallow copy of one context object with ``ext`` cut to ``allowed`` (M12).

    :param entry: A run, document or problem mapping (anything else is returned as is).
    :param allowed: The template's ``requires_extensions``.
    :returns: The copy: ``ext`` holds only allowed members, and is dropped when
        nothing is allowed.
    """
    if type(entry) is not dict or _EXT_KEY not in entry:
        return entry
    copy = dict(entry)
    members = copy.pop(_EXT_KEY)
    if allowed:
        copy[_EXT_KEY] = (
            {name: value for name, value in members.items() if name in allowed} if type(members) is dict else members
        )
    return copy


def scope_extension_data(context: Mapping[str, JsonValue], requires: Sequence[str]) -> Mapping[str, JsonValue]:
    """Return the context a template may see: only the extensions it requires (M12).

    ``ext`` at the run, document and problem levels (``documents``,
    ``documents_with_problems``, each ``problems`` list and the flat ``findings``)
    keeps only the members listed in ``requires_extensions``; a template that lists
    none sees no ``ext`` key at all, so a whole-object sink such as ``{doc|json}``
    or ``{"$var": "documents"}`` emits exactly what it would without extensions.
    Nothing is mutated; untouched branches are shared, and a document reached from
    two lists is copied once.

    :param context: The render context.
    :param requires: The template's ``requires_extensions``.
    :returns: The scoped context (``context`` itself when it holds no ``ext``).
    """
    allowed = frozenset(requires)
    if type(context) is not dict or not any(_EXT_KEY in item for item in _ext_holders(context)):
        return context
    scoped: dict[str, JsonValue] = dict(_scoped(context, allowed))  # type: ignore[call-overload]
    memo: dict[int, object] = {}

    def document(entry: object) -> object:
        marker = id(entry)
        if marker not in memo:
            copy = _scoped(entry, allowed)
            if type(copy) is dict and type(copy.get("problems")) is list:
                copy = copy if copy is not entry else dict(copy)
                copy["problems"] = [_scoped(problem, allowed) for problem in copy["problems"]]
            memo[marker] = copy
        return memo[marker]

    for key in _DOCUMENT_LISTS:
        if type(scoped.get(key)) is list:
            scoped[key] = [document(entry) for entry in scoped[key]]
    if type(scoped.get(_FLAT_PROBLEMS)) is list:
        scoped[_FLAT_PROBLEMS] = [_scoped(problem, allowed) for problem in scoped[_FLAT_PROBLEMS]]
    return scoped


def _ext_holders(context: Mapping[str, JsonValue]) -> list[Mapping[str, Any]]:
    """Return the run mapping and every document/problem mapping that may hold ``ext``.

    :param context: The render context.
    :returns: The mappings (non-dict entries skipped).
    """
    holders: list[Mapping[str, Any]] = [context]
    for key in _DOCUMENT_LISTS:
        entries = context.get(key)
        if type(entries) is not list:
            continue
        for entry in entries:
            if type(entry) is dict:
                holders.append(entry)
                problems = entry.get("problems")
                if type(problems) is list:
                    holders.extend(problem for problem in problems if type(problem) is dict)
    flat = context.get(_FLAT_PROBLEMS)
    if type(flat) is list:
        holders.extend(problem for problem in flat if type(problem) is dict)
    return holders


# --------------------------------------------------------------------------- data contract (M13-M16)


def freeze(value: JsonValue, memo: Optional[dict[int, Any]] = None) -> Any:
    """Return a deep-frozen copy of a JSON tree (M13).

    Dicts become ``MappingProxyType`` over new dicts and lists become tuples,
    recursively; a container shared by several parents is frozen once.

    :param value: The JSON tree.
    :param memo: Shared ``id -> frozen`` memo.
    :returns: The frozen tree; it never aliases a mutable container of ``value``.
    """
    memo = {} if memo is None else memo
    kind = type(value)
    if kind is not dict and kind is not list and kind is not tuple:
        return value
    marker = id(value)
    if marker in memo:
        return memo[marker][1]
    if kind is dict:
        frozen: Any = MappingProxyType({key: freeze(item, memo) for key, item in value.items()})
    else:
        frozen = tuple(freeze(item, memo) for item in value)
    memo[marker] = (value, frozen)
    return frozen


def _value_kind(value: object) -> str:
    """Return ``scalar``/``list``/``dict`` for a JSON value (anything else is ``other``).

    :param value: A context value.
    :returns: Its kind.
    """
    if type(value) is list:
        return "list"
    if type(value) is dict:
        return "dict"
    return "scalar" if _is_exact_scalar(value) else "other"


def _is_exact_scalar(value: object) -> bool:
    """Return whether ``value`` is an exact JSON scalar within the M15 bounds.

    :param value: Any value.
    :returns: ``True`` for exact ``str`` without lone surrogates, ``bool``,
        ``None``, ``int`` with ``|x| <= 2**53`` or finite ``float``.
    """
    kind = type(value)
    if value is None or kind is bool:
        return True
    if kind is str:
        return _SURROGATE_RE.search(value) is None  # type: ignore[arg-type]
    if kind is int:
        return -MAX_INT <= value <= MAX_INT  # type: ignore[operator]
    return kind is float and math.isfinite(value)  # type: ignore[arg-type]


class _Shape(Exception):
    """Internal: a hook return that breaks the data contract."""


class _Oversize(_Shape):
    """Internal: a hook return past its size limit."""


_LEAVE: Final[object] = object()
_APPEND: Final[object] = object()


def _scalar_chars(value: object) -> int:
    """Return the estimated serialized size of a valid scalar.

    :param value: An exact scalar.
    :returns: Characters.
    :raises _Shape: For a value outside the scalar contract.
    """
    kind = type(value)
    if kind is str:
        return len(value) + 2  # type: ignore[arg-type]
    if value is None or kind is bool:
        return 5
    if kind is int:
        if not -MAX_INT <= value <= MAX_INT:  # type: ignore[operator]
            raise _Shape("an integer outside +/-2**53")
        return len(int.__repr__(value))  # type: ignore[arg-type]
    if kind is float:
        if not math.isfinite(value):  # type: ignore[arg-type]
            raise _Shape("a non-finite number")
        return len(float.__repr__(value))  # type: ignore[arg-type]
    raise _Shape("a value that is not exact JSON data (dict, list, str, int, float, bool or None)")


def validated_copy(value: object, limit: int) -> tuple[dict[str, JsonValue], int]:
    """Copy a hook return into fresh builtin objects, enforcing M14 and M15.

    An iterative depth-first walk: exact ``dict``/``list``/``tuple`` containers
    (tuples become lists), exact scalars, no cycles, depth at most
    :data:`MAX_DEPTH` from the root, at most :data:`MAX_CONTAINER_ENTRIES` entries
    per container, ``str`` keys of at most :data:`MAX_KEY_CHARS` characters, and
    no lone surrogates. The estimated serialized size is counted as the walk goes
    and the walk stops as soon as it passes ``limit``, so nothing is serialized and
    an oversized return is never copied in full.

    :param value: The hook return (``None`` must be handled by the caller).
    :param limit: The size limit in estimated characters.
    :returns: The copy and its estimated size.
    :raises _Shape: When the return breaks the contract (``_Oversize`` for size).
    """
    if type(value) is not dict:
        raise _Shape("a hook must return a dict or None")
    used = 0
    on_path: set[int] = set()
    root: dict[str, JsonValue] = {}
    stack: list[Any] = [(value, None, None, 1)]

    def charge(count: int):
        nonlocal used
        used += count
        if used > limit:
            raise _Oversize("is too large")

    while stack:
        item = stack.pop()
        if item[0] is _LEAVE:
            on_path.discard(item[1])
            continue
        source, parent, key, depth = item
        kind = type(source)
        if kind is dict or kind is list or kind is tuple:
            if depth > MAX_DEPTH:
                raise _Shape(f"nesting deeper than {MAX_DEPTH}")
            marker = id(source)
            if marker in on_path:
                raise _Shape("a reference cycle")
            size = len(source)
            if size > MAX_CONTAINER_ENTRIES:
                raise _Shape(f"a container with more than {MAX_CONTAINER_ENTRIES} entries")
            charge(2 + max(size - 1, 0))
            target: Any = root if parent is None else ({} if kind is dict else [])
            if parent is not None:
                _attach(parent, key, target)
            on_path.add(marker)
            stack.append((_LEAVE, marker))
            children: list[Any] = []
            if kind is dict:
                for child_key, child in source.items():
                    if type(child_key) is not str:
                        raise _Shape("an object key that is not a str")
                    if len(child_key) > MAX_KEY_CHARS:
                        raise _Shape(f"an object key longer than {MAX_KEY_CHARS} characters")
                    if _SURROGATE_RE.search(child_key):
                        raise _Shape("an object key with a lone surrogate")
                    charge(len(child_key) + 3)
                    children.append((child, target, child_key, depth + 1))
            else:
                children.extend((child, target, _APPEND, depth + 1) for child in source)
            stack.extend(reversed(children))
            continue
        charge(_scalar_chars(source))
        if kind is str and _SURROGATE_RE.search(source):
            raise _Shape("a string with a lone surrogate")
        _attach(parent, key, source)
    return root, used


def _attach(parent: Any, key: Any, value: Any):
    """Attach a copied value to its copied parent.

    :param parent: The destination dict or list.
    :param key: The dict key, or :data:`_APPEND` for a list.
    :param value: The copied value.
    """
    if key is _APPEND:
        parent.append(value)
    else:
        parent[key] = value


def _call(subject: str, hook: str, function: Callable[..., Any], *args: Any) -> Any:
    """Call one extension hook or factory; failures become :class:`ExtensionError` (M17).

    ``Exception`` and ``SystemExit`` (so ``SystemExit(0)`` cannot choose the exit
    code) and every other ``BaseException`` except an exact ``KeyboardInterrupt`` are
    wrapped; a ``KeyboardInterrupt`` *subclass* is extension-defined and wrapped too
    (amended 2026-11-03, F4), so it cannot escape the wrapping and the final M6 check.

    :param subject: The extension name or spec.
    :param hook: The hook name.
    :param function: The callable.
    :param args: Its arguments.
    :returns: Its return value.
    :raises ExtensionError: When it raises.
    """
    try:
        return function(*args)
    except BaseException as exc:
        if type(exc) is KeyboardInterrupt:
            raise
        raise _hook_failure(subject, hook, exc) from None


class _Budget:
    """Aggregate size budget of extension output in one render (M16)."""

    def __init__(self):
        """Start empty."""
        self.total = 0
        self.per_extension: dict[str, int] = {}

    def limit(self, name: str) -> int:
        """Return the limit for the next hook return of ``name``.

        :param name: The extension name.
        :returns: The smallest of the per-hook, per-extension and global remainders.
        """
        own = MAX_EXTENSION_CHARS - self.per_extension.get(name, 0)
        return max(min(MAX_HOOK_CHARS, own, MAX_TOTAL_EXTENSION_CHARS - self.total), 0)

    def reason(self, name: str) -> str:
        """Return which cap a too-large return passed.

        :param name: The extension name.
        :returns: A short description of the cap.
        """
        own = MAX_EXTENSION_CHARS - self.per_extension.get(name, 0)
        overall = MAX_TOTAL_EXTENSION_CHARS - self.total
        if MAX_HOOK_CHARS <= min(own, overall):
            return f"more than {MAX_HOOK_CHARS} characters in one hook return"
        if own <= overall:
            return f"more than {MAX_EXTENSION_CHARS} characters across the render"
        return f"more than {MAX_TOTAL_EXTENSION_CHARS} characters across all extensions"

    def spend(self, name: str, count: int):
        """Record ``count`` characters of ``name``'s output.

        :param name: The extension name.
        :param count: Estimated characters.
        """
        self.per_extension[name] = self.per_extension.get(name, 0) + count
        self.total += count


def _run_hook(
    extension: LoadedExtension, hook: str, function: Callable[..., Any], args: tuple[Any, ...], budget: _Budget
) -> Optional[dict[str, JsonValue]]:
    """Call one data hook and return a validated, budgeted copy of its result.

    :param extension: The extension.
    :param hook: The hook name.
    :param function: The hook.
    :param args: Its frozen arguments.
    :param budget: The render's aggregate budget.
    :returns: The copy, or ``None`` when the hook returned ``None``.
    :raises ExtensionError: When the hook raises or returns invalid or oversized data.
    """
    result = _call(extension.name, hook, function, *args)
    if result is None:
        return None
    try:
        copied, size = validated_copy(result, budget.limit(extension.name))
    except _Oversize:
        raise ExtensionError(f"extension {extension.name}: {hook} returned {budget.reason(extension.name)}") from None
    except _Shape as exc:
        raise ExtensionError(f"extension {extension.name}: {hook} returned invalid data: {exc}") from None
    except RecursionError:
        raise ExtensionError(f"extension {extension.name}: {hook} returned data that cannot be checked") from None
    budget.spend(extension.name, size)
    return copied


def apply_report_hooks(
    context: dict[str, JsonValue],
    loaded: LoadedExtensions,
    flat_problems: Mapping[int, dict[str, JsonValue]] = MappingProxyType({}),
):
    """Run every hook and attach the results under ``ext.<name>`` (M13-M17, M26).

    The context is frozen once before the first hook, so hooks see core data only
    and never a live object. ``ext`` is created by this function at the run level,
    on every document and on every problem (and its flat ``findings`` twin), so a
    hook return can never add, replace or remove a core key.

    :param context: The core context from ``ReportModel.build``; extended in place.
    :param loaded: The registry.
    :param flat_problems: ``id(nested problem) -> flat findings entry``, so each
        problem's data also reaches ``findings[].ext``.
    Before the first hook and before every later one, ``sys.path`` is checked
    again (M6 prevention), so an entry inside the boundary added by a factory or an
    earlier hook fails the run before the next hook can import through it.

    :raises ExtensionError: When a hook raises, or returns invalid or oversized data,
        a ``sys.path`` entry lies inside the boundary, or a ``python:`` extension's
        hooks imported a module from the checkout (M6).
    """
    if not loaded:
        return
    loaded.check_modules()
    frozen_model = freeze(context)
    documents = context["documents"]
    frozen_documents = frozen_model["documents"]
    run_ext: dict[str, JsonValue] = {}
    context["ext"] = run_ext
    for document in documents:
        document["ext"] = {}
        for problem in document["problems"]:
            problem["ext"] = {}
            twin = flat_problems.get(id(problem))
            if twin is not None:
                twin["ext"] = {}
    budget = _Budget()
    for extension in loaded.extensions:
        if extension.provide_run is not None:
            loaded.check_import_path()
            value = _run_hook(extension, HOOK_RUN, extension.provide_run, (frozen_model,), budget)
            if value is not None:
                run_ext[extension.name] = value
        if extension.provide_document is None and extension.provide_problem is None:
            continue
        for document, frozen_document in zip(documents, frozen_documents, strict=True):
            if extension.provide_document is not None:
                loaded.check_import_path()
                value = _run_hook(
                    extension, HOOK_DOCUMENT, extension.provide_document, (frozen_document, frozen_model), budget
                )
                if value is not None:
                    document["ext"][extension.name] = value
            if extension.provide_problem is None:
                continue
            for problem, frozen_problem in zip(document["problems"], frozen_document["problems"], strict=True):
                loaded.check_import_path()
                value = _run_hook(
                    extension,
                    HOOK_PROBLEM,
                    extension.provide_problem,
                    (frozen_problem, frozen_document, frozen_model),
                    budget,
                )
                if value is not None:
                    problem["ext"][extension.name] = value
                    twin = flat_problems.get(id(problem))
                    if twin is not None:
                        twin["ext"][extension.name] = value
    loaded.check_modules()


class EventHookGuard:
    """Run problem hooks on the fault-event path, swallowing failures (M29).

    For the Milestone 0006 emission path: a hook ``Exception``/``SystemExit`` or an
    invalid return is swallowed, the event keeps its core fields, and **one**
    bounded, neutralized warning is written per extension per run. Refusals are not
    handled here: they happen in :func:`resolve_extensions` and are never swallowed
    (M4). Neither is a module-origin refusal (M6): ``sys.path`` is checked before
    every hook, and :meth:`ModuleWatch.check` runs unconditionally after each event's
    hooks; their :class:`ExtensionError` propagates. Only an exact
    ``KeyboardInterrupt`` propagates; a hook raising a subclass is a hook failure.
    """

    def __init__(self, loaded: LoadedExtensions, *, warn: Callable[[str], None]):
        """Bind the registry and the warning sink.

        :param loaded: The registry.
        :param warn: Called once per failing extension with the bounded message.
        """
        self._loaded = loaded
        self._warn = warn
        self._failed: set[str] = set()
        self._budget = _Budget()

    def problem_ext(
        self, problem: Mapping[str, Any], doc: Mapping[str, Any], model: Mapping[str, Any]
    ) -> dict[str, JsonValue]:
        """Return ``{name: data}`` from every healthy extension's problem hook.

        :param problem: The problem mapping (frozen before the hook sees it).
        :param doc: Its document mapping.
        :param model: The run-level context.
        :returns: Extension data by name; failing extensions are omitted.
        :raises ExtensionError: When a ``sys.path`` entry lies inside the boundary, or
            a hook imported a module from the checkout (M6).
        """
        result: dict[str, JsonValue] = {}
        arguments: Optional[tuple[Any, ...]] = None
        for extension in self._loaded.extensions:
            if extension.provide_problem is None or extension.name in self._failed:
                continue
            if arguments is None:
                arguments = (freeze(dict(problem)), freeze(dict(doc)), freeze(dict(model)))
            self._loaded.check_import_path()
            try:
                value = _run_hook(extension, HOOK_PROBLEM, extension.provide_problem, arguments, self._budget)
            except ExtensionError as exc:
                self._failed.add(extension.name)
                self._warn(f"warning: extension {extension.name} disabled for fault events: {exc}")
                continue
            if value is not None:
                result[extension.name] = value
        watch = self._loaded.watch
        if watch is not None:
            watch.check()
        return result


__all__ = [
    "BUILTIN_PREFIX",
    "EXTENSION_NAME_PATTERN",
    "EXT_FILTER_PREFIX",
    "NO_EXTENSIONS",
    "PYTHON_PREFIX",
    "BoundFilter",
    "EventHookGuard",
    "Extension",
    "ExtensionError",
    "ExtensionFilter",
    "LoadedExtension",
    "LoadedExtensions",
    "ModuleWatch",
    "PROJECT_ROOT_MARKERS",
    "admit_extensions",
    "apply_report_hooks",
    "check_template",
    "freeze",
    "load_python_target",
    "missing_extensions_message",
    "project_roots",
    "resolve_extensions",
    "scope_extension_data",
    "validated_copy",
]
