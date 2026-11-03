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
* **M6** -- every dotted prefix of the module is resolved with
  ``importlib.util.find_spec`` (or read from an existing ``sys.modules`` entry)
  and refused, before the module executes, when any origin or search location lies
  inside the scan root or the current directory. ``sys.path`` is never changed.

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
  sinks (a truthy ``sink`` attribute is refused), live only in the per-render
  :class:`LoadedExtensions` registry (never in ``loader.FILTERS``), and at render
  time must return an exact JSON scalar; any failure is a bounded ``TemplateError``.
* **M25/M26** -- builtin names are reserved against ``python:`` extensions; names and
  specs are unique; returned trees are attached only under ``ext.<name>``.
* **M17/M27/M29** -- a hook's ``Exception`` or ``SystemExit`` becomes an
  :class:`ExtensionError` on the report path (``KeyboardInterrupt`` propagates) and
  is swallowed with one warning per extension by :class:`EventHookGuard`. Messages
  echo only the spec or name, the hook, the exception ``__qualname__`` and at most
  200 characters of ``str(exc)``, each neutralized, capped at 512 characters.

Accepted residual risks (threat model R1-R4): an admitted ``python:`` extension is
full in-process code; a hook that never returns is not stopped (decision D-C); the
M6 origin check is point-in-time.
"""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import math
import os
import re
import sys
import types
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
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

_NAME_RE = re.compile(EXTENSION_NAME_PATTERN)
_FILTER_LEAF_RE = re.compile(r"[a-z_][a-z0-9_]{0,63}")
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


def _describe(exc: BaseException) -> str:
    """Return ``QualName: detail`` for an exception, bounded and neutralized (M27).

    Never ``repr(exc)`` or a traceback; a ``__str__`` that itself fails yields
    ``<unprintable>``.

    :param exc: The exception.
    :returns: The bounded description.
    """
    qualname = getattr(type(exc), "__qualname__", None)
    try:
        detail = str(exc)
    except KeyboardInterrupt:
        raise
    except BaseException:
        detail = "<unprintable>"
    shown = _echo(qualname, _MAX_QUALNAME) if isinstance(qualname, str) else "<exception>"
    text = _echo(detail, MAX_DETAIL_CHARS) if isinstance(detail, str) else ""
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


def _anchors(root: Path, cwd: Path) -> tuple[tuple[str, Optional[os.stat_result]], ...]:
    """Return the scan root and cwd, both as given and canonical, with ``stat`` results.

    :param root: The scan root.
    :param cwd: The current directory.
    :returns: ``(path, stat or None)`` pairs: the absolute and the canonical
        spelling of each anchor.
    """
    anchors = []
    for anchor in (root, cwd):
        text = os.fspath(anchor)
        for spelling in dict.fromkeys((os.path.abspath(text), os.path.realpath(text))):
            try:
                info: Optional[os.stat_result] = os.stat(spelling)
            except OSError:
                info = None
            anchors.append((spelling, info))
    return tuple(anchors)


def _is_inside(location: object, anchors: tuple[tuple[str, Optional[os.stat_result]], ...]) -> bool:
    """Return whether a module origin or search location lies inside an anchor (M6).

    Both the location as written (so an in-root symlink to an outside file is
    still refused) and its canonical path are checked: lexically against every
    anchor spelling, then by walking their ancestors comparing device/inode with
    each anchor, so a case-insensitive filesystem or a second spelling of the root
    cannot hide containment. Fails closed: a location that cannot be resolved, or
    whose ancestor chain is implausibly long, counts as inside.

    :param location: A path string from a module spec or namespace.
    :param anchors: From :func:`_anchors`.
    :returns: ``True`` when the location is inside the scan root or the cwd.
    """
    if not isinstance(location, str) or not location:
        return False
    text = str.__str__(location)
    try:
        candidates = tuple(dict.fromkeys((os.path.abspath(text), os.path.realpath(text))))
    except (OSError, ValueError):
        return True
    stats = [info for _, info in anchors if info is not None]
    for candidate in candidates:
        for anchor, _ in anchors:
            try:
                if os.path.commonpath([candidate, anchor]) == anchor:
                    return True
            except ValueError:
                continue
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
    except Exception:
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


def _module_locations(module: object) -> list[object]:
    """Return the file locations of an imported module, read from its ``__dict__`` only.

    Reading the namespace directly never triggers a module ``__getattr__``.

    :param module: A ``sys.modules`` entry.
    :returns: Path strings to check.
    :raises ExtensionError: For an entry that is not a module object.
    """
    if not isinstance(module, types.ModuleType):
        raise ExtensionError("python extension refused: a sys.modules entry is not a module")
    namespace = module.__dict__
    found: list[object] = []
    spec = namespace.get("__spec__")
    if spec is not None:
        found.extend(_spec_locations(spec))
    found.append(namespace.get("__file__"))
    found.extend(_locations(namespace.get("__path__")))
    return found


def _check_origins(module: str, anchors: tuple[tuple[str, Optional[os.stat_result]], ...]):
    """Refuse a module when any dotted prefix resolves inside the root or cwd (M6).

    Prefixes are checked outermost first, so a parent package is checked before
    ``find_spec`` of a child imports it.

    :param module: The validated module path.
    :param anchors: From :func:`_anchors`.
    :raises ExtensionError: When a prefix is missing, not standard, or inside.
    """
    parts = module.split(".")
    for count in range(1, len(parts) + 1):
        prefix = ".".join(parts[:count])
        loaded = sys.modules.get(prefix)
        if loaded is not None:
            locations = _module_locations(loaded)
        else:
            try:
                spec = importlib.util.find_spec(prefix)
            except KeyboardInterrupt:
                raise
            except BaseException as exc:
                raise ExtensionError(
                    f"python extension module {_echo(module)} could not be located: {_echo(type(exc).__qualname__)}"
                ) from None
            if spec is None:
                raise ExtensionError(f"python extension module {_echo(module)} was not found")
            locations = _spec_locations(spec)
        if any(_is_inside(location, anchors) for location in locations):
            raise ExtensionError(
                f"python extension module {_echo(module)} is refused: it resolves inside the scan root "
                "or the current directory"
            )


def load_python_target(spec: str, *, allow_python: bool, root: Path, cwd: Path) -> object:
    """Resolve a ``python:<module>:<callable>`` spec to its callable (M2, M3, M5, M6).

    The single shared ``importlib`` helper (Milestone 0007 extensions and the
    Milestone 0006 ``python:`` sink). Order: the gate, before any import machinery
    is touched; the grammar; the origin check of every dotted prefix; then the one
    ``import_module`` call; then the origin check again on the imported module;
    then ``getattr`` over the validated callable segments.

    :param spec: The spec, as given by the invoker.
    :param allow_python: The invoker's explicit gate decision; anything but ``True``
        refuses. There is deliberately no default.
    :param root: The scan root; a module inside it is refused.
    :param cwd: The current directory; a module inside it is refused.
    :returns: The resolved callable (not yet called).
    :raises ExtensionError: When refused by the gate, the grammar or the origin
        check, or when the import or attribute lookup fails, or the target is not
        callable. Nothing is executed for a refused spec.
    """
    if allow_python is not True:
        raise ExtensionError(
            f"python extension {_echo(spec)} is refused: python: extensions run arbitrary code and need the "
            "invoker's explicit opt-in (--allow-python-extensions, or allow_python_extensions=True)"
        )
    parsed = _parse_spec(spec)
    if parsed.kind != "python":
        raise ExtensionError(f"not a python extension spec: {_echo(spec)}")
    anchors = _anchors(root, cwd)
    _check_origins(parsed.target, anchors)
    try:
        module = importlib.import_module(parsed.target)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise ExtensionError(
            f"python extension module {_echo(parsed.target)} could not be imported: {_echo(type(exc).__qualname__)}"
        ) from None
    if any(_is_inside(location, anchors) for location in _module_locations(module)):
        raise ExtensionError(
            f"python extension module {_echo(parsed.target)} is refused: it resolves inside the scan root "
            "or the current directory"
        )
    target: object = module
    for segment in parsed.attribute.split("."):
        try:
            target = getattr(target, segment)
        except KeyboardInterrupt:
            raise
        except BaseException:
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
    """

    name: str
    extension: str
    function: Callable[..., JsonScalar]
    arity: int
    input_kinds: frozenset[str]

    def __call__(self, value: JsonValue, args: tuple[str, ...]) -> JsonScalar:
        """Apply the filter at render time (M10).

        A container input is passed as a deep-frozen copy. The result must be an
        exact JSON scalar; anything else, and any exception (``KeyboardInterrupt``
        aside), is a bounded :class:`~docsentinel.telemetry.filters.TemplateError`.

        :param value: The JSON input.
        :param args: The literal arguments.
        :returns: The scalar result.
        :raises TemplateError: On a wrong argument count or input kind, a raising
            filter or a non-scalar result.
        """
        if len(args) != self.arity:
            raise TemplateError(f"filter {_echo(self.name)} takes {self.arity} argument(s)")
        kind = _value_kind(value)
        if kind not in self.input_kinds:
            raise TemplateError(f"filter {_echo(self.name)} cannot take a {kind} value")
        argument = freeze(value) if kind != "scalar" else value
        try:
            result = self.function(argument, *args)
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
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
    """

    extensions: tuple[LoadedExtension, ...] = ()
    filters: Mapping[str, BoundFilter] = field(default_factory=lambda: MappingProxyType({}))

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
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
        raise ExtensionError(f"extension {_echo(subject)}: reading {attribute} failed: {_describe(exc)}") from None


def _admit_filters(raw: object, name: str) -> dict[str, BoundFilter]:
    """Validate the mapping a ``filters()`` hook returned (M7, M9).

    :param raw: The returned value.
    :param name: The owning extension name.
    :returns: Full name -> bound filter.
    :raises ExtensionError: For a non-mapping, too many filters, a foreign or
        malformed name, a non-:class:`ExtensionFilter`, a truthy ``sink``, or a bad
        function/arity/input-kind declaration.
    """
    if type(raw) not in (dict, MappingProxyType):
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
        if _lookup(value, "sink", name):
            raise ExtensionError(
                f"extension {name}: filter {_echo(key)} declares itself a sink; extension filters are never sinks"
            )
        function, arity, kinds = value.function, value.arity, value.input_kinds
        if not callable(function):
            raise ExtensionError(f"extension {name}: filter {_echo(key)} function is not callable")
        if type(arity) is not int or arity not in (0, 1):
            raise ExtensionError(f"extension {name}: filter {_echo(key)} arity must be 0 or 1")
        if type(kinds) is not frozenset or not kinds or not kinds <= FILTER_INPUT_KINDS:
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


def _registry(admitted: Sequence[tuple[LoadedExtension, dict[str, BoundFilter]]]) -> LoadedExtensions:
    """Build the immutable registry, refusing duplicate names (M25).

    :param admitted: Admitted extensions with their filters.
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
    return LoadedExtensions(tuple(extension for extension, _ in admitted), MappingProxyType(filters))


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
) -> LoadedExtensions:
    """Select, gate, import and validate the extensions of one run (M1-M6, M13, M25, M30).

    Specs are taken in order: ``config.telemetry_extensions`` first (re-checked:
    builtin only), then ``specs`` (the invoker's argv-equivalent list). Every spec
    is parsed and the gate is checked for every ``python:`` spec before any
    extension is resolved, so a refusal executes nothing.

    :param specs: Invoker-supplied specs (``--extension``).
    :param config: The effective configuration.
    :param allow_python: The invoker's explicit gate decision (no default).
    :param root: The scan root, for the M6 origin check.
    :param cwd: The current directory, for the M6 origin check.
    :returns: The registry.
    :raises ConfigError: When ``config.telemetry_extensions`` holds a non-builtin entry.
    :raises ExtensionError: For a malformed, unknown, duplicate or refused spec, a
        failing factory, or an invalid extension.
    """
    configured = validate_telemetry_extensions(config.telemetry_extensions)
    if isinstance(specs, (str, bytes)) or not isinstance(specs, Sequence):
        raise ExtensionError("extensions must be a sequence of extension specs")
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
        load_python_target(first.text, allow_python=False, root=root, cwd=cwd)
    for item in parsed:
        if item.kind == "builtin" and builtin.builtin_factory(item.target) is None:
            raise ExtensionError(f"unknown builtin extension: {_echo(item.text)}")
    admitted = []
    for item in parsed:
        if item.kind == "builtin":
            factory = builtin.builtin_factory(item.target)
            instance = _call(item.text, "factory", factory)
            admitted.append(_admit(instance, spec=item.text, is_builtin=True, expected=item.target))
        else:
            target = load_python_target(item.text, allow_python=allow_python, root=root, cwd=cwd)
            instance = _call(item.text, "factory", target)
            admitted.append(_admit(instance, spec=item.text, is_builtin=False))
    return _registry(admitted)


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
        raise _Shape("must return a dict or None")
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
                raise _Shape(f"is nested deeper than {MAX_DEPTH}")
            marker = id(source)
            if marker in on_path:
                raise _Shape("holds a reference cycle")
            size = len(source)
            if size > MAX_CONTAINER_ENTRIES:
                raise _Shape(f"has a container with more than {MAX_CONTAINER_ENTRIES} entries")
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
                        raise _Shape("has an object key that is not a str")
                    if len(child_key) > MAX_KEY_CHARS:
                        raise _Shape(f"has an object key longer than {MAX_KEY_CHARS} characters")
                    if _SURROGATE_RE.search(child_key):
                        raise _Shape("has an object key with a lone surrogate")
                    charge(len(child_key) + 3)
                    children.append((child, target, child_key, depth + 1))
            else:
                children.extend((child, target, _APPEND, depth + 1) for child in source)
            stack.extend(reversed(children))
            continue
        charge(_scalar_chars(source))
        if kind is str and _SURROGATE_RE.search(source):
            raise _Shape("holds a string with a lone surrogate")
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
    code) and every other ``BaseException`` except ``KeyboardInterrupt`` are wrapped.

    :param subject: The extension name or spec.
    :param hook: The hook name.
    :param function: The callable.
    :param args: Its arguments.
    :returns: Its return value.
    :raises ExtensionError: When it raises.
    """
    try:
        return function(*args)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:
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
        raise ExtensionError(f"extension {extension.name}: {hook} returned a value that {exc}") from None
    except RecursionError:
        raise ExtensionError(f"extension {extension.name}: {hook} returned a value that cannot be checked") from None
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
    :raises ExtensionError: When a hook raises, or returns invalid or oversized data.
    """
    if not loaded:
        return
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
            value = _run_hook(extension, HOOK_RUN, extension.provide_run, (frozen_model,), budget)
            if value is not None:
                run_ext[extension.name] = value
        if extension.provide_document is None and extension.provide_problem is None:
            continue
        for document, frozen_document in zip(documents, frozen_documents, strict=True):
            if extension.provide_document is not None:
                value = _run_hook(
                    extension, HOOK_DOCUMENT, extension.provide_document, (frozen_document, frozen_model), budget
                )
                if value is not None:
                    document["ext"][extension.name] = value
            if extension.provide_problem is None:
                continue
            for problem, frozen_problem in zip(document["problems"], frozen_document["problems"], strict=True):
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


class EventHookGuard:
    """Run problem hooks on the fault-event path, swallowing failures (M29).

    For the Milestone 0006 emission path: a hook ``Exception``/``SystemExit`` or an
    invalid return is swallowed, the event keeps its core fields, and **one**
    bounded, neutralized warning is written per extension per run. Refusals are not
    handled here: they happen in :func:`resolve_extensions` and are never swallowed
    (M4). ``KeyboardInterrupt`` propagates.
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
        """
        result: dict[str, JsonValue] = {}
        arguments: Optional[tuple[Any, ...]] = None
        for extension in self._loaded.extensions:
            if extension.provide_problem is None or extension.name in self._failed:
                continue
            if arguments is None:
                arguments = (freeze(dict(problem)), freeze(dict(doc)), freeze(dict(model)))
            try:
                value = _run_hook(extension, HOOK_PROBLEM, extension.provide_problem, arguments, self._budget)
            except ExtensionError as exc:
                self._failed.add(extension.name)
                self._warn(f"warning: extension {extension.name} disabled for fault events: {exc}")
                continue
            if value is not None:
                result[extension.name] = value
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
    "admit_extensions",
    "apply_report_hooks",
    "check_template",
    "freeze",
    "load_python_target",
    "missing_extensions_message",
    "resolve_extensions",
    "validated_copy",
]
