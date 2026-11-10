"""Resolve the base directory for site-root-absolute link targets (``link_root``).

A Markdown target with a leading ``/`` (for example ``/docs/adr/README.md``) is
resolved by GitHub against the *repository* root, not against the directory being
scanned. When DocSentinel scans a subdirectory such as ``docs/``, joining ``/``
onto the scan root would turn that link into ``docs/docs/adr/README.md`` and report
a false dangling link. :func:`resolve_link_root` computes the directory ``/``
targets are joined onto, once per scan, from the ``link_root`` option:

* ``"auto"`` (the default) -- the nearest ancestor of the scan root, the scan root
  included, that holds a ``.git`` entry. A ``.git`` *file* counts as well as a
  directory, because worktrees and submodules use one. Only ``os.path.lexists`` is
  called on each candidate ``.git``; nothing is opened, listed or followed, and no
  ``gitdir`` file is read. Without any ``.git`` above the scan root the scan root
  itself is returned, which reproduces the historical behaviour exactly.
* any other value -- a path relative to the scan root, normalised lexically, that
  must name the scan root or an ancestor (``"."`` for an MkDocs-style site where
  ``/`` means the docs directory, ``".."`` for its parent). The configured value is
  repository-supplied and therefore untrusted, so an ancestor above the scan root
  is accepted only when it is clearly the same project: with a ``.git``-holding
  ancestor it may not go above the nearest one; without one, the named directory
  itself must directly contain a project marker (:data:`PROJECT_MARKERS`, checked
  with ``os.path.lexists`` only, never opened). The filesystem root is always
  refused. Anything else fails closed with :class:`~docsentinel.config.ConfigError`,
  so a scanned repository's config can never widen the existence checks to the
  host.

A repository whose ``.git`` ancestor is the user's home directory or above (a
"dotfiles" checkout, compared with ``os.path.samestat``, never by string) is not
trusted as a link root: ``"auto"`` falls back to the scan root and an explicit
configured ancestor fails closed.

The invoker can also choose the link root directly (``scan --link-root PATH`` or
``docsentinel.scan(..., link_root=PATH)``). That value is trusted invoker input,
like ``--template``: :func:`resolve_invoker_link_root` accepts an absolute path or
one relative to the current directory, resolves it with ``realpath`` and requires
an existing directory that is the scan root or one of its ancestors, with no
``.git`` requirement; only the filesystem root is refused, as a footgun.

Filesystem probing is split by layer. Only the engine calls
:func:`resolve_link_root`, once per scan and only when a rule in
:data:`LINK_ROOT_RULES` is active, and hands the validated directory to each
analyzer that accepts a ``link_root`` keyword. A detector called without one falls
back to :func:`link_root_for`, which is purely lexical and therefore accepts only
values that mean the scan root (``"auto"`` or, for example, ``"."``); any other
explicit value needs the engine's ``.git`` bound and is refused with
``ConfigError``. A detector never touches a path outside the scan root to decide
its link root.

The link root only changes ``/`` targets. Relative targets keep resolving against
the referring document, and their ``..`` escapes stay bounded by the scan root.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Final, Optional, Union

from docsentinel.config import LINK_ROOT_AUTO, Config, ConfigError, validate_link_root

__all__ = ["LINK_ROOT_RULES", "PROJECT_MARKERS", "link_root_for", "resolve_invoker_link_root", "resolve_link_root"]

#: Rules whose analyzers resolve ``/`` targets against the link root; the engine
#: resolves (and probes for) the link root only when one of them is active.
LINK_ROOT_RULES: Final = frozenset({"DS101", "DS103", "DS112", "DS113", "DS116"})

#: Files whose presence (``os.path.lexists`` only) marks a directory without ``.git``
#: as a project root a configured ``link_root`` may name.
PROJECT_MARKERS: Final = ("pyproject.toml", "docsentinel.toml", "doc_sentinel.toml")


def _within(candidate: str, ancestor: str) -> bool:
    """Return whether a normalised path is ``ancestor`` itself or lives under it.

    Separator-aware, so an ``ancestor`` of ``/`` does not become ``//``.

    :param candidate: An ``os.path.normpath``-ed absolute path string.
    :param ancestor: An ``os.path.normpath``-ed absolute path string.
    :returns: ``True`` when ``candidate`` is contained in ``ancestor``.
    """
    if candidate == ancestor:
        return True
    prefix = ancestor if ancestor.endswith(os.sep) else ancestor + os.sep
    return candidate.startswith(prefix)


def _find_git_ancestor(scan_root: Path) -> Optional[Path]:
    """Return the nearest ancestor of ``scan_root`` (itself included) holding ``.git``.

    Only ``os.path.lexists`` (an ``lstat``) runs on each fixed ``<ancestor>/.git``
    name; nothing is opened, listed, followed or read (a ``gitdir`` file is never
    parsed), and no name derives from document content.

    :param scan_root: The absolute, normalised scan root.
    :returns: That ancestor, or ``None`` when no ancestor holds a ``.git`` entry.
    """
    for directory in (scan_root, *scan_root.parents):
        if os.path.lexists(directory / ".git"):
            return directory
    return None


def _is_filesystem_root(path: str) -> bool:
    """Return whether a normalised absolute path is a filesystem (or drive) root.

    :param path: An ``os.path.normpath``-ed absolute path string.
    :returns: ``True`` for ``/`` on POSIX or a drive/UNC root on Windows.
    """
    return os.path.dirname(path) == path


def _is_home_or_above(directory: Path) -> bool:
    """Return whether ``directory`` is the user's home directory or one of its ancestors.

    Compared by device and inode (``os.path.samestat``), never by string, so case or
    symlink spelling differences cannot bypass it. When the home directory cannot be
    determined or stat-ed the check reports ``False``.

    :param directory: A candidate repository root.
    :returns: ``True`` when ``directory`` is home or above it.
    """
    try:
        home = Path(os.path.realpath(Path.home()))
        target = os.stat(directory)
        chain = [os.stat(candidate) for candidate in (home, *home.parents)]
    except (RuntimeError, KeyError, OSError):
        # No determinable or stat-able home: nothing to compare against.
        chain = []
        target = None
    return target is not None and any(os.path.samestat(target, entry) for entry in chain)


def _trusted_repository(base: Path) -> Optional[Path]:
    """Return the nearest ``.git`` ancestor unless it is home or above (a dotfiles repo).

    :param base: The absolute scan root.
    :returns: The repository root, or ``None`` when there is none or it is untrusted.
    """
    repository = _find_git_ancestor(base)
    if repository is not None and _is_home_or_above(repository):
        return None
    return repository


def _has_project_marker(directory: str) -> bool:
    """Return whether ``directory`` directly contains a :data:`PROJECT_MARKERS` entry.

    Only ``os.path.lexists`` runs on each fixed name; nothing is opened or followed.

    :param directory: A normalised absolute directory path.
    :returns: ``True`` when a marker entry exists in it.
    """
    return any(os.path.lexists(os.path.join(directory, name)) for name in PROJECT_MARKERS)


def _scan_root_or_ancestor(base: Path, value: str) -> str:
    """Return the lexically normalised explicit value, refusing a non-ancestor.

    :param base: The absolute scan root.
    :param value: A lexically validated, non-``"auto"`` ``link_root`` value.
    :returns: The normalised candidate path string.
    :raises ConfigError: When the value is not the scan root or an ancestor of it.
    """
    candidate = os.path.normpath(os.path.join(os.fspath(base), value))
    if not _within(os.fspath(base), candidate):
        raise ConfigError("link_root must name the scan root or one of its ancestors")
    return candidate


def _bounded_config_candidate(base: Path, value: str) -> Path:
    """Return the explicit, repository-supplied link root after applying its bounds.

    :param base: The absolute scan root.
    :param value: A lexically validated, non-``"auto"`` ``link_root`` value.
    :returns: The scan root or a permitted ancestor.
    :raises ConfigError: When the value is not an ancestor, is the filesystem root,
        lies above the nearest ``.git`` ancestor, names an ancestor while that
        repository is home or above, or (without a repository) names an ancestor
        that does not directly contain a project marker.
    """
    candidate = _scan_root_or_ancestor(base, value)
    if candidate == os.fspath(base):
        return base
    if _is_filesystem_root(candidate):
        raise ConfigError("link_root in a configuration file may not be the filesystem root")
    repository = _find_git_ancestor(base)
    if repository is not None:
        if _is_home_or_above(repository):
            raise ConfigError(
                "link_root in a configuration file may not name an ancestor inside a repository rooted at the "
                "home directory or above"
            )
        if not _within(candidate, os.fspath(repository)):
            raise ConfigError("link_root in a configuration file may not be above the enclosing git repository root")
        return Path(candidate)
    if not _has_project_marker(candidate):
        raise ConfigError(
            "link_root in a configuration file may name an ancestor outside git only if it directly contains "
            "pyproject.toml, docsentinel.toml or doc_sentinel.toml"
        )
    return Path(candidate)


def link_root_for(scan_root: Path, config: Config) -> Path:
    """Return the fallback link root of a detector called without an engine value.

    Purely lexical: it cannot see ``.git``, so it accepts only values that mean the
    scan root (``"auto"``, or an explicit value such as ``"."`` that normalises to
    it). Any other explicit value can be bounded only by the engine's ``.git`` walk,
    so it fails closed; run the scan through :func:`docsentinel.scan`, or pass the
    detector a ``link_root`` from :func:`resolve_link_root`.

    :param scan_root: The scan root directory, as the detector uses it.
    :param config: Effective settings supplying ``link_root``.
    :returns: The scan root, as an absolute path.
    :raises ConfigError: When ``link_root`` is lexically invalid or names anything
        other than the scan root.
    """
    value = validate_link_root(config.link_root)
    base = Path(os.path.abspath(scan_root))
    if value != LINK_ROOT_AUTO and _scan_root_or_ancestor(base, value) != os.fspath(base):
        raise ConfigError(
            "an explicit link_root ancestor must be validated by the engine; run docsentinel.scan or pass "
            "link_root= to the detector"
        )
    return base


def resolve_link_root(scan_root: Path, config: Config) -> Path:
    """Return the directory that site-root-absolute (``/``) targets resolve against.

    This is the engine-side resolution of the *configured* (untrusted) value:
    ``"auto"`` walks up to the nearest ``.git`` entry (unless it is home or above),
    else the scan root; an explicit
    value must name the scan root or a permitted ancestor (see the module docstring)
    and an existing directory. The scan root is used lexically as given (``os.path.abspath``, no
    symlink resolution), so callers pass the same canonical root they use for every
    other containment decision. The configured value is re-validated lexically
    first, so an injected :class:`~docsentinel.config.Config` that bypassed
    ``load_config`` fails closed exactly like a loaded one.

    :param scan_root: The scan root directory (canonical in every engine call).
    :param config: Effective settings supplying ``link_root``.
    :returns: The scan root or a bounded ancestor of it, as an absolute path.
    :raises ConfigError: When ``link_root`` is lexically invalid, is not the scan
        root or a permitted ancestor of it, or names a directory that does not exist.
    """
    value = validate_link_root(config.link_root)
    base = Path(os.path.abspath(scan_root))
    if value == LINK_ROOT_AUTO:
        repository = _trusted_repository(base)
        return repository if repository is not None else base

    # Ancestry and the bounds are decided lexically (plus the fixed .git probe)
    # before any stat, so a refused value is never stat-ed.
    candidate = _bounded_config_candidate(base, value)
    try:
        info = os.stat(candidate)
    except OSError as exc:
        raise ConfigError("link_root names a directory that does not exist") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError("link_root names a directory that does not exist")
    return candidate


def resolve_invoker_link_root(scan_root: Path, value: Union[str, os.PathLike[str]]) -> Path:
    """Return the link root chosen by the invoker (``--link-root`` / ``scan(link_root=)``).

    Trusted invoker input, like ``--template``: an absolute path, or a path relative
    to the current working directory, resolved with ``realpath``. It must be an
    existing directory that is the scan root or one of its ancestors; no ``.git`` is
    required. The filesystem (or drive) root is refused as a footgun. The value is
    never echoed in an error.

    :param scan_root: The canonical scan root.
    :param value: The invoker's path.
    :returns: The canonical link root directory.
    :raises ConfigError: For an empty or unusable value, a missing directory, a
        directory that is not the scan root or an ancestor, or the filesystem root.
    """
    if not isinstance(value, (str, os.PathLike)) or not os.fspath(value):
        raise ConfigError("--link-root must be a nonempty directory path")
    try:
        candidate = os.path.realpath(os.path.abspath(os.fspath(value)))
        info = os.stat(candidate)
    except (OSError, ValueError) as exc:
        raise ConfigError("--link-root names a directory that does not exist") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise ConfigError("--link-root names a directory that does not exist")
    if not _within(os.path.abspath(scan_root), candidate):
        raise ConfigError("--link-root must be the scan root or one of its ancestors")
    if _is_filesystem_root(candidate):
        raise ConfigError("--link-root may not be the filesystem root")
    return Path(candidate)
