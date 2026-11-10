"""Narrow allowances for the engine's ``link_root`` probes in filesystem oracles.

Resolving ``link_root`` may check, with ``os.path.lexists`` (an ``lstat``) only:

* ``<ancestor-or-self>/.git`` for each ancestor of the scan root (``"auto"`` and the
  bound of a configured value), and
* ``<ancestor>/pyproject.toml``, ``docsentinel.toml`` or ``doc_sentinel.toml`` in the
  exact ancestor a configured ``link_root`` names when there is no ``.git``.

The outside-root filesystem oracles must tolerate exactly those probes and nothing
else, so this module offers two pieces used together:

* :func:`is_git_marker_probe` / :func:`is_project_marker_probe` -- the path-only
  allowances for the oracles' outside-root loop.
* :class:`GitMarkerGuard` / :func:`install_git_marker_guard` -- the call-kind check
  the path-only recorders cannot make: any access to a path with a ``.git``
  component other than an exact ``lexists``/``lstat`` of ``<ancestor-or-self>/.git``,
  and any non-``lexists``/``lstat`` access to an ancestor's project marker, is
  recorded as a violation.
"""

from __future__ import annotations

import builtins
import os
from pathlib import Path

import pytest

#: The literal marker name the ``.git`` walk probes.
GIT_MARKER = ".git"

#: The project marker names a configured ``link_root`` ancestor is probed for.
PROJECT_MARKER_NAMES = frozenset({"pyproject.toml", "docsentinel.toml", "doc_sentinel.toml"})

#: The only calls allowed on a protected path: existence checks that never follow.
_ALLOWED_PROBE_CALLS = frozenset({"lexists", "lstat"})

#: Module-level callables wrapped by the guard (every reachable filesystem entry point).
_GUARDED_CALLS = (
    (builtins, "open"),
    (os, "open"),
    (os, "stat"),
    (os, "lstat"),
    (os, "scandir"),
    (os, "listdir"),
    (os, "readlink"),
    (os.path, "exists"),
    (os.path, "lexists"),
    (os.path, "realpath"),
    (os.path, "isfile"),
    (os.path, "isdir"),
)

#: ``Path`` methods wrapped by the guard.
_GUARDED_METHODS = (
    "open",
    "read_text",
    "read_bytes",
    "iterdir",
    "readlink",
    "resolve",
    "stat",
    "lstat",
    "exists",
    "is_file",
    "is_dir",
)


def _within(candidate: str, directory: str) -> bool:
    """Return whether a normalised path equals or lives under a directory.

    :param candidate: A normalised path string.
    :param directory: A normalised directory string.
    :returns: ``True`` when ``candidate`` is ``directory`` or a descendant.
    """
    if candidate == directory:
        return True
    prefix = directory if directory.endswith(os.sep) else directory + os.sep
    return candidate.startswith(prefix)


def is_git_marker_probe(recorded: str, scan_root: str) -> bool:
    """Return whether ``recorded`` is exactly ``<ancestor-or-self-of-scan_root>/.git``.

    :param recorded: A normalised path recorded by a filesystem oracle.
    :param scan_root: The normalised canonical scan root.
    :returns: ``True`` only for an ancestor directory (or the scan root itself) joined
        with the literal name ``.git``.
    """
    head, name = os.path.split(os.path.normpath(recorded))
    return name == GIT_MARKER and _within(os.path.normpath(scan_root), head)


def is_project_marker_probe(recorded: str, scan_root: str) -> bool:
    """Return whether ``recorded`` is exactly ``<strict-ancestor-of-scan_root>/<marker>``.

    :param recorded: A normalised path recorded by a filesystem oracle.
    :param scan_root: The normalised canonical scan root.
    :returns: ``True`` only for a strict ancestor joined with a project marker name.
    """
    root = os.path.normpath(scan_root)
    head, name = os.path.split(os.path.normpath(recorded))
    return name in PROJECT_MARKER_NAMES and head != root and _within(root, head)


class GitMarkerGuard:
    """Records every disallowed access to a ``.git`` path or an ancestor's project marker.

    :ivar scan_root: The normalised canonical scan root.
    :ivar violations: ``(call, path)`` pairs, empty when only exact existence probes ran.
    """

    def __init__(self, scan_root: str):
        """Initialize the guard for one scan root.

        :param scan_root: The canonical scan root of the scan under test.
        """
        self.scan_root = os.path.normpath(scan_root)
        self.violations: list[tuple[str, str]] = []

    def check(self, call: str, candidate: object):
        """Record a violation for a disallowed access to a protected path.

        :param call: The name of the intercepted callable.
        :param candidate: The first argument passed to it.
        """
        if not isinstance(candidate, (str, os.PathLike)):
            return
        normalised = os.path.normpath(os.fspath(candidate))
        probe_call = call.removeprefix("Path.") in _ALLOWED_PROBE_CALLS
        if GIT_MARKER in Path(normalised).parts:
            if not (probe_call and is_git_marker_probe(normalised, self.scan_root)):
                self.violations.append((call, normalised))
        elif is_project_marker_probe(normalised, self.scan_root) and not probe_call:
            self.violations.append((call, normalised))


def install_git_marker_guard(monkeypatch: pytest.MonkeyPatch, guard: GitMarkerGuard):
    """Wrap every reachable filesystem entry point so protected paths are checked.

    Each wrapper records, then delegates to the saved original, so the scan behaves
    normally; it composes with the oracle's own recorder in either install order.

    :param monkeypatch: The monkeypatch (or ``MonkeyPatch.context()``) to patch with.
    :param guard: The guard collecting violations.
    """
    for module, name in _GUARDED_CALLS:
        original = getattr(module, name)

        def wrapper(path: object, *args: object, _original=original, _name=name, **kwargs: object) -> object:
            """Check a path reaching a guarded call, then delegate.

            :param path: The first argument of the wrapped callable.
            :param args: Remaining positional arguments.
            :param kwargs: Keyword arguments.
            :returns: The original callable's result.
            """
            guard.check(_name, path)
            return _original(path, *args, **kwargs)

        monkeypatch.setattr(module, name, wrapper)

    for method in _GUARDED_METHODS:
        original_method = getattr(Path, method)

        def method_wrapper(
            self: Path, *args: object, _original=original_method, _name=method, **kwargs: object
        ) -> object:
            """Check a Path reaching a guarded method, then delegate.

            :param self: The bound path.
            :param args: Remaining positional arguments.
            :param kwargs: Keyword arguments.
            :returns: The original method's result.
            """
            guard.check(f"Path.{_name}", self)
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(Path, method, method_wrapper)
