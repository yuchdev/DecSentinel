"""Static table of the builtin report extensions (Milestone 0007 Story 04.0).

``builtin:<name>`` resolves only through :data:`BUILTIN_EXTENSIONS`, a fixed mapping
from a name to a zero-argument factory defined in this package (threat model
0007-extensions M5). The user-supplied name is only ever a dictionary key: it is
never interpolated into an import, so an unknown name (``builtin:os``,
``builtin:../x``, ``builtin:__init__``) is refused before anything is imported, and
``builtin:`` never needs the ``python:`` trust gate.

:data:`RESERVED_BUILTIN_NAMES` lists every builtin name, including those whose
implementation lands in a later task (``domain`` and ``document_stats`` arrive in
Story 04.0 Task 02). A ``python:`` extension may not use one of them, whether or not
that builtin is available or loaded (M25).
"""

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final, Optional

#: Builtin extension name -> zero-argument factory returning the extension object.
#: Empty until Story 04.0 Task 02 adds ``domain`` and ``document_stats``.
BUILTIN_EXTENSIONS: Final[Mapping[str, Callable[[], object]]] = MappingProxyType({})

#: Every builtin extension name, reserved against ``python:`` extensions (M25).
RESERVED_BUILTIN_NAMES: Final[frozenset[str]] = frozenset({"domain", "document_stats"}) | frozenset(BUILTIN_EXTENSIONS)


def builtin_factory(name: object) -> Optional[Callable[[], object]]:
    """Return the factory of a builtin extension, or ``None`` for an unknown name.

    :param name: The ``<name>`` part of a ``builtin:<name>`` spec.
    :returns: The factory from :data:`BUILTIN_EXTENSIONS`, or ``None``; nothing is
        imported here.
    """
    if type(name) is not str:
        return None
    return BUILTIN_EXTENSIONS.get(name)


def is_reserved_name(name: object) -> bool:
    """Return whether ``name`` is a builtin extension name (M25).

    :param name: An extension name.
    :returns: ``True`` for a name in :data:`RESERVED_BUILTIN_NAMES` or the live table.
    """
    return type(name) is str and (name in RESERVED_BUILTIN_NAMES or name in BUILTIN_EXTENSIONS)


__all__ = ["BUILTIN_EXTENSIONS", "RESERVED_BUILTIN_NAMES", "builtin_factory", "is_reserved_name"]
