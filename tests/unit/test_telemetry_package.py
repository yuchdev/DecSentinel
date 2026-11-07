"""Unit tests for the ``docsentinel.telemetry`` package surface (Milestone 0007, Story 01.0 Task 01)."""

import importlib

from docsentinel import telemetry
from docsentinel.telemetry import events

_PUBLIC_NAMES: frozenset[str] = frozenset(
    {"FaultEvent", "to_json_dict", "utc_now_iso", "SCHEMA_VERSION", "TIER_VOCABULARY", "OUTCOME_VOCABULARY"}
)


def test_package_all_is_exact():
    """
    [Unit] telemetry package: verifies ``__all__`` lists exactly the previously public names.

    Scenario:
        Given the restructured telemetry package
        When its ``__all__`` is read
        Then it equals the six public names with no duplicates.

    Boundaries:
        - Focus: the exported name set of ``docsentinel/telemetry/__init__.py``
        - Fixtures/params: none
        - Scope: import-time attributes only

    On failure, first check:
        - Whether a name was added to or dropped from ``__all__``
    """
    assert len(telemetry.__all__) == len(_PUBLIC_NAMES)
    assert set(telemetry.__all__) == _PUBLIC_NAMES


def test_public_names_are_the_events_module_objects():
    """
    [Unit] telemetry package: verifies each re-export is the very object defined in ``events``.

    Scenario:
        Given the package and its ``events`` module
        When each public name is looked up on both
        Then the package attribute is identical to the ``events`` attribute.

    Boundaries:
        - Focus: re-exports are aliases, not copies or wrappers
        - Fixtures/params: none
        - Scope: import-time attributes only

    On failure, first check:
        - Whether ``__init__.py`` redefines a name instead of importing it
    """
    for name in _PUBLIC_NAMES:
        assert getattr(telemetry, name) is getattr(events, name), name


def test_star_import_exposes_only_public_names():
    """
    [Unit] telemetry package: verifies a star import binds exactly the public names.

    Scenario:
        Given the telemetry package
        When ``from docsentinel.telemetry import *`` runs in a fresh namespace
        Then only the six public names are bound (no ``events`` submodule, no helpers).

    Boundaries:
        - Focus: ``__all__`` governs star-import behaviour
        - Fixtures/params: none
        - Scope: an isolated ``exec`` namespace

    On failure, first check:
        - Whether ``__all__`` contains a name that is not public
    """
    namespace: dict[str, object] = {}
    exec("from docsentinel.telemetry import *", namespace)
    namespace.pop("__builtins__", None)

    assert set(namespace) == _PUBLIC_NAMES


def test_old_module_path_is_now_a_package():
    """
    [Unit] telemetry package: verifies ``docsentinel.telemetry`` resolves to a package, not a module file.

    Scenario:
        Given the restructure moved ``telemetry.py`` to ``telemetry/events.py``
        When ``docsentinel.telemetry`` is imported
        Then it is a package (has ``__path__``) whose ``events`` submodule is importable.

    Boundaries:
        - Focus: the layout change itself
        - Fixtures/params: none
        - Scope: import machinery only

    On failure, first check:
        - Whether a stale ``telemetry.py`` file shadows the package
    """
    module = importlib.import_module("docsentinel.telemetry")

    assert hasattr(module, "__path__")
    assert importlib.import_module("docsentinel.telemetry.events") is events
