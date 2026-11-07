"""A plain ``reporting.render`` never reads the process cwd (Milestone 0007 Story 04.0 review)."""

from pathlib import Path

import pytest

from docsentinel import reporting
from docsentinel.models import ScanResult

_RESULT = ScanResult(profile="fast", documents=(), findings=(), enabled_rules=(), pending=())


def test_render_without_python_extensions_does_not_call_path_cwd(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] reporting cwd access (mock): verifies a render with no ``python:`` spec never asks for the cwd.

    Scenario:
        Given ``Path.cwd`` replaced with a function that raises ``FileNotFoundError``
        When ``render`` runs with the default arguments for the text and json formats
        Then it returns a report instead of raising, because the cwd only feeds the origin check
            of a ``python:`` extension.

    Boundaries:
        - Focus: the default render path keeps working when the process cwd was deleted
        - Fixtures/params: monkeypatched ``Path.cwd``
        - Scope: the ``reporting`` module only

    On failure, first check:
        - Whether ``render`` reads ``Path.cwd()`` before it knows a ``python:`` spec is present
    """

    def gone() -> Path:
        """Stand in for a process whose working directory no longer exists."""
        raise FileNotFoundError("cwd was removed")

    monkeypatch.setattr(Path, "cwd", staticmethod(gone))

    assert reporting.render(_RESULT, "text") != ""
    assert reporting.render(_RESULT, "json").startswith("{")
