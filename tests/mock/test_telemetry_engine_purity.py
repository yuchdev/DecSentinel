"""Mock tests: ``render_template`` touches no file, environment variable or clock.

Milestone 0007 Story 02.0 Task 02, threat model "Elevation / AI / secrets": the
render path must not read files, env vars or the clock. The file-system, environment
and time entry points are replaced with stand-ins that raise while rendering.
"""

import builtins
import io
import os
import time
from collections.abc import Callable, Iterator, MutableMapping
from typing import Any, NoReturn

import pytest

from docsentinel.config import Config
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.telemetry.engine import render_template
from docsentinel.telemetry.loader import Template, validate_template
from docsentinel.telemetry.model import ReportModel


class _ForbiddenEnviron(MutableMapping[str, str]):
    """Stand-in for ``os.environ`` whose every access raises."""

    def _refuse(self, *_args: Any) -> NoReturn:
        """Raise on any access."""
        raise AssertionError("render_template read the environment")

    __getitem__ = _refuse
    __setitem__ = _refuse
    __delitem__ = _refuse
    __contains__ = _refuse
    get = _refuse

    def __iter__(self) -> Iterator[str]:
        """Raise on iteration."""
        self._refuse()

    def __len__(self) -> int:
        """Raise on ``len``."""
        self._refuse()


def _forbidden(what: str) -> Callable[..., NoReturn]:
    """Return a callable that raises naming ``what``."""

    def refuse(*_args: Any, **_kwargs: Any) -> NoReturn:
        """Raise naming the forbidden entry point."""
        raise AssertionError(f"render_template called {what}")

    return refuse


def _templates() -> list[Template]:
    """Return a text and a json template covering every node kind."""
    text = validate_template(
        {
            "template_version": 1,
            "name": "t",
            "type": "text",
            "lines": [
                {"type": "line", "text": "Profile: {profile}", "variables_used": ["profile"]},
                {
                    "type": "loop",
                    "over": "documents_with_problems",
                    "as": "doc",
                    "body": [
                        {"type": "line", "text": "{doc.path|neutralize}", "variables_used": ["doc.path"]},
                        {
                            "type": "loop",
                            "over": "doc.problems",
                            "as": "p",
                            "placement": "one-line",
                            "separator": ", ",
                            "text": "{p.rule}:{p.message|neutralize}",
                            "variables_used": ["p.rule", "p.message"],
                        },
                    ],
                },
                {
                    "type": "group",
                    "when": {"var": "pending", "falsy": True},
                    "body": [{"type": "line", "text": "ok", "variables_used": []}],
                },
            ],
        }
    )
    body = {
        "docs": {
            "$for": "documents",
            "as": "doc",
            "each": {"path": {"$str": "{doc.path|json}"}, "n": {"$var": "doc.problem_count"}},
        },
        "model": {"$var": "model", "$default": "none"},
        "deep": {"$if": {"var": "profile", "eq": "deep"}, "then": True},
    }
    as_json = validate_template({"template_version": 1, "name": "j", "type": "json", "body": body})
    return [text, as_json]


def test_render_template_reads_no_file_env_or_clock(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] engine (mock): verifies render_template performs no file, environment or clock access.

    Scenario:
        Given text and json templates and a ReportModel context built beforehand
        When file, stat, environment and clock entry points all raise during rendering
        Then rendering succeeds with the same output as an unpatched render.

    Boundaries:
        - Focus: render purity (Task 02 contract; threat model INFO item)
        - Fixtures/params: monkeypatch over builtins, io, os and time
        - Scope: render_template only; templates and context are prepared first

    On failure, first check:
        - Any new import-time or call-time I/O in ``telemetry/engine.py`` or ``filters.py``
    """
    finding = Finding(rule="DS101", path="docs/a.md", message="dangling link -> x.md", severity="error", line=1)
    result = ScanResult(
        profile="fast",
        documents=(Document(path="docs/a.md", bytes=4),),
        findings=(finding,),
        enabled_rules=("DS101",),
        pending=(),
    )
    context = ReportModel.build(result, Config())
    templates = _templates()
    expected = [render_template(template, context) for template in templates]

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", _forbidden("open"))
        patch.setattr(io, "open", _forbidden("io.open"))
        patch.setattr(os, "open", _forbidden("os.open"))
        patch.setattr(os, "stat", _forbidden("os.stat"))
        patch.setattr(os, "lstat", _forbidden("os.lstat"))
        patch.setattr(os, "getenv", _forbidden("os.getenv"))
        patch.setattr(os, "environ", _ForbiddenEnviron())
        patch.setattr(time, "time", _forbidden("time.time"))
        patch.setattr(time, "time_ns", _forbidden("time.time_ns"))
        patch.setattr(time, "monotonic", _forbidden("time.monotonic"))
        rendered = [render_template(template, context) for template in templates]

    assert rendered == expected
    assert rendered[0] == "Profile: fast\ndocs/a.md\nDS101:dangling link -> x.md\nok"
