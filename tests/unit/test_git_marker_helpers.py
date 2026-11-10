"""Unit tests for the ``.git`` probe allowance shared by the filesystem oracles."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.git_marker_helpers import (
    GitMarkerGuard,
    install_git_marker_guard,
    is_git_marker_probe,
    is_project_marker_probe,
)

_ROOT = os.path.normpath("/work/repo/docs")


@pytest.mark.parametrize(
    "recorded",
    [os.path.normpath("/work/repo/.git"), os.path.normpath("/work/.git"), os.path.normpath("/.git"), _ROOT + "/.git"],
)
def test_ancestor_git_marker_is_allowed(recorded: str):
    """
    [Unit] git marker helpers: exactly ``<ancestor-of-scan-root>/.git`` is an allowed probe.

    Scenario:
        Given an ancestor (or the scan root itself) joined with the literal name .git
        When is_git_marker_probe classifies it
        Then it is allowed.

    Boundaries:
        - Focus: the positive allowance
        - Fixtures/params: recorded
        - Scope: this test case only

    On failure, first check:
        - The os.path.split / ancestor comparison in is_git_marker_probe
    """
    assert is_git_marker_probe(recorded, _ROOT)


@pytest.mark.parametrize(
    "recorded",
    [
        "/work/repo/.git/config",
        "/work/repo/.git/HEAD",
        "/work/repo/.gitx",
        "/work/repo/git",
        "/work/repo/src/.git",
        "/work/other/.git",
        "/elsewhere/.git",
        "/work/repo",
    ],
)
def test_any_other_outside_path_is_not_allowed(recorded: str):
    """
    [Unit] git marker helpers: deeper, sibling, non-ancestor or differently named paths stay forbidden.

    Scenario:
        Given paths inside a .git directory, near-miss names, and .git under non-ancestors
        When is_git_marker_probe classifies them
        Then none is allowed.

    Boundaries:
        - Focus: narrowness of the allowance
        - Fixtures/params: recorded
        - Scope: this test case only

    On failure, first check:
        - That only the literal basename .git under an ancestor qualifies
    """
    assert not is_git_marker_probe(os.path.normpath(recorded), _ROOT)


def test_project_marker_probe_allows_only_strict_ancestors():
    """
    [Unit] git marker helpers: project markers are allowed only directly in a strict ancestor.

    Scenario:
        Given marker paths in strict ancestors, in the scan root, deeper, or under a non-ancestor
        When is_project_marker_probe classifies them
        Then only the strict-ancestor markers are allowed.

    Boundaries:
        - Focus: narrowness of the marker allowance
        - Fixtures/params: none
        - Scope: this test case only

    On failure, first check:
        - The head != root and ancestor comparison in is_project_marker_probe
    """
    for allowed in ("/work/repo/pyproject.toml", "/work/docsentinel.toml", "/doc_sentinel.toml"):
        assert is_project_marker_probe(os.path.normpath(allowed), _ROOT)
    for refused in (
        _ROOT + "/pyproject.toml",
        "/work/repo/sub/pyproject.toml",
        "/other/pyproject.toml",
        "/work/x.toml",
    ):
        assert not is_project_marker_probe(os.path.normpath(refused), _ROOT)


def test_guard_allows_lstat_but_flags_open_list_and_follow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] git marker helpers: the guard accepts exact existence probes and records every other access.

    Scenario:
        Given a real tmp/.git directory with a config file, a tmp/pyproject.toml, and the guard for tmp/docs
        When lexists runs on tmp/.git and tmp/pyproject.toml, then listdir/stat/realpath/read_text run on
          .git paths, lexists on tmp/.git/config, and open on the marker
        Then the exact lexists probes record nothing and every other access is a violation.

    Boundaries:
        - Focus: call-kind and exact-path discrimination of GitMarkerGuard
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: this test case only

    On failure, first check:
        - GitMarkerGuard.check and _GUARDED_CALLS / _GUARDED_METHODS
    """
    marker = tmp_path / ".git"
    marker.mkdir()
    (marker / "config").write_text("[core]\n", encoding="utf-8")
    project = tmp_path / "pyproject.toml"
    project.write_text("", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    guard = GitMarkerGuard(str(tmp_path / "docs"))
    install_git_marker_guard(monkeypatch, guard)

    assert os.path.lexists(marker)
    assert os.path.lexists(project)
    assert guard.violations == []

    os.listdir(marker)
    os.stat(marker)
    os.path.realpath(marker)
    os.path.lexists(marker / "config")
    with pytest.raises(IsADirectoryError):
        marker.read_text(encoding="utf-8")
    with open(project, encoding="utf-8"):
        pass

    calls = [call for call, _path in guard.violations]
    assert calls[:3] == ["listdir", "stat", "realpath"]
    assert any(path.endswith(os.path.join(".git", "config")) for _call, path in guard.violations)
    assert "Path.read_text" in calls
    assert any(call == "open" and path == str(project) for call, path in guard.violations)
