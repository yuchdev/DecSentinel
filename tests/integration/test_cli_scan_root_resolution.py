"""CLI scan-root resolution failures (Milestone 0007 Story 04.0 Task 02, security follow-up L-b).

Strict ``Path.resolve`` detects symlink loops on Python 3.12 and 3.13. Before the fix a
Python 3.12 ``RuntimeError`` escaped as a traceback with exit 1. It must be a
configuration failure: exit 2 with one neutralized ``Scan failed:`` / ``Baseline generation
failed:`` line on stderr and nothing on stdout.
"""

import os
from pathlib import Path

import pytest

from docsentinel import cli
from docsentinel.config import ConfigError

ESC = chr(0x1B)


def _loop(directory: Path, name: str = "a") -> Path:
    """Create ``<name> -> b`` and ``b -> <name>`` in ``directory`` and return the first link."""
    os.symlink(directory / "b", directory / name)
    os.symlink(directory / name, directory / "b")
    return directory / name


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are not available")
@pytest.mark.parametrize("command", ["scan", "baseline"])
def test_symlink_loop_root_is_exit_two_with_a_neutralized_message(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] cli scan root resolution: verifies a symlink-loop root is exit 2, never a traceback (L-b).

    Scenario:
        Given a scan root ``<dir>/a\\x1bx`` that is half of a two-link symlink loop (an ESC in its name)
        When ``docsentinel scan`` or ``docsentinel baseline`` runs on it
        Then it exits 2, stdout is empty, and stderr is one line naming the symlink loop with the ESC escaped.

    Boundaries:
        - Focus: RuntimeError from ``Path.resolve`` becomes a ConfigError
        - Fixtures/params: both commands that resolve the root
        - Scope: in-process CLI call

    On failure, first check:
        - ``cli._resolve_root`` and its use in the scan and baseline branches of ``cli.main``
    """
    root = _loop(tmp_path, f"a{ESC}x")

    code = cli.main([command, str(root)])
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "symlink loop" in captured.err and ESC not in captured.err
    assert captured.err.startswith(("Scan failed: cannot resolve", "Baseline generation failed: cannot resolve"))
    assert len(captured.err.splitlines()) == 1


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are not available")
def test_resolve_root_bounds_the_echoed_argument(tmp_path: Path):
    """
    [Integration] cli scan root resolution: verifies the echoed root is bounded (L-b).

    Scenario:
        Given a symlink-loop root reached through a 300-character relative spelling
        When ``cli._resolve_root`` resolves it
        Then a ConfigError is raised whose message keeps at most 200 characters of the argument.

    Boundaries:
        - Focus: bounded echo of invoker input
        - Fixtures/params: none
        - Scope: ``cli._resolve_root``

    On failure, first check:
        - ``cli._MAX_ROOT_ECHO``
    """
    root = _loop(tmp_path)
    spelled = str(root.parent) + "/." * 150 + "/a"

    with pytest.raises(ConfigError, match="symlink loop") as caught:
        cli._resolve_root(spelled)

    assert spelled not in str(caught.value) and "..." in str(caught.value)


def test_resolvable_root_is_returned_resolved(tmp_path: Path):
    """
    [Integration] cli scan root resolution: verifies an ordinary root resolves as before (L-b control).

    Scenario:
        Given an existing directory spelled with a ``..`` component
        When ``cli._resolve_root`` resolves it
        Then the canonical path is returned.

    Boundaries:
        - Focus: no behaviour change for valid roots
        - Fixtures/params: none
        - Scope: ``cli._resolve_root``

    On failure, first check:
        - ``cli._resolve_root``
    """
    (tmp_path / "docs").mkdir()

    assert cli._resolve_root(str(tmp_path / "docs" / "..")) == tmp_path.resolve()


@pytest.mark.parametrize("spelling", ["missing", "missing/child", "missing/../other"])
def test_nonexistent_root_retains_non_strict_resolution(spelling: str, tmp_path: Path):
    """
    [Integration] cli scan root resolution: preserves missing-root canonicalization.

    Scenario:
        Given a missing root anchored in an existing directory
        When ``cli._resolve_root`` resolves its spelling
        Then non-strict canonicalization is preserved for later scan-engine validation.

    Boundaries:
        - Focus: missing roots retain non-strict resolution
        - Fixtures/params: simple, nested and parent-normalized missing-root spellings
        - Scope: ``cli._resolve_root``

    On failure, first check:
        - The strict-resolution fallback in ``cli._resolve_root``

    :param spelling: A missing-root spelling, including a normalized parent component.
    :param tmp_path: An existing directory anchoring the missing root.
    """
    root = tmp_path / spelling

    assert cli._resolve_root(str(root)) == root.resolve()


def test_non_directory_component_retains_non_strict_resolution(tmp_path: Path):
    """
    [Integration] cli scan root resolution: preserves non-directory-root canonicalization.

    Scenario:
        Given a root ``file/child`` whose intermediate component is an existing regular file
        When ``cli._resolve_root`` resolves its spelling
        Then the same non-strict ``Path.resolve()`` result is returned.

    Boundaries:
        - Focus: NotADirectoryError falls back to non-strict resolution
        - Fixtures/params: an existing regular file and a child component
        - Scope: ``cli._resolve_root``, leaving root validation to the scan engine

    On failure, first check:
        - The NotADirectoryError fallback in ``cli._resolve_root``

    :param tmp_path: An existing directory anchoring the regular file.
    """
    file = tmp_path / "file"
    file.write_text("regular file", encoding="utf-8")
    root = file / "child"

    with pytest.raises(NotADirectoryError):
        root.resolve(strict=True)

    assert cli._resolve_root(str(root)) == root.resolve()
