"""CLI scan-root resolution failures (Milestone 0007 Story 04.0 Task 02, security follow-up L-b).

``Path.resolve`` raises ``RuntimeError`` on a symlink loop (Python 3.12). Before the fix it escaped
``cli.main`` as a traceback with exit 1 -- the exit code of "blocking findings". It must be a
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
