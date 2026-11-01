"""End-to-end reporter hardening against a real hostile file name (Story 15.0 Task 02 A).

Unlike the unit tests, this exercises the CLI as a subprocess over a genuine file whose
name carries an ANSI escape, CR, LF and a forged GitHub workflow command, writing to a
tmp scan root and capturing the raw stdout bytes for each of the three output formats.
If the host filesystem refuses the deliberately hostile name, the test skips with the
reason string already allowlisted by the milestone final audit.
"""

import subprocess
import sys
from pathlib import Path

import pytest

#: A legally-named file (every byte is a permitted path character on POSIX) whose name
#: nonetheless carries an ANSI colour escape, CR, LF and a spoofed ``::error::`` command.
_HOSTILE_NAME: str = "evil\x1b[31m\r\n::error::spoofed.md"

#: Control bytes that must never reach a terminal or CI log from untrusted content.
_FORBIDDEN_BYTES: tuple[bytes, ...] = (b"\x1b", b"\x07", b"\x00", b"\x7f")


def _make_hostile_root(tmp_path: Path) -> Path:
    """Create a scan root containing one file with the hostile name, or skip.

    :param tmp_path: The pytest temporary directory.
    :returns: The scan root path holding the hostile document.
    """
    root = tmp_path / "hostile_repo"
    root.mkdir()
    (root / "docsentinel.toml").write_text('profile = "fast"\n', encoding="utf-8")
    try:
        (root / _HOSTILE_NAME).write_text(
            "# Title\n\n[dead](./missing-target.md)\n",
            encoding="utf-8",
        )
    except OSError:
        pytest.skip("filesystem rejected the hostile file name")
    return root


def _scan(root: Path, fmt: str) -> subprocess.CompletedProcess[bytes]:
    """Run ``docsentinel scan`` over a root in the given format, capturing raw bytes.

    :param root: Scan root to inspect.
    :param fmt: A packaged template name such as ``text``, ``github`` or ``json``.
    :returns: The completed subprocess with byte stdout/stderr.
    """
    return subprocess.run(
        [sys.executable, "-m", "docsentinel.cli", "scan", str(root), "--format", fmt],
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize("fmt", ["text", "github", "json", "json-v1", "json-documents"])
def test_hostile_filename_never_emits_raw_control_bytes(fmt: str, tmp_path: Path):
    """
    [Integration] reporter hostile filename: verifies no raw control byte reaches any sink.

    Scenario:
        Given a real on-disk file whose name carries ESC, CR, LF and a forged ``::error::`` command
        When the CLI scans its root and renders text, github or json
        Then the dangling-link finding is produced (exit 1), no raw ESC/BEL/NUL/DEL byte appears in
        stdout, and stderr carries no traceback -- the hostile name is rendered inertly.

    Boundaries:
        - Focus: the tool-wide reporter neutralisation on a genuine hostile path, end to end
        - Fixtures/params: parametrized over the five packaged templates; skips if the OS rejects the name
        - Scope: one CLI subprocess per format

    On failure, first check:
        - Which forbidden byte survived in stdout for the reported format
        - Whether the scan crashed (traceback on stderr) instead of reporting a finding
    """
    root = _make_hostile_root(tmp_path)
    completed = _scan(root, fmt)

    assert completed.returncode == 1, f"{fmt}: expected exit 1 (dangling link), got {completed.returncode}"
    assert b"Traceback" not in completed.stderr, f"{fmt}: scan raised a traceback: {completed.stderr!r}"
    for forbidden in _FORBIDDEN_BYTES:
        assert forbidden not in completed.stdout, f"{fmt}: raw control byte {forbidden!r} leaked into stdout"


def test_hostile_filename_text_sink_cannot_forge_a_log_line(tmp_path: Path):
    """
    [Integration] reporter hostile filename: verifies the CR/LF in the name cannot start a new line.

    Scenario:
        Given the hostile file whose name embeds CR+LF before a forged ``::error::spoofed.md``
        When the CLI renders text
        Then the forged token never begins its own output line -- it stays on the finding line as the
        visible escape ``\\x0d\\x0a::error::spoofed.md`` -- so no line of stdout is a bare spoof.

    Boundaries:
        - Focus: line-injection specifically (the CR/LF break), beyond the generic byte check
        - Fixtures/params: skips if the OS rejects the name
        - Scope: one text-format CLI subprocess

    On failure, first check:
        - Whether any stdout line equals or starts with the forged ``::error::spoofed.md`` token
    """
    root = _make_hostile_root(tmp_path)
    completed = _scan(root, "text")
    text = completed.stdout.decode("utf-8")

    assert "\\x0d\\x0a::error::spoofed.md" in text
    for line in text.splitlines():
        assert not line.startswith("::error::spoofed.md"), f"forged token began a line: {line!r}"


def test_scan_failed_error_line_neutralises_control_bytes_from_config_keys(tmp_path: Path):
    """
    [Integration] reporter hostile filename: verifies the CLI error lines neutralise untrusted text.

    Scenario:
        Given a docsentinel.toml whose unknown option name carries an ANSI escape and a line feed
        When the scan fails with the documented configuration error
        Then the exit code is 2 and stderr holds a visible escape instead of any raw control byte,
            so an error message built from untrusted text cannot spoof a terminal or a log line.

    Boundaries:
        - Focus: the cli.py error paths that bypass the report renderers
        - Fixtures/params: tmp_path

    On failure, first check:
        - Whether cli.py routes exception text through reporting.neutralize_text
    """
    root = tmp_path / "bad_config"
    root.mkdir()
    (root / "docsentinel.toml").write_text('"evil\\u001b[31m\\u000a::error::x" = 1\n', encoding="utf-8")
    (root / "README.md").write_text("# T\n", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-m", "docsentinel.cli", "scan", str(root)],
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert b"Scan failed" in completed.stderr
    assert b"Traceback" not in completed.stderr
    for forbidden in _FORBIDDEN_BYTES:
        assert forbidden not in completed.stderr
    assert completed.stderr.count(b"\n") == 1
