#!/usr/bin/env python3
"""Stop hook - gate the end of a session on lint + tests.

Runs, in order, the same checks CI expects a clean session to satisfy:

  1. ``uv run ruff check . --fix``  - auto-fix what's mechanically fixable.
  2. ``uv run ruff check .``        - fail if anything remains unfixed.
  3. ``uv run pytest -q`` - skipped when ``src/`` and ``tests/`` are byte-identical
     to the state the last passing run covered (see :func:`_code_fingerprint`).

If any step fails, the hook returns a ``block`` decision so the agent is told to analyze that tool's
own output and fix what it flagged before ending the session - not to weaken
the check. To avoid infinite loops the agent host suppresses this hook when the
stop was itself triggered by a prior stop-hook block (``stop_hook_active``).

Skip the gate for a known-WIP session by exporting ``DOC_SENTINEL_SKIP_TESTS=1``.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from typing import Optional

from _common import REPO_ROOT, allow, append_log, read_event, stop_block

TIMEOUT_SECONDS = 900
CODE_DIRS = ("src", "tests")
STATE_FILE = REPO_ROOT / ".copilot" / "state" / "stop-tests-green.sha"


def _git(*args: str) -> Optional[bytes]:
    """Return the stdout of ``git <args>`` from the repo root, or None if git fails."""
    try:
        proc = subprocess.run(["git", *args], cwd=str(REPO_ROOT), capture_output=True, timeout=60, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _code_fingerprint() -> Optional[str]:
    """Return a digest of the committed, modified and untracked content of ``src/`` and ``tests/``.

    Combines the HEAD tree ids, the uncommitted diff against HEAD and the blob hashes of
    untracked, non-ignored files, so it changes exactly when code the suite exercises
    changes -- whether or not it was committed in between. Returns None when git cannot
    answer, which means "unknown": the caller then runs the tests.
    """
    parts = [
        _git("rev-parse", *(f"HEAD:{d}" for d in CODE_DIRS)),
        _git("diff", "HEAD", "--", *CODE_DIRS),
        _git("ls-files", "-o", "--exclude-standard", "-z", "--", *CODE_DIRS),
    ]
    if any(part is None for part in parts):
        return None
    digest = hashlib.sha256()
    for part in parts[:2]:
        digest.update(part)
    for name in sorted(filter(None, parts[2].split(b"\0"))):
        digest.update(name)
        digest.update((REPO_ROOT / name.decode("utf-8", "surrogateescape")).read_bytes())
    return digest.hexdigest()


def _last_green() -> Optional[str]:
    """Return the fingerprint recorded by the last passing run, if any."""
    try:
        return STATE_FILE.read_text(encoding="ascii").strip() or None
    except (OSError, UnicodeDecodeError):
        return None


def _record_green(fingerprint: Optional[str]) -> None:
    """Remember ``fingerprint`` as green; a write failure only costs a later re-run."""
    if fingerprint is None:
        return
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(fingerprint, encoding="ascii")
    except OSError:
        pass


def _run(cmd: list[str]) -> Optional[subprocess.CompletedProcess[str]]:
    """Run ``cmd`` from the repo root, returning None if the runner is unavailable."""
    try:
        return subprocess.run(
            cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _tail(proc: subprocess.CompletedProcess[str], n: int = 40) -> str:
    return "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-n:])


def main():
    event = read_event()
    if event.get("stop_hook_active"):
        allow()
    if os.environ.get("DOC_SENTINEL_SKIP_TESTS") == "1":
        append_log("tests.log", "SKIPPED (DOC_SENTINEL_SKIP_TESTS=1)")
        allow()

    steps = [
        ("ruff --fix", ["uv", "run", "ruff", "check", ".", "--fix"]),
        ("ruff check", ["uv", "run", "ruff", "check", "."]),
        ("pytest", ["uv", "run", "pytest", "-q"]),
    ]

    fingerprint = _code_fingerprint()
    unchanged = fingerprint is not None and fingerprint == _last_green()

    for label, cmd in steps:
        if label == "pytest" and unchanged:
            append_log("tests.log", "SKIPPED pytest (src/ and tests/ unchanged since the last passing run)")
            continue
        proc = _run(cmd)
        if proc is None:
            append_log("tests.log", f"SKIPPED (runner unavailable: {label})")
            allow()
        if proc.returncode != 0:
            append_log("tests.log", f"FAIL ({label})")
            stop_block(
                f"Stop blocked by DocSentinel run-tests: `{' '.join(cmd)}` failed.\n"
                f"{_tail(proc)}\n"
                f"Analyze the {label} output above and fix every warning/error it left behind "
                "before ending the session. If a fix isn't clearly safe, ask the user instead of "
                "guessing. Export DOC_SENTINEL_SKIP_TESTS=1 only if this is intentional WIP."
            )

    _record_green(fingerprint)
    append_log("tests.log", "PASS")
    allow()


if __name__ == "__main__":
    main()
