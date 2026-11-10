#!/usr/bin/env python3
"""PreToolUse delivery gate - no commit/push/PR while flakeforge reports an XNNN violation.

Fires on a Bash command that delivers code (``git commit``, ``git push``,
``gh pr create``, ``gh pr merge``) and on the GitHub MCP write tools (push files,
create/update a file, create/merge a pull request). Every other tool call passes
untouched, so the ~20 s lint cost is paid only at delivery time.

The gate runs ``uv run flakeforge check src tests --select X`` from the repo root
(the project's ``[tool.flakeforge]`` config still applies: excludes, noqa policy).
Outcome:

  * exit 0 -> allow the delivery.
  * exit 1 -> block; flakeforge's own report is returned to the agent so it fixes
    the flagged code (never by adding ``# noqa`` or narrowing the selection).
  * anything else (uv/flakeforge missing, crash, timeout) -> block (fail closed):
    an unverifiable tree is never delivered.

There is deliberately no bypass variable: two pushes already reached GitHub with
flakeforge violations. If delivery must happen anyway, the user runs it manually.
"""

from __future__ import annotations

import re
import subprocess

from _common import REPO_ROOT, allow, append_log, block, read_event, tool_input

TIMEOUT_SECONDS = 300
CHECK_CMD = ["uv", "run", "flakeforge", "check", "src", "tests", "--select", "X"]

# A delivery verb inside one shell segment (segments split on ; & | newline), so
# `git -C repo commit`, `cd x && git push` and `git commit -m "..."` all match.
_BASH_DELIVERY = re.compile(
    r"\bgit\b[^;&|\n]*?\s(?:commit|push)\b|\bgh\s+pr\s+(?:create|merge)\b",
    re.IGNORECASE,
)
_MCP_DELIVERY = re.compile(
    r"^mcp__github__(?:push_files|create_or_update_file|create_pull_request|merge_pull_request)$"
)


def _is_delivery(event: dict) -> bool:
    """Return True when the tool call would put code on a branch or a PR."""
    tool_name = str(event.get("tool_name", ""))
    if _MCP_DELIVERY.match(tool_name):
        return True
    if tool_name != "Bash":
        return False
    return bool(_BASH_DELIVERY.search(str(tool_input(event).get("command", ""))))


def _refuse_unverified(action: str, code: object, output: str):
    """Block delivery because the check itself could not produce a verdict (fail closed)."""
    append_log("flakeforge-gate.log", f"BLOCKED [check-failed exit={code}] :: {action}")
    block(
        "Blocked by DocSentinel flakeforge gate: the flakeforge check could not complete "
        f"(exit {code}), so delivery is refused (fail closed).\n\n{output}\n\n"
        "Fix the environment (`uv sync --extra test --extra standard --extra deep`) and retry."
    )


def _run_flakeforge(action: str) -> tuple[int, str]:
    """Run the XNNN check and return (exit code, combined output); block if it cannot run."""
    try:
        proc = subprocess.run(
            CHECK_CMD,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        _refuse_unverified(action, "n/a", f"`uv` was not found on PATH ({exc}).")
        raise
    except subprocess.TimeoutExpired as exc:
        _refuse_unverified(action, "timeout", f"flakeforge did not finish within {exc.timeout} s.")
        raise
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def main():
    """Gate one PreToolUse event: allow non-delivery calls, run flakeforge for delivery ones."""
    event = read_event()
    if not _is_delivery(event):
        allow()

    action = str(tool_input(event).get("command", "")) or str(event.get("tool_name", ""))
    code, output = _run_flakeforge(action)
    if code == 0:
        allow()

    if code == 1:
        append_log("flakeforge-gate.log", f"BLOCKED [violations] :: {action}")
        block(
            "Blocked by DocSentinel flakeforge gate: `flakeforge check src tests --select X` "
            "reports XNNN violations, so this commit/push/PR is not allowed.\n\n"
            f"{output}\n\n"
            "Fix every violation in the code itself (do not add `# noqa`, change "
            "[tool.flakeforge], or narrow the check), re-run "
            "`uv run flakeforge check src tests --select X` until it exits 0, then retry."
        )

    _refuse_unverified(action, code, output)


if __name__ == "__main__":
    main()
