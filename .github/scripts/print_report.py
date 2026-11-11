"""Print a DocSentinel report file to the CI log without flooding it.

Usage: ``python .github/scripts/print_report.py FILE``

A report with at most ``REPORT_PRINT_MAX_FINDINGS`` findings (default 15) is printed:
a text report whole, a JSON report as its ``summary`` plus only the documents that have
problems (schema 2 lists every document, clean ones included). A larger report is not
printed; the log gets its finding count, line count and path instead, plus -- for a text
report -- the "Blocking findings" recap, capped at ``REPORT_TAIL_LINES`` lines (default 60),
so the reason for a failed step stays visible. The full file is uploaded as an artifact.
"""

import json
import os
import re
import sys
from pathlib import Path

_PROBLEM_LINE = re.compile(r"^  (?:error|warning|info): ")
_RECAP_HEADER = "Blocking findings:"


def _limit(name: str, default: int) -> int:
    """Read a non-negative integer limit from the environment.

    :param name: Environment variable name.
    :param default: Value used when the variable is unset or empty.
    :returns: The limit.
    """
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


def _note(path: Path, findings: int, lines: int, limit: int) -> str:
    """Return the one-line notice printed instead of an oversized report.

    :param path: The report file.
    :param findings: Number of findings in the report.
    :param lines: Number of lines in the report file.
    :param limit: The configured finding limit.
    :returns: A GitHub Actions notice command.
    """
    return (
        f"::notice title=DocSentinel report not printed::{findings} findings (limit {limit}), "
        f"{lines} lines: {path} (uploaded in the docsentinel-reports artifact)"
    )


def _print_json(path: Path, text: str, limit: int):
    """Print a schema-2 JSON report, or a notice when it holds too many findings.

    :param path: The report file.
    :param text: The report content.
    :param limit: Maximum number of findings printed.
    """
    report = json.loads(text)
    summary = report.get("summary", {})
    findings = int(summary.get("findings", 0))
    if findings > limit:
        print(_note(path, findings, text.count("\n") + 1, limit))
        print("summary:", json.dumps(summary, sort_keys=True))
        return
    flagged = [doc for doc in report.get("documents", []) if doc.get("problems")]
    print(json.dumps({"summary": summary, "documents_with_problems": flagged}, indent=2))


def _print_text(path: Path, text: str, limit: int, recap_lines: int):
    """Print a text report, or a notice plus its blocking recap when it is too large.

    :param path: The report file.
    :param text: The report content.
    :param limit: Maximum number of findings printed.
    :param recap_lines: Maximum number of recap lines printed for an oversized report.
    """
    lines = text.splitlines()
    recap_at = next((i for i, line in enumerate(lines) if line.startswith(_RECAP_HEADER)), len(lines))
    findings = sum(1 for line in lines[:recap_at] if _PROBLEM_LINE.match(line))
    if findings <= limit:
        print(text)
        return
    print(_note(path, findings, len(lines), limit))
    recap = lines[recap_at:]
    if recap:
        print("\n".join(recap[:recap_lines]))
        if len(recap) > recap_lines:
            print(f"... {len(recap) - recap_lines} more blocking line(s) in {path}")


def main(argv: list[str]) -> int:
    """Print the report named on the command line.

    :param argv: Command-line arguments; ``argv[1]`` is the report path.
    :returns: Process exit status (always 0: the scan step owns the verdict).
    """
    if len(argv) != 2:
        print("usage: print_report.py FILE", file=sys.stderr)
        return 0
    path = Path(argv[1])
    if not path.is_file():
        print(f"print_report: no report at {path}")
        return 0
    text = path.read_text(encoding="utf-8")
    limit = _limit("REPORT_PRINT_MAX_FINDINGS", 15)
    if path.suffix == ".json":
        _print_json(path, text, limit)
    else:
        _print_text(path, text, limit, _limit("REPORT_TAIL_LINES", 60))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
