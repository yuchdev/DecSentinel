"""Detect stray HTML comments in Markdown documents."""

import re
from pathlib import Path
from typing import Optional

from docsentinel import models, rules

DS102 = rules.register_rule(
    rules.Rule(
        code="DS102",
        profile="fast",
        title="Stray HTML comment",
        description="An HTML comment was left in rendered Markdown.",
        severity="warning",
    )
)

_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


def _strip_fenced_blocks(text: str) -> str:
    """Return text with fenced code blocks blanked while preserving offsets."""
    stripped_lines: list[str] = []
    in_fence = False
    fence_marker: Optional[str] = None

    for line in text.splitlines(keepends=True):
        fence = _FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)[0]
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif marker == fence_marker:
                in_fence, fence_marker = False, None

        if in_fence or fence:
            blank_line = "".join(character if character in "\r\n" else " " for character in line)
            stripped_lines.append(blank_line)
        else:
            stripped_lines.append(line)

    return "".join(stripped_lines)


def _read_text(path: Path) -> str:
    """Read UTF-8 text from a path."""
    with path.open(encoding="utf-8") as stream:
        return stream.read()


def detect(root: Path, documents: tuple[models.Document, ...]) -> tuple[models.Finding, ...]:
    """Return DS102 findings for Markdown documents in their supplied order."""
    findings: list[models.Finding] = []
    for document in documents:
        if not document.path.endswith(".md"):
            continue

        text = _read_text(root / document.path)
        if "-->" not in text:
            continue

        text = _strip_fenced_blocks(text)
        if "-->" not in text:
            continue

        last_closer_end = text.rfind("-->") + len("-->")
        line = 1
        line_cursor = 0
        for match in _COMMENT_RE.finditer(text, 0, last_closer_end):
            start, end = match.span()
            line += text.count("\n", line_cursor, start)
            line_cursor = start
            display_text = repr(text[start : min(end, start + 80)])
            if end - start > 80:
                display_text += "..."
            findings.append(
                models.Finding(
                    rule=DS102.code,
                    path=document.path,
                    message=f"stray HTML comment: {display_text}",
                    severity=DS102.severity,
                    line=line,
                    column=start - (text.rfind("\n", 0, start) + 1) + 1,
                    type="stray html comment",
                )
            )
    return tuple(findings)


rules.ANALYZERS[DS102.code] = detect
