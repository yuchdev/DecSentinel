"""Hostile ``message``/``value``/``pending`` through every sink and a custom ``--template`` (Story 05.0 Task 01).

Closes checklist item 2 of ``docs/security/threat-model-0007-closure-2026-11-04.md``: the existing
CLI fixture (``test_reporter_hostile_filename.py``) only carries a hostile *path*. Here a real fast
scan produces a DS101 finding whose link target (``value`` and ``message``) holds bidi and
zero-width code points, and a DS103 finding whose code-span path holds ESC, BEL, a C1 CSI and DEL.
The ``pending`` reason cannot be made hostile through a real scan (the engine writes it from
literals), so ``cli.scan`` is wrapped to add one carrying an ANSI clear-screen, CR/LF and a forged
``::error::`` command. Each case renders through ``docsentinel scan`` with a packaged template or an
invoker-supplied ``--template`` that prints ``value`` and ``pending``, which no packaged text template
does. The control-character inputs are built in the test body (``tests/assets/README.md``).
"""

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from docsentinel import cli

#: Link target of the DS101 finding: RLO, ZWSP and LRI inside an otherwise ordinary path.
_BIDI_TARGET = "./y‮bidi​z⁦.md"
#: Code-span path of the DS103 finding: an OSC title sequence (ESC ... BEL), RLO, C1 CSI and DEL.
_CONTROL_PATH = "docs/z\x1b]0;t\x07‮\x9b\x7f.md"
#: Pending reason injected after the scan: clear-screen, CR/LF line forgery and a fake annotation.
_HOSTILE_PENDING = "pend\x1b[2J\r\n::error file=x::forged ‮\x9b"

_DOCUMENT = f"# Title\n\n[b]({_BIDI_TARGET})\n\nSee `{_CONTROL_PATH}` here.\n"

_BIDI_AND_INVISIBLE = frozenset(
    {0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029, 0xFEFF}
    | set(range(0x202A, 0x202F))
    | set(range(0x2066, 0x206A))
)


def _unsafe(character: str) -> bool:
    """Return whether a character must never reach a terminal or CI log raw (LF is the line separator)."""
    point = ord(character)
    if character == "\n":
        return False
    return point < 0x20 or 0x7F <= point <= 0x9F or point in _BIDI_AND_INVISIBLE or 0xD800 <= point <= 0xDFFF


def _write_template(directory: Path, name: str, sink: str, line: dict[str, Any], pending: bool) -> Path:
    """Write a text template that prints every problem with ``line`` and, optionally, every pending reason.

    :param directory: Where to write the file (outside the scan root).
    :param name: Template name and file stem.
    :param sink: ``terminal`` or ``github``.
    :param line: The per-problem line node (inside ``doc``/``p`` loops).
    :param pending: Whether to add a ``Pending:`` loop.
    :returns: The template path.
    """
    lines: list[dict[str, Any]] = [
        {
            "type": "loop",
            "over": "documents_with_problems",
            "as": "doc",
            "placement": "block",
            "body": [{"type": "loop", "over": "doc.problems", "as": "p", "placement": "block", "body": [line]}],
        }
    ]
    if pending:
        lines.append(
            {
                "type": "loop",
                "over": "pending",
                "as": "reason",
                "placement": "block",
                "body": [{"type": "line", "text": "Pending: {reason|neutralize}", "variables_used": ["reason"]}],
            }
        )
    raw = {
        "template_version": 1,
        "name": name,
        "type": "text",
        "requires_extensions": [],
        "output": {"join": "\n", "trailing_newline": False, "sink": sink},
        "lines": lines,
    }
    path = directory / f"{name}.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _custom_text(directory: Path) -> Path:
    """Return a terminal template echoing path, rule, message and value of each problem, plus pending."""
    line = {
        "type": "line",
        "when": {"var": "p.value", "ne": None},
        "text": "{p.rule}|{doc.path|neutralize}|{p.message|neutralize}|value={p.value|neutralize}",
        "variables_used": ["p.rule", "doc.path", "p.message", "p.value"],
    }
    return _write_template(directory, "hostile-text", "terminal", line, pending=True)


def _custom_github(directory: Path) -> Path:
    """Return a github-sink template putting ``value`` in a command property and in the message."""
    line = {
        "type": "line",
        "when": {"var": "p.value", "ne": None},
        "text": "::warning file={doc.path|gha_property},title={p.value|gha_property}::{p.message|gha_data}",
        "variables_used": ["doc.path", "p.value", "p.message"],
    }
    return _write_template(directory, "hostile-github", "github", line, pending=False)


@pytest.fixture
def hostile_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Return a scan root with the hostile document; ``cli.scan`` adds the hostile pending reason."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text(_DOCUMENT, encoding="utf-8")
    real = cli.scan

    def with_pending(*args: Any, **kwargs: Any) -> Any:
        """Run the real scan, then append the hostile pending reason."""
        result = real(*args, **kwargs)
        return dataclasses.replace(result, pending=(*result.pending, _HOSTILE_PENDING))

    monkeypatch.setattr(cli, "scan", with_pending)
    return root


def _run(root: Path, args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    """Run ``docsentinel scan`` over ``root`` with ``args``; return the exit code and stdout."""
    code = cli.main(["scan", str(root), *args])
    captured = capsys.readouterr()
    assert captured.err == "", captured.err
    return code, captured.out


def test_hostile_scan_really_carries_the_hostile_value_and_message(hostile_root: Path):
    """
    [Integration] report hostile values cli: verifies the fixture's findings carry the raw hostile tokens.

    Scenario:
        Given the hostile document
        When it is scanned with the fast profile
        Then DS101 carries the bidi target and DS103 the control-character path verbatim in ``value`` and
            ``message``, so the sink tests below are not vacuous.

    Boundaries:
        - Focus: guard that the injection fixture reaches the report model unchanged
        - Fixtures/params: hostile_root
        - Scope: the wrapped ``cli.scan``

    On failure, first check:
        - whether DS101/DS103 changed which token they echo in ``value``
    """
    result = cli.scan(hostile_root)

    found = {finding.rule: finding for finding in result.findings}
    assert set(found) == {"DS101", "DS103"}
    assert found["DS101"].value == _BIDI_TARGET and _BIDI_TARGET in found["DS101"].message
    assert found["DS103"].value == _CONTROL_PATH and _CONTROL_PATH in found["DS103"].message
    assert result.pending[-1] == _HOSTILE_PENDING


@pytest.mark.parametrize("source", ["text", "custom-text"])
def test_terminal_sinks_print_no_raw_control_or_bidi_code_point(
    source: str, hostile_root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] report hostile values cli: verifies text and a custom terminal template neutralize every token.

    Scenario:
        Given findings with hostile ``value``/``message`` and a hostile ``pending`` reason
        When ``scan --format text`` or ``scan --template <custom>`` (printing value and pending) runs
        Then stdout holds no C0/C1/DEL, bidi, zero-width or separator code point, no forged line starts with
            ``::``, and the visible escapes of the hostile tokens are present.

    Boundaries:
        - Focus: output safety of ``message``, ``value`` and ``pending`` in the terminal sink (spec §7)
        - Fixtures/params: packaged ``text`` and an invoker template that echoes ``value``
        - Scope: in-process CLI call

    On failure, first check:
        - ``filters.neutralize`` and the trust check of the custom template in ``loader``
    """
    args = ["--format", "text"] if source == "text" else ["--template", str(_custom_text(tmp_path))]

    code, out = _run(hostile_root, args, capsys)

    assert code == 1
    assert [hex(ord(character)) for character in out if _unsafe(character)] == []
    assert not any(line.startswith("::") for line in out.split("\n"))
    assert "Pending: pend" in out
    if source == "custom-text":
        values = [line.split("|value=", 1)[1] for line in out.split("\n") if "|value=" in line]
        assert len(values) == 2
        assert all("\\" in value for value in values)


@pytest.mark.parametrize("source", ["github", "custom-github"])
def test_github_sinks_emit_exactly_one_well_formed_command_per_problem(
    source: str, hostile_root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] report hostile values cli: verifies github output cannot be forged by ``value``/``message``.

    Scenario:
        Given findings with hostile ``value``/``message`` (and a pending reason carrying ``::error``)
        When ``scan --format github`` or a custom github-sink template with ``value`` in ``title=`` runs
        Then stdout is exactly two lines, each one ``::warning``/``::error`` command whose property segment
            holds no raw ``:`` or ``,`` from the token, and no unsafe code point appears anywhere.

    Boundaries:
        - Focus: workflow-command injection through ``value`` in a property and ``message`` in the data
        - Fixtures/params: packaged ``github`` and an invoker github template
        - Scope: in-process CLI call

    On failure, first check:
        - ``filters.gha_property`` / ``gha_data`` and the github-sink trust rule in ``loader``
    """
    args = ["--format", "github"] if source == "github" else ["--template", str(_custom_github(tmp_path))]

    code, out = _run(hostile_root, args, capsys)

    assert out.endswith("\n")
    lines = out[:-1].split("\n")
    assert code == 1
    assert len(lines) == 2
    assert all(line.startswith(("::error ", "::warning ")) for line in lines)
    assert all(line.count("::") == 2 for line in lines)
    assert [hex(ord(character)) for character in out if _unsafe(character)] == []
    assert "forged" not in out


def _strings(node: object) -> list[str]:
    """Return every string value in a parsed JSON tree."""
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [text for value in node.values() for text in _strings(value)]
    if isinstance(node, list):
        return [text for value in node for text in _strings(value)]
    return []


@pytest.mark.parametrize("name", ["json", "json-v1", "json-documents"])
def test_json_sinks_are_ascii_and_round_trip_the_hostile_tokens_exactly(
    name: str, hostile_root: Path, capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] report hostile values cli: verifies JSON escapes hostile tokens but keeps them intact.

    Scenario:
        Given findings with hostile ``value``/``message`` and a hostile pending reason
        When ``scan --format <json template>`` runs
        Then stdout is pure ASCII, parses, and the parsed strings hold the hostile tokens byte-exact
            (escaped, not altered), with pending present where the schema carries it.

    Boundaries:
        - Focus: JSON sink safety (``ensure_ascii``, M8) without integrity loss
        - Fixtures/params: the three packaged JSON templates
        - Scope: in-process CLI call

    On failure, first check:
        - the forced ``ensure_ascii`` in ``telemetry.engine`` and the template's value/pending variables
    """
    code, out = _run(hostile_root, ["--format", name], capsys)

    assert code == 1
    assert out.isascii()
    strings = _strings(json.loads(out))
    assert any(_CONTROL_PATH in text for text in strings)
    assert any(_BIDI_TARGET in text for text in strings)
    if name != "json-documents":
        assert _HOSTILE_PENDING in strings
