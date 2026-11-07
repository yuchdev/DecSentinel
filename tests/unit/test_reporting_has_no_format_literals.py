"""Hardcode-ban tripwire for the template-only reporting path (Milestone 0007 Story 03.0 Task 02).

``reporting.py`` and ``telemetry/engine.py`` must hold no output format of their own: every
report byte comes from a template. The tripwire parses both modules with :mod:`ast` and fails
on a string constant equal to a format name, a string carrying a fragment of a legacy layout
(the GitHub ``::`` command marker, ``Schema version``, ``Profile:``, ``bytes)``), a
``json.dumps`` call in ``reporting.py``, or a comparison against a format name. A second case
re-adds such a literal to a temp copy and asserts the tripwire fires, so it cannot rot into a
no-op.
"""

import ast
from pathlib import Path

import pytest

from docsentinel import reporting
from docsentinel.telemetry import engine
from docsentinel.telemetry.loader import packaged_template_names

#: Format names a module may not spell: the legacy three plus every packaged template name.
_FORMAT_NAMES: frozenset[str] = frozenset({"text", "json", "github"}) | frozenset(packaged_template_names())

#: Substrings of the legacy hand-built layouts.
_LAYOUT_FRAGMENTS: tuple[str, ...] = ("::", "Schema version", "Profile:", "bytes)")


def _is_format_name(node: ast.AST) -> bool:
    """Return whether ``node`` is a string constant equal to a format name.

    :param node: Any AST node.
    :returns: ``True`` for a ``str`` constant in :data:`_FORMAT_NAMES`.
    """
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in _FORMAT_NAMES


def _is_json_dumps(node: ast.AST) -> bool:
    """Return whether ``node`` calls ``json.dumps`` (or a bare ``dumps``).

    :param node: Any AST node.
    :returns: ``True`` for a ``json.dumps(...)`` or ``dumps(...)`` call.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr == "dumps" and isinstance(func.value, ast.Name) and func.value.id == "json"
    return isinstance(func, ast.Name) and func.id == "dumps"


def violations(source: str, *, ban_json_dumps: bool) -> list[str]:
    """Return every hardcode-ban violation in a module's source.

    :param source: Python source text.
    :param ban_json_dumps: Also flag ``json.dumps`` calls (``reporting.py`` only).
    :returns: One ``line N: reason`` entry per violation, in walk order.
    """
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        line = getattr(node, "lineno", 0)
        if _is_format_name(node):
            found.append(f"line {line}: format-name literal {node.value!r}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.extend(
                f"line {line}: layout fragment {fragment!r}" for fragment in _LAYOUT_FRAGMENTS if fragment in node.value
            )
        if isinstance(node, ast.Compare) and any(
            _is_format_name(operand) for operand in (node.left, *node.comparators)
        ):
            found.append(f"line {line}: comparison against a format name")
        if ban_json_dumps and _is_json_dumps(node):
            found.append(f"line {line}: json.dumps call")
    return found


@pytest.mark.parametrize(
    ("module_file", "ban_json_dumps"),
    [(reporting.__file__, True), (engine.__file__, False)],
    ids=["reporting", "telemetry_engine"],
)
def test_module_holds_no_format_literals(module_file: str, ban_json_dumps: bool):
    """
    [Unit] reporting tripwire: verifies the render path spells no format name, layout fragment or serializer.

    Scenario:
        Given the source of ``reporting.py`` or ``telemetry/engine.py``
        When it is parsed with ``ast`` and every node is inspected
        Then no format-name constant, legacy layout fragment, format-name comparison or (reporting) ``json.dumps``
            call is found.

    Boundaries:
        - Focus: the template-only output contract (Story 03.0 Task 02, ADR 0003)
        - Fixtures/params: parametrized over the two modules
        - Scope: static source analysis; nothing is imported beyond locating the files

    On failure, first check:
        - Whether an output format or line layout was re-added in Python instead of a template
        - Whether a new constant should come from ``telemetry.loader`` (e.g. ``DEFAULT_TEMPLATE``, ``TYPE_TEXT``)
    """
    source = Path(module_file).read_text(encoding="utf-8")

    assert violations(source, ban_json_dumps=ban_json_dumps) == []


@pytest.mark.parametrize(
    "injected",
    [
        'LEGACY = "text"\n',
        'def _line(path):\n    return f"  {path} (1 bytes)"\n',
        'BANNER = "Schema version: 1"\n',
        'HEADER = "Profile: fast"\n',
        'def _annotate(level):\n    return f"::{level} file=x"\n',
        "import json\n\ndef _dump(data):\n    return json.dumps(data)\n",
        "def _pick(fmt):\n    return 1 if fmt == FORMATS['json-v1'] else 0\nFORMATS = {'json-v1': 1}\n",
    ],
    ids=["format-name", "bytes-suffix", "schema-header", "profile-header", "gha-marker", "json-dumps", "compare"],
)
def test_tripwire_fires_on_a_reinjected_literal(injected: str, tmp_path: Path):
    """
    [Unit] reporting tripwire: verifies the tripwire fails a copy of ``reporting.py`` with a re-added literal.

    Scenario:
        Given a temp copy of ``reporting.py`` with one banned literal or call appended
        When the tripwire inspects the copy
        Then it reports at least one violation, while the untouched copy reports none.

    Boundaries:
        - Focus: the tripwire cannot silently become a no-op
        - Fixtures/params: parametrized over one injection per banned category; ``tmp_path`` for the copy
        - Scope: static source analysis of a temp file

    On failure, first check:
        - Whether ``violations`` stopped walking a node type (``Constant``, ``Compare``, ``Call``)
        - Whether ``_FORMAT_NAMES`` or ``_LAYOUT_FRAGMENTS`` lost an entry
    """
    original = Path(reporting.__file__).read_text(encoding="utf-8")
    copy = tmp_path / "reporting.py"
    copy.write_text(original + "\n\n" + injected, encoding="utf-8")

    assert violations(original, ban_json_dumps=True) == []
    assert violations(copy.read_text(encoding="utf-8"), ban_json_dumps=True)
