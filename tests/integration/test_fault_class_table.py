"""Parity of ``telemetry.classify.FAULT_CLASSES`` with ``src/docsentinel/fault_classes.md`` and the rule registry.

The Markdown table is the hand-maintained source documented for reviewers; the dict is what the
report model and the Milestone 0006 adapter consume. Both must list the same rows, and every
registered rule must have exactly one.
"""

import importlib
import re
from pathlib import Path

import docsentinel.detectors.loader as loader
from docsentinel.rules import RULES
from docsentinel.telemetry.classify import FAULT_CLASSES

# Importing the engine registers the fast rules; DS301 registers on import of its module.
for _module in ("docsentinel.engine", "docsentinel.detectors.contradictions"):
    importlib.import_module(_module)

_TABLE: Path = Path(__file__).resolve().parents[2] / "src" / "docsentinel" / "fault_classes.md"
_ROW_RE = re.compile(r"^\|\s*(DS\d{3})\s*\|\s*(\w+)\s*\|\s*`([a-z_]+)`\s*\|", re.MULTILINE)


def _table_rows() -> dict[str, tuple[str, str]]:
    """Parse ``rule -> (profile, fault class)`` from the Markdown table."""
    rows: dict[str, tuple[str, str]] = {}
    for code, profile, fault_class in _ROW_RE.findall(_TABLE.read_text(encoding="utf-8")):
        assert code not in rows, f"duplicate row for {code}"
        rows[code] = (profile, fault_class)
    return rows


def test_fault_class_dict_matches_markdown_table():
    """
    [Integration] fault class table: verifies the classify table equals the fault_classes.md rows.

    Scenario:
        Given the rule-to-fault-class Markdown table shipped beside ``rules.py``
        When its rows are parsed
        Then they equal ``FAULT_CLASSES`` exactly, with no duplicate rows.

    Boundaries:
        - Focus: documentation/code parity of the fault-class mapping
        - Fixtures/params: none
        - Scope: reads one repository source document

    On failure, first check:
        - Whether a row was added to one source but not the other
    """
    rows = _table_rows()

    assert {code: fault_class for code, (_, fault_class) in rows.items()} == FAULT_CLASSES


def test_every_registered_rule_has_one_row_with_its_profile():
    """
    [Integration] fault class table: verifies every registered rule has a row naming its profile.

    Scenario:
        Given all fast, standard and deep rules registered
        When the table rows are compared with the registry
        Then the code sets are equal and each row's profile is the rule's profile.

    Boundaries:
        - Focus: no registered rule falls back to ``unmapped``
        - Fixtures/params: none
        - Scope: rule registry plus one source document

    On failure, first check:
        - A newly registered rule missing from ``fault_classes.md``
    """
    loader.ensure_standard_loaded()
    rows = _table_rows()

    assert set(rows) == set(RULES)
    assert {code: profile for code, (profile, _) in rows.items()} == {
        code: rule.profile for code, rule in RULES.items()
    }
