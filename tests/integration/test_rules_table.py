"""Parity of ``docs/user/reference/rules.md`` with the rule registry and ``docsentinel rules``.

The Markdown table is the single user-facing table of checks; the registry (``Rule`` registrations
collected in ``docsentinel.rules.RULES``) is the reference. Every registered rule must have exactly
one row whose profile, severity, activation, title, description and fault class equal the code,
and the ``docsentinel rules`` listing must agree with the table.
"""

import contextlib
import dataclasses
import importlib
import io
import re
from pathlib import Path

import docsentinel.detectors.loader as loader
from docsentinel import cli
from docsentinel.config import Config
from docsentinel.rules import RULES
from docsentinel.telemetry.classify import FAULT_CLASSES

# Importing the engine registers the fast rules; DS301 registers on import of its module.
for _module in ("docsentinel.engine", "docsentinel.detectors.contradictions"):
    importlib.import_module(_module)

_TABLE: Path = Path(__file__).resolve().parents[2] / "docs" / "user" / "reference" / "rules.md"
_COLUMNS: tuple[str, ...] = (
    "code",
    "profile",
    "severity",
    "activation",
    "title",
    "description",
    "fault_class",
    "config_keys",
)
_ROW_RE = re.compile(r"^\|\s*(DS\d{3})\s*\|.*\|\s*$", re.MULTILINE)
_LISTING_RE = re.compile(r"^  (DS\d{3}): (.+?)(?: \[opt-in: set (\w+)\])?$")


def _table_rows() -> dict[str, dict[str, str]]:
    """Parse the rule table into ``code -> {column: cell}``, refusing duplicate rows."""
    rows: dict[str, dict[str, str]] = {}
    for match in _ROW_RE.finditer(_TABLE.read_text(encoding="utf-8")):
        cells = [cell.strip() for cell in match.group(0).strip().strip("|").split("|")]
        assert len(cells) == len(_COLUMNS), f"row {match.group(1)} has {len(cells)} cells"
        row = dict(zip(_COLUMNS, cells, strict=True))
        assert row["code"] not in rows, f"duplicate row for {row['code']}"
        rows[row["code"]] = row
    return rows


def _expected_activation(opt_in_option: str) -> str:
    """Return the Activation cell text the table must carry for a rule."""
    return f"opt-in: `{opt_in_option}`" if opt_in_option else "always"


def _cli_listing() -> dict[str, tuple[str, str]]:
    """Run ``docsentinel rules`` and parse ``code -> (title, opt-in option)``."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert cli.main(["rules"]) == 0
    listing: dict[str, tuple[str, str]] = {}
    for line in buffer.getvalue().splitlines():
        match = _LISTING_RE.match(line)
        if match:
            listing[match.group(1)] = (match.group(2), match.group(3) or "")
    return listing


def test_every_registered_rule_has_exactly_one_row():
    """
    [Integration] rules table: verifies the table and the registry list the same rule codes.

    Scenario:
        Given all fast, standard and deep rules registered
        When the rules.md table rows are parsed
        Then the set of row codes equals the set of registered codes, with no duplicates.

    Boundaries:
        - Focus: no rule is missing from, or invented in, the single table of checks
        - Fixtures/params: none
        - Scope: rule registry plus one repository document

    On failure, first check:
        - A newly registered rule without a row in docs/user/reference/rules.md
    """
    loader.ensure_standard_loaded()

    assert set(_table_rows()) == set(RULES)


def test_row_columns_match_rule_registration():
    """
    [Integration] rules table: verifies each row repeats its rule registration word for word.

    Scenario:
        Given every registered rule and its table row
        When profile, severity, activation, title, description and fault class are compared
        Then each cell equals the registered value (fault class from FAULT_CLASSES).

    Boundaries:
        - Focus: documentation/code parity of rule metadata
        - Fixtures/params: none
        - Scope: rule registry, FAULT_CLASSES and one repository document

    On failure, first check:
        - A changed Rule(...) title, description, severity or opt_in_option not copied to the table
    """
    loader.ensure_standard_loaded()
    rows = _table_rows()

    expected = {
        code: {
            "profile": rule.profile,
            "severity": rule.severity,
            "activation": _expected_activation(rule.opt_in_option),
            "title": rule.title,
            "description": rule.description,
            "fault_class": f"`{FAULT_CLASSES[code]}`",
        }
        for code, rule in RULES.items()
    }
    actual = {code: {key: row[key] for key in expected[code]} for code, row in rows.items() if code in expected}

    assert actual == expected


def test_cli_rules_listing_matches_table():
    """
    [Integration] rules table: verifies ``docsentinel rules`` prints the same codes, titles and opt-ins.

    Scenario:
        Given the CLI ``rules`` command run in-process
        When its listing lines are parsed
        Then every listed code has a row with the same title and opt-in option, and vice versa.

    Boundaries:
        - Focus: the user-visible rule listing and the table cannot drift apart
        - Fixtures/params: none
        - Scope: CLI output plus one repository document

    On failure, first check:
        - Whether cli._opt_in_suffix or the listing format changed
    """
    rows = _table_rows()
    listing = _cli_listing()

    assert listing == {
        code: (
            row["title"],
            row["activation"].removeprefix("opt-in: `").removesuffix("`") if row["activation"] != "always" else "",
        )
        for code, row in rows.items()
    }


def test_config_keys_are_config_fields():
    """
    [Integration] rules table: verifies every config key named in the table is a ``Config`` field.

    Scenario:
        Given the Config keys column of every row
        When each backticked key is looked up among the Config dataclass fields
        Then all of them exist, and an opt-in rule lists its enabling option.

    Boundaries:
        - Focus: no renamed or removed option lingers in the table
        - Fixtures/params: none
        - Scope: Config dataclass plus one repository document

    On failure, first check:
        - A renamed config option, or a typo in the table's Config keys cell
    """
    loader.ensure_standard_loaded()
    fields = {field.name for field in dataclasses.fields(Config)}
    rows = _table_rows()

    unknown = {
        code: key
        for code, row in rows.items()
        for key in re.findall(r"`(\w+)`", row["config_keys"])
        if key not in fields
    }
    missing_opt_in = [
        code
        for code, rule in RULES.items()
        if rule.opt_in_option and f"`{rule.opt_in_option}`" not in rows[code]["config_keys"]
    ]

    assert unknown == {}
    assert missing_opt_in == []
