"""Unit tests for ``docsentinel.telemetry.filters`` (Milestone 0007 Story 02.0 Task 02).

The neutralization tables and the GitHub escapers were moved here from
``docsentinel.reporting``. The Story 03.0 cut-over deleted the originals, so this module
keeps a frozen reference copy of the pre-move algorithm (``_reference_*``) and pins the
moved copies byte-identical to it over the full code-point range. Non-printable code
points are spelled with ``chr()``.
"""

from typing import Any

import pytest

from docsentinel import reporting
from docsentinel.telemetry import filters, loader
from docsentinel.telemetry.filters import (
    FILTER_NAMES,
    MAX_MESSAGE,
    TemplateError,
    apply_filter,
    gha_data,
    gha_property,
    neutralize,
    to_text,
)

ESC = chr(0x1B)
RLO = chr(0x202E)
ZWSP = chr(0x200B)
LONE_SURROGATE = chr(0xD800)

#: Every code point, surrogates included, as one string (``str.translate`` maps each
#: character independently, so equality of the whole string is per-code-point parity).
_ALL_CODE_POINTS: str = "".join(chr(code_point) for code_point in range(0x110000))


def _reference_escape(code_point: int) -> str:
    """Return the pre-move backslash escape of one code point (frozen copy of the deleted original)."""
    if code_point <= 0xFF:
        return f"\\x{code_point:02x}"
    if code_point <= 0xFFFF:
        return f"\\u{code_point:04x}"
    return f"\\U{code_point:08x}"


def _reference_table(*, keep_crlf: bool) -> dict[int, str]:
    """Return the pre-move control table (frozen copy of ``reporting._build_control_table``)."""
    code_points: set[int] = set(range(0x00, 0x20)) | {0x7F} | set(range(0x80, 0xA0))
    code_points |= {0x061C, 0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF}
    code_points |= set(range(0x202A, 0x202F))
    code_points |= {0x2066, 0x2067, 0x2068, 0x2069}
    code_points |= {0x2028, 0x2029}
    code_points |= set(range(0xD800, 0xE000))
    if keep_crlf:
        code_points -= {0x0D, 0x0A}
    return {code_point: _reference_escape(code_point) for code_point in code_points}


def _reference_neutralize(value: str, *, keep_crlf: bool = False) -> str:
    """Return the pre-move ``reporting._neutralize_controls`` output."""
    return value.translate(_reference_table(keep_crlf=keep_crlf))


def _reference_property(value: str) -> str:
    """Return the pre-move ``reporting._escape_property`` output."""
    neutral = _reference_neutralize(value, keep_crlf=True)
    return neutral.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _reference_data(value: str) -> str:
    """Return the pre-move ``reporting._escape_data`` output."""
    neutral = _reference_neutralize(value, keep_crlf=True)
    return neutral.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def test_filter_names_match_loader_signature_table():
    """
    [Unit] filters: verifies the runtime filter table has exactly the loader's load-time signatures.

    Scenario:
        Given the loader's ``FILTERS`` signature table and the runtime ``FILTER_NAMES``
        When their key sets are compared
        Then they are equal, so no validated filter lacks an implementation.

    Boundaries:
        - Focus: closed filter table parity (spec §7)
        - Fixtures/params: none
        - Scope: module constants only

    On failure, first check:
        - ``filters._FUNCTIONS`` and ``loader.FILTERS`` were edited together
    """
    assert FILTER_NAMES == frozenset(loader.FILTERS)


def test_moved_tables_equal_reporting_originals():
    """
    [Unit] filters: verifies the moved control tables equal the pre-move originals entry for entry.

    Scenario:
        Given the text and GitHub control tables in ``filters`` and the frozen pre-move reference copy
        When they are compared
        Then both pairs are equal dicts.

    Boundaries:
        - Focus: Story DoD "same tables"
        - Fixtures/params: none
        - Scope: private module tables

    On failure, first check:
        - ``filters._build_control_table`` drifted from the deleted ``reporting._build_control_table``
    """
    assert filters._TEXT_CONTROL_TABLE == _reference_table(keep_crlf=False)
    assert filters._GITHUB_CONTROL_TABLE == _reference_table(keep_crlf=True)
    assert filters._build_control_table(keep_crlf=False) == _reference_table(keep_crlf=False)


def test_moved_functions_match_originals_over_every_code_point():
    """
    [Unit] filters: verifies neutralize/gha_property/gha_data equal the originals on every code point.

    Scenario:
        Given one string holding every code point U+0000..U+10FFFF, lone surrogates included
        When it passes through each moved function and the frozen copy of its deleted reporting.py original
        Then the outputs are identical, and ``reporting.neutralize_text`` agrees too.

    Boundaries:
        - Focus: Story DoD "same outputs" (full control, bidi, zero-width, separator, surrogate sets)
        - Fixtures/params: none
        - Scope: pure string functions

    On failure, first check:
        - The ``replace`` chains of ``_escape_property`` / ``_escape_data``
    """
    assert neutralize(_ALL_CODE_POINTS) == _reference_neutralize(_ALL_CODE_POINTS)
    assert reporting.neutralize_text(_ALL_CODE_POINTS) == _reference_neutralize(_ALL_CODE_POINTS)
    assert gha_property(_ALL_CODE_POINTS) == _reference_property(_ALL_CODE_POINTS)
    assert gha_data(_ALL_CODE_POINTS) == _reference_data(_ALL_CODE_POINTS)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (f"a{ESC}[31mb", "a\\x1b[31mb"),
        ("line\r\nforged", "line\\x0d\\x0aforged"),
        (f"x{RLO}y", "x\\u202ey"),
        (f"hid{ZWSP}den", "hid\\u200bden"),
        (f"name{LONE_SURROGATE}", "name\\ud800"),
        ("plain ASCII and Unicode: café", "plain ASCII and Unicode: café"),
    ],
    ids=["esc", "cr-lf", "rlo", "zwsp", "lone-surrogate", "printable"],
)
def test_neutralize_matches_pre_move_output(raw: str, expected: str):
    """
    [Unit] filters: verifies neutralize gives the pre-move escape for each hostile class.

    Scenario:
        Given ESC, CR-LF, U+202E, U+200B, a lone surrogate and printable text
        When ``neutralize`` and the reporting.py originals are applied
        Then all give the same documented escape and printable text is unchanged.

    Boundaries:
        - Focus: normal and edge cases of the text sink filter (threat model T11 kept verbatim)
        - Fixtures/params: one case per code-point class
        - Scope: pure string function

    On failure, first check:
        - ``filters._escaped`` formatting
    """
    assert neutralize(raw) == expected
    assert _reference_neutralize(raw) == expected
    assert reporting.neutralize_text(raw) == expected


def test_reporting_neutralize_text_is_repointed_to_filters():
    """
    [Unit] reporting: verifies the public neutralize_text now delegates to filters.neutralize.

    Scenario:
        Given ``reporting.neutralize_text`` and ``filters.neutralize``
        When ``reporting``'s bound helper is inspected and both are called on a non-string
        Then the helper is ``filters.neutralize`` and both raise ``TemplateError``.

    Boundaries:
        - Focus: Task 02 re-pointing; the public name stays
        - Fixtures/params: none
        - Scope: module attributes

    On failure, first check:
        - The ``from docsentinel.telemetry.filters import neutralize`` line in reporting.py
    """
    assert reporting._neutralize is filters.neutralize
    assert loader.neutralize_text is filters.neutralize
    with pytest.raises(TemplateError):
        reporting.neutralize_text(123)  # type: ignore[arg-type]


def test_gha_data_escapes_percent_cr_lf_only():
    """
    [Unit] filters: verifies gha_data percent-encodes % CR LF and neutralizes other controls.

    Scenario:
        Given a message with ``%``, CR, LF, ``:``, ``,``, ``;`` and ESC
        When ``gha_data`` is applied
        Then ``%``/CR/LF become ``%25``/``%0D``/``%0A``, ESC is backslash-escaped and ``: , ;`` stay.

    Boundaries:
        - Focus: GitHub command data contract (spec §7)
        - Fixtures/params: none
        - Scope: pure string function

    On failure, first check:
        - ``filters._escape_data``
    """
    assert gha_data(f"100%\r\nx: a, b; {ESC}") == "100%25%0D%0Ax: a, b; \\x1b"


def test_gha_property_escapes_percent_cr_lf_colon_comma():
    """
    [Unit] filters: verifies gha_property percent-encodes % CR LF : , and leaves other punctuation.

    Scenario:
        Given a forged property value ``a,title=X:%\\r\\n;b`` with an RLO
        When ``gha_property`` is applied
        Then ``,`` ``:`` ``%`` CR LF are percent-encoded, RLO is escaped and ``;`` ``=`` are untouched.

    Boundaries:
        - Focus: GitHub command property contract (spec §7, threat model T2); ``;`` is not a
          runner property delimiter and the pre-move function never encoded it
        - Fixtures/params: none
        - Scope: pure string function

    On failure, first check:
        - ``filters._escape_property``
    """
    assert gha_property(f"a,title=X:%\r\n;b{RLO}") == "a%2Ctitle=X%3A%25%0D%0A;b\\u202e"


@pytest.mark.parametrize(
    ("name", "value", "args"),
    [
        ("neutralize", ["a"], ()),
        ("gha_property", {"a": 1}, ()),
        ("gha_data", ["a"], ()),
        ("lower", {"a": 1}, ()),
        ("upper", ["a"], ()),
        ("default", ["a"], ("x",)),
        ("join", "not-a-list", (", ",)),
        ("join", [{"a": 1}], (", ",)),
        ("join", [["nested"]], (", ",)),
        ("len", 3, ()),
        ("len", None, ()),
        ("json", object(), ()),
        ("neutralize", float("nan"), ()),
    ],
    ids=[
        "neutralize-list",
        "gha-property-object",
        "gha-data-list",
        "lower-object",
        "upper-list",
        "default-list",
        "join-string",
        "join-objects",
        "join-nested",
        "len-int",
        "len-null",
        "json-object-instance",
        "neutralize-nan",
    ],
)
def test_filter_given_wrong_kind_raises_template_error(name: str, value: Any, args: tuple[str, ...]):
    """
    [Unit] filters: verifies every filter rejects a wrong-kind input with TemplateError, never TypeError.

    Scenario:
        Given a filter and a value of a kind it does not accept
        When ``apply_filter`` runs
        Then a ``TemplateError`` naming the filter (not the value) is raised.

    Boundaries:
        - Focus: invalid input; filters are pure and total (Task 02 contract)
        - Fixtures/params: one case per filter and wrong kind
        - Scope: apply_filter

    On failure, first check:
        - The kind guard at the top of the matching ``_filter_*`` function
    """
    with pytest.raises(TemplateError) as caught:
        apply_filter(name, value, args)
    assert name in str(caught.value)
    assert not isinstance(caught.value, TypeError)


@pytest.mark.parametrize("function", [neutralize, gha_property, gha_data])
def test_public_sink_functions_reject_non_strings(function: Any):
    """
    [Unit] filters: verifies the public sink functions raise TemplateError for a non-string.

    Scenario:
        Given an int passed straight to ``neutralize``/``gha_property``/``gha_data``
        When the function is called
        Then ``TemplateError`` is raised instead of ``AttributeError``/``TypeError``.

    Boundaries:
        - Focus: invalid input of the public functions
        - Fixtures/params: the three sink functions
        - Scope: pure functions

    On failure, first check:
        - ``filters._require_text``
    """
    with pytest.raises(TemplateError):
        function(7)


def test_scalar_filters_use_json_spelling_for_non_strings():
    """
    [Unit] filters: verifies scalar filters stringify null/bool/number in JSON spelling before escaping.

    Scenario:
        Given null, true, an int and a float
        When neutralize, gha_property, lower, upper and to_text are applied
        Then they yield ``null``, ``true``/``TRUE``, ``3`` and ``1.5``.

    Boundaries:
        - Focus: edge case: a trusted int such as ``p.line`` through ``gha_property``
        - Fixtures/params: none
        - Scope: apply_filter, to_text

    On failure, first check:
        - ``filters.to_text``
    """
    assert apply_filter("neutralize", None) == "null"
    assert apply_filter("gha_property", 3) == "3"
    assert apply_filter("upper", True) == "TRUE"
    assert apply_filter("lower", False) == "false"
    assert to_text(1.5) == "1.5" and to_text("s") == "s"
    with pytest.raises(TemplateError):
        to_text(["a"])


def test_plain_transforms_normal_and_empty_cases():
    """
    [Unit] filters: verifies join/len/default/json/lower/upper on normal and empty inputs.

    Scenario:
        Given lists, objects, strings and null
        When each plain transform runs
        Then join joins scalar text, len counts, default replaces only null, json is ASCII-safe.

    Boundaries:
        - Focus: normal and edge cases (empty list, null default, non-ASCII json)
        - Fixtures/params: none
        - Scope: apply_filter

    On failure, first check:
        - The matching ``_filter_*`` function
    """
    assert apply_filter("join", ["a", 1, None, True], (", ",)) == "a, 1, null, true"
    assert apply_filter("join", [], (", ",)) == ""
    assert apply_filter("len", ["a", "b"]) == 2 and apply_filter("len", {}) == 0 and apply_filter("len", "abc") == 3
    assert apply_filter("default", None, ("n/a",)) == "n/a"
    assert apply_filter("default", 0, ("n/a",)) == 0
    assert apply_filter("default", "", ("n/a",)) == ""
    assert apply_filter("json", ["DS101", "DS102"]) == '["DS101", "DS102"]'
    assert apply_filter("json", f"caf{chr(0xE9)}{ESC}") == '"caf\\u00e9\\u001b"'
    assert apply_filter("lower", "AbC") == "abc" and apply_filter("upper", "AbC") == "ABC"


def test_apply_filter_rejects_unknown_name_and_bad_arity():
    """
    [Unit] filters: verifies apply_filter refuses names outside the closed table and wrong argument counts.

    Scenario:
        Given an unknown name, ``join`` with no argument and ``lower`` with one
        When ``apply_filter`` runs
        Then each raises ``TemplateError``.

    Boundaries:
        - Focus: invalid input; the table is closed (spec §7)
        - Fixtures/params: none
        - Scope: apply_filter

    On failure, first check:
        - The arity check in ``apply_filter``
    """
    with pytest.raises(TemplateError, match="unknown filter"):
        apply_filter("format", "x")
    with pytest.raises(TemplateError, match="join"):
        apply_filter("join", ["a"])
    with pytest.raises(TemplateError, match="lower"):
        apply_filter("lower", "a", ("x",))


def test_template_error_message_is_neutralized_and_bounded():
    """
    [Unit] filters: verifies the moved TemplateError neutralizes and bounds its message (M16).

    Scenario:
        Given a message holding ESC and RLO and one longer than ``MAX_MESSAGE``
        When ``TemplateError`` is constructed
        Then the message is escaped, bounded, and the class is ``loader.TemplateError``.

    Boundaries:
        - Focus: regression guard for moving the class out of the loader
        - Fixtures/params: none
        - Scope: exception construction

    On failure, first check:
        - ``filters.TemplateError.__init__``
    """
    assert str(TemplateError(f"bad{ESC}{RLO}")) == "bad\\x1b\\u202e"
    long = str(TemplateError("x" * (MAX_MESSAGE * 2)))
    assert len(long) == MAX_MESSAGE and long.endswith("...")
    assert loader.TemplateError is TemplateError and loader.MAX_MESSAGE == MAX_MESSAGE
