"""Reporter control-character neutralisation (Story 15.0 Task 02 A).

These tests pin the tool-wide hardening that neutralises ANSI escapes, C0/C1
controls, DEL, bidirectional overrides and zero-width format characters before the
human-facing text and GitHub-annotation sinks render an untrusted path or message.
They also assert the two invariants the fix must not break: ASCII-printable input
renders byte-identically, and baseline fingerprints (hashed from the raw
:class:`~docsentinel.models.Finding` fields) are unaffected by the escaped output.
"""

import hashlib
import json

from docsentinel.baseline import fingerprint
from docsentinel.config import Config
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.reporting import neutralize_text, render
from docsentinel.telemetry.filters import _neutralize_controls
from docsentinel.telemetry.filters import gha_data as _escape_data
from docsentinel.telemetry.filters import gha_property as _escape_property

#: An untrusted file name carrying an ANSI colour escape, CR, LF and a spoofed
#: GitHub workflow command, exactly the shape a legally-named repository file can take.
_HOSTILE_PATH: str = "docs/evil\x1b[31m\r\n::error::spoofed.md"


def _result(findings: tuple[Finding, ...], documents: tuple[Document, ...] = ()) -> ScanResult:
    """Build a minimal fast-profile scan result for rendering.

    :param findings: Findings to render.
    :param documents: Documents to list; defaults to none.
    :returns: A :class:`~docsentinel.models.ScanResult` with those findings.
    """
    return ScanResult(
        profile="fast",
        documents=documents,
        findings=findings,
        enabled_rules=("DS101",),
        pending=(),
    )


def test_text_sink_neutralises_escape_cr_lf_in_path_and_message():
    """
    [Unit] reporting control characters: verifies the text sink neutralises ESC/CR/LF.

    Scenario:
        Given a finding whose path and message carry an ANSI escape plus CR and LF
        When the result is rendered as text
        Then no raw ESC, CR or LF from the untrusted strings survives, each is shown as a
        visible backslash escape, and the forged ``::error::`` text cannot start its own line.

    Boundaries:
        - Focus: C0/ESC/CR/LF neutralisation in the text sink's path and message fields
        - Fixtures/params: none
        - Scope: text rendering of one finding

    On failure, first check:
        - Whether a raw control byte leaked into the rendered text
        - Whether the escape form changed from the documented ``\\xHH`` spelling
    """
    message = "dangling link ->\x1b[0m ./x\r\n::warning::spoof"
    rendered = render(_result((Finding(rule="DS101", path=_HOSTILE_PATH, message=message, severity="error", line=1),)))
    assert "\x1b" not in rendered
    # The only CR/LF in the output are the renderer's own line separators, never from content.
    content_line = next(line for line in rendered.splitlines() if line.startswith("  error:"))
    assert "\x1b" not in content_line and "\r" not in content_line
    assert "\\x1b" in content_line and "\\x0d" in content_line and "\\x0a" in content_line
    assert "docs/evil\\x1b[31m\\x0d\\x0a::error::spoofed.md" in content_line


def test_text_sink_neutralises_document_path():
    """
    [Unit] reporting control characters: verifies the text sink neutralises a document path.

    Scenario:
        Given a document whose path carries an ANSI escape and a line feed
        When the result is rendered as text
        Then the document listing line shows the path with visible escapes and no raw control byte.

    Boundaries:
        - Focus: the documents listing, not only findings
        - Fixtures/params: none
        - Scope: text rendering of one document

    On failure, first check:
        - Whether Document.path bypassed neutralisation in the documents listing
    """
    rendered = render(
        _result((), documents=(Document(path=_HOSTILE_PATH, bytes=10),)),
        config=Config(report_show_clean_documents=True),  # the text report hides clean documents by default
    )
    doc_line = next(line for line in rendered.splitlines() if "spoofed.md" in line)
    assert "\x1b" not in doc_line and "\r" not in doc_line
    assert "docs/evil\\x1b[31m\\x0d\\x0a::error::spoofed.md (10 bytes)" == doc_line.strip()


def test_text_sink_neutralises_c1_del_bidi_and_zero_width():
    """
    [Unit] reporting control characters: verifies C1, DEL, bidi and zero-width are neutralised.

    Scenario:
        Given a message holding a C1 control, DEL, a right-to-left override and a zero-width space
        When the result is rendered as text
        Then each is replaced by its visible backslash escape and none survives raw.

    Boundaries:
        - Focus: the extended neutralisation set beyond C0 (C1/DEL/bidi/zero-width)
        - Fixtures/params: none
        - Scope: text rendering of one finding's message

    On failure, first check:
        - Which of the C1/DEL/bidi/zero-width code points leaked raw into the output
    """
    message = "a\x85b\x7fc‮d​e"
    rendered = render(_result((Finding(rule="DS101", path="a.md", message=message, severity="warning", line=2),)))
    for raw in ("\x85", "\x7f", "‮", "​"):
        assert raw not in rendered
    assert "\\x85" in rendered and "\\x7f" in rendered and "\\u202e" in rendered and "\\u200b" in rendered


def test_github_sink_neutralises_escape_but_keeps_percent_encoding():
    """
    [Unit] reporting control characters: verifies the github sink neutralises ESC yet keeps %0D/%0A/%3A.

    Scenario:
        Given a hostile path with an ANSI escape, CR, LF, a colon and a comma
        When the result is rendered as github annotations
        Then the ESC is neutralised to a visible escape while CR/LF/`:`/`,` stay percent-encoded
        (``%0D``/``%0A``/``%3A``/``%2C``), so the pre-existing GitHub property escaping is preserved.

    Boundaries:
        - Focus: ESC neutralisation layered on top of the existing GitHub percent escaping
        - Fixtures/params: none
        - Scope: github rendering of one finding

    On failure, first check:
        - Whether a raw ESC leaked, or whether CR/LF/`:`/`,` stopped being percent-encoded
    """
    rendered = render(
        _result((Finding(rule="DS101", path=_HOSTILE_PATH, message="x", severity="error", line=3),)),
        "github",
    )
    assert "\x1b" not in rendered and "\r" not in rendered and "\n" not in rendered
    assert "\\x1b" in rendered
    assert "%0D%0A" in rendered  # CR/LF preserved as GitHub percent escapes
    assert "%3A%3Aerror%3A%3A" in rendered  # colons still property-escaped


def test_json_sink_already_escapes_controls_and_stays_ascii():
    """
    [Unit] reporting control characters: verifies the JSON sink escapes controls and is ASCII-safe.

    Scenario:
        Given a finding with an ANSI escape, CR, LF and a non-ASCII letter in path and message
        When the result is rendered as JSON
        Then json.dumps has escaped every control code point, emitted pure ASCII (ensure_ascii), and
        the parsed payload still round-trips to the exact original strings.

    Boundaries:
        - Focus: the JSON sink needs no extra neutralisation; it must remain lossless and ASCII
        - Fixtures/params: none
        - Scope: json rendering and round-trip of one finding

    On failure, first check:
        - Whether a raw control byte appears in the serialized JSON text
        - Whether ensure_ascii was disabled (non-ASCII bytes present) or the round-trip changed
    """
    message = "ünïcode\x1b\r\nbody"
    serialized = render(
        _result((Finding(rule="DS101", path=_HOSTILE_PATH, message=message, severity="error", line=4),)),
        "json",
    )
    assert "\x1b" not in serialized and "\r" not in serialized
    assert serialized.isascii()  # ensure_ascii default escaped the non-ASCII letter
    payload = json.loads(serialized)
    assert payload["documents"][0]["path"] == _HOSTILE_PATH  # lossless round-trip (raw preserved)
    assert payload["documents"][0]["problems"][0]["message"] == message


def test_ordinary_unicode_and_ascii_render_byte_identically():
    """
    [Unit] reporting control characters: verifies ordinary text is untouched by neutralisation.

    Scenario:
        Given findings whose path and message are ordinary ASCII or ordinary Unicode letters
        When text and github sinks render them
        Then the output is exactly what it was before neutralisation existed (no stray escapes),
        proving letters, digits and punctuation pass through unchanged.

    Boundaries:
        - Focus: the byte-identical-for-normal-input invariant
        - Fixtures/params: none
        - Scope: text and github rendering of benign findings

    On failure, first check:
        - Whether _neutralize_controls altered an ordinary letter or punctuation mark
    """
    assert _neutralize_controls("docs/guide_日本語.md") == "docs/guide_日本語.md"
    assert _neutralize_controls("Broken anchor -> #section", keep_crlf=True) == "Broken anchor -> #section"
    result = _result((Finding(rule="DS101", path="docs/intro.md", message="Dangling link", severity="error", line=7),))
    assert render(result, "github") == "::error file=docs/intro.md,line=7,title=DS101::Dangling link"
    assert "error: docs/intro.md: Dangling link" in render(result, "text")


def test_escape_helpers_preserve_percent_cr_lf_colon_comma():
    """
    [Unit] reporting control characters: verifies the github escape helpers keep their contract.

    Scenario:
        Given the property and data escapers fed percent, CR, LF, colon and comma plus an ESC
        When each helper runs
        Then percent/CR/LF (and colon/comma for properties) are percent-encoded as before and the
        ESC is additionally neutralised, with the percent-first ordering intact.

    Boundaries:
        - Focus: the helper-level contract that the 2026-10-10 review pinned, plus ESC neutralisation
        - Fixtures/params: none
        - Scope: _escape_property and _escape_data directly

    On failure, first check:
        - Whether the percent-first escaping order regressed or ESC stopped being neutralised
    """
    assert _escape_data("%\r\n") == "%25%0D%0A"
    assert _escape_data("%0A") == "%250A"
    assert _escape_property("%\r\n:,") == "%25%0D%0A%3A%2C"
    assert _escape_property("%2C%3A") == "%252C%253A"
    assert _escape_data("x\x1by") == "x\\x1by"
    assert _escape_property("x\x1by") == "x\\x1by"


def test_fingerprint_is_independent_of_rendered_neutralisation():
    """
    [Unit] reporting control characters: verifies baseline fingerprints ignore the escaped rendering.

    Scenario:
        Given a finding whose path and message carry control characters
        When its baseline fingerprint is computed and its text rendering produced
        Then the fingerprint hashes the raw Finding fields (not the escaped text), so it matches a
        direct hash of the raw strings and is unchanged by the reporter's neutralisation.

    Boundaries:
        - Focus: the fix is a rendering-only concern and must not shift baseline fingerprints
        - Fixtures/params: none
        - Scope: baseline.fingerprint versus reporting.render on one finding

    On failure, first check:
        - Whether fingerprint() started hashing rendered output instead of raw Finding fields
    """
    finding = Finding(rule="DS101", path=_HOSTILE_PATH, message="msg\x1b\r\nend", severity="error", line=5)

    expected_hash = hashlib.sha256(finding.message.encode("utf-8")).hexdigest()[:12]
    assert fingerprint(finding) == f"DS101:{_HOSTILE_PATH}:{expected_hash}"
    rendered = render(_result((finding,)))
    assert "\\x1b" in rendered  # rendering escaped it, fingerprint did not


def test_line_paragraph_separators_and_lone_surrogates_are_neutralised():
    """
    [Unit] reporting control characters: verifies U+2028/U+2029 and lone surrogates are escaped.

    Scenario:
        Given a string holding LINE SEPARATOR, PARAGRAPH SEPARATOR and a lone surrogate (as produced by
            surrogateescape for an undecodable POSIX file name)
        When it is neutralised for the text and GitHub sinks and rendered end to end
        Then none of those code points survive, the result is encodable as UTF-8, and ordinary letters
            around them are untouched.

    Boundaries:
        - Focus: security-review MEDIUM findings for Story 15.0 shared components
        - Fixtures/params: none

    On failure, first check:
        - Whether _build_control_table still includes 0x2028, 0x2029 and the 0xD800-0xDFFF range
    """
    hostile = "a b c" + chr(0xDC80) + "d"
    for text in (_neutralize_controls(hostile), _neutralize_controls(hostile, keep_crlf=True), neutralize_text(hostile)):
        assert " " not in text and " " not in text and chr(0xDC80) not in text
        text.encode("utf-8")
        assert text.startswith("a") and text.endswith("d")

    path = "docs/x" + chr(0xDC80) + ".md"
    result = _result(
        (Finding(rule="DS101", path=path, message="bad\u2028link", severity="error", line=3),),
        documents=(Document(path=path, bytes=1),),
    )
    for output_format in ("text", "github", "json"):
        render(result, output_format).encode("utf-8")
