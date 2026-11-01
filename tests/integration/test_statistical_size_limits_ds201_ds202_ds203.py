"""End-to-end tests that the statistical size-limit keys change DS201/DS202/DS203 output.

Driven through ``scan(...)`` with an explicit ``Config(profile="standard", ...)`` and
through the CLI with a standalone ``docsentinel.toml``. Tiny inline documents written
to ``tmp_path``; no committed assets are used.
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("sklearn")
pytest.importorskip("textstat")
pytest.importorskip("docsig")

from docsentinel.cli import main
from docsentinel.config import Config
from docsentinel.engine import scan

# Two identical four-word paragraphs: below the default 5-word floor, so excluded by
# default; identical once admitted, so a DS202 near-duplicate when the floor is lowered.
_DUPLICATE_DOC = (
    "# Title\n\nantidisestablishmentarianism quux corge grault\n\nantidisestablishmentarianism quux corge grault\n"
)


def _rule_codes(findings) -> set[str]:
    """Return the set of rule codes present in a findings collection.

    :param findings: An iterable of findings.
    :returns: The distinct rule codes.
    """
    return {finding.rule for finding in findings}


def test_scan_paragraph_word_floor_changes_ds202(tmp_path: Path):
    """
    [Integration] standard scan: lowering min_paragraph_words admits a DS202 duplicate.

    Scenario:
        Given two identical short paragraphs below the default word floor
        When scan runs at the default and at a lowered min_paragraph_words
        Then DS202 is absent by default and present once lowered.

    Boundaries:
        - Focus: the paragraph word floor through the full engine
        - Fixtures/params: tmp_path
        - Scope: assertions in this test only

    On failure, first check:
        - duplication.detect passing config.min_paragraph_words
        - The build_corpus_model cache key
    """
    (tmp_path / "dup.md").write_text(_DUPLICATE_DOC, encoding="utf-8")

    default = scan(tmp_path, config=Config(profile="standard"))
    lowered = scan(tmp_path, config=Config(profile="standard", min_paragraph_words=4))

    assert "DS202" not in _rule_codes(default.findings)
    assert "DS202" in _rule_codes(lowered.findings)


def test_scan_repeats_in_one_process_without_stale_cache(tmp_path: Path):
    """
    [Integration] standard scan: repeated scans with different floors do not leak a stale corpus.

    Scenario:
        Given the same document scanned twice in one process
        When the two scans use different paragraph word floors
        Then their DS202 outcomes differ.

    Boundaries:
        - Focus: no stale lru_cache leak across differing settings
        - Fixtures/params: tmp_path
        - Scope: assertions in this test only

    On failure, first check:
        - clear_standard_caches at scan start and the floor-keyed cache
    """
    (tmp_path / "dup.md").write_text(_DUPLICATE_DOC, encoding="utf-8")

    first = scan(tmp_path, config=Config(profile="standard", min_paragraph_words=4))
    second = scan(tmp_path, config=Config(profile="standard"))

    assert "DS202" in _rule_codes(first.findings)
    assert "DS202" not in _rule_codes(second.findings)


def test_cli_doc_sentinel_toml_applies_paragraph_floor(tmp_path: Path, capsys):
    """
    [Integration] CLI: a docsentinel.toml paragraph floor reaches the standard scan.

    Scenario:
        Given a docsentinel.toml lowering min_paragraph_words under the standard profile
        When the scan CLI runs with JSON output
        Then a DS202 finding appears in the structured report.

    Boundaries:
        - Focus: config file -> engine wiring through the CLI
        - Fixtures/params: tmp_path, capsys
        - Scope: assertions in this test only

    On failure, first check:
        - load_config reading the key from the standalone file
        - That DS202 warnings keep the exit code at 0
    """
    (tmp_path / "dup.md").write_text(_DUPLICATE_DOC, encoding="utf-8")
    (tmp_path / "docsentinel.toml").write_text(
        'profile = "standard"\nmin_paragraph_words = 4\n',
        encoding="utf-8",
    )

    exit_code = main(["scan", str(tmp_path), "--format", "json-v1"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert any(finding["rule"] == "DS202" for finding in payload["findings"])
