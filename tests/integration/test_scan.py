import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Optional, Union

import pytest

from docsentinel import Config, ConfigError, cli, load_config, scan
from docsentinel.cli import _exit_code, main
from docsentinel.detectors.loader import ensure_standard_loaded
from docsentinel.engine import ANALYZERS
from docsentinel.errors import ExtraNotInstalledError
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.reporting import render
from docsentinel.rules import RULES, Rule, register_rule


@pytest.fixture
def fake_fast_analyzer() -> Iterator[list[tuple[Path, tuple[Document, ...]]]]:
    """Fixture providing a registered test analyzer for the fast profile."""
    calls: list[tuple[Path, tuple[Document, ...]]] = []
    rule = register_rule(Rule("DS199", "fast", "Fake fast rule", "Exercises selection."))

    def analyzer(root: Path, documents: tuple[Document, ...]) -> tuple[Finding, ...]:
        """Record invocation arguments and return empty findings."""
        calls.append((root, documents))
        return ()

    ANALYZERS[rule.code] = analyzer
    try:
        yield calls
    finally:
        RULES.pop(rule.code, None)
        ANALYZERS.pop(rule.code, None)


@pytest.fixture
def captured_cli_configs(monkeypatch: pytest.MonkeyPatch) -> list[Config]:
    """Fixture capturing Config instances passed to docsentinel.scan via CLI."""
    configs: list[Config] = []

    def fake_scan(root: str, *, config: Config) -> ScanResult:
        """Capture configuration argument and return stub ScanResult."""
        configs.append(config)
        return ScanResult(
            profile=config.profile,
            documents=(),
            findings=(),
            enabled_rules=(),
            pending=(),
        )

    monkeypatch.setattr(cli, "scan", fake_scan)
    return configs


def test_empty_scan_is_inventory_not_detection(tmp_path: Path):
    """
    [Integration] scan: verifies empty scan is inventory not detection.

    Scenario:
        Given test inputs and fixtures for empty scan is inventory not detection
        When test_empty_scan_is_inventory_not_detection executes the target flow
        Then the expected outcome for empty scan is inventory not detection is confirmed.

    Boundaries:
        - Focus: empty scan is inventory not detection
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to empty scan is inventory not detection
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = scan(tmp_path, config=Config(profile="deep"))
    assert result.documents == ()
    assert result.findings == ()
    assert result.enabled_rules == ()
    assert "explicit opt-in" in result.notice
    assert json.loads(render(result, "json-v1"))["enabled_rules"] == []


def test_scan_runs_analyzer_for_active_profile(
    tmp_path: Path,
    fake_fast_analyzer: list[tuple[Path, tuple[Document, ...]]],
):
    """
    [Integration] scan: verifies scan runs analyzer for active profile.

    Scenario:
        Given test inputs and fixtures for scan runs analyzer for active profile
        When test_scan_runs_analyzer_for_active_profile executes the target flow
        Then the expected outcome for scan runs analyzer for active profile is confirmed.

    Boundaries:
        - Focus: scan runs analyzer for active profile
        - Fixtures/params: tmp_path, fake_fast_analyzer
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan runs analyzer for active profile
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    scan(tmp_path, config=Config(profile="fast"))
    assert len(fake_fast_analyzer) == 1

    fake_fast_analyzer.clear()
    scan(tmp_path, config=Config(profile="standard"))
    assert fake_fast_analyzer == []


def test_standard_scan_passes_resolved_config_to_analyzers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies standard scan passes resolved config to analyzers.

    Scenario:
        Given test inputs and fixtures for standard scan passes resolved config to analyzers
        When test_standard_scan_passes_resolved_config_to_analyzers executes the target flow
        Then the expected outcome for standard scan passes resolved config to analyzers is confirmed.

    Boundaries:
        - Focus: standard scan passes resolved config to analyzers
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan passes resolved config to analyzers
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    ensure_standard_loaded()
    received: list[Config] = []

    def analyzer(root: Path, documents: tuple[Document, ...], config: Config) -> tuple[Finding, ...]:
        """Record the configuration each standard analyzer receives."""
        received.append(config)
        return ()

    for code in ("DS201", "DS202", "DS203", "DS204"):
        monkeypatch.setitem(ANALYZERS, code, analyzer)

    settings = Config(profile="standard", max_grade_level=9.0, duplicate_similarity=0.7)
    scan(tmp_path, config=settings)

    assert received == [settings] * 4


def test_scan_respects_select(
    tmp_path: Path,
    fake_fast_analyzer: list[tuple[Path, tuple[Document, ...]]],
):
    """
    [Integration] scan: verifies scan respects select.

    Scenario:
        Given test inputs and fixtures for scan respects select
        When test_scan_respects_select executes the target flow
        Then the expected outcome for scan respects select is confirmed.

    Boundaries:
        - Focus: scan respects select
        - Fixtures/params: tmp_path, fake_fast_analyzer
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan respects select
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    scan(tmp_path, config=Config(select=("DS1",)))
    assert len(fake_fast_analyzer) == 1

    fake_fast_analyzer.clear()
    scan(tmp_path, config=Config(select=("DS9",)))
    assert fake_fast_analyzer == []


def test_scan_respects_ignore_over_select(
    tmp_path: Path,
    fake_fast_analyzer: list[tuple[Path, tuple[Document, ...]]],
):
    """
    [Integration] scan: verifies scan respects ignore over select.

    Scenario:
        Given test inputs and fixtures for scan respects ignore over select
        When test_scan_respects_ignore_over_select executes the target flow
        Then the expected outcome for scan respects ignore over select is confirmed.

    Boundaries:
        - Focus: scan respects ignore over select
        - Fixtures/params: tmp_path, fake_fast_analyzer
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan respects ignore over select
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    scan(tmp_path, config=Config(select=("DS1",), ignore=("DS1",)))
    assert fake_fast_analyzer == []


def test_scan_notice_reflects_rules_evaluated(
    tmp_path: Path,
    fake_fast_analyzer: list[tuple[Path, tuple[Document, ...]]],
):
    """
    [Integration] scan: verifies scan notice reflects rules evaluated.

    Scenario:
        Given test inputs and fixtures for scan notice reflects rules evaluated
        When test_scan_notice_reflects_rules_evaluated executes the target flow
        Then the expected outcome for scan notice reflects rules evaluated is confirmed.

    Boundaries:
        - Focus: scan notice reflects rules evaluated
        - Fixtures/params: tmp_path, fake_fast_analyzer
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan notice reflects rules evaluated
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = scan(tmp_path, config=Config(profile="fast", select=("DS199",)))

    assert len(fake_fast_analyzer) == 1
    assert "evaluated" in result.notice
    assert "not implemented" not in result.notice
    assert result.enabled_rules == ("DS199",)


def test_scan_notice_distinguishes_unimplemented_profile_from_filtered_out(
    tmp_path: Path,
    fake_fast_analyzer: list[tuple[Path, tuple[Document, ...]]],
):
    """
    [Integration] scan: verifies scan notice distinguishes unimplemented profile from filtered out.

    Scenario:
        Given test inputs and fixtures for scan notice distinguishes unimplemented profile from filtered out
        When test_scan_notice_distinguishes_unimplemented_profile_from_filtered_out executes the target flow
        Then the expected outcome for scan notice distinguishes unimplemented profile from filtered out is confirmed.

    Boundaries:
        - Focus: scan notice distinguishes unimplemented profile from filtered out
        - Fixtures/params: tmp_path, fake_fast_analyzer
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan notice distinguishes unimplemented profile from filtered out
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    unimplemented = scan(tmp_path, config=Config(profile="deep"))
    filtered = scan(tmp_path, config=Config(profile="fast", ignore=("DS1",)))

    assert fake_fast_analyzer == []
    assert "deep profile requires explicit opt-in" in unimplemented.pending[0]
    assert filtered.pending == ("all fast rules were excluded by select/ignore",)
    assert "not implemented" not in filtered.notice
    assert "evaluated" not in filtered.notice


def test_discovery_is_sorted_filtered_and_does_not_follow_symlinks(tmp_path: Path):
    """
    [Integration] scan: verifies discovery is sorted filtered and does not follow symlinks.

    Scenario:
        Given test inputs and fixtures for discovery is sorted filtered and does not follow symlinks
        When test_discovery_is_sorted_filtered_and_does_not_follow_symlinks executes the target flow
        Then the expected outcome for discovery is sorted filtered and does not follow symlinks is confirmed.

    Boundaries:
        - Focus: discovery is sorted filtered and does not follow symlinks
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to discovery is sorted filtered and does not follow symlinks
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "b.md").write_text("abc", encoding="utf-8")
    (tmp_path / "a.md").write_text("x", encoding="utf-8")
    (tmp_path / "docs" / "ignore.txt").write_text("not docs", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hidden.md").write_text("hidden", encoding="utf-8")
    (tmp_path / "alias.md").symlink_to(tmp_path / "a.md")
    result = scan(tmp_path)
    assert [(doc.path, doc.bytes) for doc in result.documents] == [
        ("a.md", 1),
        ("docs/b.md", 3),
    ]


def test_discovery_prunes_excluded_directories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies discovery prunes excluded directories.

    Scenario:
        Given test inputs and fixtures for discovery prunes excluded directories
        When test_discovery_prunes_excluded_directories executes the target flow
        Then the expected outcome for discovery prunes excluded directories is confirmed.

    Boundaries:
        - Focus: discovery prunes excluded directories
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to discovery prunes excluded directories
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    excluded = tmp_path / ".git"
    excluded.mkdir()
    (excluded / "hidden.md").write_text("hidden", encoding="utf-8")
    original_scandir = os.scandir

    def scandir(path: Union[str, bytes, Path]) -> Iterator[os.DirEntry[Any]]:
        """Intercept os.scandir calls to verify directory traversal pruning."""
        if Path(path) == excluded:
            raise AssertionError("excluded directory was traversed")
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    assert scan(tmp_path).documents == ()


def test_discovery_propagates_directory_listing_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies discovery propagates directory listing errors.

    Scenario:
        Given test inputs and fixtures for discovery propagates directory listing errors
        When test_discovery_propagates_directory_listing_errors executes the target flow
        Then the expected outcome for discovery propagates directory listing errors is confirmed.

    Boundaries:
        - Focus: discovery propagates directory listing errors
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to discovery propagates directory listing errors
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    original_scandir = os.scandir

    def scandir(path: Union[str, bytes, Path]) -> Iterator[os.DirEntry[Any]]:
        """Intercept os.scandir calls to simulate permission error."""
        if Path(path) == unreadable:
            raise PermissionError("cannot list directory")
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    with pytest.raises(PermissionError, match="cannot list directory"):
        scan(tmp_path)


def test_config_and_pending_profile(tmp_path: Path):
    """
    [Integration] scan: verifies config and pending profile.

    Scenario:
        Given test inputs and fixtures for config and pending profile
        When test_config_and_pending_profile executes the target flow
        Then the expected outcome for config and pending profile is confirmed.

    Boundaries:
        - Focus: config and pending profile
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to config and pending profile
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "a.md").write_text("x", encoding="utf-8")
    (tmp_path / "b.markdown").write_text("y", encoding="utf-8")
    (tmp_path / "docsentinel.toml").write_text(
        'profile = "deep"\ninclude = ["*.markdown"]\n',
        encoding="utf-8",
    )
    result = scan(tmp_path)
    assert [doc.path for doc in result.documents] == ["b.markdown"]
    assert "deep profile requires explicit opt-in" in result.pending[0]
    assert result.enabled_rules == ()


@pytest.mark.parametrize(
    "contents",
    [
        'profile = "wrong"\n',
        'include = "not a list"\n',
        "unknown = 1\n",
        "bad toml ===",
    ],
)
def test_bad_config_fails_clearly(tmp_path: Path, contents: str):
    """
    [Integration] scan: verifies bad config fails clearly.

    Scenario:
        Given test inputs and fixtures for bad config fails clearly
        When test_bad_config_fails_clearly executes the target flow
        Then the expected outcome for bad config fails clearly is confirmed.

    Boundaries:
        - Focus: bad config fails clearly
        - Fixtures/params: tmp_path, contents (parametrized, 4 cases)
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to bad config fails clearly
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "docsentinel.toml").write_text(contents, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_invalid_utf8_config_raises_config_error(tmp_path: Path):
    """
    [Integration] scan: verifies invalid utf8 config raises config error.

    Scenario:
        Given test inputs and fixtures for invalid utf8 config raises config error
        When test_invalid_utf8_config_raises_config_error executes the target flow
        Then the expected outcome for invalid utf8 config raises config error is confirmed.

    Boundaries:
        - Focus: invalid utf8 config raises config error
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to invalid utf8 config raises config error
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "docsentinel.toml").write_bytes(b"\xff")
    with pytest.raises(ConfigError):
        load_config(tmp_path)
    with pytest.raises(ConfigError):
        scan(tmp_path)


def test_init_creates_doc_sentinel_toml(tmp_path: Path):
    """
    [Integration] scan: verifies init creates doc sentinel toml.

    Scenario:
        Given test inputs and fixtures for init creates doc sentinel toml
        When test_init_creates_doc_sentinel_toml executes the target flow
        Then the expected outcome for init creates doc sentinel toml is confirmed.

    Boundaries:
        - Focus: init creates doc sentinel toml
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to init creates doc sentinel toml
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    assert main(["init", str(tmp_path)]) == 0

    target = tmp_path / "docsentinel.toml"
    assert target.is_file()
    initial_content = target.read_text(encoding="utf-8")
    assert load_config(tmp_path) == Config()

    assert main(["init", str(tmp_path)]) == 2
    assert target.read_text(encoding="utf-8") == initial_content


def test_init_refuses_when_legacy_doc_sentinel_toml_exists(tmp_path: Path):
    """
    [Integration] scan: verifies init does not create a second config next to doc_sentinel.toml.

    Scenario:
        Given a directory that already holds the doc_sentinel.toml alias
        When the init command runs there
        Then it exits 2 and creates no docsentinel.toml, avoiding an ambiguous pair.

    Boundaries:
        - Focus: init versus the legacy config alias
        - Fixtures/params: tmp_path
        - Scope: CLI init only

    On failure, first check:
        - The legacy-file guard in _run_init
    """
    (tmp_path / "doc_sentinel.toml").write_text("", encoding="utf-8")

    assert main(["init", str(tmp_path)]) == 2
    assert not (tmp_path / "docsentinel.toml").exists()


def test_init_defaults_to_current_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies init defaulting to the current directory.

    Scenario:
        Given a temporary directory layout for init defaulting to the current directory
        When test_init_defaults_to_current_directory runs the init command
        Then the expected outcome for init defaulting to the current directory is confirmed.

    Boundaries:
        - Focus: init defaulting to the current directory
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Location resolution in cli.find_project_root and cli._run_init
        - Fixture or parameter values used by this test
    """
    monkeypatch.chdir(tmp_path)

    assert main(["init"]) == 0

    assert (tmp_path / "docsentinel.toml").is_file()


def test_init_project_root_walks_up_to_marker(tmp_path: Path):
    """
    [Integration] scan: verifies init --project-root choosing the ancestor with pyproject.toml.

    Scenario:
        Given a temporary directory layout for init --project-root choosing the ancestor with pyproject.toml
        When test_init_project_root_walks_up_to_marker runs the init command
        Then the expected outcome for init --project-root choosing the ancestor with pyproject.toml is confirmed.

    Boundaries:
        - Focus: init --project-root choosing the ancestor with pyproject.toml
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Location resolution in cli.find_project_root and cli._run_init
        - Fixture or parameter values used by this test
    """
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    nested = tmp_path / "docs" / "deep"
    nested.mkdir(parents=True)

    assert main(["init", str(nested), "--project-root"]) == 0

    assert (tmp_path / "docsentinel.toml").is_file()
    assert not (nested / "docsentinel.toml").exists()


def test_init_project_root_accepts_uv_lock_marker(tmp_path: Path):
    """
    [Integration] scan: verifies init --project-root recognising uv.lock.

    Scenario:
        Given a temporary directory layout for init --project-root recognising uv.lock
        When test_init_project_root_accepts_uv_lock_marker runs the init command
        Then the expected outcome for init --project-root recognising uv.lock is confirmed.

    Boundaries:
        - Focus: init --project-root recognising uv.lock
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Location resolution in cli.find_project_root and cli._run_init
        - Fixture or parameter values used by this test
    """
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()

    assert main(["init", str(nested), "--project-root"]) == 0

    assert (tmp_path / "docsentinel.toml").is_file()


def test_init_project_root_without_marker_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies init --project-root failing when no marker exists.

    Scenario:
        Given a temporary directory layout for init --project-root failing when no marker exists
        When test_init_project_root_without_marker_fails runs the init command
        Then the expected outcome for init --project-root failing when no marker exists is confirmed.

    Boundaries:
        - Focus: init --project-root failing when no marker exists
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Location resolution in cli.find_project_root and cli._run_init
        - Fixture or parameter values used by this test
    """
    monkeypatch.setattr(cli, "find_project_root", lambda start: None)

    assert main(["init", str(tmp_path), "--project-root"]) == 2

    assert not (tmp_path / "docsentinel.toml").exists()


def test_init_declined_confirmation_creates_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies init respecting a declined confirmation.

    Scenario:
        Given a temporary directory layout for init respecting a declined confirmation
        When test_init_declined_confirmation_creates_nothing runs the init command
        Then the expected outcome for init respecting a declined confirmation is confirmed.

    Boundaries:
        - Focus: init respecting a declined confirmation
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Location resolution in cli.find_project_root and cli._run_init
        - Fixture or parameter values used by this test
    """
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")

    assert main(["init", str(tmp_path)]) == 0

    assert not (tmp_path / "docsentinel.toml").exists()


def test_init_yes_skips_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies init --yes never prompting.

    Scenario:
        Given a temporary directory layout for init --yes never prompting
        When test_init_yes_skips_confirmation runs the init command
        Then the expected outcome for init --yes never prompting is confirmed.

    Boundaries:
        - Focus: init --yes never prompting
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Location resolution in cli.find_project_root and cli._run_init
        - Fixture or parameter values used by this test
    """
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)

    def fail_prompt(prompt: str = "") -> str:
        """Fail the test if the init command prompts despite ``--yes``.

        Parameters
        ----------
        prompt : str
            Prompt text passed to ``input``.

        Returns
        -------
        str
            Never returns; always raises.
        """
        raise AssertionError("must not prompt with --yes")

    monkeypatch.setattr("builtins.input", fail_prompt)

    assert main(["init", str(tmp_path), "--yes"]) == 0

    assert (tmp_path / "docsentinel.toml").is_file()


def test_cli_select_flag_parses_comma_separated(
    tmp_path: Path,
    captured_cli_configs: list[Config],
):
    """
    [Integration] scan: verifies cli select flag parses comma separated.

    Scenario:
        Given test inputs and fixtures for cli select flag parses comma separated
        When test_cli_select_flag_parses_comma_separated executes the target flow
        Then the expected outcome for cli select flag parses comma separated is confirmed.

    Boundaries:
        - Focus: cli select flag parses comma separated
        - Fixtures/params: tmp_path, captured_cli_configs
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli select flag parses comma separated
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    assert main(["scan", str(tmp_path), "--select", "DS1, DS2"]) == 0

    assert captured_cli_configs == [Config(select=("DS1", "DS2"))]


def test_cli_ignore_flag_works_without_config(
    tmp_path: Path,
    captured_cli_configs: list[Config],
):
    """
    [Integration] scan: verifies cli ignore flag works without config.

    Scenario:
        Given test inputs and fixtures for cli ignore flag works without config
        When test_cli_ignore_flag_works_without_config executes the target flow
        Then the expected outcome for cli ignore flag works without config is confirmed.

    Boundaries:
        - Focus: cli ignore flag works without config
        - Fixtures/params: tmp_path, captured_cli_configs
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli ignore flag works without config
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    assert main(["scan", str(tmp_path), "--ignore", "DS3"]) == 0

    assert captured_cli_configs == [Config(ignore=("DS3",))]


def test_cli_ignore_flag_overrides_config_file(
    tmp_path: Path,
    captured_cli_configs: list[Config],
):
    """
    [Integration] scan: verifies cli ignore flag overrides config file.

    Scenario:
        Given test inputs and fixtures for cli ignore flag overrides config file
        When test_cli_ignore_flag_overrides_config_file executes the target flow
        Then the expected outcome for cli ignore flag overrides config file is confirmed.

    Boundaries:
        - Focus: cli ignore flag overrides config file
        - Fixtures/params: tmp_path, captured_cli_configs
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli ignore flag overrides config file
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "docsentinel.toml").write_text('ignore = ["DS101"]\n', encoding="utf-8")

    assert main(["scan", str(tmp_path), "--ignore", "DS2"]) == 0

    assert captured_cli_configs == [Config(ignore=("DS2",))]


@pytest.mark.parametrize(
    ("arguments", "expected_profile", "expected_select", "expected_ignore", "expected_baseline"),
    [
        (("--profile", "standard"), "standard", ("DS10",), ("DS90",), None),
        (("--select", "DS2, DS3"), "deep", ("DS2", "DS3"), ("DS90",), None),
        (("--ignore", "DS201"), "deep", ("DS10",), ("DS201",), None),
        (("--baseline", "custom-baseline.json"), "deep", ("DS10",), ("DS90",), "custom-baseline.json"),
    ],
    ids=("profile", "select", "ignore", "baseline"),
)
def test_cli_explicit_override_preserves_other_loaded_settings(
    tmp_path: Path,
    captured_cli_configs: list[Config],
    arguments: tuple[str, ...],
    expected_profile: str,
    expected_select: tuple[str, ...],
    expected_ignore: tuple[str, ...],
    expected_baseline: Optional[str],
):
    """
    [Integration] scan: verifies cli explicit override preserves other loaded settings.

    Scenario:
        Given test inputs and fixtures for cli explicit override preserves other loaded settings
        When test_cli_explicit_override_preserves_other_loaded_settings executes the target flow
        Then the expected outcome for cli explicit override preserves other loaded settings is confirmed.

    Boundaries:
        - Focus: cli explicit override preserves other loaded settings
        - Fixtures/params: tmp_path, captured_cli_configs, arguments, expected_profile, expected_select, expected_ignore, expected_baseline (parametrized, 4 cases)
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli explicit override preserves other loaded settings
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "docsentinel.toml").write_text(
        'profile = "deep"\n'
        'include = ["*.markdown"]\n'
        'exclude = ["build"]\n'
        'select = ["DS10"]\n'
        'ignore = ["DS90"]\n'
        "max_grade_level = 11.5\n"
        "duplicate_similarity = 0.75\n"
        "min_information_score = 0.25\n"
        'docsig_paths = ["lib"]\n',
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), *arguments]) == 0

    assert captured_cli_configs == [
        Config(
            include=("*.markdown",),
            exclude=("build",),
            profile=expected_profile,
            select=expected_select,
            ignore=expected_ignore,
            baseline=expected_baseline,
            max_grade_level=11.5,
            duplicate_similarity=0.75,
            min_information_score=0.25,
            docsig_paths=("lib",),
        )
    ]


def test_rules_command_lists_real_registry(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] scan: verifies rules command lists real registry.

    Scenario:
        Given test inputs and fixtures for rules command lists real registry
        When test_rules_command_lists_real_registry executes the target flow
        Then the expected outcome for rules command lists real registry is confirmed.

    Boundaries:
        - Focus: rules command lists real registry
        - Fixtures/params: capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to rules command lists real registry
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    expected_codes = (
        "DS101",
        "DS102",
        "DS103",
        "DS104",
        "DS105",
        "DS106",
        "DS108",
        "DS109",
        "DS110",
        "DS112",
        "DS113",
        "DS114",
        "DS115",
        "DS116",
        "DS117",
        "DS118",
    )
    assert main(["rules"]) == 0

    output = capsys.readouterr().out
    profiles = ("fast", "standard", "deep")
    positions = tuple(output.index(profile) for profile in profiles)
    assert positions == tuple(sorted(positions))
    for index, start in enumerate(positions):
        end = positions[index + 1] if index + 1 < len(positions) else len(output)
        profile_output = output[start:end]
        if profiles[index] == "fast":
            assert all(code in profile_output for code in expected_codes)
            assert "(none registered)" not in profile_output
        elif profiles[index] == "standard":
            assert "DS201" in profile_output
            assert "DS202" in profile_output
            assert "DS203" in profile_output
            assert "DS204" in profile_output
            assert "(none registered)" not in profile_output
        else:
            assert "DS301" in profile_output
            assert "(none registered)" not in profile_output
    assert tuple(sorted(RULES)) == (*expected_codes, "DS201", "DS202", "DS203", "DS204", "DS301")


def test_doctor_command_reports_counts(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] scan: verifies doctor command reports counts.

    Scenario:
        Given test inputs and fixtures for doctor command reports counts
        When test_doctor_command_reports_counts executes the target flow
        Then the expected outcome for doctor command reports counts is confirmed.

    Boundaries:
        - Focus: doctor command reports counts
        - Fixtures/params: capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to doctor command reports counts
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    expected_codes = (
        "DS101",
        "DS102",
        "DS103",
        "DS104",
        "DS105",
        "DS106",
        "DS108",
        "DS109",
        "DS110",
        "DS112",
        "DS113",
        "DS114",
        "DS115",
        "DS116",
        "DS117",
        "DS118",
        "DS201",
        "DS202",
        "DS203",
        "DS204",
        "DS301",
    )
    assert main(["doctor"]) == 0

    output = capsys.readouterr().out
    assert "Inventory: available" in output
    assert "standard profile: available" in output
    assert "deep profile:" in output
    assert "fast rules: 16 registered (4 opt-in, off unless configured: DS110, DS112, DS115, DS118)" in output
    assert "standard rules: 4 registered" in output
    assert "deep rules: 1 registered" in output
    assert tuple(sorted(RULES)) == expected_codes


def test_rules_and_doctor_mark_an_opt_in_standard_rule(capsys: pytest.CaptureFixture[str]):
    """
    [Integration] scan: verifies the opt-in markers extend to the standard profile listing.

    Scenario:
        Given a throwaway opt-in standard rule registered for the duration of the test
        When `docsentinel rules` and `docsentinel doctor` run
        Then the standard rules listing tags it `[opt-in: set navigation_indexes]` and the doctor
        standard-profile count reports it among the opt-in rules off unless configured, proving the
        opt-in markers are not fast-profile-specific.

    Boundaries:
        - Focus: parity of the opt-in suffix and doctor count wording across the standard listing
        - Fixtures/params: capsys; a throwaway rule removed in a finally block

    On failure, first check:
        - That _standard_rule_lines applies _opt_in_suffix
        - That the doctor loop counts opt-in rules for every profile, not only fast
    """
    try:
        ensure_standard_loaded()
    except ExtraNotInstalledError:
        pytest.skip("standard extra not installed; the standard listing cannot be exercised")

    register_rule(Rule("DS299", "standard", "Throwaway opt-in", "Test rule.", opt_in_option="navigation_indexes"))
    try:
        assert main(["rules"]) == 0
        rules_output = capsys.readouterr().out
        assert "DS299: Throwaway opt-in [opt-in: set navigation_indexes]" in rules_output

        assert main(["doctor"]) == 0
        doctor_output = capsys.readouterr().out
        assert "standard rules: 5 registered (1 opt-in, off unless configured: DS299)" in doctor_output
    finally:
        del RULES["DS299"]


def test_cli_scan_returns_one_and_renders_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] scan: verifies cli scan returns one and renders findings.

    Scenario:
        Given test inputs and fixtures for cli scan returns one and renders findings
        When test_cli_scan_returns_one_and_renders_findings executes the target flow
        Then the expected outcome for cli scan returns one and renders findings is confirmed.

    Boundaries:
        - Focus: cli scan returns one and renders findings
        - Fixtures/params: tmp_path, monkeypatch, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli scan returns one and renders findings
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """

    def fake_scan(root: str, *, config: Config) -> ScanResult:
        """Return stub scan result with one error finding."""
        return ScanResult(
            profile=config.profile,
            documents=(),
            findings=(Finding(rule="DS101", path="README.md", message="Broken link", severity="error"),),
            enabled_rules=("DS101",),
            pending=(),
            notice="1 rule evaluated.",
        )

    monkeypatch.setattr(cli, "scan", fake_scan)

    assert main(["scan", str(tmp_path)]) == 1
    assert "  error: README.md: Broken link" in capsys.readouterr().out.splitlines()


def test_invalid_root(tmp_path: Path):
    """
    [Integration] scan: verifies invalid root.

    Scenario:
        Given test inputs and fixtures for invalid root
        When test_invalid_root executes the target flow
        Then the expected outcome for invalid root is confirmed.

    Boundaries:
        - Focus: invalid root
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to invalid root
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    assert main(["scan", str(tmp_path / "missing")]) == 2


def test_public_config_can_select_only_nested_files(tmp_path: Path):
    """
    [Integration] scan: verifies public config can select only nested files.

    Scenario:
        Given test inputs and fixtures for public config can select only nested files
        When test_public_config_can_select_only_nested_files executes the target flow
        Then the expected outcome for public config can select only nested files is confirmed.

    Boundaries:
        - Focus: public config can select only nested files
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to public config can select only nested files
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("guide", encoding="utf-8")
    (tmp_path / "README.md").write_text("readme", encoding="utf-8")
    assert [doc.path for doc in scan(tmp_path, config=Config(include=("docs/*.md",))).documents] == ["docs/guide.md"]


def test_scan_accepts_a_single_selected_file(tmp_path: Path):
    """
    [Integration] scan: verifies scan accepts a single selected file.

    Scenario:
        Given test inputs and fixtures for scan accepts a single selected file
        When test_scan_accepts_a_single_selected_file executes the target flow
        Then the expected outcome for scan accepts a single selected file is confirmed.

    Boundaries:
        - Focus: scan accepts a single selected file
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan accepts a single selected file
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "a.md").write_text("a", encoding="utf-8")
    (tmp_path / "b.md").write_text("bb", encoding="utf-8")
    result = scan(tmp_path / "b.md")
    assert [(item.path, item.bytes) for item in result.documents] == [("b.md", 2)]


def test_cli_scan_selected_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """
    [Integration] scan: verifies cli scan selected file.

    Scenario:
        Given test inputs and fixtures for cli scan selected file
        When test_cli_scan_selected_file executes the target flow
        Then the expected outcome for cli scan selected file is confirmed.

    Boundaries:
        - Focus: cli scan selected file
        - Fixtures/params: tmp_path, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli scan selected file
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "a.md").write_text("a", encoding="utf-8")
    assert main(["scan", str(tmp_path / "a.md"), "--format", "json-v1"]) == 0
    assert json.loads(capsys.readouterr().out)["documents"][0]["path"] == "a.md"


def test_exit_code_zero_for_warnings_only_by_default():
    """
    [Integration] scan: verifies exit code zero for warnings only by default.

    Scenario:
        Given test inputs and fixtures for exit code zero for warnings only by default
        When test_exit_code_zero_for_warnings_only_by_default executes the target flow
        Then the expected outcome for exit code zero for warnings only by default is confirmed.

    Boundaries:
        - Focus: exit code zero for warnings only by default
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to exit code zero for warnings only by default
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(
            Finding(rule="DS102", path="README.md", message="Stray comment", severity="warning"),
            Finding(rule="DS103", path="docs.md", message="Unresolvable path", severity="warning"),
        ),
        enabled_rules=("DS102", "DS103"),
        pending=(),
    )
    assert _exit_code(result, strict=False) == 0


def test_exit_code_one_for_any_error_by_default():
    """
    [Integration] scan: verifies exit code one for any error by default.

    Scenario:
        Given test inputs and fixtures for exit code one for any error by default
        When test_exit_code_one_for_any_error_by_default executes the target flow
        Then the expected outcome for exit code one for any error by default is confirmed.

    Boundaries:
        - Focus: exit code one for any error by default
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to exit code one for any error by default
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(
            Finding(rule="DS102", path="README.md", message="Stray comment", severity="warning"),
            Finding(rule="DS101", path="links.md", message="Dangling link", severity="error"),
            Finding(rule="DS103", path="docs.md", message="Unresolvable path", severity="warning"),
        ),
        enabled_rules=("DS101", "DS102", "DS103"),
        pending=(),
    )
    assert _exit_code(result, strict=False) == 1


def test_exit_code_strict_fails_on_warnings_too():
    """
    [Integration] scan: verifies exit code strict fails on warnings too.

    Scenario:
        Given test inputs and fixtures for exit code strict fails on warnings too
        When test_exit_code_strict_fails_on_warnings_too executes the target flow
        Then the expected outcome for exit code strict fails on warnings too is confirmed.

    Boundaries:
        - Focus: exit code strict fails on warnings too
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to exit code strict fails on warnings too
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS102", path="README.md", message="Stray comment", severity="warning"),),
        enabled_rules=("DS102",),
        pending=(),
    )
    assert _exit_code(result, strict=True) == 1


def test_exit_code_zero_when_no_findings_regardless_of_strict():
    """
    [Integration] scan: verifies exit code zero when no findings regardless of strict.

    Scenario:
        Given test inputs and fixtures for exit code zero when no findings regardless of strict
        When test_exit_code_zero_when_no_findings_regardless_of_strict executes the target flow
        Then the expected outcome for exit code zero when no findings regardless of strict is confirmed.

    Boundaries:
        - Focus: exit code zero when no findings regardless of strict
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to exit code zero when no findings regardless of strict
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = ScanResult(
        profile="fast",
        documents=(),
        findings=(),
        enabled_rules=("DS101", "DS102", "DS103"),
        pending=(),
    )
    assert _exit_code(result, strict=False) == 0
    assert _exit_code(result, strict=True) == 0


def _symlink_or_skip(link: Path, target: Path):
    """Create a symlink pointing to target, or skip the test if symlinks are unsupported."""
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")


def test_scan_selected_symlink_raises_value_error(tmp_path: Path):
    """
    [Integration] scan: verifies scan selected symlink raises value error.

    Scenario:
        Given test inputs and fixtures for scan selected symlink raises value error
        When test_scan_selected_symlink_raises_value_error executes the target flow
        Then the expected outcome for scan selected symlink raises value error is confirmed.

    Boundaries:
        - Focus: scan selected symlink raises value error
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan selected symlink raises value error
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    target = tmp_path / "target.md"
    target.write_text("content\n", encoding="utf-8")
    link = tmp_path / "link.md"
    _symlink_or_skip(link, target)

    with pytest.raises(ValueError, match=f"^Symlinked files are not inventoried: {re.escape(str(link))}$"):
        scan(link)


def test_scan_exclude_exact_relative_root_file(tmp_path: Path):
    """
    [Integration] scan: verifies scan exclude exact relative root file.

    Scenario:
        Given test inputs and fixtures for scan exclude exact relative root file
        When test_scan_exclude_exact_relative_root_file executes the target flow
        Then the expected outcome for scan exclude exact relative root file is confirmed.

    Boundaries:
        - Focus: scan exclude exact relative root file
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan exclude exact relative root file
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    (tmp_path / "skip.md").write_text("skip\n", encoding="utf-8")
    (tmp_path / "keep.md").write_text("keep\n", encoding="utf-8")
    result = scan(tmp_path, config=Config(exclude=("skip.md",)))
    assert [doc.path for doc in result.documents] == ["keep.md"]


def test_scan_exclude_parent_path_pattern_nested_document(tmp_path: Path):
    """
    [Integration] scan: verifies scan exclude parent path pattern nested document.

    Scenario:
        Given test inputs and fixtures for scan exclude parent path pattern nested document
        When test_scan_exclude_parent_path_pattern_nested_document executes the target flow
        Then the expected outcome for scan exclude parent path pattern nested document is confirmed.

    Boundaries:
        - Focus: scan exclude parent path pattern nested document
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to scan exclude parent path pattern nested document
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    sub_dir = tmp_path / "sub"
    sub_dir.mkdir()
    (sub_dir / "doc.md").write_text("nested doc\n", encoding="utf-8")
    (sub_dir / "preserve.md").write_text("nested preserve\n", encoding="utf-8")
    (tmp_path / "root.md").write_text("root\n", encoding="utf-8")

    result = scan(tmp_path, config=Config(exclude=("sub/doc.md",)))
    assert [doc.path for doc in result.documents] == ["root.md", "sub/preserve.md"]


def test_fast_scan_does_not_import_standard_subpackage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies fast scan does not import standard subpackage.

    Scenario:
        Given test inputs and fixtures for fast scan does not import standard subpackage
        When test_fast_scan_does_not_import_standard_subpackage executes the target flow
        Then the expected outcome for fast scan does not import standard subpackage is confirmed.

    Boundaries:
        - Focus: fast scan does not import standard subpackage
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to fast scan does not import standard subpackage
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    calls: list[None] = []

    def fake_loader():
        """Record loader call."""
        calls.append(None)

    monkeypatch.setattr("docsentinel.engine.ensure_standard_loaded", fake_loader)
    scan(tmp_path, config=Config(profile="fast"))

    assert calls == []


def test_standard_scan_calls_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies standard scan calls loader.

    Scenario:
        Given test inputs and fixtures for standard scan calls loader
        When test_standard_scan_calls_loader executes the target flow
        Then the expected outcome for standard scan calls loader is confirmed.

    Boundaries:
        - Focus: standard scan calls loader
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan calls loader
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    calls: list[None] = []

    def fake_loader():
        """Record loader call."""
        calls.append(None)

    monkeypatch.setattr("docsentinel.engine.ensure_standard_loaded", fake_loader)
    scan(tmp_path, config=Config(profile="standard"))

    assert len(calls) == 1


def test_standard_scan_without_extra_raises_actionable_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies standard scan without extra raises actionable error.

    Scenario:
        Given test inputs and fixtures for standard scan without extra raises actionable error
        When test_standard_scan_without_extra_raises_actionable_error executes the target flow
        Then the expected outcome for standard scan without extra raises actionable error is confirmed.

    Boundaries:
        - Focus: standard scan without extra raises actionable error
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to standard scan without extra raises actionable error
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    cause = ModuleNotFoundError("No module named 'sklearn'", name="sklearn")

    def fake_loader():
        """Simulate missing optional extra error."""
        raise ExtraNotInstalledError("standard", cause)

    monkeypatch.setattr("docsentinel.engine.ensure_standard_loaded", fake_loader)

    with pytest.raises(ExtraNotInstalledError) as exc_info:
        scan(tmp_path, config=Config(profile="standard"))

    assert exc_info.value.extra == "standard"
    assert "docsentinel[standard]" in str(exc_info.value)


def test_cli_scan_standard_without_extra_exits_2_with_guidance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] scan: verifies cli scan standard without extra exits 2 with guidance.

    Scenario:
        Given test inputs and fixtures for cli scan standard without extra exits 2 with guidance
        When test_cli_scan_standard_without_extra_exits_2_with_guidance executes the target flow
        Then the expected outcome for cli scan standard without extra exits 2 with guidance is confirmed.

    Boundaries:
        - Focus: cli scan standard without extra exits 2 with guidance
        - Fixtures/params: tmp_path, monkeypatch, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli scan standard without extra exits 2 with guidance
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    cause = ModuleNotFoundError("No module named 'sklearn'", name="sklearn")

    def fake_loader():
        """Simulate missing optional extra error."""
        raise ExtraNotInstalledError("standard", cause)

    monkeypatch.setattr("docsentinel.engine.ensure_standard_loaded", fake_loader)
    assert main(["scan", str(tmp_path), "--profile", "standard"]) == 2
    captured = capsys.readouterr()
    assert "docsentinel[standard]" in captured.err
    assert "Scan failed:" in captured.err


def test_cli_rules_lists_standard_when_extra_present(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] scan: verifies cli rules lists standard when extra present.

    Scenario:
        Given test inputs and fixtures for cli rules lists standard when extra present
        When test_cli_rules_lists_standard_when_extra_present executes the target flow
        Then the expected outcome for cli rules lists standard when extra present is confirmed.

    Boundaries:
        - Focus: cli rules lists standard when extra present
        - Fixtures/params: monkeypatch, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli rules lists standard when extra present
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    monkeypatch.setattr("docsentinel.cli.ensure_standard_loaded", lambda: None)
    rule = register_rule(Rule("DS299", "standard", "Fake standard rule", "Tests standard CLI rules listing."))
    try:
        assert main(["rules"]) == 0
        output = capsys.readouterr().out
        assert "DS299: Fake standard rule" in output
    finally:
        RULES.pop(rule.code, None)


def test_cli_rules_notes_missing_extra_and_still_exits_0(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """
    [Integration] scan: verifies cli rules notes missing extra and still exits 0.

    Scenario:
        Given test inputs and fixtures for cli rules notes missing extra and still exits 0
        When test_cli_rules_notes_missing_extra_and_still_exits_0 executes the target flow
        Then the expected outcome for cli rules notes missing extra and still exits 0 is confirmed.

    Boundaries:
        - Focus: cli rules notes missing extra and still exits 0
        - Fixtures/params: monkeypatch, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli rules notes missing extra and still exits 0
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    cause = ModuleNotFoundError("No module named 'sklearn'", name="sklearn")

    def fake_loader():
        """Simulate missing optional extra error."""
        raise ExtraNotInstalledError("standard", cause)

    monkeypatch.setattr("docsentinel.cli.ensure_standard_loaded", fake_loader)
    assert main(["rules"]) == 0
    output = capsys.readouterr().out
    assert "standard profile: install docsentinel[standard] to enable (DS2xx)" in output


@pytest.mark.parametrize(
    ("loader_raises", "expected_fragment"),
    [
        (False, "standard profile: available"),
        (True, "standard profile: not installed (pip install docsentinel[standard])"),
    ],
    ids=("available", "not_installed"),
)
def test_cli_doctor_reports_standard_availability(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    loader_raises: bool,
    expected_fragment: str,
):
    """
    [Integration] scan: verifies cli doctor reports standard availability.

    Scenario:
        Given test inputs and fixtures for cli doctor reports standard availability
        When test_cli_doctor_reports_standard_availability executes the target flow
        Then the expected outcome for cli doctor reports standard availability is confirmed.

    Boundaries:
        - Focus: cli doctor reports standard availability
        - Fixtures/params: monkeypatch, capsys, loader_raises, expected_fragment (parametrized, 2 cases)
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli doctor reports standard availability
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    if loader_raises:
        cause = ModuleNotFoundError("No module named 'sklearn'", name="sklearn")

        def fake_loader():
            """Simulate missing optional extra error."""
            raise ExtraNotInstalledError("standard", cause)

        monkeypatch.setattr("docsentinel.cli.ensure_standard_loaded", fake_loader)
    else:
        monkeypatch.setattr("docsentinel.cli.ensure_standard_loaded", lambda: None)

    assert main(["doctor"]) == 0
    output = capsys.readouterr().out
    assert expected_fragment in output


def test_cli_scan_fast_profile_never_loads_standard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """
    [Integration] scan: verifies cli scan fast profile never loads standard.

    Scenario:
        Given test inputs and fixtures for cli scan fast profile never loads standard
        When test_cli_scan_fast_profile_never_loads_standard executes the target flow
        Then the expected outcome for cli scan fast profile never loads standard is confirmed.

    Boundaries:
        - Focus: cli scan fast profile never loads standard
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to cli scan fast profile never loads standard
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    calls: list[None] = []

    def fake_loader():
        """Record loader call."""
        calls.append(None)

    monkeypatch.setattr("docsentinel.engine.ensure_standard_loaded", fake_loader)
    monkeypatch.setattr("docsentinel.cli.ensure_standard_loaded", fake_loader)

    assert main(["scan", str(tmp_path)]) == 0
    assert calls == []


def test_deep_unconfirmed_reports_opt_in_pending(tmp_path: Path):
    """
    [Integration] scan: verifies deep unconfirmed reports opt in pending.

    Scenario:
        Given test inputs and fixtures for deep unconfirmed reports opt in pending
        When test_deep_unconfirmed_reports_opt_in_pending executes the target flow
        Then the expected outcome for deep unconfirmed reports opt in pending is confirmed.

    Boundaries:
        - Focus: deep unconfirmed reports opt in pending
        - Fixtures/params: tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep unconfirmed reports opt in pending
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = scan(tmp_path, config=Config(profile="deep"))
    assert result.findings == ()
    assert result.enabled_rules == ()
    assert "deep profile requires explicit opt-in" in result.pending[0]
    assert "explicit opt-in" in result.notice


def test_deep_confirmed_via_config_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies deep confirmed via config flag.

    Scenario:
        Given test inputs and fixtures for deep confirmed via config flag
        When test_deep_confirmed_via_config_flag executes the target flow
        Then the expected outcome for deep confirmed via config flag is confirmed.

    Boundaries:
        - Focus: deep confirmed via config flag
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep confirmed via config flag
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    monkeypatch.setattr("docsentinel.engine.deep_ready", lambda: True)
    monkeypatch.setitem(ANALYZERS, "DS301", lambda root, docs: ())
    result = scan(tmp_path, config=Config(profile="deep", deep_confirm=True))
    assert result.findings == ()
    assert result.enabled_rules == ("DS301",)
    assert "evaluated" in result.notice


def test_deep_confirmed_via_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies deep confirmed via env var.

    Scenario:
        Given test inputs and fixtures for deep confirmed via env var
        When test_deep_confirmed_via_env_var executes the target flow
        Then the expected outcome for deep confirmed via env var is confirmed.

    Boundaries:
        - Focus: deep confirmed via env var
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep confirmed via env var
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    monkeypatch.setenv("DOCSENTINEL_DEEP_CONFIRM", "1")
    monkeypatch.setattr("docsentinel.engine.deep_ready", lambda: True)
    monkeypatch.setitem(ANALYZERS, "DS301", lambda root, docs: ())
    result = scan(tmp_path, config=Config(profile="deep"))
    assert result.findings == ()
    assert result.enabled_rules == ("DS301",)
    assert "evaluated" in result.notice


def test_deep_confirmed_via_cli_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] scan: verifies deep confirmed via cli flag.

    Scenario:
        Given test inputs and fixtures for deep confirmed via cli flag
        When test_deep_confirmed_via_cli_flag executes the target flow
        Then the expected outcome for deep confirmed via cli flag is confirmed.

    Boundaries:
        - Focus: deep confirmed via cli flag
        - Fixtures/params: tmp_path, monkeypatch, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep confirmed via cli flag
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    monkeypatch.setattr("docsentinel.engine.deep_ready", lambda: True)
    monkeypatch.setitem(ANALYZERS, "DS301", lambda root, docs: ())
    code = main(["scan", str(tmp_path), "--profile", "deep", "--i-understand-deep-is-heuristic"])
    assert code == 0
    out = capsys.readouterr().out
    assert "1 deep rule(s) evaluated" in out


def test_deep_confirmed_but_deps_missing_reports_pending(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies deep confirmed but deps missing reports pending.

    Scenario:
        Given test inputs and fixtures for deep confirmed but deps missing reports pending
        When test_deep_confirmed_but_deps_missing_reports_pending executes the target flow
        Then the expected outcome for deep confirmed but deps missing reports pending is confirmed.

    Boundaries:
        - Focus: deep confirmed but deps missing reports pending
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep confirmed but deps missing reports pending
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    monkeypatch.setattr("docsentinel.engine.deep_ready", lambda: False)
    result = scan(tmp_path, config=Config(profile="deep", deep_confirm=True))
    assert result.findings == ()
    assert result.enabled_rules == ()
    assert "deep profile confirmed, but its dependencies are unavailable" in result.pending[0]
    assert "pip install docsentinel[deep]" in result.pending[0]


def test_deep_findings_never_fail_exit_code():
    """
    [Integration] scan: verifies deep findings never fail exit code.

    Scenario:
        Given test inputs and fixtures for deep findings never fail exit code
        When test_deep_findings_never_fail_exit_code executes the target flow
        Then the expected outcome for deep findings never fail exit code is confirmed.

    Boundaries:
        - Focus: deep findings never fail exit code
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep findings never fail exit code
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = ScanResult(
        profile="deep",
        documents=(),
        findings=(Finding(rule="DS301", path="a.md", message="candidate contradiction", severity="warning"),),
        enabled_rules=("DS301",),
        pending=(),
    )
    assert _exit_code(result, strict=False) == 0


def test_deep_findings_exempt_even_under_strict():
    """
    [Integration] scan: verifies deep findings exempt even under strict.

    Scenario:
        Given test inputs and fixtures for deep findings exempt even under strict
        When test_deep_findings_exempt_even_under_strict executes the target flow
        Then the expected outcome for deep findings exempt even under strict is confirmed.

    Boundaries:
        - Focus: deep findings exempt even under strict
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep findings exempt even under strict
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = ScanResult(
        profile="deep",
        documents=(),
        findings=(Finding(rule="DS301", path="a.md", message="candidate contradiction", severity="warning"),),
        enabled_rules=("DS301",),
        pending=(),
    )
    assert _exit_code(result, strict=True) == 0


def test_deep_exemption_holds_even_for_error_severity():
    """
    [Integration] scan: verifies deep exemption holds even for error severity.

    Scenario:
        Given test inputs and fixtures for deep exemption holds even for error severity
        When test_deep_exemption_holds_even_for_error_severity executes the target flow
        Then the expected outcome for deep exemption holds even for error severity is confirmed.

    Boundaries:
        - Focus: deep exemption holds even for error severity
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep exemption holds even for error severity
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    result = ScanResult(
        profile="deep",
        documents=(),
        findings=(Finding(rule="DS301", path="a.md", message="hypothetical error", severity="error"),),
        enabled_rules=("DS301",),
        pending=(),
    )
    assert _exit_code(result, strict=False) == 0
    assert _exit_code(result, strict=True) == 0


def test_fast_and_standard_exit_codes_unchanged():
    """
    [Integration] scan: verifies fast and standard exit codes unchanged.

    Scenario:
        Given test inputs and fixtures for fast and standard exit codes unchanged
        When test_fast_and_standard_exit_codes_unchanged executes the target flow
        Then the expected outcome for fast and standard exit codes unchanged is confirmed.

    Boundaries:
        - Focus: fast and standard exit codes unchanged
        - Fixtures/params: none
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to fast and standard exit codes unchanged
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    fast_err = ScanResult(
        profile="fast",
        documents=(),
        findings=(Finding(rule="DS101", path="a.md", message="error", severity="error"),),
        enabled_rules=("DS101",),
        pending=(),
    )
    assert _exit_code(fast_err, strict=False) == 1

    std_warn = ScanResult(
        profile="standard",
        documents=(),
        findings=(Finding(rule="DS201", path="a.md", message="warning", severity="warning"),),
        enabled_rules=("DS201",),
        pending=(),
    )
    assert _exit_code(std_warn, strict=False) == 0
    assert _exit_code(std_warn, strict=True) == 1


def test_deep_evaluated_notice_is_advisory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Integration] scan: verifies deep evaluated notice is advisory.

    Scenario:
        Given test inputs and fixtures for deep evaluated notice is advisory
        When test_deep_evaluated_notice_is_advisory executes the target flow
        Then the expected outcome for deep evaluated notice is advisory is confirmed.

    Boundaries:
        - Focus: deep evaluated notice is advisory
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - Assertion details tied to deep evaluated notice is advisory
        - Fixture or parameter values used by this test
        - Recent changes in code paths exercised by scan
    """
    monkeypatch.setattr("docsentinel.engine.deep_ready", lambda: True)
    monkeypatch.setitem(ANALYZERS, "DS301", lambda root, docs: ())
    result = scan(tmp_path, config=Config(profile="deep", deep_confirm=True))
    assert "evaluated" in result.notice
    assert "advisory" in result.notice
    assert "not implemented" not in result.notice
