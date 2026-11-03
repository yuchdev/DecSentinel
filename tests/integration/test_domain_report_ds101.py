"""``builtin:domain`` over a live DS101 scan (Milestone 0007 Story 04.0 Task 02).

The ``ds101/dangling_file_link`` case is loaded twice, under ``.claude/agents/`` and under
``docs/``, so each copy carries one dangling link. Pins threat model
``docs/security/threat-model-0007-extensions-2026-11-03.md`` M23 (first match wins), M24 (the core
``doc.domain`` from ``domain_for``; the report and ``FaultEvent.domain`` cannot disagree) and the
shipped example configuration ``examples/telemetry-domains.toml``.
"""

import importlib
import json
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from docsentinel import cli
from docsentinel.config import load_config
from docsentinel.engine import scan
from docsentinel.telemetry.builtin.domain import domain_for
from tests.asset_helpers import load_asset_case

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPO_ROOT / "examples" / "telemetry-domains.toml"

AGENT_DOC = ".claude/agents/README.md"
DOCS_DOC = "docs/README.md"


def _root(tmp_path: Path) -> Path:
    """Compose the DS101 case under ``.claude/agents/`` and ``docs/`` and copy the example config."""
    load_asset_case("ds101", "dangling_file_link", tmp_path / ".claude" / "agents")
    load_asset_case("ds101", "dangling_file_link", tmp_path / "docs")
    (tmp_path / "docsentinel.toml").write_bytes(EXAMPLE_CONFIG.read_bytes())
    return tmp_path


def _events_adapter() -> Optional[Callable[..., Any]]:
    """Return the Milestone 0006 Story 03.0 ``events_for_result`` adapter, or ``None`` until it is merged."""
    for module in ("docsentinel.telemetry", "docsentinel.telemetry.adapter"):
        try:
            found = getattr(importlib.import_module(module), "events_for_result", None)
        except ImportError:
            found = None
        if found is not None:
            return found
    return None


def test_example_config_labels_agent_and_docs_documents_in_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """
    [Integration] domain report ds101: verifies the example config labels agent and docs documents (M23, M24).

    Scenario:
        Given ``examples/telemetry-domains.toml`` as the root config and a dangling link in
        ``.claude/agents/README.md`` and in ``docs/README.md``
        When ``docsentinel scan --format json`` runs
        Then the first document's ``domain`` is ``agent``, the second's ``docs``, and the exit code stays 1.

    Boundaries:
        - Focus: end to end from TOML to the packaged ``json`` template's ``doc.domain``
        - Fixtures/params: two copies of the DS101 case
        - Scope: in-process CLI call

    On failure, first check:
        - ``templates/json.json`` (``$var doc.domain``) and ``ReportModel._document``
    """
    root = _root(tmp_path)

    code = cli.main(["scan", str(root), "--format", "json"])
    report = json.loads(capsys.readouterr().out)

    assert code == 1
    assert {doc["path"]: doc["domain"] for doc in report["documents"]} == {AGENT_DOC: "agent", DOCS_DOC: "docs"}
    assert all(doc["problems"] for doc in report["documents"])


def test_example_config_is_valid_and_ordered():
    """
    [Integration] domain report ds101: verifies the shipped example config loads with its documented order (M23).

    Scenario:
        Given ``examples/telemetry-domains.toml``
        When ``load_config`` reads it as an explicit config file
        Then it enables ``builtin:domain`` and keeps the five rules in file order, catch-all last.

    Boundaries:
        - Focus: the example cannot rot
        - Fixtures/params: none
        - Scope: ``config.load_config``

    On failure, first check:
        - the example file and ``config.validate_telemetry_domains``
    """
    settings = load_config(REPO_ROOT, EXAMPLE_CONFIG)

    assert settings.telemetry_extensions == ("builtin:domain",)
    assert settings.telemetry_domains == (
        (".claude/agents/**", "agent"),
        (".claude/skills/**", "agent"),
        ("docs/**", "docs"),
        ("adr/**", "docs"),
        ("**", "docs"),
    )


def test_domain_without_the_extension_stays_docs(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    """
    [Integration] domain report ds101: verifies the table alone changes nothing without ``builtin:domain`` (M24).

    Scenario:
        Given the example table but ``telemetry_extensions`` removed from the config
        When ``docsentinel scan --format json`` runs
        Then every document is in the ``docs`` domain; adding ``--extension builtin:domain`` labels the agent one.

    Boundaries:
        - Focus: the extension gate of the core key, and argv builtins merged into the effective Config
        - Fixtures/params: none
        - Scope: in-process CLI calls

    On failure, first check:
        - the ``builtin_specs`` merge in ``cli.main``
    """
    root = _root(tmp_path)
    text = EXAMPLE_CONFIG.read_text(encoding="utf-8").replace('telemetry_extensions = ["builtin:domain"]\n', "")
    (root / "docsentinel.toml").write_text(text, encoding="utf-8")

    cli.main(["scan", str(root), "--format", "json"])
    plain = json.loads(capsys.readouterr().out)
    cli.main(["scan", str(root), "--format", "json", "--extension", "builtin:domain"])
    labelled = json.loads(capsys.readouterr().out)

    assert {doc["domain"] for doc in plain["documents"]} == {"docs"}
    assert {doc["path"]: doc["domain"] for doc in labelled["documents"]} == {AGENT_DOC: "agent", DOCS_DOC: "docs"}


def test_fault_event_domain_equals_report_domain(tmp_path: Path):
    """
    [Integration] domain report ds101: verifies ``FaultEvent.domain`` equals ``doc.domain`` for both paths (M24).

    Scenario:
        Given the composed root under the example config
        When the Milestone 0006 ``events_for_result`` adapter emits events for the scan with the same Config
        Then each finding's event domain equals ``domain_for`` of its path: ``agent`` and ``docs``.

    Boundaries:
        - Focus: the report and the event stream cannot disagree
        - Fixtures/params: skipped until Milestone 0006 Story 03.0 (the adapter) is merged
        - Scope: scan plus the 0006 adapter

    On failure, first check:
        - that the adapter calls ``docsentinel.telemetry.builtin.domain.domain_for`` with the effective Config
    """
    adapter = _events_adapter()
    if adapter is None:
        pytest.skip(
            "Milestone 0006 Story 03.0 (the events_for_result fault-event adapter) is not merged; "
            "FaultEvent.domain cannot be compared yet"
        )
    root = _root(tmp_path)
    settings = load_config(root)
    result = scan(root, config=settings)

    events = [event for event in adapter(result, model=None, suppressed=(), config=settings) if event.rule == "DS101"]

    assert sorted(event.domain for event in events) == ["agent", "docs"]
    assert {domain_for(path, settings) for path in (AGENT_DOC, DOCS_DOC)} == {"agent", "docs"}
