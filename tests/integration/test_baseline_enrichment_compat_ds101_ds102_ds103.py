"""A pre-Milestone-0007 baseline file still matches after ``Finding`` enrichment (Story 05.0 Task 01).

Matrix row "Baselines": Milestone 0007 added ``column``, ``value`` and ``type`` to ``Finding``
(``compare=False``) and must not change baseline fingerprints. ``report/baseline_pre_0007`` holds a
baseline recorded by ``docsentinel baseline`` at commit ``164a708`` (the last commit before the
milestone's first code change) over exactly the tree composed here: ``ds101/dangling_file_link``,
``ds102/stray_comment_file`` and ``ds103/unresolvable_path_file`` -- the three rules that populate
the new fields. Do not regenerate the asset with current code: it would compare the code with itself.
"""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from docsentinel import cli
from docsentinel.baseline import fingerprint
from docsentinel.config import load_config
from docsentinel.engine import scan
from docsentinel.telemetry.loader import packaged_template_names
from tests.asset_helpers import AssetCase, load_asset_case

_BASELINE = "baseline-pre-0007.json"


def _tree(asset_case: Callable[[str, str], AssetCase]) -> Path:
    """Return the composed DS101/DS102/DS103 root holding the frozen pre-0007 baseline."""
    root = asset_case("ds101", "dangling_file_link").root
    load_asset_case("ds102", "stray_comment_file", root)
    load_asset_case("ds103", "unresolvable_path_file", root)
    load_asset_case("report", "baseline_pre_0007", root)
    return root


def test_enriched_findings_fingerprint_like_the_pre_0007_baseline(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] baseline enrichment compat ds101 ds102 ds103: verifies fingerprints are unchanged by enrichment.

    Scenario:
        Given the tree and the baseline recorded for it by pre-0007 code
        When it is scanned now
        Then every finding carries the new ``column``/``value``/``type`` fields, and the set of current
            fingerprints equals the frozen baseline's set exactly.

    Boundaries:
        - Focus: ``baseline.fingerprint`` ignores the report-only fields
        - Fixtures/params: ds101/dangling_file_link + ds102/stray_comment_file + ds103/unresolvable_path_file +
          report/baseline_pre_0007
        - Scope: engine scan and baseline fingerprinting

    On failure, first check:
        - whether ``fingerprint`` or the DS101/DS102/DS103 messages changed (the message hash is part of it)
    """
    root = _tree(asset_case)
    frozen = json.loads((root / _BASELINE).read_text(encoding="utf-8"))["fingerprints"]

    result = scan(root, config=load_config(root))

    assert sorted(finding.rule for finding in result.findings) == ["DS101", "DS102", "DS103"]
    assert all(finding.column is not None and finding.type is not None for finding in result.findings)
    assert sorted(fingerprint(finding) for finding in result.findings) == sorted(frozen)


@pytest.mark.parametrize("name", packaged_template_names())
def test_pre_0007_baseline_suppresses_every_finding_through_the_cli(
    name: str, asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] baseline enrichment compat ds101 ds102 ds103: verifies the old baseline file filters via the CLI.

    Scenario:
        Given the tree and the frozen pre-0007 baseline
        When ``scan --strict --baseline <file> --format <name>`` runs, and the same without the baseline
        Then with the baseline it exits 0 and reports no finding; without it exits 1 (DS101 error).

    Boundaries:
        - Focus: an existing user's baseline keeps working after the upgrade, for every template
        - Fixtures/params: the composed tree; every packaged template
        - Scope: in-process CLI calls

    On failure, first check:
        - ``engine.scan`` baseline filtering, then the fingerprint test above
    """
    root = _tree(asset_case)

    without = cli.main(["scan", str(root), "--format", name])
    capsys.readouterr()
    code = cli.main(["scan", str(root), "--strict", "--baseline", str(root / _BASELINE), "--format", name])
    captured = capsys.readouterr()

    assert (without, code) == (1, 0)
    assert captured.err == ""
    for message in ("dangling link", "stray HTML comment", "unresolvable path"):
        assert message not in captured.out
