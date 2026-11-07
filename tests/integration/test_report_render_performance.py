"""Report rendering scales linearly at the 358-document scale (Story 05.0 Task 01, matrix row "Performance").

The synthetic results follow the ``scripts/bench_corpus.py`` pattern: fully deterministic, built
from the document index alone, so a run is reproducible across machines and versions. Each document
carries three enriched DS101 findings (alternating error/warning, with ``line``/``column``/``value``/
``type``), which exercises every packaged template's per-problem path. The sizes are a doubling
series bracketing the 358-document acceptance corpus (90, 180, 360, 720).

The bound is relative, never a wall-clock absolute: :func:`tests.timing_helpers.assert_scales_linearly`
(CPU time, best of three, floored baseline, log-log slope) fails when rendering becomes super-linear in
the number of documents/problems. The roadmap's "within 2x of the pre-milestone render time" is a
separate, owner-level acceptance number and is not asserted here.
"""

import pytest

from docsentinel.models import Document, Finding, ScanResult
from docsentinel.reporting import render
from docsentinel.telemetry.loader import packaged_template_names
from tests.timing_helpers import assert_scales_linearly

#: Doubling series bracketing the 358-document acceptance corpus.
_SIZES = (90, 180, 360, 720)
#: Findings per synthetic document.
_PER_DOCUMENT = 3
#: A token present once per rendered problem in every packaged template (the message, not ``type``).
_MARKER = "dangling link ->"


def _result(count: int) -> ScanResult:
    """Return a deterministic fast-profile result of ``count`` documents with three findings each.

    :param count: Number of documents.
    :returns: The scan result.
    """
    documents = tuple(Document(path=f"docs/{index:05d}.md", bytes=900 + index % 97) for index in range(count))
    findings = tuple(
        Finding(
            rule="DS101",
            path=f"docs/{index:05d}.md",
            message=f"{_MARKER} {(index + slot + 1) % count:05d}-{slot}.md",
            severity="error" if (index + slot) % 2 else "warning",
            line=3 + slot * 4,
            column=1 + slot,
            value=f"{(index + slot + 1) % count:05d}-{slot}.md",
            type="dangling link",
        )
        for index in range(count)
        for slot in range(_PER_DOCUMENT)
    )
    return ScanResult(
        profile="fast",
        documents=documents,
        findings=findings,
        enabled_rules=("DS101",),
        pending=(),
        notice="1 fast rule(s) evaluated.",
        rules_evaluated=1,
    )


@pytest.mark.parametrize("name", packaged_template_names())
def test_rendering_scales_linearly_through_the_358_document_scale(name: str):
    """
    [Integration] report render performance: verifies every packaged template renders in linear time.

    Scenario:
        Given deterministic results of 90, 180, 360 and 720 documents with three findings each
        When each is rendered with the packaged template (CPU time, best of three)
        Then every problem is rendered (3 per document, counted by its message) and the time scales
            near-linearly: per-doubling ratio <= 6 and log-log slope <= 1.4.

    Boundaries:
        - Focus: no super-linear step in ReportModel.build or the template engine (loops, grouping,
          documents_with_problems)
        - Fixtures/params: one packaged template per case; payloads built outside the timed region
        - Scope: ``reporting.render`` in process

    On failure, first check:
        - the report's sizes/times/slope in the assertion message, then per-document list scans in
          ``telemetry.model`` or repeated string concatenation in ``telemetry.engine``
    """

    def run(result: ScanResult) -> list[str]:
        """Render ``result`` and return the lines carrying a problem message."""
        return [line for line in render(result, name).split("\n") if _MARKER in line]

    assert_scales_linearly(
        _result,
        run,
        _SIZES,
        expected_count=lambda count: count * _PER_DOCUMENT,
        label=f"render {name}",
    )
