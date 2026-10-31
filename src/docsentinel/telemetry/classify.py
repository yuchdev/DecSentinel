"""Shared finding classification: fault class, tier, outcome and domain.

This is the **single** classification function for both consumers of a finding's
telemetry labels -- the report model (:mod:`docsentinel.telemetry.model`) and the
Milestone 0006 fault-event adapter -- so a report and the event stream can never
disagree about a finding. The vocabularies follow
``docs/specs/fault-event-contract.md`` §2; the rule-to-class table mirrors
``src/docsentinel/fault_classes.md`` row for row (a unit test enforces the parity).
"""

from dataclasses import dataclass
from typing import Final, Optional

from docsentinel.config import Config
from docsentinel.models import Finding
from docsentinel.rules import RULES

#: Rule code -> fault class, mirroring every row of ``fault_classes.md``.
FAULT_CLASSES: Final[dict[str, str]] = {
    "DS101": "dangling_reference",
    "DS102": "residual_markup",
    "DS103": "unresolvable_path",
    "DS104": "identifier_collision",
    "DS105": "structure_violation",
    "DS106": "empty_content",
    "DS108": "reference_integrity",
    "DS109": "fence_violation",
    "DS110": "fence_language_missing",
    "DS112": "navigation_integrity",
    "DS113": "missing_asset",
    "DS114": "duplicate_identity",
    "DS115": "deprecated_reference",
    "DS116": "path_escape",
    "DS117": "table_malformed",
    "DS118": "naming_policy",
    "DS201": "high_complexity",
    "DS202": "duplicate_text",
    "DS203": "low_information",
    "DS204": "contract_mismatch",
    "DS301": "contradiction_candidate",
}

#: Fallback class for a rule with no ``fault_classes.md`` row (a review failure).
UNMAPPED_FAULT_CLASS: Final[str] = "unmapped"

#: Default content domain until an extension (``builtin:domain``) assigns one.
DEFAULT_DOMAIN: Final[str] = "documentation"


@dataclass(frozen=True)
class Classification:
    """Telemetry labels of one finding.

    :ivar fault_class: Fault class from :data:`FAULT_CLASSES`, or ``unmapped``.
    :ivar tier: ``deterministic`` (fast/standard) or ``heuristic`` (deep).
    :ivar outcome: ``rejected`` for a blocking finding, ``advisory`` for a
        non-blocking one, or ``None`` when the severity maps to neither.
    :ivar domain: Content domain; :data:`DEFAULT_DOMAIN` in the core provider.
    """

    fault_class: str
    tier: str
    outcome: Optional[str]
    domain: str = DEFAULT_DOMAIN


def tier_for_profile(profile: str) -> str:
    """Return the contract tier for a rule profile.

    :param profile: ``fast``, ``standard`` or ``deep``.
    :returns: ``heuristic`` for ``deep``, otherwise ``deterministic``.
    """
    return "heuristic" if profile == "deep" else "deterministic"


def classify(finding: Finding, config: Config, *, strict: bool = False) -> Classification:
    """Classify a reported finding with the fault-event contract vocabularies.

    The tier comes from the producing rule's registered profile (falling back to
    ``config.profile`` for a rule that is not registered). The outcome follows
    contract §2.2: every heuristic (deep) finding is ``advisory``; otherwise an
    ``error`` is ``rejected`` and a ``warning`` is ``advisory``, or ``rejected``
    under ``strict`` (the CLI's ``--strict``). Any other severity has no mapped
    outcome (``None``). Baselined findings never reach this function, so
    ``suppressed`` is not produced here; ``pass`` describes a clean rule, not a
    finding.

    :param finding: The reported finding.
    :param config: The effective scan configuration.
    :param strict: Whether warnings are blocking (``--strict``).
    :returns: The finding's classification.
    """
    rule = RULES.get(finding.rule)
    tier = tier_for_profile(rule.profile if rule is not None else config.profile)
    if tier == "heuristic":
        outcome: Optional[str] = "advisory"
    elif finding.severity == "error":
        outcome = "rejected"
    elif finding.severity == "warning":
        outcome = "rejected" if strict else "advisory"
    else:
        outcome = None
    return Classification(
        fault_class=FAULT_CLASSES.get(finding.rule, UNMAPPED_FAULT_CLASS),
        tier=tier,
        outcome=outcome,
    )
