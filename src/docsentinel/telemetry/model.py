"""Report model: the JSON-shaped context every report template renders from.

:class:`ReportModel` is the *core provider* of the template pipeline described in
``docs/specs/report-template-format.md`` §1 and §6. It turns a
:class:`~docsentinel.models.ScanResult` into a plain tree of ``dict``/``list``/
``str``/``int``/``bool``/``None`` -- never an object -- so a template can reach data
but not attributes, methods or introspection. :data:`CONTEXT_SCHEMA` declares every
variable with its type and trust tag for the Story 02.0 template loader.

The model is deterministic for a given ``(ScanResult, config)``: per-run values
(``run.generated_at``, ``run.id``) appear only when explicitly requested.
"""

import re
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Optional

from docsentinel.config import Config
from docsentinel.models import Finding, ScanResult
from docsentinel.rules import RULES
from docsentinel.telemetry.classify import classify
from docsentinel.telemetry.events import utc_now_iso

#: Deep-profile advisory banner, carried as data in the ``advisory`` variable.
ADVISORY_BANNER: Final[str] = "Deep findings are heuristic candidates for review - they do not fail the build."

#: Default ``report_schema_version`` (the schema of the standard ``json.json`` template).
REPORT_SCHEMA_VERSION: Final[int] = 2

#: Trust tags (spec §8): an untrusted variable must pass a sink filter in a text template.
TRUSTED: Final[str] = "trusted"
UNTRUSTED: Final[str] = "untrusted"

#: Bound on the invoker-supplied ``model`` id (threat model T8/M15). ``model`` is
#: tagged trusted, so it may reach the text and GitHub sinks unfiltered; this
#: ASCII-only charset and 128-character length cap is what makes that tag safe
#: (no control, bidi, whitespace, ``%``, ``,`` or newline can ever be carried).
MODEL_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}")

JsonValue = Any


@dataclass(frozen=True)
class Variable:
    """Schema entry for one context variable.

    :ivar type: Type descriptor, e.g. ``int``, ``str``, ``int|null``, ``list[str]``,
        ``dict[str,int]``, ``list[document]``, ``list[problem]``, ``object``.
    :ivar trust: :data:`TRUSTED`, :data:`UNTRUSTED`, or ``None`` for a container
        whose members carry their own tags.
    :ivar fields: Member schema of an ``object`` or of each element of a list of objects.
    :ivar opt_in: ``True`` when the variable is present only on explicit request.
    """

    type: str
    trust: Optional[str]
    fields: Mapping[str, "Variable"] = field(default_factory=lambda: MappingProxyType({}))
    opt_in: bool = False


def _frozen(entries: dict[str, Variable]) -> Mapping[str, Variable]:
    """Return a read-only view of a schema mapping.

    :param entries: Variable name -> schema entry.
    :returns: An immutable mapping proxy.
    """
    return MappingProxyType(entries)


#: Members of a problem nested under ``documents[].problems``.
PROBLEM_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {
        "rule": Variable("str", TRUSTED),
        "rule_title": Variable("str|null", TRUSTED),
        "type": Variable("str|null", TRUSTED),
        "message": Variable("str", UNTRUSTED),
        "value": Variable("str|null", UNTRUSTED),
        "severity": Variable("str", TRUSTED),
        "line": Variable("int|null", TRUSTED),
        "column": Variable("int|null", TRUSTED),
        "fault_class": Variable("str", TRUSTED),
        "tier": Variable("str", TRUSTED),
        "outcome": Variable("str|null", TRUSTED),
    }
)

#: Members of a problem in the flat ``findings`` list (adds ``document_path``).
FLAT_PROBLEM_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {**PROBLEM_SCHEMA, "document_path": Variable("str", UNTRUSTED)}
)

#: Members of a document. ``bytes`` is null only for a finding path outside the
#: discovered inventory (for example a ``DS204`` Python source).
DOCUMENT_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {
        "path": Variable("str", UNTRUSTED),
        "bytes": Variable("int|null", TRUSTED),
        "problem_count": Variable("int", TRUSTED),
        "severity_counts": Variable("dict[str,int]", TRUSTED),
        "problems": Variable("list[problem]", None, PROBLEM_SCHEMA),
    }
)

#: Members of an ``opt_in_off`` element.
OPT_IN_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {"code": Variable("str", TRUSTED), "option": Variable("str", TRUSTED)}
)

#: Members of the opt-in ``run`` object.
RUN_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {"generated_at": Variable("str", TRUSTED), "id": Variable("str", TRUSTED)}
)

#: Top-level context schema (spec §6), consumed by the Story 02.0 template loader.
CONTEXT_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {
        "schema_version": Variable("int", TRUSTED),
        "report_schema_version": Variable("int", TRUSTED),
        "profile": Variable("str", TRUSTED),
        "enabled_rules": Variable("list[str]", TRUSTED),
        "documents_count": Variable("int", TRUSTED),
        "documents_with_problems_count": Variable("int", TRUSTED),
        "findings_count": Variable("int", TRUSTED),
        "rules_evaluated": Variable("int", TRUSTED),
        "rules_type": Variable("str", TRUSTED),
        "opt_in_off": Variable("list[object]", None, OPT_IN_SCHEMA),
        "notice": Variable("str", TRUSTED),
        "advisory": Variable("str|null", TRUSTED),
        "pending": Variable("list[str]", UNTRUSTED),
        "severity_counts": Variable("dict[str,int]", TRUSTED),
        "rule_counts": Variable("dict[str,int]", TRUSTED),
        "model": Variable("str|null", TRUSTED),
        "documents": Variable("list[document]", None, DOCUMENT_SCHEMA),
        "documents_with_problems": Variable("list[document]", None, DOCUMENT_SCHEMA),
        "findings": Variable("list[problem]", None, FLAT_PROBLEM_SCHEMA),
        "run": Variable("object", None, RUN_SCHEMA, opt_in=True),
    }
)


def _sorted_counts(values: Sequence[str]) -> dict[str, int]:
    """Count values into a key-sorted dict, so the result is deterministic.

    :param values: The values to count.
    :returns: ``value -> count`` with keys in sorted order.
    """
    counts = Counter(values)
    return {key: counts[key] for key in sorted(counts)}


def _derived_type(finding: Finding) -> Optional[str]:
    """Return the finding's short category, deriving it from the rule title when unset.

    :param finding: The reported finding.
    :returns: ``finding.type``, else the rule title with a lower-cased first letter,
        else ``None`` for an unregistered rule.
    """
    if finding.type is not None:
        return finding.type
    rule = RULES.get(finding.rule)
    if rule is None or not rule.title:
        return None
    return rule.title[0].lower() + rule.title[1:]


def _problem(finding: Finding, config: Config, *, strict: bool) -> dict[str, JsonValue]:
    """Build one problem entry of the context.

    :param finding: The reported finding.
    :param config: The effective scan configuration.
    :param strict: Whether warnings are blocking.
    :returns: The JSON-shaped problem mapping.
    """
    labels = classify(finding, config, strict=strict)
    rule = RULES.get(finding.rule)
    return {
        "rule": finding.rule,
        "rule_title": rule.title if rule is not None else None,
        "type": _derived_type(finding),
        "message": finding.message,
        "value": finding.value,
        "severity": finding.severity,
        "line": finding.line,
        "column": finding.column,
        "fault_class": labels.fault_class,
        "tier": labels.tier,
        "outcome": labels.outcome,
    }


class ReportModel:
    """Core context provider for report templates (spec §6)."""

    @staticmethod
    def build(
        result: ScanResult,
        config: Config,
        *,
        extensions: Sequence[object] = (),
        strict: bool = False,
        model: Optional[str] = None,
        report_include_run_meta: bool = False,
        report_schema_version: int = REPORT_SCHEMA_VERSION,
    ) -> dict[str, JsonValue]:
        """Build the JSON-shaped report context for a completed scan.

        Every discovered document appears in ``documents`` in scan order with its
        ``problems`` attached by path (``[]`` for a clean document); a finding whose
        path is not in the inventory gets an appended document entry with
        ``bytes = None`` so no finding is ever dropped from a document-grouped report.
        Problems keep the order of ``result.findings``.

        :param result: The completed scan.
        :param config: The effective scan configuration.
        :param extensions: Extension providers (spec §9). Not implemented yet; a
            non-empty value raises rather than being silently ignored.
        :param strict: Whether warnings are blocking (``--strict``); feeds ``outcome``.
        :param model: Invoker-supplied generator model id, or ``None``.
        :param report_include_run_meta: Add the per-run ``run.generated_at`` and
            ``run.id`` values; off by default so the context is deterministic.
        :param report_schema_version: The schema declared by the rendering template.
        :returns: The context tree (``dict``/``list``/``str``/``int``/``bool``/``None`` only).
        :raises NotImplementedError: If ``extensions`` is non-empty.
        :raises ValueError: If ``model`` does not match :data:`MODEL_ID_PATTERN`; the
            rejected value is never echoed, as it is untrusted invoker input.
        """
        if extensions:
            raise NotImplementedError("report extensions are not supported yet (Milestone 0007 Story 04.0)")
        if model is not None and (not isinstance(model, str) or MODEL_ID_PATTERN.fullmatch(model) is None):
            raise ValueError(
                "report model id must be 1-128 ASCII characters from [A-Za-z0-9._:/@+-], starting with a letter or digit"
            )

        documents: dict[str, dict[str, JsonValue]] = {}
        for document in result.documents:
            documents.setdefault(document.path, ReportModel._document(document.path, document.bytes))
        flat: list[dict[str, JsonValue]] = []
        for finding in result.findings:
            problem = _problem(finding, config, strict=strict)
            target = documents.setdefault(finding.path, ReportModel._document(finding.path, None))
            target["problems"].append(problem)
            flat.append({**problem, "document_path": finding.path})
        for entry in documents.values():
            entry["problem_count"] = len(entry["problems"])
            entry["severity_counts"] = _sorted_counts([problem["severity"] for problem in entry["problems"]])

        document_list = list(documents.values())
        with_problems = [entry for entry in document_list if entry["problems"]]
        context: dict[str, JsonValue] = {
            "schema_version": result.schema_version,
            "report_schema_version": report_schema_version,
            "profile": result.profile,
            "enabled_rules": list(result.enabled_rules),
            "documents_count": len(document_list),
            "documents_with_problems_count": len(with_problems),
            "findings_count": len(result.findings),
            "rules_evaluated": result.rules_evaluated,
            "rules_type": result.profile,
            "opt_in_off": [{"code": code, "option": option} for code, option in result.opt_in_off],
            "notice": result.notice,
            "advisory": ADVISORY_BANNER if result.profile == "deep" and result.findings else None,
            "pending": list(result.pending),
            "severity_counts": _sorted_counts([finding.severity for finding in result.findings]),
            "rule_counts": _sorted_counts([finding.rule for finding in result.findings]),
            "model": model,
            "documents": document_list,
            "documents_with_problems": with_problems,
            "findings": flat,
        }
        if report_include_run_meta:
            context["run"] = {"generated_at": utc_now_iso(), "id": uuid.uuid4().hex}
        return context

    @staticmethod
    def _document(path: str, size: Optional[int]) -> dict[str, JsonValue]:
        """Return an empty document entry; counts are filled once all problems are attached.

        :param path: Document path relative to the scan root.
        :param size: Size in bytes, or ``None`` for a path outside the inventory.
        :returns: The document mapping with an empty ``problems`` list.
        """
        return {"path": path, "bytes": size, "problem_count": 0, "severity_counts": {}, "problems": []}
