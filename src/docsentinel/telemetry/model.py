"""Report model: the JSON-shaped context every report template renders from.

:class:`ReportModel` is the *core provider* of the template pipeline described in
``docs/specs/report-template-format.md`` §1 and §6. It turns a
:class:`~docsentinel.models.ScanResult` into a plain tree of ``dict``/``list``/
``str``/``int``/``bool``/``None`` -- never an object -- so a template can reach data
but not attributes, methods or introspection. :data:`CONTEXT_SCHEMA` declares every
variable with its type and trust tag for the Story 02.0 template loader.

The model is deterministic for a given ``(ScanResult, config)``: per-run values
(``run.generated_at``, ``run.id``) appear only when explicitly requested.

Extension data (spec §6, §9; threat model 0007-extensions M11, M26) lives only under
``ext`` at the run, document and problem level. ``ext`` is present only when at
least one extension is loaded, is built by
:func:`~docsentinel.telemetry.extensions.apply_report_hooks` rather than by any
hook, and is untrusted at every depth.
"""

import re
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Optional, Union

from docsentinel.config import Config
from docsentinel.models import Finding, ScanResult
from docsentinel.telemetry.builtin.domain import DomainTable, domain_table
from docsentinel.telemetry.classify import classify, rule_title
from docsentinel.telemetry.events import utc_now_iso
from docsentinel.telemetry.extensions import LoadedExtensions, apply_report_hooks

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
        ``dict[str,int]``, ``list[document]``, ``list[problem]``, ``object``, or
        ``ext`` for the extension namespace (members are the template's
        ``requires_extensions``; every value below them has the kind ``any``).
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


#: The extension namespace (M11): always untrusted, present only when an extension
#: is loaded, members resolved per template from ``requires_extensions``.
EXT_VARIABLE: Final[Variable] = Variable("ext", UNTRUSTED, opt_in=True)

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
        "ext": EXT_VARIABLE,
    }
)

#: Members of a problem in the flat ``findings`` list (adds ``document_path``).
FLAT_PROBLEM_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {**PROBLEM_SCHEMA, "document_path": Variable("str", UNTRUSTED)}
)

#: Members of a document. ``bytes`` is null only for a finding path outside the
#: discovered inventory (for example a ``DS204`` Python source). ``domain`` is a core
#: key (threat model 0007-extensions M24): always present, set from
#: :func:`~docsentinel.telemetry.builtin.domain.domain_for` and never from a hook;
#: untrusted, as the repository asserts it.
DOCUMENT_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {
        "path": Variable("str", UNTRUSTED),
        "bytes": Variable("int|null", TRUSTED),
        "domain": Variable("str", UNTRUSTED),
        "problem_count": Variable("int", TRUSTED),
        "severity_counts": Variable("dict[str,int]", TRUSTED),
        "problems": Variable("list[problem]", None, PROBLEM_SCHEMA),
        "ext": EXT_VARIABLE,
    }
)

#: Members of an ``inventory`` element: exactly the legacy ``ScanResult.documents``
#: record, for the schema-1 ``json-v1`` template (no appended out-of-inventory entry).
INVENTORY_SCHEMA: Final[Mapping[str, Variable]] = _frozen(
    {"path": Variable("str", UNTRUSTED), "bytes": Variable("int", TRUSTED)}
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
        "show_clean_documents": Variable("bool", TRUSTED),
        "documents": Variable("list[document]", None, DOCUMENT_SCHEMA),
        "documents_with_problems": Variable("list[document]", None, DOCUMENT_SCHEMA),
        "findings": Variable("list[problem]", None, FLAT_PROBLEM_SCHEMA),
        "inventory": Variable("list[object]", None, INVENTORY_SCHEMA),
        "run": Variable("object", None, RUN_SCHEMA, opt_in=True),
        "ext": EXT_VARIABLE,
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

    The title comes from :func:`~docsentinel.telemetry.classify.rule_title`, so the
    result does not depend on whether the lazily loaded standard detectors ran.

    :param finding: The reported finding.
    :returns: ``finding.type``, else the rule title with a lower-cased first letter,
        else ``None`` for an unknown rule.
    """
    if finding.type is not None:
        return finding.type
    title = rule_title(finding.rule)
    if title is None:
        return None
    return title[0].lower() + title[1:]


def _problem(finding: Finding, config: Config, *, strict: bool) -> dict[str, JsonValue]:
    """Build one problem entry of the context.

    :param finding: The reported finding.
    :param config: The effective scan configuration.
    :param strict: Whether warnings are blocking.
    :returns: The JSON-shaped problem mapping.
    """
    labels = classify(finding, config, strict=strict)
    return {
        "rule": finding.rule,
        "rule_title": rule_title(finding.rule),
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
        extensions: Union[LoadedExtensions, Sequence[object]] = (),
        strict: bool = False,
        model: Optional[str] = None,
        report_include_run_meta: bool = False,
        report_schema_version: int = REPORT_SCHEMA_VERSION,
        show_clean_documents: bool = False,
    ) -> dict[str, JsonValue]:
        """Build the JSON-shaped report context for a completed scan.

        Every discovered document appears in ``documents`` in scan order with its
        ``problems`` attached by path (``[]`` for a clean document); a finding whose
        path is not in the inventory gets an appended document entry with
        ``bytes = None`` so no finding is ever dropped from a document-grouped report.
        ``documents_count`` and ``documents_with_problems_count`` count inventory
        documents only (the fault-rate denominator and the legacy ``Documents: N``),
        so an appended out-of-inventory entry is listed but never counted.
        Problems keep the order of ``result.findings``. ``inventory`` repeats
        ``result.documents`` verbatim as ``{path, bytes}`` records, so the schema-1
        ``json-v1`` template can reproduce the legacy ``documents`` list exactly.
        Every document carries the core ``domain`` from
        :func:`~docsentinel.telemetry.builtin.domain.domain_for` (``"docs"`` unless
        ``builtin:domain`` is in ``config.telemetry_extensions``); no hook can set it.

        :param result: The completed scan.
        :param config: The effective scan configuration.
        :param extensions: The loaded extension registry (spec §9) from
            :func:`~docsentinel.telemetry.extensions.resolve_extensions`; its hooks
            run after the core context is built and their data is attached under
            ``ext.<name>``, ``doc.ext.<name>`` and ``p.ext.<name>``. Empty by default.
        :param strict: Whether warnings are blocking (``--strict``); feeds ``outcome``.
        :param model: Invoker-supplied generator model id, or ``None``.
        :param report_include_run_meta: Add the per-run ``run.generated_at`` and
            ``run.id`` values; off by default so the context is deterministic.
        :param report_schema_version: The schema declared by the rendering template.
        :param show_clean_documents: Value of the ``show_clean_documents`` flag, which
            a text template reads to list documents without problems
            (``--show-clean-documents`` / ``report_show_clean_documents``).
        :returns: The context tree (``dict``/``list``/``str``/``int``/``bool``/``None`` only).
        :raises TypeError: If ``extensions`` is a non-empty value that is not a
            :class:`~docsentinel.telemetry.extensions.LoadedExtensions`.
        :raises docsentinel.telemetry.extensions.ExtensionError: If a hook fails or
            returns invalid or oversized data.
        :raises ValueError: If ``model`` does not match :data:`MODEL_ID_PATTERN`; the
            rejected value is never echoed, as it is untrusted invoker input.
        :raises docsentinel.config.ConfigError: If an injected ``config`` holds an
            invalid ``telemetry_domains`` or ``telemetry_extensions`` value.
        """
        if extensions and not isinstance(extensions, LoadedExtensions):
            raise TypeError("extensions must be a LoadedExtensions registry from resolve_extensions")
        if model is not None and (not isinstance(model, str) or MODEL_ID_PATTERN.fullmatch(model) is None):
            raise ValueError(
                "report model id must be 1-128 ASCII characters from [A-Za-z0-9._:/@+-], starting with a letter or digit"
            )

        domains = domain_table(config)
        documents: dict[str, dict[str, JsonValue]] = {}
        for document in result.documents:
            if document.path not in documents:
                documents[document.path] = ReportModel._document(document.path, document.bytes, domains)
        flat: list[dict[str, JsonValue]] = []
        flat_for: dict[int, dict[str, JsonValue]] = {}
        for finding in result.findings:
            problem = _problem(finding, config, strict=strict)
            target = documents.get(finding.path)
            if target is None:
                target = documents[finding.path] = ReportModel._document(finding.path, None, domains)
            target["problems"].append(problem)
            twin = {**problem, "document_path": finding.path}
            flat.append(twin)
            flat_for[id(problem)] = twin
        for entry in documents.values():
            entry["problem_count"] = len(entry["problems"])
            entry["severity_counts"] = _sorted_counts([problem["severity"] for problem in entry["problems"]])

        document_list = list(documents.values())
        with_problems = [entry for entry in document_list if entry["problems"]]
        inventory_paths = {document.path for document in result.documents}
        context: dict[str, JsonValue] = {
            "schema_version": result.schema_version,
            "report_schema_version": report_schema_version,
            "profile": result.profile,
            "enabled_rules": list(result.enabled_rules),
            "documents_count": len(result.documents),
            "documents_with_problems_count": sum(1 for entry in with_problems if entry["path"] in inventory_paths),
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
            "show_clean_documents": bool(show_clean_documents),
            "documents": document_list,
            "documents_with_problems": with_problems,
            "findings": flat,
            "inventory": [{"path": document.path, "bytes": document.bytes} for document in result.documents],
        }
        if report_include_run_meta:
            context["run"] = {"generated_at": utc_now_iso(), "id": uuid.uuid4().hex}
        if isinstance(extensions, LoadedExtensions) and extensions:
            apply_report_hooks(context, extensions, flat_for)
        return context

    @staticmethod
    def _document(path: str, size: Optional[int], domains: DomainTable) -> dict[str, JsonValue]:
        """Return an empty document entry; counts are filled once all problems are attached.

        :param path: Document path relative to the scan root.
        :param size: Size in bytes, or ``None`` for a path outside the inventory.
        :param domains: The effective configuration's domain table; ``domain`` comes
            only from it (M24).
        :returns: The document mapping with an empty ``problems`` list.
        """
        return {
            "path": path,
            "bytes": size,
            "domain": domains.domain(path),
            "problem_count": 0,
            "severity_counts": {},
            "problems": [],
        }
