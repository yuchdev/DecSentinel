"""Render a scan through a report template (Milestone 0007 Story 03.0 Task 02).

Every report -- the human-readable listing, GitHub workflow annotations, the
schema-2 and schema-1 JSON documents, and any user template -- is produced by the
template engine of ``docs/specs/report-template-format.md``: :func:`render` resolves
a template, builds the :class:`~docsentinel.telemetry.model.ReportModel` context and
hands both to :func:`~docsentinel.telemetry.engine.render_template`. This module
holds no output format of its own: no format name, line layout or serializer lives
here, and a unit test parses it to keep it that way (the hardcode-ban tripwire).

A finding's ``path`` and ``message`` -- and a document's ``path`` -- originate in
scanned repository content and are untrusted. The templates route them through the
sink filters of :mod:`docsentinel.telemetry.filters`, and the loader refuses a text
template that would emit one unfiltered. Baseline fingerprints hash the raw
:class:`~docsentinel.models.Finding` fields, never rendered output.
"""

import os
from pathlib import Path
from typing import Optional, Union

from docsentinel.config import Config
from docsentinel.models import ScanResult
from docsentinel.telemetry.engine import render_template
from docsentinel.telemetry.filters import TemplateError
from docsentinel.telemetry.filters import neutralize as _neutralize
from docsentinel.telemetry.loader import DEFAULT_TEMPLATE, Template, load_named_template, load_template
from docsentinel.telemetry.model import REPORT_SCHEMA_VERSION, ReportModel


def neutralize_text(value: str) -> str:
    """Return ``value`` with unsafe control, format and surrogate code points escaped.

    Public entry point for output paths outside the report templates (for example
    the command-line error lines), so untrusted text such as a scanned path inside
    an exception message never reaches a terminal or log with raw control bytes.
    Delegates to :func:`docsentinel.telemetry.filters.neutralize`, the table the
    ``neutralize`` template filter applies.

    :param value: Text that may embed untrusted path or content characters.
    :returns: The text with every unsafe code point rendered as a visible escape.
    """
    return _neutralize(value)


def _resolve(
    format: str,
    template: Union[Template, str, os.PathLike[str], None],
    config: Config,
    root: Optional[Path],
) -> Template:
    """Return the template to render: ``template`` when given, else ``format`` by name.

    :param format: A template name (packaged, then ``config.report_templates_dir``).
    :param template: A loaded template, or an invoker-supplied template file path.
    :param config: The effective configuration.
    :param root: The scan root ``report_templates_dir`` is relative to.
    :returns: The validated template.
    :raises TemplateError: On any resolution, read or validation failure.
    """
    if isinstance(template, Template):
        return template
    if template is not None:
        return load_template(Path(os.fspath(template)))
    return load_named_template(format, root=root, templates_dir=config.report_templates_dir)


def render(
    result: ScanResult,
    format: str = DEFAULT_TEMPLATE,
    *,
    config: Optional[Config] = None,
    template: Union[Template, str, os.PathLike[str], None] = None,
    root: Optional[Path] = None,
    strict: bool = False,
) -> str:
    """Render a scan result through a report template.

    The template is ``template`` when given (a loaded
    :class:`~docsentinel.telemetry.loader.Template`, or a file path the invoker
    trusts, which still passes the loader's regular-file/size/encoding gate);
    otherwise ``format`` is looked up as a template *name* -- never as a path --
    among the packaged templates and then ``config.report_templates_dir``.

    :param result: Completed scan to render.
    :param format: Template name, e.g. a packaged name listed by ``docsentinel doctor``.
    :param config: The effective configuration; ``Config()`` when omitted. Supplies
        ``report_templates_dir``, ``report_show_clean_documents`` and
        ``report_include_run_meta``, and drives the per-problem classification.
    :param template: A template or template file path; wins over ``format``.
    :param root: The scan root ``report_templates_dir`` is resolved against.
    :param strict: Whether warnings are blocking (``--strict``); feeds ``outcome``.
    :returns: The rendered report.
    :raises ValueError: If the template is unknown, unreadable, invalid, needs an
        extension that is not loaded, or fails to render; the message is bounded and
        neutralized, and the :class:`~docsentinel.telemetry.filters.TemplateError`
        is chained as the cause.
    """
    settings = config if config is not None else Config()
    try:
        chosen = _resolve(format, template, settings, root)
        context = ReportModel.build(
            result,
            settings,
            strict=strict,
            report_include_run_meta=settings.report_include_run_meta,
            report_schema_version=chosen.schema_version or REPORT_SCHEMA_VERSION,
            show_clean_documents=settings.report_show_clean_documents,
        )
        return render_template(chosen, context)
    except TemplateError as exc:
        raise ValueError(str(exc)) from exc
