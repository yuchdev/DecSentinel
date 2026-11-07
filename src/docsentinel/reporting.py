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

Extensions (spec §9) are resolved here only from explicit arguments: ``render``
never reads the environment, and a ``python:`` spec runs only when the caller passes
``allow_python_extensions=True`` (threat model 0007-extensions M2).
"""

import os
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Optional, Union

from docsentinel.config import Config
from docsentinel.models import ScanResult
from docsentinel.telemetry.engine import render_template
from docsentinel.telemetry.extensions import (
    PYTHON_PREFIX,
    ExtensionError,
    LoadedExtensions,
    check_template,
    resolve_extensions,
)
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


def _has_python_spec(extensions: object) -> bool:
    """Return whether an ``extensions=`` sequence holds a ``python:`` spec string.

    :param extensions: The ``extensions`` argument of :func:`render`.
    :returns: The decision; malformed values are left to ``resolve_extensions``.
    """
    if isinstance(extensions, (str, bytes)) or not isinstance(extensions, Sequence):
        return False
    return any(isinstance(spec, str) and spec.startswith(PYTHON_PREFIX) for spec in extensions)


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
    extensions: Union[Sequence[str], LoadedExtensions] = (),
    allow_python_extensions: bool = False,
) -> str:
    """Render a scan result through a report template.

    The template is ``template`` when given (a loaded
    ``Template``, or a file path the invoker
    trusts, which still passes the loader's regular-file/size/encoding gate);
    otherwise ``format`` is looked up as a template *name* -- never as a path --
    among the packaged templates and then ``config.report_templates_dir``.

    :param result: Completed scan to render.
    :param format: Template name, e.g. a packaged name listed by ``docsentinel doctor``.
    :param config: The effective configuration; ``Config()`` when omitted. Supplies
        ``report_templates_dir``, ``report_show_clean_documents`` and
        ``report_include_run_meta``, and drives the per-problem classification. Its
        ``telemetry_extensions`` is replaced by the loaded builtin specs, so
        ``doc.domain`` follows ``builtin:domain`` whether it was selected in config,
        in ``extensions`` or in a resolved registry.
    :param template: A template or template file path; wins over ``format``.
    :param root: The scan root ``report_templates_dir`` is resolved against, and the
        anchor of the ``python:`` origin check; required when ``extensions`` holds a
        ``python:`` spec. Pass it as the user spelled it, never pre-resolved, and
        absolute against the logical current directory when the caller knows one: a
        relative ``root`` is made absolute against the physical ``os.getcwd()`` (this
        function never reads ``$PWD``), which can hide a checkout entered through an
        outward symlink (M6, amended 2026-11-03, N5/I2).
    :param strict: Whether warnings are blocking (``--strict``); feeds ``outcome``.
    :param extensions: Extension specs equivalent to ``--extension`` (``builtin:<name>``
        or ``python:<module>:<callable>``), resolved after ``config.telemetry_extensions``;
        or a registry already resolved by
        ``resolve_extensions`` (as the CLI does
        before the scan), used as-is.
    :param allow_python_extensions: The explicit trust gate for ``python:`` specs;
        never taken from the environment.
    :returns: The rendered report.
    :raises ValueError: If the template is unknown, unreadable, invalid, needs an
        extension that is not loaded, or fails to render; the message is bounded and
        neutralized, and the ``TemplateError``
        is chained as the cause.
    :raises docsentinel.telemetry.extensions.ExtensionError: If an extension is
        refused (including a ``python:`` spec without ``root``), cannot be loaded, or
        fails, or a ``python:`` extension imported a module from the checkout during
        the render (a ``ValueError``; bounded message).
    :raises docsentinel.config.ConfigError: If ``config.telemetry_extensions`` holds a
        non-``builtin:`` entry.
    """
    settings = config if config is not None else Config()
    if isinstance(extensions, LoadedExtensions):
        loaded = extensions
    else:
        if root is None and allow_python_extensions is True and _has_python_spec(extensions):
            raise ExtensionError(
                "a python: extension needs root= (the scan root) so its origin can be checked against the checkout"
            )
        # root/cwd only feed the M6 origin check of a python: spec, so a plain render
        # never reads the process cwd (it may no longer exist).
        needs_origin = _has_python_spec(extensions)
        loaded = resolve_extensions(
            extensions,
            config=settings,
            allow_python=allow_python_extensions,
            root=Path(root) if root is not None else (Path.cwd() if needs_origin else Path(".")),
            cwd=Path.cwd() if needs_origin else Path("."),
        )
    if loaded.builtin_specs != settings.telemetry_extensions:
        # The effective Config names exactly the loaded builtins (argv specs merged),
        # so domain_for -- hence doc.domain -- sees builtin:domain only when it runs (M24).
        settings = replace(settings, telemetry_extensions=loaded.builtin_specs)
    try:
        chosen = _resolve(format, template, settings, root)
        check_template(chosen, loaded)
        context = ReportModel.build(
            result,
            settings,
            extensions=loaded,
            strict=strict,
            report_include_run_meta=settings.report_include_run_meta,
            report_schema_version=chosen.schema_version or REPORT_SCHEMA_VERSION,
            show_clean_documents=settings.report_show_clean_documents,
        )
        report = render_template(chosen, context, extensions=loaded)
    except TemplateError as exc:
        raise ValueError(str(exc)) from exc
    loaded.check_modules()
    return report
