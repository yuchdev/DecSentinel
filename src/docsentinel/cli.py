"""Command-line access to the shared scan engine."""

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from typing import Optional

from docsentinel import deep_support
from docsentinel.baseline import save_baseline
from docsentinel.config import Config, ConfigError, load_config
from docsentinel.detectors.loader import ensure_standard_loaded
from docsentinel.engine import scan
from docsentinel.errors import ExtraNotInstalledError
from docsentinel.models import ScanResult
from docsentinel.reporting import neutralize_text, render
from docsentinel.rules import Rule, rules_for_profile
from docsentinel.telemetry.filters import TemplateError
from docsentinel.telemetry.loader import (
    DEFAULT_TEMPLATE,
    Template,
    available_templates,
    load_named_template,
    load_template,
    packaged_template_names,
)

TEMPLATE = (
    'profile = "fast"\n'
    'include = ["*.md", "**/*.md"]\n'
    'exclude = [".git", ".venv", "node_modules"]\n'
    "select = []\n"
    "ignore = []\n"
    "\n"
    '# Standard profile thresholds (profile = "standard"); defaults shown.\n'
    "# max_grade_level = 14.0          # DS201: flag prose above this readability grade\n"
    "# duplicate_similarity = 0.85     # DS202: flag paragraph pairs at/above this cosine similarity\n"
    "# min_information_score = 0.15    # DS203: flag paragraphs scoring below this information score\n"
    '# docsig_paths = ["src"]          # DS204: Python source roots checked against docstrings\n'
    "#\n"
    "# Statistical size limits (standard profile); defaults shown.\n"
    "# min_document_words = 50         # DS201: skip documents with fewer prose words\n"
    "# min_paragraph_words = 5         # DS202/DS203: skip paragraphs with fewer words\n"
    "# min_paragraph_chars = 30        # DS202/DS203: skip paragraphs shorter than this\n"
)


def _opt_in_suffix(rule: Rule) -> str:
    """Return the ``rules`` listing suffix marking an opt-in policy rule, else empty.

    :param rule: A registered rule.
    :returns: ``" [opt-in: set <option>]"`` for an opt-in policy rule, or ``""``
        for an ordinary always-active rule.
    """
    return f" [opt-in: set {rule.opt_in_option}]" if rule.opt_in_option else ""


def _standard_rule_lines() -> list[str]:
    """Return formatted rule lines for the standard profile, or install guidance if missing."""
    try:
        ensure_standard_loaded()
    except ExtraNotInstalledError:
        missing_msg = ["standard profile: install docsentinel[standard] to enable (DS2xx)"]
        return missing_msg
    registered = rules_for_profile("standard")
    if registered:
        return [f"  {rule.code}: {rule.title}{_opt_in_suffix(rule)}" for rule in registered]
    return ["  (none registered)"]


def _deep_doctor_lines() -> list[str]:
    """Return formatted lines for doctor describing deep profile readiness."""
    libs = deep_support.libraries_available()
    model = deep_support.model_available()
    ready = deep_support.deep_ready()

    lines = []
    if ready:
        lines.append("deep profile: ready")
        lines.append("  ✓ deep libraries installed (spacy, textacy)")
        lines.append(f"  ✓ deep model installed ({deep_support.MODEL_NAME})")
    else:
        lines.append("deep profile: not ready")
        if libs:
            lines.append("  ✓ deep libraries installed (spacy, textacy)")
        else:
            lines.append(f"  ✗ deep libraries missing: {deep_support.DEEP_EXTRA_HINT}")
        if model:
            lines.append(f"  ✓ deep model installed ({deep_support.MODEL_NAME})")
        else:
            lines.append(
                f"  ✗ deep model missing ({deep_support.MODEL_NAME}): python -m spacy download {deep_support.MODEL_NAME}"
            )
    return lines


def _exit_code(result: ScanResult, *, strict: bool = False) -> int:
    """Return the exit code for a scan result.

    Deep profile findings are heuristic candidates and advisory-only: they never fail
    the exit code (returning 0), even when strict is True. This profile-keyed exemption
    ensures candidate contradictions inform review without breaking builds.
    A future --fail-on-deep flag / deep_fail setting is deferred.

    For fast and standard profiles, returns 1 if strict mode is enabled and there are any
    findings, or if any finding has severity == "error". Otherwise, returns 0.
    """
    if result.profile == "deep":
        return 0
    if strict:
        return 1 if result.findings else 0
    return 1 if any(finding.severity == "error" for finding in result.findings) else 0


def _report_template(format_name: str, template_path: Optional[Path], settings: Config, root: Path) -> Template:
    """Resolve the report template for ``scan`` before the scan runs.

    ``--template PATH`` wins and is trusted invoker input, read through the loader's
    regular-file/size/encoding gate. Otherwise ``--format`` must name one of the
    discovered templates (packaged, then ``report_templates_dir``).

    :param format_name: The ``--format`` value.
    :param template_path: The ``--template`` value, or ``None``.
    :param settings: The effective configuration.
    :param root: The scan root directory ``report_templates_dir`` is relative to.
    :returns: The validated template.
    :raises TemplateError: When the template is unknown, unreadable or invalid.
    """
    if template_path is not None:
        return load_template(template_path)
    names = available_templates(root, settings.report_templates_dir)
    if format_name not in names:
        raise TemplateError(f"unknown --format {format_name[:80]!r}; choose from: {', '.join(names)}")
    return load_named_template(format_name, root=root, templates_dir=settings.report_templates_dir)


def _doctor_template_lines() -> list[str]:
    """Return the ``doctor`` lines listing the selectable report templates.

    The packaged templates are always listed. When the configuration discovered in
    the current directory sets ``report_templates_dir``, its templates are listed
    too; a configuration or directory problem is reported on one neutralized line
    instead of failing ``doctor``.

    :returns: The formatted lines.
    """
    lines = [f"report templates (packaged): {', '.join(packaged_template_names())}"]
    try:
        settings = load_config(Path.cwd())
        if settings.report_templates_dir:
            packaged = set(packaged_template_names())
            extra = [
                name for name in available_templates(Path.cwd(), settings.report_templates_dir) if name not in packaged
            ]
            lines.append(f"report templates (report_templates_dir): {', '.join(extra) or '(none)'}")
    except (ConfigError, TemplateError, OSError) as exc:
        lines.append(f"report templates (report_templates_dir): unavailable: {neutralize_text(str(exc))}")
    return lines


PROJECT_ROOT_MARKERS = ("uv.lock", "pyproject.toml")


def find_project_root(start: Path) -> Optional[Path]:
    """Find the nearest directory at or above ``start`` that marks a project root.

    Parameters
    ----------
    start : Path
        Directory to begin the upward search from.

    Returns
    -------
    Optional[Path]
        The first directory holding ``uv.lock`` or ``pyproject.toml``, or ``None`` when
        the search reaches the filesystem root without finding either.
    """
    current = start.resolve()
    for candidate in (current, *current.parents):
        if any((candidate / marker).is_file() for marker in PROJECT_ROOT_MARKERS):
            return candidate
    return None


def _run_init(root: Path, *, project_root: bool, assume_yes: bool) -> int:
    """Create a starter ``docsentinel.toml``.

    Parameters
    ----------
    root : Path
        Directory to create the file in, or to start the project-root search from.
    project_root : bool
        When true, use the nearest ancestor of ``root`` holding ``uv.lock`` or ``pyproject.toml``.
    assume_yes : bool
        When true, never ask for confirmation. Without it, confirmation is requested only
        when standard input is an interactive terminal, so scripts and CI never block.

    Returns
    -------
    int
        0 when the file was created or the user declined, 2 on failure.
    """
    directory = root
    if project_root:
        found = find_project_root(root)
        if found is None:
            names = " or ".join(PROJECT_ROOT_MARKERS)
            print(f"No {names} found at or above {root.resolve()}", file=sys.stderr)
            return 2
        directory = found
    target = directory / "docsentinel.toml"
    legacy = directory / "doc_sentinel.toml"
    if legacy.exists():
        print(f"{legacy} already configures DocSentinel; not creating a second config file", file=sys.stderr)
        return 2
    if not assume_yes and sys.stdin.isatty():
        try:
            answer = input(f"Create {target}? [Y/n] ").strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("", "y", "yes"):
            print("Aborted: no file created")
            return 0
    try:
        with target.open("x", encoding="utf-8") as stream:
            stream.write(TEMPLATE)
    except OSError as exc:
        print(f"Cannot create {target}: {neutralize_text(str(exc))}", file=sys.stderr)
        return 2
    print(f"Created {target}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Run the DocSentinel command line interface.

    Parameters
    ----------
    argv : Optional[list[str]]
        Command-line arguments; defaults to ``sys.argv[1:]`` when omitted.

    Returns
    -------
    int
        Process exit code: 0 on success, 1 for blocking findings, 2 on failure.
    """
    parser = argparse.ArgumentParser(prog="docsentinel")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Inventory Markdown documents")
    scan_parser.add_argument("root", nargs="?", default=".", help="Directory or file to check")
    scan_parser.add_argument("--config", type=Path)
    scan_parser.add_argument("--profile", choices=("fast", "standard", "deep"))
    scan_parser.add_argument("--select", type=str, default=None)
    scan_parser.add_argument("--ignore", type=str, default=None)
    scan_parser.add_argument("--baseline", type=Path, default=None)
    scan_parser.add_argument(
        "--format",
        default=DEFAULT_TEMPLATE,
        metavar="NAME",
        help=(
            f"Report template name: one of {', '.join(packaged_template_names())}, "
            "or a template in report_templates_dir (default: %(default)s)"
        ),
    )
    scan_parser.add_argument(
        "--template",
        type=Path,
        default=None,
        metavar="PATH",
        help="Render with this template file (wins over --format)",
    )
    scan_parser.add_argument(
        "--show-clean-documents",
        action="store_true",
        help="List documents without problems in the text report as well",
    )
    scan_parser.add_argument("--strict", action="store_true")
    scan_parser.add_argument(
        "--i-understand-deep-is-heuristic",
        action="store_true",
        dest="deep_confirm",
        help="Explicitly confirm execution of heuristic deep profile detectors",
    )
    baseline_parser = commands.add_parser("baseline", help="Record current findings into a baseline file")
    baseline_parser.add_argument("root", nargs="?", default=".", help="Directory or file to check")
    baseline_parser.add_argument("--config", type=Path)
    baseline_parser.add_argument("--output", type=Path)
    baseline_parser.add_argument("--profile", choices=("fast", "standard", "deep"))
    init_parser = commands.add_parser("init", help="Create a starter config")
    init_parser.add_argument(
        "root", nargs="?", default=".", help="Directory for docsentinel.toml (default: current directory)"
    )
    init_parser.add_argument(
        "--project-root",
        action="store_true",
        help="Create the file at the nearest ancestor of ROOT that holds uv.lock or pyproject.toml",
    )
    init_parser.add_argument(
        "--yes", "-y", action="store_true", help="Do not ask for confirmation when running in a terminal"
    )
    commands.add_parser("rules", help="List active detection rules")
    commands.add_parser("doctor", help="Show M0 capabilities")
    args = parser.parse_args(argv)
    if args.command == "init":
        return _run_init(Path(args.root), project_root=args.project_root, assume_yes=args.yes)
    if args.command == "rules":
        for profile in ("fast", "standard", "deep"):
            print(f"{profile}:")
            if profile == "standard":
                for line in _standard_rule_lines():
                    print(line)
            else:
                registered = rules_for_profile(profile)
                if registered:
                    for rule in registered:
                        print(f"  {rule.code}: {rule.title}{_opt_in_suffix(rule)}")
                else:
                    print("  (none registered)")
        return 0
    if args.command == "doctor":
        print("Inventory: available")
        standard_lines = _standard_rule_lines()
        if standard_lines == ["standard profile: install docsentinel[standard] to enable (DS2xx)"]:
            print("standard profile: not installed (pip install docsentinel[standard])")
        else:
            print("standard profile: available")
        for line in _deep_doctor_lines():
            print(line)
        for profile in ("fast", "standard", "deep"):
            registered = rules_for_profile(profile)
            opt_in = tuple(rule for rule in registered if rule.opt_in_option)
            summary = f"{profile} rules: {len(registered)} registered"
            if opt_in:
                codes = ", ".join(rule.code for rule in opt_in)
                summary += f" ({len(opt_in)} opt-in, off unless configured: {codes})"
            print(summary)
        for line in _doctor_template_lines():
            print(line)
        return 0
    if args.command == "baseline":
        try:
            target = Path(args.root).resolve()
            directory = target.parent if target.is_file() else target
            settings = load_config(directory, args.config)
            if args.profile is not None:
                settings = replace(settings, profile=args.profile)
            if args.output is not None:
                output_path = Path(args.output) if Path(args.output).is_absolute() else Path.cwd() / args.output
            elif settings.baseline is not None:
                output_path = (
                    Path(settings.baseline) if Path(settings.baseline).is_absolute() else directory / settings.baseline
                )
            else:
                output_path = directory / ".docsentinel-baseline.json"

            unbaselined_config = replace(settings, baseline=None)
            result = scan(args.root, config=unbaselined_config)
            save_baseline(output_path, result.findings)
        except (ConfigError, ValueError, OSError) as exc:
            print(f"Baseline generation failed: {neutralize_text(str(exc))}", file=sys.stderr)
            return 2
        print(f"Saved baseline: {output_path}")
        return 0
    try:
        target = Path(args.root).resolve()
        directory = target.parent if target.is_file() else target
        settings = load_config(directory, args.config)
        changes = {}
        if args.profile is not None:
            changes["profile"] = args.profile
        if args.select is not None:
            changes["select"] = tuple(item.strip() for item in args.select.split(",") if item.strip())
        if args.ignore is not None:
            changes["ignore"] = tuple(item.strip() for item in args.ignore.split(",") if item.strip())
        if args.baseline is not None:
            changes["baseline"] = str(args.baseline)
        if getattr(args, "deep_confirm", False):
            changes["deep_confirm"] = True
        if args.show_clean_documents:
            changes["report_show_clean_documents"] = True
        if changes:
            settings = replace(settings, **changes)
        template = _report_template(args.format, args.template, settings, directory)
        result = scan(args.root, config=settings)
        report = render(result, config=settings, template=template, root=directory, strict=args.strict)
    except (ConfigError, ValueError, OSError, TemplateError, NotImplementedError) as exc:
        print(f"Scan failed: {neutralize_text(str(exc))}", file=sys.stderr)
        return 2
    print(report)
    return _exit_code(result, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
