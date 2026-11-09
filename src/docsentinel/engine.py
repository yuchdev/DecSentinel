"""Single entry point for all scan consumers."""

import inspect
import os
from functools import lru_cache
from pathlib import Path
from typing import Callable, Optional, Union

from docsentinel.baseline import filter_baselined, load_baseline
from docsentinel.config import Config, load_config
from docsentinel.deep_support import DEEP_EXTRA_HINT, deep_ready
from docsentinel.detectors.loader import clear_standard_caches, ensure_standard_loaded
from docsentinel.discovery import discover
from docsentinel.link_root import LINK_ROOT_RULES, resolve_invoker_link_root, resolve_link_root
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.rules import ANALYZERS, RULES, effective_rules, opt_in_satisfied

Analyzer = Callable[..., tuple[Finding, ...]]


#: Dispatch mode for an analyzer: it takes no config (legacy two-argument form),
#: config as a keyword (``config=settings``), or config as a third positional
#: argument (``settings`` after ``root`` and ``documents``).
_CONFIG_NONE = "none"
_CONFIG_KEYWORD = "keyword"
_CONFIG_POSITIONAL = "positional"


@lru_cache(maxsize=256)
def _analyzer_config_mode(analyzer: Analyzer) -> str:
    """Return how the engine must forward effective config to an analyzer.

    The preferred analyzer contract is ``detect(root, documents, config=None)``,
    while the legacy ``detect(root, documents)`` two-argument form stays
    supported. Inspecting the signature lets the engine always forward effective
    config to analyzers that accept it without breaking two-argument detectors,
    and -- critically -- choose *how* to pass it so the call never raises
    ``TypeError`` from a missing positional slot:

    * A parameter literally named ``config`` that is keyword-acceptable
      (positional-or-keyword or keyword-only) is filled as ``config=settings``,
      which works for both ``detect(..., config=None)`` and a keyword-only
      ``detect(..., *, config=None)``.
    * A ``*args`` (``VAR_POSITIONAL``) analyzer, or one declaring three or more
      ordinary positional parameters with no ``config`` name, receives config as
      a third positional argument.
    * Everything else -- including a ``**kwargs``-only callable, which has **no**
      third positional slot and so would raise if called positionally -- is the
      legacy two-argument form. ``VAR_KEYWORD`` alone therefore does *not* mark
      an analyzer as config-aware.

    Registered analyzers are ordinarily module-level functions whose signatures
    introspect cleanly, but some callables (for example C builtins or objects
    whose ``__signature__`` raises) cannot be inspected; those raise
    ``ValueError`` or ``TypeError`` from :func:`inspect.signature` and are
    treated as the legacy two-argument form rather than crashing the scan. The
    cache has a fixed ``maxsize``; once it is full the least-recently-used entry
    is evicted, so an evicted analyzer is simply re-introspected on its next use
    (a bounded, repeatable cost) rather than the cache growing without bound.

    :param analyzer: A registered analyzer callable.
    :returns: One of :data:`_CONFIG_NONE`, :data:`_CONFIG_KEYWORD`, or
        :data:`_CONFIG_POSITIONAL`.
    """
    try:
        signature = inspect.signature(analyzer)
    except (ValueError, TypeError):
        # A callable whose signature cannot be introspected (for example a C
        # builtin, or an object whose __signature__ raises) cannot declare a
        # config parameter; record that absence and dispatch it below via the
        # legacy two-argument form rather than swallowing the condition here.
        signature = None
    if signature is None:
        return _CONFIG_NONE
    parameters = list(signature.parameters.values())
    config_param = signature.parameters.get("config")
    if config_param is not None and config_param.kind in (
        inspect.Parameter.KEYWORD_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    ):
        return _CONFIG_KEYWORD
    if any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters):
        return _CONFIG_POSITIONAL
    positional = [
        parameter
        for parameter in parameters
        if parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) >= 3:
        return _CONFIG_POSITIONAL
    return _CONFIG_NONE


@lru_cache(maxsize=256)
def _analyzer_accepts_link_root(analyzer: Analyzer) -> bool:
    """Return True when an analyzer declares a keyword-acceptable ``link_root`` parameter.

    Analyzers that resolve site-root-absolute (``/``) targets accept the engine's
    validated link root as ``link_root=``; every other analyzer is called exactly as
    before. Signatures that cannot be introspected are treated as not accepting it.

    :param analyzer: A registered analyzer callable.
    :returns: True when ``link_root`` is forwarded by keyword.
    """
    try:
        parameter = inspect.signature(analyzer).parameters.get("link_root")
    except (ValueError, TypeError):
        # Not introspectable: it cannot declare link_root; call it the legacy way.
        parameter = None
    return parameter is not None and parameter.kind in (
        inspect.Parameter.KEYWORD_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    )


def _analyzer_accepts_config(analyzer: Analyzer) -> bool:
    """Return True when the engine forwards effective config to an analyzer.

    This is a thin predicate over :func:`_analyzer_config_mode`; the mode also
    records *how* config is forwarded so the call cannot raise ``TypeError``.

    :param analyzer: A registered analyzer callable.
    :returns: True when config is forwarded (by keyword or position), else False.
    """
    return _analyzer_config_mode(analyzer) != _CONFIG_NONE


def _run_analyzer(
    analyzer: Analyzer,
    directory: Path,
    documents: tuple[Document, ...],
    settings: Config,
    link_root: Optional[Path] = None,
) -> tuple[Finding, ...]:
    """Invoke an analyzer, forwarding effective config when its signature accepts it.

    :param analyzer: The analyzer callable to run.
    :param directory: The resolved scan root directory.
    :param documents: Discovered documents to inspect, in scan order.
    :param settings: Effective settings for this scan.
    :param link_root: The engine-validated link root, forwarded as ``link_root=``
        to analyzers that declare it; ``None`` forwards nothing.
    :returns: The analyzer's findings.
    """
    extra: dict[str, Path] = {}
    if link_root is not None and _analyzer_accepts_link_root(analyzer):
        extra["link_root"] = link_root
    mode = _analyzer_config_mode(analyzer)
    if mode == _CONFIG_KEYWORD:
        return analyzer(directory, documents, config=settings, **extra)
    if mode == _CONFIG_POSITIONAL:
        return analyzer(directory, documents, settings, **extra)
    return analyzer(directory, documents, **extra)


def _env_confirms() -> bool:
    """Return True if DOCSENTINEL_DEEP_CONFIRM is set to a truthy value."""
    return os.environ.get("DOCSENTINEL_DEEP_CONFIRM", "").lower() in {"1", "true", "yes"}


def _resolve_deep_confirm(settings: Config) -> bool:
    """Return True if deep profile execution is confirmed via settings or env."""
    return settings.deep_confirm or _env_confirms()


def evaluated_notice(profile: str, rules_evaluated: int, opt_in_off: tuple[tuple[str, str], ...]) -> str:
    """Build the legacy ``ScanResult.notice`` for a scan that ran at least one active rule.

    This is the single source of the notice text: :func:`scan` stores
    ``rules_evaluated`` and ``opt_in_off`` on the result and derives the notice from
    them here, so the structured fields and the string can never disagree.

    :param profile: The scan profile (``fast``/``standard``/``deep``).
    :param rules_evaluated: Active rules that genuinely evaluated.
    :param opt_in_off: ``(code, option)`` pairs for active opt-in rules whose policy is off.
    :returns: The byte-identical legacy notice string.
    """
    if profile == "deep":
        # The deep notice has always counted every active rule.
        return f"{rules_evaluated + len(opt_in_off)} deep rule(s) evaluated (heuristic, advisory-only)."
    notice = f"{rules_evaluated} {profile} rule(s) evaluated"
    if opt_in_off:
        disabled = ", ".join(f"{code} (set {option})" for code, option in opt_in_off)
        return f"{notice}; opt-in rule(s) not enabled: {disabled}."
    return f"{notice}."


def scan(
    root: Union[Path, str] = ".",
    *,
    config: Optional[Config] = None,
    link_root: Optional[Union[Path, str]] = None,
) -> ScanResult:
    """Inventory documents and run registered analyzers, without implicit deep checks.

    :param root: The directory or single file to scan.
    :param config: Settings to use verbatim, or ``None`` to load them from ``root``.
    :param link_root: Trusted invoker override for the base of site-root-absolute
        (``/``) targets (``scan --link-root``): an absolute path or one relative to the
        current directory that must resolve to an existing scan root or ancestor (not
        the filesystem root). It wins over ``config.link_root``; ``None`` uses the
        configured, bounded value.
    :returns: The scan result.
    :raises ConfigError: When the configured or invoker link root is invalid.
    """
    target = Path(root).resolve()
    selected_file = target.is_file()
    directory = target.parent if selected_file else target
    settings = config if config is not None else load_config(directory)
    if selected_file:
        # An explicitly selected file bypasses include/exclude patterns.
        if Path(root).is_symlink():
            raise ValueError(f"Symlinked files are not inventoried: {root}")
        documents = (Document(target.name, target.stat().st_size),)
    else:
        documents = discover(directory, settings)

    if settings.profile == "deep":
        if not _resolve_deep_confirm(settings):
            pending = (
                "deep profile requires explicit opt-in: set deep_confirm = true, "
                "pass --i-understand-deep-is-heuristic, or set DOCSENTINEL_DEEP_CONFIRM=1 "
                "(deep checks are heuristic and may report false positives)",
            )
            return ScanResult(
                profile=settings.profile,
                documents=documents,
                findings=(),
                enabled_rules=(),
                pending=pending,
                notice="Deep profile detection skipped until explicit opt-in is provided.",
            )
        if not deep_ready():
            pending = (f"deep profile confirmed, but its dependencies are unavailable - {DEEP_EXTRA_HINT}",)
            return ScanResult(
                profile=settings.profile,
                documents=documents,
                findings=(),
                enabled_rules=(),
                pending=pending,
                notice="Deep profile detection skipped because dependencies are unavailable.",
            )

    if settings.profile == "standard":
        ensure_standard_loaded()
        clear_standard_caches()

    profile_codes = tuple(code for code, rule in RULES.items() if rule.profile == settings.profile)
    active_codes = effective_rules(profile_codes, settings.select, settings.ignore)
    # Resolve ``link_root`` once per scan (the ``.git`` walk runs a single time, and
    # only when a rule that resolves ``/`` targets is active) and hand the validated
    # directory to the analyzers that declare ``link_root``; an invalid or unbounded
    # value fails closed with ConfigError before any analyzer runs.
    # An invoker override is validated unconditionally (trusted input, fail closed).
    if link_root is not None:
        resolved_link_root: Optional[Path] = resolve_invoker_link_root(directory, link_root)
    elif LINK_ROOT_RULES.intersection(active_codes):
        resolved_link_root = resolve_link_root(directory, settings)
    else:
        resolved_link_root = None
    findings = tuple(
        finding
        for code in active_codes
        if code in ANALYZERS
        for finding in _run_analyzer(ANALYZERS[code], directory, documents, settings, resolved_link_root)
    )
    if settings.baseline is not None:
        baseline_path = (
            Path(settings.baseline)
            if Path(settings.baseline).is_absolute()
            else (directory / settings.baseline).resolve()
        )
        known = load_baseline(baseline_path)
        findings = filter_baselined(findings, known)
    rules_evaluated = 0
    opt_in_off: tuple[tuple[str, str], ...] = ()
    if active_codes:
        pending = ()
        # Opt-in policy rules that are active but whose policy is off evaluate
        # nothing, so the notice must not count them among the evaluated rules;
        # it names them instead so a disabled policy never masquerades as audited.
        opt_in_off = tuple(
            (code, RULES[code].opt_in_option) for code in active_codes if not opt_in_satisfied(RULES[code], settings)
        )
        rules_evaluated = len(active_codes) - len(opt_in_off)
        notice = evaluated_notice(settings.profile, rules_evaluated, opt_in_off)
    elif not profile_codes:
        if settings.profile == "deep":
            pending = ("deep profile confirmed, but no deep rules are registered",)
        else:
            pending = ("standard detectors are not implemented in M0",) if settings.profile == "standard" else ()
        notice = "Detection rules are not implemented in M0; this is an inventory only."
    else:
        pending = (f"all {settings.profile} rules were excluded by select/ignore",)
        notice = f"All {settings.profile} rules were excluded by select/ignore."
    return ScanResult(
        profile=settings.profile,
        documents=documents,
        findings=findings,
        enabled_rules=active_codes,
        pending=pending,
        notice=notice,
        rules_evaluated=rules_evaluated,
        opt_in_off=opt_in_off,
    )
