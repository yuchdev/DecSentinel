"""Unit tests for the report extension API, loader and data contract (Milestone 0007 Story 04.0 Task 01).

Each test cites the mitigation of ``docs/security/threat-model-0007-extensions-2026-11-03.md`` it
pins. Extensions here are in-memory objects admitted with ``admit_extensions`` or builtin factories
patched into the static table, so no module is ever imported.
"""

import importlib
import importlib.util
import math
import sys
import tracemalloc
import types
from types import MappingProxyType, SimpleNamespace
from typing import Any, Optional

import pytest

from docsentinel import config as config_module
from docsentinel.config import Config, ConfigError
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.telemetry import builtin, engine, extensions, filters, loader
from docsentinel.telemetry.extensions import (
    EXTENSION_NAME_PATTERN,
    EventHookGuard,
    ExtensionError,
    ExtensionFilter,
    LoadedExtensions,
    admit_extensions,
    load_python_target,
    resolve_extensions,
    validated_copy,
)
from docsentinel.telemetry.model import ReportModel

ESC = chr(0x1B)
RLO = chr(0x202E)

_FINDING = Finding(rule="DS101", path="b.md", message="dangling link -> x.md", severity="error", line=2)


def _result(findings: tuple[Finding, ...] = (_FINDING,)) -> ScanResult:
    """Build a tiny scan result over two documents (``a.md`` clean)."""
    return ScanResult(
        profile="fast",
        documents=(Document("a.md", 1), Document("b.md", 2)),
        findings=findings,
        enabled_rules=("DS101",),
        pending=(),
        notice="1 fast rule(s) evaluated.",
        rules_evaluated=1,
    )


def _ext(name: str = "calc", **hooks: Any) -> SimpleNamespace:
    """Return an extension object carrying only the given hooks."""
    return SimpleNamespace(name=name, **hooks)


def _build(*objects: object, result: Optional[ScanResult] = None) -> dict[str, Any]:
    """Build the report context with the given extension objects admitted."""
    return ReportModel.build(result or _result(), Config(), extensions=admit_extensions(objects))


@pytest.fixture
def no_import(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make ``import_module``/``find_spec`` raise and record any call."""
    calls: list[str] = []

    def refuse(name: str, *args: Any, **kwargs: Any) -> Any:
        calls.append(name)
        raise AssertionError(f"import machinery called for {name}")

    monkeypatch.setattr(importlib, "import_module", refuse)
    monkeypatch.setattr(importlib.util, "find_spec", refuse)
    return calls


@pytest.fixture
def calc_builtin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Register a ``calc`` builtin in the static table for the duration of a test."""
    factory = lambda: _ext("calc", provide_run=lambda model: {"documents": len(model["documents"])})  # noqa: E731
    monkeypatch.setattr(builtin, "BUILTIN_EXTENSIONS", MappingProxyType({"calc": factory}))


# --------------------------------------------------------------------------- M5 grammar, builtins


@pytest.mark.parametrize(
    "spec",
    [
        "python:.rel:x",
        "python:os:__class__",
        "python:m:_private",
        "python:m",
        "python:m:a:b",
        "python:m:" + "a" * 260,
        "python:a..b:x",
        "python:m:a.__dict__",
    ],
)
def test_python_spec_grammar_is_refused_before_any_import(spec: str, no_import: list[str], tmp_path):
    """
    [Unit] extensions: verifies malformed python: specs are refused at the grammar stage (M5).

    Scenario:
        Given a relative module, a dunder or underscore callable, a wrong part count or an over-long spec
        When load_python_target runs with the gate open
        Then an ExtensionError is raised and the import machinery is never called.

    Boundaries:
        - Focus: threat model T2/M5 grammar
        - Fixtures/params: one spec per case; ``no_import`` makes import_module/find_spec raise
        - Scope: load_python_target

    On failure, first check:
        - ``extensions._MODULE_RE`` / ``_CALLABLE_RE`` / ``MAX_SPEC_CHARS``
    """
    with pytest.raises(ExtensionError):
        load_python_target(spec, allow_python=True, root=tmp_path, cwd=tmp_path)
    assert no_import == []


@pytest.mark.parametrize("spec", ["builtin:../x", "builtin:os", "builtin:__init__", "builtin:domain", "other:x", ""])
def test_unknown_or_malformed_builtin_is_refused_without_import(spec: str, no_import: list[str], tmp_path):
    """
    [Unit] extensions: verifies a builtin spec resolves only through the static table (M5).

    Scenario:
        Given a traversal, a stdlib module name, a dunder, a not-yet-shipped builtin and an unknown prefix
        When resolve_extensions runs
        Then each is an ExtensionError and import_module/find_spec are never called.

    Boundaries:
        - Focus: threat model M5 builtin table
        - Fixtures/params: one spec per case
        - Scope: resolve_extensions

    On failure, first check:
        - ``builtin.builtin_factory`` and ``extensions._parse_spec``
    """
    with pytest.raises(ExtensionError):
        resolve_extensions((spec,), config=Config(), allow_python=True, root=tmp_path, cwd=tmp_path)
    assert no_import == []


def test_builtin_resolves_through_the_static_table(calc_builtin: None, no_import: list[str], tmp_path):
    """
    [Unit] extensions: verifies builtin:<name> from config and argv loads with no gate and no import (M5, M25).

    Scenario:
        Given a ``calc`` builtin in the static table
        When it is selected from config, and separately from argv with the gate closed
        Then it loads, its spec is reported for the effective Config, and nothing is imported.

    Boundaries:
        - Focus: builtin selection, config-first merge order
        - Fixtures/params: ``calc_builtin``, ``no_import``
        - Scope: resolve_extensions

    On failure, first check:
        - ``resolve_extensions`` ordering and ``LoadedExtensions.builtin_specs``
    """
    from_config = resolve_extensions(
        (), config=Config(telemetry_extensions=("builtin:calc",)), allow_python=False, root=tmp_path, cwd=tmp_path
    )
    from_argv = resolve_extensions(("builtin:calc",), config=Config(), allow_python=False, root=tmp_path, cwd=tmp_path)

    assert from_config.names == from_argv.names == ("calc",)
    assert from_argv.builtin_specs == ("builtin:calc",)
    assert no_import == []


def test_spec_given_twice_is_refused(calc_builtin: None, tmp_path):
    """
    [Unit] extensions: verifies one spec in config and argv (or twice in argv) is an ExtensionError (M25).

    Scenario:
        Given ``builtin:calc`` in config and again on argv, and twice on argv
        When resolve_extensions runs
        Then both are refused.

    Boundaries:
        - Focus: duplicate spec detection
        - Fixtures/params: ``calc_builtin``
        - Scope: resolve_extensions

    On failure, first check:
        - the ``seen`` set in ``resolve_extensions``
    """
    with pytest.raises(ExtensionError, match="given twice"):
        resolve_extensions(
            ("builtin:calc",),
            config=Config(telemetry_extensions=("builtin:calc",)),
            allow_python=False,
            root=tmp_path,
            cwd=tmp_path,
        )
    with pytest.raises(ExtensionError, match="given twice"):
        resolve_extensions(
            ("builtin:calc", "builtin:calc"), config=Config(), allow_python=False, root=tmp_path, cwd=tmp_path
        )


def test_builtin_reporting_a_different_name_is_refused(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """
    [Unit] extensions: verifies a builtin factory must return an extension carrying its table name.

    Scenario:
        Given the table entry ``calc`` whose factory returns an extension named ``other``
        When it is resolved
        Then an ExtensionError is raised.

    Boundaries:
        - Focus: builtin identity
        - Fixtures/params: patched builtin table
        - Scope: resolve_extensions

    On failure, first check:
        - the ``expected`` check in ``extensions._admit``
    """
    monkeypatch.setattr(builtin, "BUILTIN_EXTENSIONS", MappingProxyType({"calc": lambda: _ext("other")}))
    with pytest.raises(ExtensionError, match="different name"):
        resolve_extensions(("builtin:calc",), config=Config(), allow_python=False, root=tmp_path, cwd=tmp_path)


def test_injected_config_with_a_python_entry_is_a_config_error(tmp_path, no_import: list[str]):
    """
    [Unit] extensions: verifies the resolver re-checks an injected Config and refuses python: there (M1).

    Scenario:
        Given a hand-built Config whose telemetry_extensions holds a python: spec
        When resolve_extensions runs with the gate open
        Then a ConfigError is raised and nothing is imported.

    Boundaries:
        - Focus: threat model M1 for library callers that bypass load_config
        - Fixtures/params: ``no_import``
        - Scope: resolve_extensions

    On failure, first check:
        - ``config.validate_telemetry_extensions`` call at the top of ``resolve_extensions``
    """
    with pytest.raises(ConfigError, match="builtin"):
        resolve_extensions(
            (), config=Config(telemetry_extensions=("python:m:f",)), allow_python=True, root=tmp_path, cwd=tmp_path
        )
    assert no_import == []


# --------------------------------------------------------------------------- M13, M25 names and hooks


@pytest.mark.parametrize("name", ["Bad", "with-hyphen", "", "a" * 65, "1abc", "abc\n", 5, None])
def test_invalid_extension_name_is_refused(name: object):
    """
    [Unit] extensions: verifies the name must be an exact str matching EXTENSION_NAME_PATTERN (M13).

    Scenario:
        Given an upper-case, hyphenated, empty, over-long, digit-led, newline-terminated or non-str name
        When the extension is admitted
        Then an ExtensionError is raised.

    Boundaries:
        - Focus: name grammar (T14 fix: no hyphen)
        - Fixtures/params: one name per case
        - Scope: admit_extensions

    On failure, first check:
        - ``extensions._NAME_RE``
    """
    with pytest.raises(ExtensionError, match="name"):
        admit_extensions([_ext(name)])  # type: ignore[arg-type]


def test_str_subclass_name_is_refused():
    """
    [Unit] extensions: verifies a str subclass name is refused, so equality cannot be overridden (M13).

    Scenario:
        Given an extension whose name is a ``str`` subclass
        When it is admitted
        Then an ExtensionError is raised.

    Boundaries:
        - Focus: exact-type name check
        - Fixtures/params: none
        - Scope: admit_extensions

    On failure, first check:
        - ``type(name) is not str`` in ``extensions._admit``
    """

    class Sneaky(str):
        pass

    with pytest.raises(ExtensionError):
        admit_extensions([_ext(Sneaky("calc"))])  # type: ignore[arg-type]


def test_name_property_is_read_once():
    """
    [Unit] extensions: verifies a name property that changes per access is read exactly once (M13).

    Scenario:
        Given an extension whose ``name`` returns ``calc`` then ``domain``
        When it is admitted and its hooks run
        Then it stays ``calc`` and the property was read once.

    Boundaries:
        - Focus: TOCTOU on the self-declared name (T5)
        - Fixtures/params: none
        - Scope: admit_extensions and ReportModel.build

    On failure, first check:
        - ``extensions._admit`` storing the name
    """
    reads: list[int] = []

    class Shifty:
        @property
        def name(self) -> str:
            reads.append(1)
            return "calc" if len(reads) == 1 else "domain"

        def provide_run(self, model: Any) -> dict[str, Any]:
            return {"ok": True}

    loaded = admit_extensions([Shifty()])
    context = ReportModel.build(_result(), Config(), extensions=loaded)

    assert loaded.names == ("calc",)
    assert context["ext"] == {"calc": {"ok": True}}
    assert len(reads) == 1


def test_hooks_are_looked_up_once():
    """
    [Unit] extensions: verifies each hook is read once with getattr, never per call (M13).

    Scenario:
        Given an extension whose attribute lookups are counted
        When it is admitted and run over a result with two documents
        Then every hook name was looked up exactly once.

    Boundaries:
        - Focus: hook lookup
        - Fixtures/params: none
        - Scope: admit_extensions and ReportModel.build

    On failure, first check:
        - ``extensions._admit`` hook loop
    """
    lookups: list[str] = []

    class Counting:
        name = "calc"

        def __getattribute__(self, attribute: str) -> Any:
            lookups.append(attribute)
            return object.__getattribute__(self, attribute)

        def provide_document(self, doc: Any, model: Any) -> None:
            return None

    _build(Counting())

    for hook in ("name", "provide_run", "provide_document", "provide_problem", "filters"):
        assert lookups.count(hook) == 1, hook


def test_non_callable_hook_is_refused():
    """
    [Unit] extensions: verifies a hook attribute that is present but not callable is refused (M13).

    Scenario:
        Given an extension with ``provide_run = 3``
        When it is admitted
        Then an ExtensionError is raised.

    Boundaries:
        - Focus: hook validation
        - Fixtures/params: none
        - Scope: admit_extensions

    On failure, first check:
        - the ``callable`` check in ``extensions._admit``
    """
    with pytest.raises(ExtensionError, match="provide_run must be callable"):
        admit_extensions([_ext(provide_run=3)])


@pytest.mark.parametrize("name", ["domain", "document_stats"])
def test_python_extension_using_a_builtin_name_is_refused(name: str):
    """
    [Unit] extensions: verifies builtin names are reserved whether or not that builtin is loaded (M25).

    Scenario:
        Given a non-builtin extension named ``domain`` or ``document_stats``
        When it is admitted
        Then an ExtensionError naming the reservation is raised.

    Boundaries:
        - Focus: impersonation of a builtin (T9)
        - Fixtures/params: both reserved names
        - Scope: admit_extensions

    On failure, first check:
        - ``builtin.RESERVED_BUILTIN_NAMES``
    """
    with pytest.raises(ExtensionError, match="reserved"):
        admit_extensions([_ext(name)])


def test_two_extensions_with_one_name_are_refused():
    """
    [Unit] extensions: verifies two extensions sharing a name are an ExtensionError (M25).

    Scenario:
        Given two objects both named ``calc``
        When they are admitted together
        Then an ExtensionError is raised.

    Boundaries:
        - Focus: duplicate names
        - Fixtures/params: none
        - Scope: admit_extensions

    On failure, first check:
        - ``extensions._registry``
    """
    with pytest.raises(ExtensionError, match="two extensions"):
        admit_extensions([_ext(), _ext()])


# --------------------------------------------------------------------------- M13, M14, M26 data flow


def test_hook_data_is_namespaced_and_cannot_touch_core_keys():
    """
    [Unit] extensions: verifies returns land only under ext.<name> and never replace a core key (M26).

    Scenario:
        Given run/document/problem hooks returning ``profile``, ``path`` and ``ext`` keys
        When the model is built
        Then core values are unchanged and the returns sit under ``ext.calc`` at each level, flat findings included.

    Boundaries:
        - Focus: namespacing and the merge step building ``ext`` itself
        - Fixtures/params: none
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions.apply_report_hooks``
    """
    context = _build(
        _ext(
            provide_run=lambda model: {"profile": "forged", "ext": {"x": 1}},
            provide_document=lambda doc, model: {"path": "forged"},
            provide_problem=lambda problem, doc, model: {"message": "forged", "rule": doc["path"]},
        )
    )

    assert context["profile"] == "fast"
    assert context["ext"] == {"calc": {"profile": "forged", "ext": {"x": 1}}}
    assert [doc["path"] for doc in context["documents"]] == ["a.md", "b.md"]
    assert context["documents"][1]["ext"] == {"calc": {"path": "forged"}}
    problem = context["documents"][1]["problems"][0]
    assert problem["message"] == "dangling link -> x.md"
    assert problem["ext"] == {"calc": {"message": "forged", "rule": "b.md"}}
    assert context["findings"][0]["ext"] == problem["ext"]
    assert context["documents_with_problems"][0]["ext"] == {"calc": {"path": "forged"}}


def test_no_extension_leaves_the_context_without_ext():
    """
    [Unit] extensions: verifies the default context carries no ``ext`` key at any level.

    Scenario:
        Given no extensions, and an empty registry
        When the model is built
        Then no ``ext`` key appears, so default reports stay byte-identical.

    Boundaries:
        - Focus: additive change
        - Fixtures/params: none
        - Scope: ReportModel.build

    On failure, first check:
        - the ``extensions`` guard at the end of ``ReportModel.build``
    """
    for value in ((), LoadedExtensions()):
        context = ReportModel.build(_result(), Config(), extensions=value)
        assert "ext" not in context
        assert all("ext" not in doc for doc in context["documents"])
        assert all("ext" not in problem for problem in context["findings"])


def test_hook_arguments_are_deep_frozen():
    """
    [Unit] extensions: verifies a hook cannot mutate nested context through its arguments (M13).

    Scenario:
        Given a document hook that tries to set a problem message, append to problems and edit the model
        When the model is built
        Then each attempt raises inside the hook and the rendered context is unchanged.

    Boundaries:
        - Focus: deep-frozen read-only views
        - Fixtures/params: none
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions.freeze``
    """
    errors: list[str] = []

    def document(doc: Any, model: Any) -> None:
        for attempt in (
            lambda: doc["problems"][0].__setitem__("message", "x") if doc["problems"] else None,
            lambda: doc["problems"].append({}),
            lambda: model["documents"][0].__setitem__("path", "x"),
            lambda: model.__setitem__("profile", "x"),
        ):
            try:
                attempt()
            except (TypeError, AttributeError) as exc:
                errors.append(type(exc).__name__)
        return None

    context = _build(_ext(provide_document=document))

    assert len(errors) == 7  # two documents; the clean one has no problem to edit
    assert context["profile"] == "fast"
    assert context["documents"][0]["path"] == "a.md"
    assert context["documents"][1]["problems"][0]["message"] == "dangling link -> x.md"


def test_mutating_a_returned_tree_after_return_does_not_change_the_report():
    """
    [Unit] extensions: verifies copy-on-return: later mutation of a returned object has no effect (M14).

    Scenario:
        Given a problem hook that keeps every tree it returned and mutates the previous one on the next call
        When the model is built over two problems and the kept trees are mutated afterwards
        Then the context holds the values as returned.

    Boundaries:
        - Focus: TOCTOU between validation and render
        - Fixtures/params: two findings
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions.validated_copy`` builds fresh containers
    """
    kept: list[dict[str, Any]] = []

    def problem(item: Any, doc: Any, model: Any) -> dict[str, Any]:
        if kept:
            kept[-1]["n"] = "mutated"
            kept[-1]["list"].append("mutated")
        tree = {"n": len(kept), "list": [len(kept)]}
        kept.append(tree)
        return tree

    second = Finding(rule="DS101", path="a.md", message="m", severity="error", line=1)
    context = _build(_ext(provide_problem=problem), result=_result((_FINDING, second)))
    for tree in kept:
        tree["n"] = "late"

    values = [entry["ext"]["calc"] for entry in context["findings"]]
    assert sorted(value["n"] for value in values) == [0, 1]
    assert all(value["list"] == [value["n"]] for value in values)


class _DictSub(dict):
    pass


class _StrSub(str):
    pass


def _cyclic() -> dict[str, Any]:
    items: list[Any] = []
    items.append(items)
    return {"items": items}


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        (_DictSub(a=1), "must return a dict"),
        ({"a": _DictSub()}, "not exact JSON data"),
        ({"a": _StrSub("x")}, "not exact JSON data"),
        (_cyclic(), "cycle"),
        (MappingProxyType({"a": 1}), "must return a dict"),
        ({"a": {1, 2}}, "not exact JSON data"),
        ({"a": b"x"}, "not exact JSON data"),
        ([1], "must return a dict"),
    ],
)
def test_non_json_returns_are_refused(value: object, fragment: str):
    """
    [Unit] extensions: verifies subclasses, cycles, proxies, sets and bytes are refused (M14).

    Scenario:
        Given a hook returning one non-JSON shape per case
        When the model is built
        Then an ExtensionError naming the problem is raised.

    Boundaries:
        - Focus: exact-type copy
        - Fixtures/params: one shape per case
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions.validated_copy`` and ``_scalar_chars``
    """
    with pytest.raises(ExtensionError, match=fragment):
        _build(_ext(provide_run=lambda model: value))


def test_tuples_are_accepted_as_lists_and_none_attaches_nothing():
    """
    [Unit] extensions: verifies a tuple is copied as a list and a None return adds no key.

    Scenario:
        Given a run hook returning a tuple member and a document hook returning None
        When the model is built
        Then the tuple becomes a list and documents carry an empty ``ext``.

    Boundaries:
        - Focus: normal-case copy
        - Fixtures/params: none
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions.validated_copy``
    """
    context = _build(_ext(provide_run=lambda model: {"t": (1, "a", None)}, provide_document=lambda doc, model: None))

    assert context["ext"]["calc"] == {"t": [1, "a", None]}
    assert type(context["ext"]["calc"]["t"]) is list
    assert all(doc["ext"] == {} for doc in context["documents"])


def _nested(depth: int) -> dict[str, Any]:
    tree: dict[str, Any] = {}
    current = tree
    for _ in range(depth - 1):
        current["n"] = {}
        current = current["n"]
    return tree


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        (_nested(9), "deeper than 8"),
        ({"s": "x" * (1024 * 1024)}, "more than 1048576"),
        ({"n": 10**4999}, "outside"),
        ({"n": 2**53 + 1}, "outside"),
        ({"n": math.nan}, "non-finite"),
        ({"n": math.inf}, "non-finite"),
        ({1: "x"}, "not a str"),
        ({"k" * 257: 1}, "longer than 256"),
        ({"s": "a\ud800b"}, "lone surrogate"),
        ({"a\udfff": 1}, "lone surrogate"),
        ({"l": list(range(10_001))}, "more than 10000"),
    ],
    ids=[
        "depth9",
        "1MiB+1",
        "5000-digit",
        "2**53+1",
        "nan",
        "inf",
        "int-key",
        "long-key",
        "surrogate",
        "surrogate-key",
        "10001",
    ],
)
def test_shape_and_size_bounds_are_refused(value: dict[Any, Any], fragment: str):
    """
    [Unit] extensions: verifies the M15 bounds: depth, per-hook size, int range, finiteness, keys, surrogates.

    Scenario:
        Given a run hook returning one out-of-bounds value per case
        When the model is built
        Then an ExtensionError naming the bound is raised.

    Boundaries:
        - Focus: threat model T6/M15
        - Fixtures/params: one bound per case
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions.validated_copy`` limits and ``_Budget.reason``
    """
    with pytest.raises(ExtensionError, match=fragment):
        _build(_ext(provide_run=lambda model: value))


def test_values_at_the_bounds_are_accepted():
    """
    [Unit] extensions: verifies depth 8, 2**53, a 256-character key and 10000 entries are accepted (M15 edge).

    Scenario:
        Given a return exactly at each bound
        When the model is built
        Then it is attached unchanged.

    Boundaries:
        - Focus: off-by-one edges of M15
        - Fixtures/params: none
        - Scope: validated_copy

    On failure, first check:
        - comparison operators in ``extensions.validated_copy``
    """
    tree = _nested(8)
    tree["k" * 256] = -(2**53)
    tree["l"] = list(range(10_000))
    context = _build(_ext(provide_run=lambda model: tree))

    assert context["ext"]["calc"] == tree


def test_size_walk_stops_at_the_limit_without_serializing(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extensions: verifies the size check is incremental and never calls json.dumps (M15).

    Scenario:
        Given a list of 10000 references to one 1000-character string (a DAG far past the limit)
        When validated_copy runs with a 50000-character limit and json.dumps patched to raise
        Then it stops with the oversize error after copying only part of the list.

    Boundaries:
        - Focus: no serialize-first measurement
        - Fixtures/params: json.dumps patched
        - Scope: validated_copy

    On failure, first check:
        - ``charge`` inside ``extensions.validated_copy``
    """
    import json

    monkeypatch.setattr(json, "dumps", lambda *a, **k: (_ for _ in ()).throw(AssertionError("serialized")))
    big = "x" * 1000
    with pytest.raises(extensions._Oversize):
        validated_copy({"l": [big] * 10_000}, 50_000)


def test_aggregate_cap_per_extension_stops_many_small_returns(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extensions: verifies a small per-problem return over many problems hits the per-extension cap (M16).

    Scenario:
        Given the per-extension cap lowered to 20000 characters and 2000 findings each returning ~60 characters
        When the model is built under tracemalloc
        Then an ExtensionError about the render-wide cap is raised and peak memory stays bounded.

    Boundaries:
        - Focus: aggregate cap and bounded peak memory
        - Fixtures/params: ``MAX_EXTENSION_CHARS`` lowered
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions._Budget``
    """
    monkeypatch.setattr(extensions, "MAX_EXTENSION_CHARS", 20_000)
    findings = tuple(
        Finding(rule="DS101", path="b.md", message=f"m{index}", severity="error", line=index) for index in range(2000)
    )
    result = _result(findings)
    tracemalloc.start()
    try:
        with pytest.raises(ExtensionError, match="across the render"):
            _build(_ext(provide_problem=lambda p, d, m: {"v": "x" * 50}), result=result)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 16 * 1024 * 1024


def test_global_cap_spans_all_extensions(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extensions: verifies the cap across all extensions fires even when each one is under its own (M16).

    Scenario:
        Given the global cap lowered to 300 characters and two extensions returning ~200 characters each
        When the model is built
        Then an ExtensionError about all extensions is raised.

    Boundaries:
        - Focus: global aggregate cap
        - Fixtures/params: ``MAX_TOTAL_EXTENSION_CHARS`` lowered
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions._Budget.limit``
    """
    monkeypatch.setattr(extensions, "MAX_TOTAL_EXTENSION_CHARS", 300)
    payload = {"v": "x" * 190}
    with pytest.raises(ExtensionError, match="across all extensions"):
        _build(_ext("one", provide_run=lambda m: payload), _ext("two", provide_run=lambda m: payload))


def test_cap_constants_match_the_engine():
    """
    [Unit] extensions: verifies the global extension cap equals the engine's MAX_OUTPUT_CHARS (M16).

    Scenario:
        Given the two constants
        When compared
        Then they are equal, and the per-hook/per-extension caps are 1 MiB and 16 MiB.

    Boundaries:
        - Focus: constant parity (the module does not import the engine)
        - Fixtures/params: none
        - Scope: module constants

    On failure, first check:
        - ``extensions.MAX_TOTAL_EXTENSION_CHARS``
    """
    assert extensions.MAX_TOTAL_EXTENSION_CHARS == engine.MAX_OUTPUT_CHARS
    assert extensions.MAX_HOOK_CHARS == 1024 * 1024
    assert extensions.MAX_EXTENSION_CHARS == 16 * 1024 * 1024


# --------------------------------------------------------------------------- M17, M27 error model


@pytest.mark.parametrize(
    "raised", [SystemExit(0), SystemExit(1), RuntimeError("boom"), RecursionError("deep"), GeneratorExit()]
)
def test_hook_exceptions_become_extension_errors(raised: BaseException):
    """
    [Unit] extensions: verifies Exception, SystemExit and other non-interrupt exits become ExtensionError (M17).

    Scenario:
        Given a run hook raising SystemExit(0), SystemExit(1), RuntimeError, RecursionError or GeneratorExit
        When the model is built
        Then an ExtensionError naming the hook and the class is raised, so no hook can pick the exit code.

    Boundaries:
        - Focus: exit-code downgrade (T7)
        - Fixtures/params: one exception per case
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions._call``
    """

    def hook(model: Any) -> None:
        raise raised

    with pytest.raises(ExtensionError, match=f"provide_run failed: {type(raised).__qualname__}") as caught:
        _build(_ext(provide_run=hook))
    assert len(str(caught.value)) <= 512


def test_keyboard_interrupt_propagates():
    """
    [Unit] extensions: verifies KeyboardInterrupt from a hook is not swallowed (M17).

    Scenario:
        Given a run hook raising KeyboardInterrupt
        When the model is built
        Then KeyboardInterrupt propagates.

    Boundaries:
        - Focus: interrupt handling
        - Fixtures/params: none
        - Scope: ReportModel.build

    On failure, first check:
        - the ``except KeyboardInterrupt: raise`` in ``extensions._call``
    """

    def hook(model: Any) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _build(_ext(provide_run=hook))


def test_hook_failure_message_is_bounded_and_neutralized():
    """
    [Unit] extensions: verifies a hostile exception gives a bounded, escaped message without paths (M27).

    Scenario:
        Given a hook raising an exception class named ``ESC[2J`` with an ESC/U+202E/1 KiB message
        When the model is built
        Then the message is at most 512 characters, holds no raw ESC/U+202E, only 200 detail characters,
        and no traceback or module path.

    Boundaries:
        - Focus: threat model T10/M27
        - Fixtures/params: none
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions._describe``
    """
    hostile = type(ESC + "[2J", (Exception,), {})
    detail = ESC + "[31m" + RLO + "y" * 1024

    def hook(model: Any) -> None:
        raise hostile(detail)

    with pytest.raises(ExtensionError) as caught:
        _build(_ext(provide_run=hook))
    message = str(caught.value)

    assert len(message) <= 512
    assert ESC not in message and RLO not in message
    assert "\\x1b[2J" in message and "\\u202e" in message
    assert message.count("y") <= 200
    assert "Traceback" not in message and __file__ not in message and extensions.__file__ not in message


def test_unprintable_exception_is_described_safely():
    """
    [Unit] extensions: verifies an exception whose __str__ raises still yields a bounded ExtensionError (M27).

    Scenario:
        Given a hook raising an exception whose ``__str__`` raises
        When the model is built
        Then the ExtensionError says ``<unprintable>``.

    Boundaries:
        - Focus: robust message construction
        - Fixtures/params: none
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions._describe``
    """

    class Bad(Exception):
        def __str__(self) -> str:
            raise ValueError("no")

    def hook(model: Any) -> None:
        raise Bad

    with pytest.raises(ExtensionError, match="<unprintable>"):
        _build(_ext(provide_run=hook))


def test_extension_error_is_a_value_error_with_safe_str():
    """
    [Unit] extensions: verifies ExtensionError is a ValueError whose str is neutralized and capped (M27).

    Scenario:
        Given an ExtensionError built from a 2000-character message holding ESC
        When it is converted to text
        Then it is a ValueError, holds no raw ESC and is at most 512 characters.

    Boundaries:
        - Focus: library callers printing the error
        - Fixtures/params: none
        - Scope: ExtensionError

    On failure, first check:
        - ``ExtensionError.__init__``
    """
    error = ExtensionError(ESC + "x" * 2000)

    assert isinstance(error, ValueError)
    assert ESC not in str(error) and len(str(error)) <= 512


# --------------------------------------------------------------------------- M7, M9 filter registration


def _filter(**overrides: Any) -> ExtensionFilter:
    values = {"function": lambda value: "ok", "arity": 0, "input_kinds": frozenset({"scalar"})}
    values.update(overrides)
    return ExtensionFilter(**values)


def test_filter_declaring_itself_a_sink_is_refused():
    """
    [Unit] extensions: verifies a filter exposing a truthy ``sink`` attribute is refused (M7).

    Scenario:
        Given an ExtensionFilter with a ``sink = True`` attribute forced onto it
        When the extension is admitted
        Then an ExtensionError says extension filters are never sinks.

    Boundaries:
        - Focus: threat model T3/M7
        - Fixtures/params: none
        - Scope: admit_extensions

    On failure, first check:
        - the ``sink`` check in ``extensions._admit_filters``
    """
    sinky = _filter()
    object.__setattr__(sinky, "sink", True)
    with pytest.raises(ExtensionError, match="never sinks"):
        admit_extensions([_ext(filters=lambda: {"ext.calc.f": sinky})])


@pytest.mark.parametrize("key", ["neutralize", "ext.other.f", "ext.calc", "ext.calc.F", "ext.calc.f.g", 3])
def test_filter_names_outside_the_own_namespace_are_refused(key: object):
    """
    [Unit] extensions: verifies a filter must be named exactly ext.<own name>.<filter> (M9).

    Scenario:
        Given filters named like a core filter, under another extension, or malformed
        When the extension is admitted
        Then an ExtensionError is raised.

    Boundaries:
        - Focus: filter namespace
        - Fixtures/params: one name per case
        - Scope: admit_extensions

    On failure, first check:
        - ``extensions._admit_filters``
    """
    with pytest.raises(ExtensionError, match="must be ext.calc.<filter>"):
        admit_extensions([_ext(filters=lambda: {key: _filter()})])


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        (_filter(arity=2), "arity"),
        (_filter(arity=True), "arity"),
        (_filter(input_kinds={"scalar"}), "input_kinds"),
        (_filter(input_kinds=frozenset({"object"})), "input_kinds"),
        (_filter(input_kinds=frozenset()), "input_kinds"),
        (_filter(function=3), "not callable"),
        (SimpleNamespace(function=lambda v: v, arity=0, input_kinds=frozenset({"scalar"})), "ExtensionFilter"),
    ],
)
def test_invalid_filter_declarations_are_refused(value: object, fragment: str):
    """
    [Unit] extensions: verifies arity, input kinds, function and type of each filter are validated (M9).

    Scenario:
        Given one invalid filter declaration per case
        When the extension is admitted
        Then an ExtensionError names the problem.

    Boundaries:
        - Focus: load-time filter signature
        - Fixtures/params: one declaration per case
        - Scope: admit_extensions

    On failure, first check:
        - ``extensions._admit_filters``
    """
    with pytest.raises(ExtensionError, match=fragment):
        admit_extensions([_ext(filters=lambda: {"ext.calc.f": value})])


def test_extension_filters_never_enter_the_core_tables():
    """
    [Unit] extensions: verifies registered filters live only in the per-render registry (M9).

    Scenario:
        Given an extension registering ``ext.calc.f``
        When it is admitted
        Then the registry holds it, and loader.FILTERS and filters.FILTER_NAMES are unchanged and still equal.

    Boundaries:
        - Focus: closed core filter table
        - Fixtures/params: none
        - Scope: admit_extensions

    On failure, first check:
        - that nothing writes to ``loader.FILTERS``/``filters._FUNCTIONS``
    """
    before = frozenset(loader.FILTERS)
    loaded = admit_extensions([_ext(filters=lambda: {"ext.calc.f": _filter()})])

    assert set(loaded.filters) == {"ext.calc.f"}
    assert frozenset(loader.FILTERS) == before == filters.FILTER_NAMES
    assert "ext.calc.f" not in filters.FILTER_NAMES
    with pytest.raises(TypeError):
        loaded.filters["ext.calc.g"] = loaded.filters["ext.calc.f"]  # type: ignore[index]


# --------------------------------------------------------------------------- M29 event path


def test_event_path_swallows_hook_failures_with_one_warning_per_extension():
    """
    [Unit] extensions: verifies 100 failing event-path calls write one warning and keep healthy data (M29).

    Scenario:
        Given one failing and one healthy problem hook
        When the event guard runs 100 times
        Then exactly one bounded warning names the failing extension and the healthy data is returned each time.

    Boundaries:
        - Focus: event-path swallowing (telemetry never fails a scan)
        - Fixtures/params: none
        - Scope: EventHookGuard

    On failure, first check:
        - ``EventHookGuard.problem_ext``
    """

    def broken(problem: Any, doc: Any, model: Any) -> None:
        raise SystemExit(ESC + "x" * 2000)

    loaded = admit_extensions(
        [_ext("bad", provide_problem=broken), _ext("good", provide_problem=lambda p, d, m: {"k": 1})]
    )
    warnings: list[str] = []
    guard = EventHookGuard(loaded, warn=warnings.append)

    results = [guard.problem_ext({"rule": "DS101"}, {"path": "a.md"}, {"profile": "fast"}) for _ in range(100)]

    assert results == [{"good": {"k": 1}}] * 100
    assert len(warnings) == 1
    assert "bad" in warnings[0] and ESC not in warnings[0] and len(warnings[0]) <= 600


def test_event_path_does_not_swallow_keyboard_interrupt():
    """
    [Unit] extensions: verifies the event guard lets KeyboardInterrupt through (M17, M29).

    Scenario:
        Given a problem hook raising KeyboardInterrupt
        When the event guard runs
        Then KeyboardInterrupt propagates.

    Boundaries:
        - Focus: interrupt on the event path
        - Fixtures/params: none
        - Scope: EventHookGuard

    On failure, first check:
        - ``extensions._call``
    """

    def interrupted(problem: Any, doc: Any, model: Any) -> None:
        raise KeyboardInterrupt

    guard = EventHookGuard(admit_extensions([_ext(provide_problem=interrupted)]), warn=lambda message: None)
    with pytest.raises(KeyboardInterrupt):
        guard.problem_ext({}, {}, {})


# --------------------------------------------------------------------------- M32 data files


def test_baseline_and_template_cannot_name_an_extension(tmp_path):
    """
    [Unit] extensions: verifies a baseline or template carrying an ``extensions`` key is refused (M32).

    Scenario:
        Given a baseline JSON and a template mapping each holding an ``extensions`` key
        When they are loaded
        Then both are refused by their unknown-key rejection.

    Boundaries:
        - Focus: neither data file can select an extension
        - Fixtures/params: a temporary baseline file
        - Scope: load_baseline and validate_template

    On failure, first check:
        - unknown-key checks in ``baseline.load_baseline`` and ``loader._Validator.template``
    """
    from docsentinel.baseline import load_baseline

    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"fingerprints": [], "extensions": ["python:m:f"]}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_baseline(baseline)
    raw = {"template_version": 1, "name": "t", "type": "text", "lines": [], "extensions": ["python:m:f"]}
    with pytest.raises(filters.TemplateError, match="unknown key"):
        loader.validate_template(raw)


# --------------------------------------------------------------------------- parity


def test_name_pattern_parity_with_loader_and_config():
    """
    [Unit] extensions: verifies the extension name grammar is the same in extensions, loader and config.

    Scenario:
        Given the three patterns
        When compared
        Then the loader and config patterns equal EXTENSION_NAME_PATTERN (config with its builtin: prefix).

    Boundaries:
        - Focus: single grammar (T14)
        - Fixtures/params: none
        - Scope: module constants

    On failure, first check:
        - ``loader._EXTENSION_PATTERN`` and ``config._BUILTIN_EXTENSION_SPEC_PATTERN``
    """
    bare = EXTENSION_NAME_PATTERN.strip("^$")
    assert loader._EXTENSION_PATTERN.pattern == bare
    assert config_module._BUILTIN_EXTENSION_SPEC_PATTERN.pattern == "builtin:" + bare


# --------------------------------------------------------------------------- close-review regressions (2026-11-03)


class _QualnameBombMeta(type):
    """A metaclass whose ``__qualname__`` read raises ``SystemExit(0)``."""

    def __getattribute__(cls, attribute: str) -> Any:
        if attribute == "__qualname__":
            raise SystemExit(0)
        return type.__getattribute__(cls, attribute)


class _QualnameBomb(Exception, metaclass=_QualnameBombMeta):
    """An exception whose class name cannot be read."""


def _raise_bomb(*args: Any) -> Any:
    raise _QualnameBomb("boom")


def test_exception_class_whose_qualname_raises_cannot_choose_the_exit():
    """
    [Unit] extensions: verifies a SystemExit from an exception class's __qualname__ stays contained (M17, M27).

    Scenario:
        Given a run hook, and separately a filter, raising an exception whose metaclass raises SystemExit(0)
            when ``__qualname__`` is read
        When the model is built / the filter is applied
        Then an ExtensionError / TemplateError with the fixed label ``<exception>`` is raised, never SystemExit.

    Boundaries:
        - Focus: close-review finding 5 (auditor repro c10-metaclass-exit0)
        - Fixtures/params: none
        - Scope: ReportModel.build, BoundFilter.__call__

    On failure, first check:
        - ``extensions._qualname`` and ``_describe``
    """
    with pytest.raises(ExtensionError, match="provide_run failed: <exception>: boom"):
        _build(_ext(provide_run=_raise_bomb))
    bound = extensions.BoundFilter("ext.calc.f", "calc", _raise_bomb, 0, frozenset({"scalar"}))
    with pytest.raises(filters.TemplateError, match="<exception>"):
        bound("x", ())


class _BoolBomb:
    """An object whose truth value raises ``SystemExit(0)``."""

    def __bool__(self) -> bool:
        raise SystemExit(0)


@pytest.mark.parametrize("sink", [_BoolBomb(), False, 0], ids=["bool-raises", "false", "zero"])
def test_any_sink_attribute_is_refused_by_identity(sink: object):
    """
    [Unit] extensions: verifies a filter carrying any ``sink`` attribute is refused without testing its truth (M7).

    Scenario:
        Given an ExtensionFilter with a ``sink`` attribute forced on: one whose ``__bool__`` raises SystemExit(0),
            ``False`` and ``0``
        When the extension is admitted
        Then an ExtensionError is raised in every case and no SystemExit escapes.

    Boundaries:
        - Focus: close-review finding 5 (probe p04 "sink __bool__ raises SystemExit")
        - Fixtures/params: one sink value per case
        - Scope: admit_extensions

    On failure, first check:
        - the ``is not None`` sink check in ``extensions._admit_filters``
    """
    flagged = _filter()
    object.__setattr__(flagged, "sink", sink)

    with pytest.raises(ExtensionError, match="never sinks"):
        admit_extensions([_ext(filters=lambda: {"ext.calc.f": flagged})])


class _ExitingMapping(dict):
    """A mapping whose ``items`` raises ``SystemExit(0)``."""

    def items(self) -> Any:
        raise SystemExit(0)


@pytest.mark.parametrize(
    "returned",
    [MappingProxyType(_ExitingMapping()), MappingProxyType({}), _ExitingMapping()],
    ids=["proxy-over-custom", "plain-proxy", "dict-subclass"],
)
def test_filters_hook_must_return_an_exact_dict(returned: object):
    """
    [Unit] extensions: verifies ``filters()`` must return an exact dict, so no mapping method runs (M9).

    Scenario:
        Given a filters() hook returning a MappingProxyType over a custom mapping whose items() raises
            SystemExit(0), a plain proxy, or a dict subclass
        When the extension is admitted
        Then an ExtensionError says filters() must return a dict.

    Boundaries:
        - Focus: close-review finding 5 (probe p04 "filters() MappingProxyType(custom...)")
        - Fixtures/params: one return per case
        - Scope: admit_extensions

    On failure, first check:
        - the exact-``dict`` check in ``extensions._admit_filters``
    """
    with pytest.raises(ExtensionError, match=r"filters\(\) must return a dict"):
        admit_extensions([_ext(filters=lambda: returned)])


class _HostileKind:
    """A frozenset member that hashes like ``scalar`` and raises ``SystemExit(0)`` on comparison."""

    def __hash__(self) -> int:
        return hash("scalar")

    def __eq__(self, other: object) -> bool:
        raise SystemExit(0)


def test_input_kinds_with_a_non_str_member_is_refused_without_comparing_it():
    """
    [Unit] extensions: verifies input_kinds members must be exact str before any set comparison (M9).

    Scenario:
        Given ``input_kinds = frozenset({<object hashing like "scalar" whose __eq__ raises SystemExit(0)>})``
        When the extension is admitted
        Then an ExtensionError names input_kinds and no SystemExit escapes.

    Boundaries:
        - Focus: close-review finding 5 (same class: attribute evaluated by user code)
        - Fixtures/params: none
        - Scope: admit_extensions

    On failure, first check:
        - the exact-``str`` member check in ``extensions._admit_filters``
    """
    hostile = _filter(input_kinds=frozenset({_HostileKind()}))

    with pytest.raises(ExtensionError, match="input_kinds"):
        admit_extensions([_ext(filters=lambda: {"ext.calc.f": hostile})])


@pytest.mark.parametrize("leaf", ["__init__", "_x", "_"])
def test_filter_leaf_starting_with_an_underscore_is_refused(leaf: str):
    """
    [Unit] extensions: verifies a filter name such as ``ext.calc.__init__`` is refused (finding 8).

    Scenario:
        Given a filter registered as ``ext.calc.<leaf>`` with a leading underscore
        When the extension is admitted
        Then an ExtensionError names the required form.

    Boundaries:
        - Focus: filter name grammar ``[a-z][a-z0-9_]{0,63}``
        - Fixtures/params: one leaf per case
        - Scope: admit_extensions

    On failure, first check:
        - ``extensions._FILTER_LEAF_RE``
    """
    with pytest.raises(ExtensionError, match="must be ext.calc.<filter>"):
        admit_extensions([_ext(filters=lambda: {f"ext.calc.{leaf}": _filter()})])


def test_invalid_data_message_reads_once():
    """
    [Unit] extensions: verifies the invalid-return message no longer repeats "a value that" (finding 8).

    Scenario:
        Given a run hook returning ``{"a": b"x"}``
        When the model is built
        Then the ExtensionError reads "returned invalid data: a value that is not exact JSON data" once.

    Boundaries:
        - Focus: regression of the duplicated phrase
        - Fixtures/params: none
        - Scope: ReportModel.build

    On failure, first check:
        - ``extensions._run_hook`` and the ``_Shape`` messages
    """
    with pytest.raises(ExtensionError) as caught:
        _build(_ext(provide_run=lambda model: {"a": b"x"}))

    assert "provide_run returned invalid data: a value that is not exact JSON data" in str(caught.value)
    assert "a value that a value that" not in str(caught.value)


class _RefusingWatch:
    """A stand-in ModuleWatch that reports a change and refuses it."""

    def changed(self) -> bool:
        return True

    def check_path(self):
        return None

    def check(self):
        raise ExtensionError("python extension refused: module planted was imported during the run")


def test_event_guard_never_swallows_a_module_origin_refusal():
    """
    [Unit] extensions: verifies EventHookGuard propagates a ModuleWatch refusal instead of warning (M4, M6).

    Scenario:
        Given a registry whose module watch refuses, with a healthy problem hook
        When the event guard runs the hooks for one problem
        Then the ExtensionError propagates and no warning is written.

    Boundaries:
        - Focus: finding 1 on the fault-event path (refusals are never swallowed)
        - Fixtures/params: a stub watch
        - Scope: EventHookGuard.problem_ext

    On failure, first check:
        - the watch check at the end of ``EventHookGuard.problem_ext``
    """
    admitted = admit_extensions([_ext(provide_problem=lambda p, d, m: {"ok": True})])
    loaded = LoadedExtensions(admitted.extensions, admitted.filters, _RefusingWatch())  # type: ignore[arg-type]
    warnings: list[str] = []

    with pytest.raises(ExtensionError, match="imported during the run"):
        EventHookGuard(loaded, warn=warnings.append).problem_ext({"rule": "DS101"}, {"path": "a.md"}, {})
    assert warnings == []


class _ExitingPath:
    """A ``__path__`` value whose iteration raises ``SystemExit(0)``."""

    def __iter__(self) -> Any:
        raise SystemExit(0)


def test_search_path_that_raises_system_exit_is_a_refusal(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extensions: verifies a sys.modules package whose __path__ raises SystemExit is refused, not escaped (M6).

    Scenario:
        Given a pre-imported package whose ``__path__`` iteration raises SystemExit(0)
        When it is loaded with the gate open
        Then an ExtensionError says the search path cannot be listed.

    Boundaries:
        - Focus: hardening in the same class as close-review finding 5
        - Fixtures/params: none
        - Scope: load_python_target

    On failure, first check:
        - ``extensions._locations``
    """
    module = types.ModuleType("ds_exiting_pkg")
    module.__path__ = _ExitingPath()  # type: ignore[assignment]
    monkeypatch.setitem(sys.modules, "ds_exiting_pkg", module)

    with pytest.raises(ExtensionError, match="cannot be listed"):
        load_python_target("python:ds_exiting_pkg:make", allow_python=True, root=tmp_path, cwd=tmp_path)


class _Impostor:
    """A sys.modules entry whose ``__class__`` read raises ``SystemExit(0)``."""

    @property
    def __class__(self) -> Any:  # type: ignore[override]
        raise SystemExit(0)


def test_module_watch_refuses_an_entry_it_cannot_inspect(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extensions: verifies ModuleWatch fails closed on a new sys.modules entry that raises when inspected (M6).

    Scenario:
        Given a watch started over an empty directory, then a new sys.modules entry whose ``__class__`` raises
            SystemExit(0)
        When the watch checks sys.modules
        Then an ExtensionError naming the entry is raised and no SystemExit escapes.

    Boundaries:
        - Focus: close-review finding 1 checker robustness
        - Fixtures/params: none
        - Scope: ModuleWatch.check

    On failure, first check:
        - the guarded inspection in ``extensions.ModuleWatch.check``
    """
    watch = extensions.ModuleWatch.start(tmp_path, tmp_path)
    monkeypatch.setitem(sys.modules, "ds_impostor", _Impostor())

    with pytest.raises(ExtensionError, match="module ds_impostor was imported during the run"):
        watch.check()


# --------------------------------------------------------------------------- re-verification regressions N2/N3 (2026-11-03)


def test_module_watch_check_path_refuses_a_root_entry_added_after_the_start(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extensions: verifies ModuleWatch.check_path refuses a sys.path entry added inside the boundary (M6, N2).

    Scenario:
        Given a watch started over a scan root, with sys.path holding nothing inside it
        When the watch checks sys.path before and after the scan root is inserted at sys.path[0]
        Then the first check passes and the second raises an ExtensionError naming sys.path (never the path).

    Boundaries:
        - Focus: re-verification finding N2 prevention layer (a factory changing sys.path)
        - Fixtures/params: none
        - Scope: ModuleWatch.check_path

    On failure, first check:
        - ``extensions.ModuleWatch.check_path`` and its ``sys.path`` cache key
    """
    watch = extensions.ModuleWatch.start(tmp_path, tmp_path)
    watch.check_path()
    monkeypatch.setattr(sys, "path", [str(tmp_path), *sys.path])

    with pytest.raises(ExtensionError, match=r"sys\.path") as caught:
        watch.check_path()
    assert str(tmp_path) not in str(caught.value)


def test_report_hooks_stop_before_the_next_hook_once_sys_path_points_inside(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extensions: verifies a hook adding the root to sys.path stops the run before the next hook (M6, N2).

    Scenario:
        Given two admitted extensions under a real watch: the first run hook inserts the scan root into sys.path,
            the second records that it ran
        When apply_report_hooks runs them in order
        Then an ExtensionError naming sys.path is raised and the second hook never ran.

    Boundaries:
        - Focus: re-verification finding N2 (sys.path re-checked before every hook)
        - Fixtures/params: none
        - Scope: apply_report_hooks with a real ModuleWatch

    On failure, first check:
        - the ``check_import_path`` calls in ``extensions.apply_report_hooks``
    """
    monkeypatch.setattr(sys, "path", list(sys.path))
    calls: list[str] = []

    def sneak(model: Any) -> None:
        sys.path.insert(0, str(tmp_path))

    admitted = admit_extensions([_ext("first", provide_run=sneak), _ext("second", provide_run=calls.append)])
    watch = extensions.ModuleWatch.start(tmp_path, tmp_path)
    loaded = LoadedExtensions(admitted.extensions, admitted.filters, watch)
    context = ReportModel.build(_result(), Config())

    with pytest.raises(ExtensionError, match=r"sys\.path"):
        extensions.apply_report_hooks(context, loaded)
    assert calls == []


def test_event_guard_checks_modules_even_when_sys_modules_keeps_its_size(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] extensions: verifies the event path catches a replaced sys.modules entry (same size) (M6, N3).

    Scenario:
        Given a real watch started while ``ds_n3_victim`` is an outside module in sys.modules, and a problem hook
            that replaces that entry with a module located inside the scan root (sys.modules keeps its size)
        When the event guard runs the hook for one problem
        Then the ExtensionError naming the module propagates and no warning is written.

    Boundaries:
        - Focus: re-verification finding N3 (the size-only ``changed()`` shortcut skipped the check)
        - Fixtures/params: none
        - Scope: EventHookGuard.problem_ext with a real ModuleWatch

    On failure, first check:
        - the unconditional ``watch.check()`` at the end of ``EventHookGuard.problem_ext``
    """
    monkeypatch.setitem(sys.modules, "ds_n3_victim", types.ModuleType("ds_n3_victim"))
    planted = types.ModuleType("ds_n3_victim")
    planted.__file__ = str(tmp_path / "ds_n3_victim.py")

    def swap(problem: Any, doc: Any, model: Any) -> dict[str, bool]:
        sys.modules["ds_n3_victim"] = planted
        return {"ok": True}

    admitted = admit_extensions([_ext(provide_problem=swap)])
    watch = extensions.ModuleWatch.start(tmp_path, tmp_path)
    loaded = LoadedExtensions(admitted.extensions, admitted.filters, watch)
    warnings: list[str] = []

    with pytest.raises(ExtensionError, match="module ds_n3_victim was imported during the run"):
        EventHookGuard(loaded, warn=warnings.append).problem_ext({"rule": "DS101"}, {"path": "a.md"}, {})
    assert warnings == []
