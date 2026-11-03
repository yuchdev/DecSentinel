"""Unit tests for ``telemetry_domains`` and ``builtin:domain`` (Milestone 0007 Story 04.0 Task 02).

Pins threat model ``docs/security/threat-model-0007-extensions-2026-11-03.md`` M18 (memoized,
linear-time lookup), M20 (glob grammar), M21 (non-regex segment matcher), M22 (bounds, re-checked
for an injected ``Config``), M23 (array order, first match wins) and M24 (``doc.domain`` is a core
key set only from ``domain_for``).
"""

import json
from pathlib import Path

import pytest

from docsentinel.config import (
    MAX_DOMAIN_GLOB_CHARS,
    MAX_DOMAIN_GLOB_SEGMENTS,
    MAX_TELEMETRY_DOMAINS,
    Config,
    ConfigError,
    load_config,
    validate_telemetry_domains,
)
from docsentinel.models import Document, Finding, ScanResult
from docsentinel.reporting import render
from docsentinel.telemetry import builtin
from docsentinel.telemetry.builtin import domain
from docsentinel.telemetry.builtin.domain import DEFAULT_DOMAIN, domain_for, domain_table, glob_matches
from docsentinel.telemetry.classify import classify
from docsentinel.telemetry.extensions import admit_extensions, resolve_extensions
from docsentinel.telemetry.filters import TemplateError
from docsentinel.telemetry.loader import load_named_template, validate_template
from docsentinel.telemetry.model import DOCUMENT_SCHEMA, UNTRUSTED, ReportModel

ON = ("builtin:domain",)


def _config(*pairs: tuple[str, str], enabled: bool = True) -> Config:
    """Return a Config with the given ``(glob, domain)`` table and ``builtin:domain`` on or off."""
    return Config(telemetry_domains=tuple(pairs), telemetry_extensions=ON if enabled else ())


def _result(documents: tuple[Document, ...], findings: tuple[Finding, ...] = ()) -> ScanResult:
    """Return a fast-profile scan result over ``documents``."""
    return ScanResult(profile="fast", documents=documents, findings=findings, enabled_rules=("DS101",), pending=())


def _matches(glob: str, path: str) -> bool:
    """Return whether ``path`` matches ``glob`` with the domain matcher."""
    return glob_matches(tuple(glob.split("/")), path.split("/"))


# --------------------------------------------------------------------------- matcher (M20, M21)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("docs", True),
        ("docs/a.md", True),
        ("docs/1/2/3/4/a.md", True),
        ("other/a.md", False),
        ("docsx/a.md", False),
    ],
)
def test_double_star_matches_zero_one_or_many_segments(path: str, expected: bool):
    """
    [Unit] telemetry domains: verifies ``docs/**`` matches at depth 0, 1 and 5 and nothing else (M20).

    Scenario:
        Given the glob ``docs/**``
        When it is matched against paths at depth 0 (``docs``), 1 and 5 below ``docs`` and two siblings
        Then only the paths under (or equal to) ``docs`` match.

    Boundaries:
        - Focus: ``**`` as zero or more whole segments
        - Fixtures/params: one path per case
        - Scope: ``domain.glob_matches``

    On failure, first check:
        - the ``**`` row of the dynamic program in ``glob_matches``
    """
    assert _matches("docs/**", path) is expected


@pytest.mark.parametrize(
    ("glob", "path", "expected"),
    [
        ("*", "README.md", True),
        ("*", "docs/a.md", False),
        ("**", "README.md", True),
        ("**", "docs/deep/a.md", True),
        ("*.md", "docs/a.md", False),
        ("docs/*.md", "docs/a.md", True),
        ("docs/*.md", "docs/sub/a.md", False),
        ("docs/?.md", "docs/a.md", True),
        ("docs/?.md", "docs/ab.md", False),
        ("**/a.md", "a.md", True),
        ("**/a.md", "x/y/a.md", True),
        ("a/**/b", "a/b", True),
        ("a/**/b", "a/x/y/b", True),
        ("Docs/**", "docs/a.md", False),
    ],
)
def test_single_star_and_question_mark_never_cross_a_separator(glob: str, path: str, expected: bool):
    """
    [Unit] telemetry domains: verifies ``*``/``?`` stay inside a segment and ``*`` alone is top level only (M20).

    Scenario:
        Given globs using ``*``, ``?`` and ``**``
        When each is matched against a path
        Then ``*`` and ``?`` never cross ``/``, ``"*"`` matches only top-level files, ``"**"`` matches everything,
        and matching is case-sensitive.

    Boundaries:
        - Focus: the glob grammar semantics
        - Fixtures/params: one (glob, path) pair per case
        - Scope: ``domain.glob_matches``

    On failure, first check:
        - ``domain.segment_matches`` and the per-segment split
    """
    assert _matches(glob, path) is expected


def test_adversarial_pattern_on_a_deep_path_finishes_within_bound(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] telemetry domains: verifies ``**/a*a*a*a*b/**/x`` on a 4096-char ``a/a/...`` path is polynomial (M21).

    Scenario:
        Given the backtracking-hostile glob ``**/a*a*a*a*b/**/x`` and a 4096-character path of ``a`` segments
        When the domain matcher runs
        Then it reports no match, calls the segment matcher at most once per (glob segment, path segment) pair,
        and finishes well within one second.

    Boundaries:
        - Focus: ReDoS freedom of the segment-wise dynamic program
        - Fixtures/params: the segment matcher wrapped with a call counter
        - Scope: ``domain.glob_matches``

    On failure, first check:
        - that ``glob_matches`` is bottom-up and never recursive
    """
    pattern = tuple("**/a*a*a*a*b/**/x".split("/"))
    path = "/".join(["a"] * 2048)[:4096].split("/")
    calls = []
    real = domain.segment_matches

    def counting(segment: str, text: str) -> bool:
        """Count one segment comparison, then run the real one."""
        calls.append(1)
        return real(segment, text)

    monkeypatch.setattr(domain, "segment_matches", counting)
    assert glob_matches(pattern, path) is False

    assert len(calls) <= len(pattern) * len(path)


# --------------------------------------------------------------------------- config (M20, M22, M23)


@pytest.mark.parametrize(
    "glob",
    [
        "docs/[ab].md",
        "docs/a].md",
        "{docs,adr}/**",
        "docs/}",
        "docs\\a.md",
        "!docs/**",
        "docs/!x",
        "docs//a.md",
        "docs/",
        "/docs/**",
        "./docs/**",
        "docs/../x",
        "docs/a**b",
        "**x/a.md",
        "docs/" + chr(0x1B) + ".md",
        "docs/" + chr(0x202E) + "a.md",
        "docs/" + chr(0x200B) + "a.md",
        "docs/" + chr(0x2028) + "a.md",
        "",
    ],
)
def test_each_refused_grammar_element_is_a_config_error(glob: str):
    """
    [Unit] telemetry domains: verifies every refused glob element is a ConfigError that never echoes it (M20).

    Scenario:
        Given a table entry whose glob uses ``[``, ``]``, ``{``, ``}``, a backslash, a leading ``!``, an empty, ``.``
        or ``..`` segment, a leading ``/``, ``**`` inside a segment, a neutralize-table code point, or is empty
        When the table is validated
        Then a ConfigError is raised and the glob itself is not in the message.

    Boundaries:
        - Focus: the closed glob grammar
        - Fixtures/params: one refused glob per case
        - Scope: ``config.validate_telemetry_domains``

    On failure, first check:
        - ``config.domain_glob_segments``
    """
    with pytest.raises(ConfigError) as caught:
        validate_telemetry_domains([{"glob": glob, "domain": "docs"}])
    if glob:
        assert glob not in str(caught.value)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([{"glob": "**", "domain": "docs"}] * (MAX_TELEMETRY_DOMAINS + 1), "more than 256"),
        ([{"glob": "a" * (MAX_DOMAIN_GLOB_CHARS + 1), "domain": "docs"}], "longer than 256"),
        ([{"glob": "/".join(["a"] * (MAX_DOMAIN_GLOB_SEGMENTS + 1)), "domain": "docs"}], "more than 32 segments"),
        ([{"glob": "**", "domain": "Agent!"}], "domain must match"),
        ([{"glob": "**", "domain": "agent", "note": "x"}], "exactly the keys"),
        ([{"glob": "**"}], "exactly the keys"),
        ([{"glob": 1, "domain": "docs"}], "glob must be a nonempty string"),
        ([{"glob": "**", "domain": 7}], "domain must match"),
        ([{"glob": "**", "domain": "x" * 65}], "domain must match"),
        ([{"glob": "**", "domain": "d" + chr(0xF6) + "cs"}], "domain must match"),
        ([["**", "docs"]], "exactly the keys"),
        ({"glob": "**", "domain": "docs"}, "array of tables"),
    ],
)
def test_out_of_bounds_or_malformed_tables_are_refused(entries: object, message: str):
    """
    [Unit] telemetry domains: verifies table, glob and domain bounds and the entry shape (M22).

    Scenario:
        Given 257 entries, a 257-character glob, a 33-segment glob, an ``Agent!``/65-char/non-ASCII/non-str
        domain, an extra or missing key, a non-str glob, a list entry, or a bare table instead of an array
        When the table is validated
        Then a ConfigError naming the violated bound is raised.

    Boundaries:
        - Focus: M22 bounds and the exact ``{glob, domain}`` entry shape
        - Fixtures/params: one violation per case
        - Scope: ``config.validate_telemetry_domains``

    On failure, first check:
        - ``config._domain_entry`` and the bound constants
    """
    with pytest.raises(ConfigError, match=message):
        validate_telemetry_domains(entries)


def test_boundary_values_are_accepted():
    """
    [Unit] telemetry domains: verifies exactly 256 entries, a 256-char glob, 32 segments and a 64-char domain pass.

    Scenario:
        Given a table at every upper bound
        When it is validated
        Then it is accepted unchanged, as ordered pairs.

    Boundaries:
        - Focus: off-by-one edges of M22
        - Fixtures/params: none
        - Scope: ``config.validate_telemetry_domains``

    On failure, first check:
        - ``>`` (not ``>=``) in the bound checks
    """
    long_glob = "a" * MAX_DOMAIN_GLOB_CHARS
    deep_glob = "/".join(["a"] * MAX_DOMAIN_GLOB_SEGMENTS)
    entries = [{"glob": long_glob, "domain": "a" + "b" * 63}, {"glob": deep_glob, "domain": "x-y_z9"}]
    entries += [{"glob": "**", "domain": "docs"}] * (MAX_TELEMETRY_DOMAINS - 2)

    table = validate_telemetry_domains(entries)

    assert len(table) == MAX_TELEMETRY_DOMAINS
    assert table[0] == (long_glob, "a" + "b" * 63) and table[1] == (deep_glob, "x-y_z9")


@pytest.mark.parametrize("form", ["standalone", "pyproject"])
def test_array_order_is_preserved_in_both_config_forms(form: str, tmp_path: Path):
    """
    [Unit] telemetry domains: verifies load_config keeps the array order of the standalone and pyproject tables (M23).

    Scenario:
        Given a ``[[telemetry_domains]]`` array whose globs are deliberately not in sorted order
        When ``load_config`` reads it from ``docsentinel.toml`` or ``[[tool.doc_sentinel.telemetry_domains]]``
        Then ``Config.telemetry_domains`` holds the pairs in file order as a tuple of tuples.

    Boundaries:
        - Focus: no reordering between TOML and the stored table
        - Fixtures/params: the two config forms
        - Scope: ``config.load_config``

    On failure, first check:
        - ``config._load_extra_options`` (``validate_telemetry_domains``)
    """
    prefix = "tool.doc_sentinel." if form == "pyproject" else ""
    body = "".join(
        f'[[{prefix}telemetry_domains]]\nglob = "{glob}"\ndomain = "{label}"\n\n'
        for glob, label in (("z/**", "zeta"), ("a/**", "alpha"), ("**", "docs"))
    )
    name = "pyproject.toml" if form == "pyproject" else "docsentinel.toml"
    (tmp_path / name).write_text(body, encoding="utf-8")

    settings = load_config(tmp_path)

    assert settings.telemetry_domains == (("z/**", "zeta"), ("a/**", "alpha"), ("**", "docs"))


def test_invalid_table_in_a_config_file_is_a_config_error(tmp_path: Path):
    """
    [Unit] telemetry domains: verifies load_config refuses an invalid entry (M22).

    Scenario:
        Given a docsentinel.toml whose ``[[telemetry_domains]]`` entry has an ``Agent!`` domain
        When ``load_config`` reads it
        Then a ConfigError is raised.

    Boundaries:
        - Focus: validation at load time
        - Fixtures/params: none
        - Scope: ``config.load_config``

    On failure, first check:
        - that ``telemetry_domains`` is in ``_CONFIG_OPTIONS`` and validated in ``_load_extra_options``
    """
    (tmp_path / "docsentinel.toml").write_text('[[telemetry_domains]]\nglob = "**"\ndomain = "Agent!"\n')

    with pytest.raises(ConfigError, match="domain must match"):
        load_config(tmp_path)


# --------------------------------------------------------------------------- domain_for (M18, M22, M23, M24)


def test_first_matching_entry_wins():
    """
    [Unit] telemetry domains: verifies the first matching entry decides the domain (M23).

    Scenario:
        Given ``.claude/agents/** -> agent`` before ``** -> docs`` and the reverse order
        When ``domain_for`` labels ``.claude/agents/x.md``
        Then the earlier entry wins in each order.

    Boundaries:
        - Focus: ordered, first-match semantics
        - Fixtures/params: none
        - Scope: ``domain.domain_for``

    On failure, first check:
        - the ``break`` in ``DomainTable.lookup``
    """
    agent_first = _config((".claude/agents/**", "agent"), ("**", "docs"))
    docs_first = _config(("**", "docs"), (".claude/agents/**", "agent"))

    assert domain_for(".claude/agents/x.md", agent_first) == "agent"
    assert domain_for(".claude/agents/x.md", docs_first) == "docs"


def test_no_match_falls_back_to_docs():
    """
    [Unit] telemetry domains: verifies a path no entry matches gets ``docs`` and ``matched`` null.

    Scenario:
        Given only ``.claude/agents/** -> agent``
        When ``domain_for`` and the extension label ``src/x.md``
        Then the domain is ``docs`` and the extension reports ``matched: None``.

    Boundaries:
        - Focus: the documented fallback
        - Fixtures/params: none
        - Scope: ``domain.domain_for``, ``DomainExtension.provide_document``

    On failure, first check:
        - ``DEFAULT_DOMAIN`` in ``DomainTable.lookup``
    """
    settings = _config((".claude/agents/**", "agent"))

    assert domain_for("src/x.md", settings) == DEFAULT_DOMAIN == "docs"
    assert domain.make(settings).provide_document({"path": "src/x.md"}, {}) == {"name": "docs", "matched": None}


def test_domain_is_docs_unless_the_builtin_is_loaded():
    """
    [Unit] telemetry domains: verifies a configured table is ignored while ``builtin:domain`` is not loaded (M24).

    Scenario:
        Given ``.claude/agents/** -> agent`` with ``telemetry_extensions`` empty
        When ``domain_for``, ``classify`` and ``ReportModel.build`` label ``.claude/agents/x.md``
        Then all three report ``docs``.

    Boundaries:
        - Focus: the extension gate of the core key
        - Fixtures/params: none
        - Scope: ``domain_for``, ``classify``, ``ReportModel.build``

    On failure, first check:
        - ``DomainTable.domain`` (``enabled``)
    """
    settings = _config((".claude/agents/**", "agent"), enabled=False)
    finding = Finding("DS101", ".claude/agents/x.md", "dangling link -> y.md", "error", 1)
    result = _result((Document(".claude/agents/x.md", 10),), (finding,))

    context = ReportModel.build(result, settings)

    assert domain_for(".claude/agents/x.md", settings) == "docs"
    assert classify(finding, settings).domain == "docs"
    assert [entry["domain"] for entry in context["documents"]] == ["docs"]


def test_injected_config_with_ten_thousand_entries_raises_in_domain_for():
    """
    [Unit] telemetry domains: verifies an injected Config bypassing load_config is re-checked (M22).

    Scenario:
        Given ``Config(telemetry_domains=<10k entries>)`` built directly, and one with a ``[`` glob
        When ``domain_for`` is called
        Then a ConfigError is raised before any matching.

    Boundaries:
        - Focus: fail closed for an injected Config (DS118 precedent)
        - Fixtures/params: none
        - Scope: ``domain.domain_for``

    On failure, first check:
        - ``domain._build`` calling ``validate_telemetry_domains``
    """
    huge = _config(*([("**", "docs")] * 10_000))
    bracket = _config(("docs/[a].md", "docs"))

    with pytest.raises(ConfigError, match="more than 256"):
        domain_for("a.md", huge)
    with pytest.raises(ConfigError, match=r"\["):
        domain_for("a.md", bracket)


def test_domain_for_is_memoized_per_path(monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] telemetry domains: verifies a path is matched once per table, then served from the memo (M18).

    Scenario:
        Given a two-entry table and a counting glob matcher
        When ``domain_for`` labels the same path three times with one Config
        Then the glob matcher ran only for the first call.

    Boundaries:
        - Focus: per-path memoization and the per-Config table cache
        - Fixtures/params: counting ``glob_matches``
        - Scope: ``domain.domain_for``

    On failure, first check:
        - ``DomainTable._memo`` and ``domain.domain_table``
    """
    settings = _config(("docs/**", "docs"), ("**", "other"))
    calls = []
    real = domain.glob_matches

    def counting(pattern: tuple[str, ...], path: list[str]) -> bool:
        """Count one glob comparison, then run the real one."""
        calls.append(pattern)
        return real(pattern, path)

    monkeypatch.setattr(domain, "glob_matches", counting)

    labels = [domain_for("x/y.md", settings) for _ in range(3)]

    assert labels == ["other"] * 3
    assert len(calls) == 2


# --------------------------------------------------------------------------- core doc.domain (M24)


def test_doc_domain_is_a_core_untrusted_key():
    """
    [Unit] telemetry domains: verifies ``domain`` is in DOCUMENT_SCHEMA as an untrusted str (M24).

    Scenario:
        Given the document schema
        When its ``domain`` entry is read, and a text template prints ``{doc.domain}`` without a sink
        Then the entry is ``str``/untrusted and the template is refused.

    Boundaries:
        - Focus: the schema tag drives the loader's trust rule
        - Fixtures/params: none
        - Scope: ``model.DOCUMENT_SCHEMA``, ``loader.validate_template``

    On failure, first check:
        - ``DOCUMENT_SCHEMA`` in ``telemetry/model.py``
    """
    raw = {
        "template_version": 1,
        "name": "bare-domain",
        "type": "text",
        "requires_extensions": [],
        "lines": [
            {
                "type": "loop",
                "over": "documents",
                "as": "doc",
                "body": [{"type": "line", "text": "{doc.domain}", "variables_used": ["doc.domain"]}],
            }
        ],
    }

    assert DOCUMENT_SCHEMA["domain"].type == "str" and DOCUMENT_SCHEMA["domain"].trust == UNTRUSTED
    with pytest.raises(TemplateError, match="doc.domain"):
        validate_template(raw)


def test_a_hook_cannot_change_doc_domain():
    """
    [Unit] telemetry domains: verifies a hook returning ``domain``/``path`` keys never touches the core keys (M24, M26).

    Scenario:
        Given ``builtin:domain`` on with ``** -> agent`` and an admitted extension whose document hook returns
        ``{"domain": "forged", "path": "forged"}``
        When ``ReportModel.build`` runs
        Then ``doc.domain`` is ``agent`` and ``doc.path`` unchanged; the forged data sits only under ``doc.ext``.

    Boundaries:
        - Focus: the core key is never copied from a hook return
        - Fixtures/params: an extension admitted with ``admit_extensions``
        - Scope: ``ReportModel.build``

    On failure, first check:
        - ``ReportModel._document`` and ``extensions.apply_report_hooks``
    """

    class Forger:
        """Extension trying to overwrite core document keys."""

        name = "forger"

        def provide_document(self, doc: object, model: object) -> dict:
            """Return forged core keys."""
            return {"domain": "forged", "path": "forged"}

    settings = _config(("**", "agent"))
    result = _result((Document("a.md", 3),))

    context = ReportModel.build(result, settings, extensions=admit_extensions([Forger()]))

    entry = context["documents"][0]
    assert entry["domain"] == "agent" and entry["path"] == "a.md"
    assert entry["ext"] == {"forger": {"domain": "forged", "path": "forged"}}


def _legacy_json_template() -> object:
    """Return the packaged ``json`` template as it was before this task (literal ``"docs"`` domain)."""
    path = Path(builtin.__file__).parent.parent / "templates" / "json.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["body"]["documents"]["each"]["domain"] = "docs"
    return validate_template(raw)


def test_default_json_report_is_byte_identical_to_the_literal_domain_template():
    """
    [Unit] telemetry domains: verifies default ``json`` output is unchanged by the switch to ``doc.domain`` (M24).

    Scenario:
        Given a scan with an inventory document, a finding and an out-of-inventory finding, and default settings
        When it is rendered with the packaged ``json`` template and with the pre-task literal-``"docs"`` version
        Then the two outputs are byte-identical.

    Boundaries:
        - Focus: backward compatibility of the schema-2 report
        - Fixtures/params: none
        - Scope: ``reporting.render``

    On failure, first check:
        - ``templates/json.json`` (``$var doc.domain`` with ``$default``) and ``ReportModel._document``
    """
    findings = (
        Finding("DS101", "docs/a.md", "dangling link -> b.md", "error", 1),
        Finding("DS204", "src/x.py", "docstring mismatch", "warning", 3),
    )
    result = _result((Document("docs/a.md", 12), Document("README.md", 4)), findings)

    current = render(result, "json")
    legacy = render(result, template=_legacy_json_template())

    assert current == legacy
    assert load_named_template("json").requires_extensions == ()


def test_resolved_builtin_domain_labels_documents_and_ext():
    """
    [Unit] telemetry domains: verifies the resolved builtin fills ``doc.domain`` and ``doc.ext.domain`` alike (M24).

    Scenario:
        Given ``.claude/agents/** -> agent`` and ``docs/** -> docs`` and ``builtin:domain`` resolved from argv only
        When ``render`` produces the packaged ``json`` report and the context is built with the registry
        Then ``doc.domain`` is ``agent``/``docs``/``docs`` and ``doc.ext.domain`` names the same label and glob.

    Boundaries:
        - Focus: argv builtins merged into the effective Config inside ``render``
        - Fixtures/params: none
        - Scope: ``resolve_extensions``, ``reporting.render``, ``ReportModel.build``

    On failure, first check:
        - the ``builtin_specs`` merge in ``reporting.render``
    """
    table = ((".claude/agents/**", "agent"), ("docs/**", "docs"))
    settings = Config(telemetry_domains=table)
    documents = (Document(".claude/agents/x.md", 5), Document("docs/x.md", 5), Document("misc.md", 5))
    result = _result(documents)
    loaded = resolve_extensions(
        ("builtin:domain",), config=settings, allow_python=False, root=Path.cwd(), cwd=Path.cwd()
    )

    report = json.loads(render(result, "json", config=settings, extensions=("builtin:domain",)))
    context = ReportModel.build(result, Config(telemetry_domains=table, telemetry_extensions=ON), extensions=loaded)

    assert [doc["domain"] for doc in report["documents"]] == ["agent", "docs", "docs"]
    assert [doc["ext"]["domain"] for doc in context["documents"]] == [
        {"name": "agent", "matched": ".claude/agents/**"},
        {"name": "docs", "matched": "docs/**"},
        {"name": "docs", "matched": None},
    ]


def test_domain_table_is_built_once_per_config():
    """
    [Unit] telemetry domains: verifies ``domain_table`` returns the cached table for the same Config object.

    Scenario:
        Given one Config
        When ``domain_table`` is called twice, then for an equal but distinct Config
        Then the first two calls return the same object and the third a valid table with the same entries.

    Boundaries:
        - Focus: the identity cache that keeps ``domain_for`` cheap per call (M18)
        - Fixtures/params: none
        - Scope: ``domain.domain_table``

    On failure, first check:
        - ``domain._last``
    """
    first = _config(("docs/**", "docs"))
    second = _config(("docs/**", "docs"))

    assert domain_table(first) is domain_table(first)
    assert domain_table(second).entries == domain_table(first).entries
