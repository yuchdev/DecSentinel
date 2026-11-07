"""Integration tests for the report template loader over committed template assets.

Milestone 0007 Story 02.0 Task 01. The ``tests/assets/report/template_dir`` case is a
miniature scan root with a ``templates/`` directory used as ``report_templates_dir``.
Pathological byte inputs (oversize, BOM, invalid UTF-8) are generated in the test body.
"""

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from docsentinel.telemetry import loader
from docsentinel.telemetry.loader import MAX_TEMPLATE_BYTES, JsonObject, TemplateError, load_template
from tests.asset_helpers import AssetCase

_PACKAGED_TEXT = (
    '{"template_version": 1, "name": "text", "type": "text", "description": "packaged",'
    ' "lines": [{"type": "line", "text": "Profile: {profile}", "variables_used": ["profile"]}]}'
)


@pytest.fixture
def template_root(asset_case: Callable[[str, str], AssetCase]) -> Path:
    """Materialize the template-directory scan root."""
    return asset_case("report", "template_dir").root


@pytest.fixture
def packaged_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the packaged-template directory at a temp dir holding a packaged ``text.json``."""
    packaged = tmp_path / "packaged"
    packaged.mkdir()
    (packaged / "text.json").write_text(_PACKAGED_TEXT, encoding="utf-8")
    monkeypatch.setattr(loader, "PACKAGED_TEMPLATES_DIR", packaged)
    loader._load_packaged_cached.cache_clear()
    return packaged


def test_named_template_loads_from_templates_dir(template_root: Path):
    """
    [Integration] loader: verifies a name resolves under ``report_templates_dir`` and records only configured text.

    Scenario:
        Given ``templates/mini.json`` in the scan root
        When ``mini`` is loaded with ``templates_dir="templates"``
        Then a text template with origin ``directory`` and source ``templates/mini.json`` is returned.

    Boundaries:
        - Focus: name resolution second step (Task 01 contract)
        - Fixtures/params: report/template_dir
        - Scope: load_template over real files

    On failure, first check:
        - ``loader._load_by_name``
    """
    template = load_template("mini", root=template_root, templates_dir="templates")

    assert template.type == "text" and template.origin == "directory"
    assert template.source == "templates/mini.json"
    assert str(template_root) not in template.source


@pytest.mark.parametrize("templates_dir", ["templates/", "templates//", "./templates", "./templates/"])
def test_templates_dir_spelling_is_normalized(template_root: Path, templates_dir: str):
    """
    [Integration] loader: verifies equivalent ``report_templates_dir`` spellings join to one configured path.

    Scenario:
        Given ``report_templates_dir`` spelled with a trailing slash, a doubled slash or a ``./`` lead
        When ``mini`` is loaded through it
        Then the template loads and its source is the normalized ``templates/mini.json``.

    Boundaries:
        - Focus: ``_load_by_name`` join normalization (security review follow-up, replaces ``rstrip('/')``)
        - Fixtures/params: report/template_dir, one spelling per case
        - Scope: load_template over real files

    On failure, first check:
        - The ``PurePosixPath`` join in ``loader._load_by_name``
    """
    template = load_template("mini", root=template_root, templates_dir=templates_dir)

    assert template.source == "templates/mini.json"


def test_root_templates_dir_never_joins_to_an_absolute_path(template_root: Path):
    """
    [Integration] loader: verifies ``report_templates_dir="/"`` is refused, never joined to ``/mini.json``.

    Scenario:
        Given ``report_templates_dir`` set to ``/``
        When ``mini`` is loaded through it
        Then TemplateError is raised by the containment gate.

    Boundaries:
        - Focus: ``_load_by_name`` join normalization edge (``rstrip('/')`` left an empty directory)
        - Fixtures/params: report/template_dir
        - Scope: load_template over real files

    On failure, first check:
        - ``loader._check_contained`` on the directory before the join is used
    """
    with pytest.raises(TemplateError, match="escapes the scan root"):
        load_template("mini", root=template_root, templates_dir="/")


def test_repository_template_cannot_shadow_packaged_name(template_root: Path, packaged_dir: Path):
    """
    [Integration] loader: verifies a repo ``text.json`` in ``report_templates_dir`` never overrides the packaged one.

    Scenario:
        Given a packaged ``text.json`` and a hostile ``templates/text.json`` printing "0 findings"
        When ``text`` is loaded with the templates dir configured
        Then the packaged template is returned.

    Boundaries:
        - Focus: M9 packaged-first resolution
        - Fixtures/params: report/template_dir, packaged dir patched to a temp dir
        - Scope: load_template over real files

    On failure, first check:
        - The packaged lookup at the top of ``loader._load_by_name``
    """
    template = load_template("text", root=template_root, templates_dir="templates")

    assert template.origin == "packaged" and template.description == "packaged"


def test_packaged_templates_are_cached_by_identity(packaged_dir: Path):
    """
    [Integration] loader: verifies packaged templates are cached and the cache follows ``(path, mtime, size)``.

    Scenario:
        Given a packaged ``text.json``
        When it is loaded twice, then rewritten with a different size and loaded again
        Then the first two loads return the same object and the third a fresh one.

    Boundaries:
        - Focus: Task 01 cache contract / M17 (cache only packaged templates)
        - Fixtures/params: packaged dir patched to a temp dir
        - Scope: load_template over real files

    On failure, first check:
        - ``loader._load_packaged_cached`` key
    """
    first = load_template("text")
    assert load_template("text") is first
    (packaged_dir / "text.json").write_text(_PACKAGED_TEXT.replace('"packaged"', '"packaged v2"'), encoding="utf-8")
    second = load_template("text")
    assert second is not first and second.description == "packaged v2"


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("dup-key", "duplicate object key: text"),
        ("typo-key", "unknown key(s): varibles_used"),
        ("wrong-stem", "name must equal the file stem wrong-stem"),
        ("absent", "unknown template: absent"),
    ],
)
def test_invalid_repository_templates_are_rejected(template_root: Path, name: str, fragment: str):
    """
    [Integration] loader: verifies duplicate keys, unknown-key typos and stem mismatches in files fail closed.

    Scenario:
        Given committed templates with a duplicate key, a ``varibles_used`` typo, a name/stem mismatch, and a
        missing name
        When each is loaded by name from the templates dir
        Then TemplateError names the defect and the configured path, never the absolute one.

    Boundaries:
        - Focus: Task 01 rule 1 (duplicate keys), rule 2 (unknown keys), spec §2 stem rule
        - Fixtures/params: report/template_dir, one template per case
        - Scope: load_template over real files

    On failure, first check:
        - ``_reject_duplicates`` / ``_Validator._object`` / ``loader._finish``
    """
    with pytest.raises(TemplateError) as caught:
        load_template(name, root=template_root, templates_dir="templates")
    assert fragment in str(caught.value)
    assert str(template_root) not in str(caught.value)


def test_config_named_and_argv_paths_load(template_root: Path):
    """
    [Integration] loader: verifies a config-named relative path and an argv absolute path both load.

    Scenario:
        Given ``templates/json-mini.json``
        When loaded with ``from_config=True`` (relative) and as an absolute argv path
        Then both return the json template with origin ``path``.

    Boundaries:
        - Focus: path sources (Task 01 contract; argv trusted like any argv path)
        - Fixtures/params: report/template_dir
        - Scope: load_template over real files

    On failure, first check:
        - The path branches of ``load_template``
    """
    configured = load_template("templates/json-mini.json", root=template_root, from_config=True)
    argv = load_template(template_root / "templates" / "json-mini.json")

    for template in (configured, argv):
        assert template.type == "json" and template.origin == "path" and isinstance(template.body, JsonObject)
        assert template.output.indent == 2


def test_in_root_symlink_is_refused_for_config_paths_only(template_root: Path):
    """
    [Integration] loader: verifies ``O_NOFOLLOW`` refuses an in-root symlinked config-named file, argv follows it.

    Scenario:
        Given ``templates/link.json`` symlinked to the in-root ``mini.json``
        When loaded as a config-named path and as an argv path
        Then the config-named load fails closed and the argv load succeeds.

    Boundaries:
        - Focus: M11 ``O_NOFOLLOW`` for config-named files (fail closed); argv trust (spec §10)
        - Fixtures/params: report/template_dir plus a runtime symlink
        - Scope: load_template over real files

    On failure, first check:
        - The ``nofollow`` flag passed to ``loader._read_gated``
    """
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("O_NOFOLLOW unavailable")
    link = template_root / "templates" / "link.json"
    link.symlink_to("mini.json")
    with pytest.raises(TemplateError, match="could not be read"):
        load_template("templates/link.json", root=template_root, from_config=True)
    assert load_template(link).name == "mini"


def test_file_at_exact_size_limit_loads_and_one_byte_more_is_rejected(tmp_path: Path):
    """
    [Integration] loader: verifies the 256 KiB bound is inclusive and MAX + 1 is rejected.

    Scenario:
        Given a valid template padded with whitespace to exactly MAX bytes, and one padded to MAX + 1
        When each is loaded as an argv path
        Then the first loads and the second raises "larger than".

    Boundaries:
        - Focus: Task 01 rule 1 size gate, edge at the limit
        - Fixtures/params: generated in the test body (README: pathological inputs)
        - Scope: load_template over real files

    On failure, first check:
        - ``MAX_TEMPLATE_BYTES`` checks in ``loader._read_gated``
    """
    body = b'{"template_version": 1, "name": "big", "type": "text", "lines": []}'
    exact = tmp_path / "exact.json"
    exact.write_bytes(body + b" " * (MAX_TEMPLATE_BYTES - len(body)))
    over = tmp_path / "over.json"
    over.write_bytes(body + b" " * (MAX_TEMPLATE_BYTES - len(body) + 1))

    assert load_template(exact).name == "big"
    with pytest.raises(TemplateError, match="larger than"):
        load_template(over)


@pytest.mark.parametrize(
    ("payload", "fragment"),
    [
        (b'\xef\xbb\xbf{"template_version": 1}', "byte order mark"),
        (b'{"name": "\xff\xfe"}', "not valid UTF-8"),
        (b"not json", "invalid JSON at line 1"),
        (b"", "invalid JSON"),
    ],
)
def test_encoding_and_syntax_gate(tmp_path: Path, payload: bytes, fragment: str):
    """
    [Integration] loader: verifies a BOM, invalid UTF-8, and non-JSON bytes become bounded TemplateErrors.

    Scenario:
        Given a template file with a UTF-8 BOM, undecodable bytes, plain text, or nothing
        When it is loaded
        Then TemplateError names the defect without echoing the bytes.

    Boundaries:
        - Focus: Task 01 rule 1 (UTF-8, valid JSON) and M11 (strict decode, no BOM)
        - Fixtures/params: generated in the test body
        - Scope: load_template over real files

    On failure, first check:
        - The decode block of ``loader._read_gated`` and ``loader._parse_json``
    """
    path = tmp_path / "bad.json"
    path.write_bytes(payload)
    with pytest.raises(TemplateError) as caught:
        load_template(path)
    assert fragment in str(caught.value) and "\xff" not in str(caught.value)
