"""Unit tests for template discovery and name-only loading (Milestone 0007 Story 03.0 Task 02).

:func:`~docsentinel.telemetry.loader.available_templates` computes the ``--format`` choices
(packaged names, then ``report_templates_dir`` entries) and
:func:`~docsentinel.telemetry.loader.load_named_template` refuses any value that is not a
template name, so a format can never be used to open a path.
"""

import os
from pathlib import Path

import pytest

from docsentinel.telemetry import loader
from docsentinel.telemetry.filters import TemplateError
from docsentinel.telemetry.loader import available_templates, load_named_template, packaged_template_names

_MINI = '{"template_version": 1, "name": "mini", "type": "text", "lines": []}'


def test_packaged_names_are_the_five_shipped_templates():
    """
    [Unit] available templates: verifies the packaged name list.

    Scenario:
        Given the packaged ``templates`` directory
        When its names are listed
        Then they are the five shipped templates, sorted.

    Boundaries:
        - Focus: ``packaged_template_names``
        - Fixtures/params: none
        - Scope: the packaged directory

    On failure, first check:
        - Whether a template file was added, renamed or removed under ``telemetry/templates``
    """
    assert packaged_template_names() == ("github", "json", "json-documents", "json-v1", "text")
    assert available_templates() == packaged_template_names()


def test_directory_templates_are_added_without_shadowing(tmp_path: Path):
    """
    [Unit] available templates: verifies directory names are merged, filtered and never shadow packaged ones.

    Scenario:
        Given a templates directory holding ``mini.json``, a ``text.json``, a non-JSON file, a badly named
            JSON file, a subdirectory named like a template, and a symlinked template
        When the available templates are listed
        Then only ``mini`` is added to the packaged names, once.

    Boundaries:
        - Focus: the listing filter (suffix, name pattern, regular file, no symlink follow)
        - Fixtures/params: tmp_path
        - Scope: ``available_templates`` on a temp tree

    On failure, first check:
        - The ``entry`` filter in ``available_templates``
    """
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "mini.json").write_text(_MINI, encoding="utf-8")
    (templates / "text.json").write_text(_MINI, encoding="utf-8")
    (templates / "notes.txt").write_text("x", encoding="utf-8")
    (templates / "Bad_Name.json").write_text(_MINI, encoding="utf-8")
    (templates / "folder.json").mkdir()
    os.symlink(templates / "mini.json", templates / "linked.json")

    names = available_templates(tmp_path, "templates")

    assert names == ("github", "json", "json-documents", "json-v1", "mini", "text")


@pytest.mark.parametrize(
    ("templates_dir", "root", "message"),
    [
        ("missing", True, "report_templates_dir"),
        ("../outside", True, "escapes the scan root"),
        ("templates", False, "needs a scan root"),
    ],
    ids=["missing-dir", "escape", "no-root"],
)
def test_directory_listing_fails_closed(templates_dir: str, root: bool, message: str, tmp_path: Path):
    """
    [Unit] available templates: verifies a missing, escaping or rootless directory is a TemplateError.

    Scenario:
        Given a ``report_templates_dir`` that does not exist, escapes the root, or has no scan root
        When the available templates are listed
        Then ``TemplateError`` is raised instead of a silent packaged-only list.

    Boundaries:
        - Focus: the containment gate reused from the loader (M10)
        - Fixtures/params: one case per failure
        - Scope: ``available_templates``

    On failure, first check:
        - ``loader._check_contained`` and the ``os.scandir`` error handling
    """
    with pytest.raises(TemplateError, match=message):
        available_templates(tmp_path if root else None, templates_dir)


def test_directory_with_too_many_templates_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] available templates: verifies a directory past the template cap is refused, not truncated.

    Scenario:
        Given a lowered cap of two templates and a directory holding three
        When the available templates are listed
        Then ``TemplateError`` names the cap.

    Boundaries:
        - Focus: ``MAX_DIRECTORY_TEMPLATES``
        - Fixtures/params: monkeypatched cap, tmp_path
        - Scope: ``available_templates``

    On failure, first check:
        - The cap check inside the ``os.scandir`` loop
    """
    monkeypatch.setattr(loader, "MAX_DIRECTORY_TEMPLATES", 2)
    templates = tmp_path / "templates"
    templates.mkdir()
    for name in ("a", "b", "c"):
        (templates / f"{name}.json").write_text(_MINI, encoding="utf-8")

    with pytest.raises(TemplateError, match="more than 2 templates"):
        available_templates(tmp_path, "templates")


@pytest.mark.parametrize("value", ["../x.json", "templates/mini.json", "Text", "", "a" * 65])
def test_load_named_template_refuses_non_names(value: str, tmp_path: Path):
    """
    [Unit] available templates: verifies a path-shaped or invalid name is an unknown template, never opened.

    Scenario:
        Given a value that is a path, upper-case, empty or longer than 64 characters
        When it is loaded as a template name
        Then ``TemplateError`` reports an unknown template.

    Boundaries:
        - Focus: ``load_named_template`` name guard
        - Fixtures/params: one value per shape
        - Scope: pure name check

    On failure, first check:
        - ``loader._is_template_name``
    """
    with pytest.raises(TemplateError, match="unknown template"):
        load_named_template(value, root=tmp_path)


def test_load_named_template_resolves_packaged_and_directory_names(tmp_path: Path):
    """
    [Unit] available templates: verifies packaged and directory names both load.

    Scenario:
        Given a templates directory holding ``mini.json``
        When ``text`` and ``mini`` are loaded by name with that directory
        Then ``text`` is the packaged template and ``mini`` comes from the directory.

    Boundaries:
        - Focus: delegation to the packaged-first name resolver
        - Fixtures/params: tmp_path
        - Scope: ``load_named_template``

    On failure, first check:
        - ``loader._load_by_name``
    """
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "mini.json").write_text(_MINI, encoding="utf-8")

    assert load_named_template("text", root=tmp_path, templates_dir="templates").origin == "packaged"
    assert load_named_template("mini", root=tmp_path, templates_dir="templates").origin == "directory"
