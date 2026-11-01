"""Unit tests for the Milestone 0007 report config options (Story 03.0 Task 02).

``report_templates_dir`` (a root-contained directory, default ``None``),
``report_show_clean_documents`` and ``report_include_run_meta`` (booleans, default
``false``) are typed and validated like the Milestone 0005 policy options, in both the
standalone file and the ``[tool.doc_sentinel]`` table.
"""

from pathlib import Path

import pytest

from docsentinel import Config, ConfigError, load_config


def test_report_option_defaults():
    """
    [Unit] config report options: verifies the three report options default to off.

    Scenario:
        Given a default Config
        When the report options are read
        Then the templates directory is ``None`` and both flags are ``False``.

    Boundaries:
        - Focus: defaults keep reports deterministic and packaged-only
        - Fixtures/params: none
        - Scope: the Config dataclass

    On failure, first check:
        - The ``report_*`` field defaults on ``Config``
    """
    config = Config()

    assert config.report_templates_dir is None
    assert config.report_show_clean_documents is False
    assert config.report_include_run_meta is False


@pytest.mark.parametrize(
    ("file_name", "prefix"),
    [("docsentinel.toml", ""), ("pyproject.toml", "[tool.doc_sentinel]\n")],
    ids=["standalone", "pyproject"],
)
def test_report_options_load_from_both_file_forms(file_name: str, prefix: str, tmp_path: Path):
    """
    [Unit] config report options: verifies the report options load from both config file forms.

    Scenario:
        Given a standalone file or a ``[tool.doc_sentinel]`` table setting all three report options
        When the config is loaded
        Then each option carries the configured value.

    Boundaries:
        - Focus: option registration in ``_CONFIG_OPTIONS`` and ``_load_extra_options``
        - Fixtures/params: parametrized over the two file forms
        - Scope: load_config on a temp directory

    On failure, first check:
        - Whether the options were added to ``_CONFIG_OPTIONS`` / ``_BOOL_OPTIONS``
    """
    body = (
        'report_templates_dir = "docs/templates"\nreport_show_clean_documents = true\nreport_include_run_meta = true\n'
    )
    (tmp_path / file_name).write_text(prefix + body, encoding="utf-8")

    config = load_config(tmp_path)

    assert config.report_templates_dir == "docs/templates"
    assert config.report_show_clean_documents is True
    assert config.report_include_run_meta is True


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ('report_templates_dir = ""', "report_templates_dir must be a nonempty"),
        ("report_templates_dir = 3", "report_templates_dir must be a nonempty"),
        ('report_templates_dir = "../outside"', "report_templates_dir must stay within the scan root"),
        ('report_templates_dir = "/etc"', "report_templates_dir must stay within the scan root"),
        ('report_templates_dir = "a\\\\b"', "report_templates_dir must stay within the scan root"),
        ('report_show_clean_documents = "yes"', "report_show_clean_documents must be true or false"),
        ("report_include_run_meta = 1", "report_include_run_meta must be true or false"),
    ],
    ids=["empty-dir", "non-string-dir", "parent-escape", "absolute", "backslash", "string-flag", "int-flag"],
)
def test_invalid_report_options_raise_config_error(line: str, message: str, tmp_path: Path):
    """
    [Unit] config report options: verifies invalid report option values fail closed.

    Scenario:
        Given a docsentinel.toml with one invalid report option
        When the config is loaded
        Then ``ConfigError`` names the option and the rule it broke.

    Boundaries:
        - Focus: type and lexical containment validation (the loader adds the symlink gate at use time)
        - Fixtures/params: one case per invalid shape
        - Scope: load_config on a temp directory

    On failure, first check:
        - The ``report_templates_dir`` block of ``_load_extra_options`` and ``_require_bool``
    """
    (tmp_path / "docsentinel.toml").write_text(line + "\n", encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_config(tmp_path)
