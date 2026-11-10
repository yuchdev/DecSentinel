"""Integration tests for site-root-absolute (``/``) targets resolved against ``link_root``.

Each case is a miniature repository (``repo/``): ``ds101``/``ds103``
``link_root_repository_absolute`` for DS101/DS103, and ``ds101/link_root_media_assets``
and ``ds101/link_root_path_boundaries`` for DS113/DS116 (kept under ``ds101`` because
the Milestone 0005 fixture catalog owns the ``ds113``/``ds116`` directories). Each
repository whose documentation lives in ``repo/docs/`` and links with
GitHub-style ``/``-targets such as ``/docs/adr/README.md``. The scan root is
``repo/docs``. A nested ``.git`` cannot be committed, so each test creates the
``.git`` marker (a directory, or a file as worktrees and submodules use) in the
``tmp_path`` copy at runtime. Detectors never probe for ``.git`` themselves, so a direct
detector call receives ``link_root=`` from :func:`resolve_link_root`, exactly what
:func:`docsentinel.scan` hands every analyzer that declares it.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from docsentinel import Config, ConfigError, models, scan
from docsentinel.baseline import fingerprint, load_baseline
from docsentinel.cli import main
from docsentinel.detectors import assets, links, path_boundaries, paths
from docsentinel.link_root import resolve_link_root
from tests.asset_helpers import AssetCase
from tests.git_marker_helpers import (
    GitMarkerGuard,
    install_git_marker_guard,
    is_git_marker_probe,
    is_project_marker_probe,
)
from tests.mock.test_path_boundaries_oracle import _install_recorder, _is_under, _Recorder

_CASE = "link_root_repository_absolute"


def _materialize(
    asset_case: Callable[[str, str], AssetCase], rule: str, *, case: str = _CASE, git: str = "dir"
) -> tuple[Path, Path]:
    """Copy a case into ``tmp_path`` and add the repository's ``.git`` marker.

    :param asset_case: The asset loader fixture.
    :param rule: The asset rule directory (``ds101`` or ``ds103``).
    :param case: The case directory name.
    :param git: ``"dir"``, ``"file"`` or ``"none"``.
    :returns: ``(repo, docs)`` absolute, canonical paths.
    """
    loaded = asset_case(rule, case)
    repo = Path(os.path.realpath(loaded.path("repo")))
    if git == "dir":
        (repo / ".git").mkdir()
    elif git == "file":
        (repo / ".git").write_text("gitdir: /elsewhere/.git/worktrees/repo\n", encoding="utf-8")
    else:
        # Precondition, not a skip: the no-.git fallback is only meaningful outside a checkout.
        assert not any(os.path.lexists(directory / ".git") for directory in (repo, *repo.parents)), (
            "pytest tmp directory sits inside a git checkout; point --basetemp outside it"
        )
    return repo, repo / "docs"


def _docs(docs: Path) -> tuple[models.Document, ...]:
    """Return the Document tuple of the scan root's README.

    :param docs: The scan root.
    :returns: A one-document tuple.
    """
    return (models.Document("README.md", (docs / "README.md").stat().st_size),)


def _engine_root(docs: Path) -> Path:
    """Return the link root the engine resolves for ``docs`` with the default config.

    :param docs: The canonical scan root.
    :returns: The validated link root directory.
    """
    return resolve_link_root(docs, Config())


def _summary(findings) -> list[tuple[str, int, str]]:
    """Return ``(rule, line, message)`` triples for compact assertions.

    :param findings: Findings to summarise.
    :returns: The triples, in finding order.
    """
    return [(finding.rule, finding.line, finding.message) for finding in findings]


# --- DS101 ----------------------------------------------------------------------------------


@pytest.mark.parametrize("git", ["dir", "file"])
def test_ds101_repository_absolute_links_resolve_against_git_root(
    asset_case: Callable[[str, str], AssetCase], git: str
):
    """
    [Integration] link root ds101: ``/docs/adr/README.md`` from a docs/ scan root is not dangling.

    Scenario:
        Given repo/.git (directory or file) and repo/docs/README.md linking /docs/adr/README.md,
          its #decision-log anchor, /src/app.py, a relative link and /docs/adr/missing.md
        When DS101 runs with the scan root at repo/docs and the default link_root
        Then only the genuinely missing /docs/adr/missing.md is reported.

    Boundaries:
        - Focus: the CanonixEngine false-positive regression
        - Fixtures/params: asset_case, git
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - links.detect resolving the link root from config
        - The .git marker created at runtime in the tmp copy
    """
    _repo, docs = _materialize(asset_case, "ds101", git=git)

    findings = links.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))

    assert _summary(findings) == [("DS101", 7, "dangling link -> /docs/adr/missing.md")]
    assert findings[0].column == 17
    assert findings[0].value == "/docs/adr/missing.md"


def test_ds101_explicit_dot_link_root_restores_scan_root_semantics(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] link root ds101: ``link_root = "."`` joins ``/`` onto the scan root (MkDocs style).

    Scenario:
        Given the same repository with .git
        When DS101 runs with link_root = "."
        Then every "/" link is resolved under repo/docs and reported as dangling, the relative one is not.

    Boundaries:
        - Focus: explicit override
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - resolve_link_root for explicit "."
    """
    _repo, docs = _materialize(asset_case, "ds101")

    findings = links.detect(docs, _docs(docs), Config(link_root="."))

    assert _summary(findings) == [
        ("DS101", 3, "dangling link -> /docs/adr/README.md"),
        ("DS101", 4, "dangling link -> /docs/adr/README.md#decision-log"),
        ("DS101", 5, "dangling link -> /src/app.py"),
        ("DS101", 7, "dangling link -> /docs/adr/missing.md"),
    ]


def test_ds101_without_git_keeps_historical_scan_root_join(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] link root ds101: with no ``.git`` above the scan root the old behaviour is unchanged.

    Scenario:
        Given the repository copy without any .git marker
        When DS101 runs with the default link_root, and again with link_root = "."
        Then both runs report exactly the same findings.

    Boundaries:
        - Focus: byte-identical fallback
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - The fallback branch of _git_ancestor
    """
    _repo, docs = _materialize(asset_case, "ds101", git="none")

    auto = links.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))

    assert auto == links.detect(docs, _docs(docs), Config(link_root="."))
    assert len(auto) == 4


def test_ds101_link_root_missing_anchor_in_repository_file_is_reported(
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] link root ds101: anchors of a ``/``-target file are still checked.

    Scenario:
        Given the repository with .git and an extra line linking /docs/adr/README.md#no-such-heading
        When DS101 runs with the default link_root
        Then the missing anchor is reported alongside the missing file.

    Boundaries:
        - Focus: anchor validation through the link root
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - heading_anchors on the link-root-resolved path
    """
    _repo, docs = _materialize(asset_case, "ds101")
    readme = docs / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "A [bad anchor](/docs/adr/README.md#no-such-heading).\n", encoding="utf-8"
    )

    findings = links.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))

    assert _summary(findings) == [
        ("DS101", 7, "dangling link -> /docs/adr/missing.md"),
        ("DS101", 8, "missing anchor '#no-such-heading' in /docs/adr/README.md"),
    ]


def test_ds101_direct_call_with_unpinned_auto_does_not_probe_for_git(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] link root ds101: a detector called with a raw "auto" config keeps scan-root joins.

    Scenario:
        Given the repository with .git
        When links.detect runs with an unpinned Config() instead of the engine-pinned one
        Then the "/" links resolve under the scan root, because only the engine walks for .git.

    Boundaries:
        - Focus: the engine/detector layering of link_root resolution
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - links.detect using link_root_for rather than resolve_link_root
    """
    _repo, docs = _materialize(asset_case, "ds101")

    assert links.detect(docs, _docs(docs), Config()) == links.detect(docs, _docs(docs), Config(link_root="."))


# --- engine and CLI -------------------------------------------------------------------------


def test_scan_of_docs_subdirectory_reports_only_missing_repository_link(
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] link root ds101 ds116: an engine scan of repo/docs has no false DS101 or DS116 findings.

    Scenario:
        Given the DS101 repository with .git
        When docsentinel.scan runs on repo/docs with the fast profile
        Then the only DS101 finding is the missing file and DS116 reports nothing for /src/app.py.

    Boundaries:
        - Focus: engine pinning of link_root
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - resolve_link_root and the link_root forwarding in engine.scan
    """
    _repo, docs = _materialize(asset_case, "ds101")

    result = scan(docs)

    assert [(f.rule, f.message) for f in result.findings if f.rule in ("DS101", "DS116")] == [
        ("DS101", "dangling link -> /docs/adr/missing.md")
    ]


def test_cli_scan_reports_missing_link_and_not_existing_repository_links(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] link root ds101: the CLI text report on repo/docs matches GitHub resolution.

    Scenario:
        Given the DS101 repository with .git
        When `docsentinel scan repo/docs --profile fast --format text` runs
        Then it exits 1 for the missing link only and never reports /docs/adr/README.md.

    Boundaries:
        - Focus: CLI end-to-end behaviour of the regression
        - Fixtures/params: asset_case, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - cli.main scan path and the engine pin
    """
    _repo, docs = _materialize(asset_case, "ds101")

    exit_code = main(["scan", str(docs), "--profile", "fast", "--format", "text"])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "dangling link -> /docs/adr/missing.md" in output
    assert "dangling link -> /docs/adr/README.md" not in output
    assert "/src/app.py" not in output


def test_cli_scan_with_dot_link_root_in_config_uses_scan_root(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] link root ds101: ``link_root = "."`` in docsentinel.toml restores scan-root joins.

    Scenario:
        Given the DS101 repository with .git and repo/docs/docsentinel.toml setting link_root = "."
        When the CLI scans repo/docs
        Then the "/" links are reported as dangling under the scan root.

    Boundaries:
        - Focus: config-file override through the CLI
        - Fixtures/params: asset_case, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - load_config reading link_root
    """
    _repo, docs = _materialize(asset_case, "ds101")
    (docs / "docsentinel.toml").write_text('link_root = "."\n', encoding="utf-8")

    exit_code = main(["scan", str(docs), "--profile", "fast", "--format", "text"])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "dangling link -> /docs/adr/README.md" in output
    assert "dangling link -> /src/app.py" in output


@pytest.mark.parametrize("value", ["adr", "../src", "/abs", "../..", "../../x/..", "../" * 40])
def test_cli_scan_with_invalid_link_root_exits_2(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str], value: str
):
    """
    [Integration] link root ds101: a link_root that is not the scan root or a bounded ancestor fails closed.

    Scenario:
        Given repo/docs/docsentinel.toml with a child, sibling, absolute, above-the-repository or
          filesystem-root ("/") link_root
        When the CLI scans repo/docs
        Then it exits 2 with a link_root error and no report.

    Boundaries:
        - Focus: fail-closed readiness error
        - Fixtures/params: asset_case, capsys, value
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - ConfigError propagation from resolve_link_root through cli
    """
    _repo, docs = _materialize(asset_case, "ds101")
    (docs / "docsentinel.toml").write_text(f'link_root = "{value}"\n', encoding="utf-8")

    exit_code = main(["scan", str(docs), "--profile", "fast", "--format", "text"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "link_root" in captured.err + captured.out
    assert "dangling link" not in captured.out


def test_config_parent_link_root_without_git_needs_a_project_marker(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] link root ds101: config ``".."`` on a non-git tree works only if repo/ holds a project marker.

    Scenario:
        Given the repository copy without any .git and repo/docs/docsentinel.toml setting link_root = ".."
        When the CLI scans repo/docs, first without a marker in repo/, then with repo/pyproject.toml
        Then the first run exits 2 with the marker error; the second resolves /docs/... links (exit 1, only
          the missing file reported).

    Boundaries:
        - Focus: the project-marker allowlist through the CLI
        - Fixtures/params: asset_case, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - _has_project_marker in _bounded_config_candidate
    """
    repo, docs = _materialize(asset_case, "ds101", git="none")
    (docs / "docsentinel.toml").write_text('link_root = ".."\n', encoding="utf-8")

    refused = main(["scan", str(docs), "--profile", "fast", "--format", "text"])
    refused_output = capsys.readouterr()
    (repo / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    accepted = main(["scan", str(docs), "--profile", "fast", "--format", "text"])
    accepted_output = capsys.readouterr().out

    assert refused == 2
    assert "pyproject.toml, docsentinel.toml or doc_sentinel.toml" in refused_output.err
    assert refused_output.out == ""
    assert accepted == 1
    assert "dangling link -> /docs/adr/missing.md" in accepted_output
    assert "dangling link -> /docs/adr/README.md" not in accepted_output


def test_config_link_root_with_marker_probes_only_by_lexists(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] link root ds101 ds116: a marker-admitted link root touches nothing else outside the scan root.

    Scenario:
        Given a no-git repo copy with repo/pyproject.toml, config link_root = ".." and a recorder plus the
          .git/marker guard installed
        When docsentinel.scan runs on repo/docs (which links /docs/adr/README.md and /src/app.py)
        Then /-targets resolve under repo, every outside-root access is an exact lexists probe of an
          ancestor's .git or project marker or lies inside the link root, and no probe is opened or followed.

    Boundaries:
        - Focus: the filesystem footprint of the marker allowlist
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - _has_project_marker using os.path.lexists only
    """
    repo, docs = _materialize(asset_case, "ds101", git="none")
    (repo / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
    config = Config(profile="fast", link_root="..")
    scan(docs, config=config)  # warm up lazy imports before recording

    recorder = _Recorder()
    guard = GitMarkerGuard(str(docs))
    with pytest.MonkeyPatch.context() as patch:
        _install_recorder(patch, recorder)
        install_git_marker_guard(patch, guard)
        result = scan(docs, config=config)

    assert [(f.rule, f.message) for f in result.findings if f.rule in ("DS101", "DS116")] == [
        ("DS101", "dangling link -> /docs/adr/missing.md")
    ]
    assert guard.violations == []
    assert str(repo / "pyproject.toml") in recorder.paths
    for recorded in recorder.paths:
        if is_git_marker_probe(recorded, str(docs)) or is_project_marker_probe(recorded, str(docs)):
            continue
        assert _is_under(recorded, str(repo)) or _is_under(str(docs), recorded), f"touched outside: {recorded}"


def test_home_level_git_does_not_widen_auto(
    asset_case: Callable[[str, str], AssetCase], monkeypatch: pytest.MonkeyPatch
):
    """
    [Integration] link root ds101: a ``.git`` at the home directory (dotfiles repo) leaves auto at the scan root.

    Scenario:
        Given a repo copy without its own .git, Path.home() patched to the tmp ancestor, and a .git there
        When docsentinel.scan runs on repo/docs with the default link_root
        Then /docs/... links resolve under the scan root (reported as dangling), as without any repository.

    Boundaries:
        - Focus: the dotfiles-repository refusal for auto
        - Fixtures/params: asset_case, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - _trusted_repository in resolve_link_root
    """
    repo, docs = _materialize(asset_case, "ds101", git="none")
    (repo.parent / ".git").mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: repo.parent))

    messages = [f.message for f in scan(docs).findings if f.rule == "DS101"]

    assert "dangling link -> /docs/adr/README.md" in messages
    assert "dangling link -> /src/app.py" in messages


def test_cli_link_root_flag_resolves_slash_links_on_a_non_git_tree(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    """
    [Integration] link root ds101: ``--link-root`` (absolute or CWD-relative) resolves ``/docs/x.md`` without .git.

    Scenario:
        Given the repository copy without any .git
        When the CLI scans repo/docs with --link-root as an absolute path, then as a path relative to the CWD
        Then both runs resolve /docs/... links under repo and report only the missing file.

    Boundaries:
        - Focus: the trusted invoker flag
        - Fixtures/params: asset_case, capsys, monkeypatch
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - cli forwarding args.link_root to scan(link_root=)
    """
    repo, docs = _materialize(asset_case, "ds101", git="none")

    absolute = main(["scan", str(docs), "--profile", "fast", "--format", "text", "--link-root", str(repo)])
    absolute_output = capsys.readouterr().out
    monkeypatch.chdir(docs)
    relative = main(["scan", ".", "--profile", "fast", "--format", "text", "--link-root", ".."])
    relative_output = capsys.readouterr().out

    for exit_code, output in ((absolute, absolute_output), (relative, relative_output)):
        assert exit_code == 1
        assert "dangling link -> /docs/adr/missing.md" in output
        assert "dangling link -> /docs/adr/README.md" not in output
        assert "dangling link -> /src/app.py" not in output


def test_cli_link_root_flag_overrides_config(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] link root ds101: ``--link-root`` wins over ``link_root`` in the config.

    Scenario:
        Given repo/.git and a config pinning link_root = "." (scan-root semantics)
        When the CLI scans repo/docs with --link-root pointing at repo
        Then /docs/... links resolve under repo despite the config.

    Boundaries:
        - Focus: precedence of the trusted flag
        - Fixtures/params: asset_case, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - The invoker branch in engine.scan
    """
    repo, docs = _materialize(asset_case, "ds101")
    (docs / "docsentinel.toml").write_text('link_root = "."\n', encoding="utf-8")

    exit_code = main(["scan", str(docs), "--profile", "fast", "--format", "text", "--link-root", str(repo)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "dangling link -> /docs/adr/README.md" not in output
    assert "dangling link -> /docs/adr/missing.md" in output


@pytest.mark.parametrize("which", ["filesystem-root", "child", "missing", "sibling"])
def test_cli_link_root_flag_refuses_root_non_ancestor_and_missing(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str], which: str
):
    """
    [Integration] link root ds101: ``--link-root`` at ``/``, a non-ancestor or a missing directory exits 2.

    Scenario:
        Given the repository copy without .git
        When the CLI scans repo/docs with --link-root set to /, docs/adr, a missing path or repo/src
        Then it exits 2 with a neutralized --link-root error on stderr and no report.

    Boundaries:
        - Focus: fail-closed trusted flag validation
        - Fixtures/params: asset_case, capsys, which
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - resolve_invoker_link_root and the cli Scan failed path
    """
    repo, docs = _materialize(asset_case, "ds101", git="none")
    value = {
        "filesystem-root": os.path.abspath(os.sep),
        "child": str(docs / "adr"),
        "missing": str(repo / "missing"),
        "sibling": str(repo / "src"),
    }[which]

    exit_code = main(["scan", str(docs), "--profile", "fast", "--format", "text", "--link-root", value])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.err.startswith("Scan failed: --link-root")
    assert captured.out == ""


def test_baseline_and_python_scan_accept_the_link_root_override(
    asset_case: Callable[[str, str], AssetCase], capsys: pytest.CaptureFixture[str]
):
    """
    [Integration] link root ds101: ``baseline --link-root`` and ``scan(link_root=)`` use the trusted override.

    Scenario:
        Given the repository copy without .git
        When docsentinel.scan runs with link_root=repo and `docsentinel baseline --link-root repo` records a baseline
        Then the scan reports only the missing file and the baseline holds exactly the scan's fingerprint set.

    Boundaries:
        - Focus: the Python keyword and the baseline command
        - Fixtures/params: asset_case, capsys
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - The baseline command forwarding args.link_root
    """
    repo, docs = _materialize(asset_case, "ds101", git="none")
    output = repo / "baseline.json"

    result = scan(docs, link_root=repo)
    exit_code = main(["baseline", str(docs), "--profile", "fast", "--output", str(output), "--link-root", str(repo)])
    capsys.readouterr()

    assert [(f.rule, f.message) for f in result.findings if f.rule == "DS101"] == [
        ("DS101", "dangling link -> /docs/adr/missing.md")
    ]
    assert exit_code == 0
    assert load_baseline(output) == frozenset(fingerprint(finding) for finding in result.findings)


def test_injected_unbounded_link_root_fails_closed_in_scan_and_detectors(
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] link root ds101 ds103: an injected Config cannot widen the link root.

    Scenario:
        Given repo/.git and an injected Config(link_root=...) resolving to "/" or above the repository
        When docsentinel.scan runs, and when DS101/DS103 are called directly with an explicit ancestor
        Then every call raises ConfigError (detectors cannot check the .git ceiling, so they refuse).

    Boundaries:
        - Focus: fail-closed handling of injected configs (audit HIGH)
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - resolve_link_root in engine.scan and link_root_for in the detectors
    """
    _repo, docs = _materialize(asset_case, "ds101")

    for value in ("../" * 40, "../.."):
        with pytest.raises(ConfigError, match="link_root"):
            scan(docs, config=Config(link_root=value))
    with pytest.raises(ConfigError, match="link_root"):
        links.detect(docs, _docs(docs), Config(link_root=".."))
    with pytest.raises(ConfigError, match="link_root"):
        paths.detect(docs, _docs(docs), Config(link_root=".."))


def test_ds101_undecodable_linked_markdown_skips_anchor_check(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] link root ds101: a non-UTF-8 ``.md`` outside the scan root reached by ``/`` is skipped, not fatal.

    Scenario:
        Given repo/.git, an invalid-UTF-8 repo/notes.md outside the docs scan root, and a link to /notes.md#x
        When DS101 runs with the engine link root
        Then the scan completes; the #x anchor is not checked and only the missing file is reported
          (an in-root target keeps the historical, propagating read).

    Boundaries:
        - Focus: the bounded, decode-safe anchor read (audit LOW)
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - _linked_anchors returning None on UnicodeDecodeError
    """
    repo, docs = _materialize(asset_case, "ds101")
    (repo / "notes.md").write_bytes(b"# Notes\n\xff\xfe\n")
    readme = docs / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "See [notes](/notes.md#x).\n", encoding="utf-8")

    findings = links.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))

    assert _summary(findings) == [("DS101", 7, "dangling link -> /docs/adr/missing.md")]


# --- DS103 ----------------------------------------------------------------------------------


def test_ds103_repository_absolute_code_span_resolves_against_git_root(
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] link root ds103: `` `/src/app.py` `` from a docs/ scan root resolves.

    Scenario:
        Given repo/.git, repo/src/app.py and code spans /src/app.py and /src/missing.py
        When DS103 runs with the default link_root, then with link_root = "."
        Then auto reports only /src/missing.py, while "." reports both.

    Boundaries:
        - Focus: DS103 link-root joins and containment
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - paths._lexical_candidate and the boundary passed to contained_path
    """
    _repo, docs = _materialize(asset_case, "ds103")

    assert _summary(paths.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))) == [
        ("DS103", 4, "unresolvable path -> /src/missing.py")
    ]
    assert _summary(paths.detect(docs, _docs(docs), Config(link_root="."))) == [
        ("DS103", 3, "unresolvable path -> /src/app.py"),
        ("DS103", 4, "unresolvable path -> /src/missing.py"),
    ]


# --- DS113 ----------------------------------------------------------------------------------


def test_ds113_repository_absolute_image_resolves_against_git_root(asset_case: Callable[[str, str], AssetCase]):
    """
    [Integration] link root ds113: ``![](/assets/diagram.png)`` from a docs/ scan root exists.

    Scenario:
        Given repo/.git, repo/assets/diagram.png and images /assets/diagram.png and /assets/missing.png
        When DS113 runs with the default link_root, then with link_root = "."
        Then auto reports only the missing image, while "." reports both.

    Boundaries:
        - Focus: DS113 link-root joins and stat boundary
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - link_root forwarding in assets.check_text
    """
    _repo, docs = _materialize(asset_case, "ds101", case="link_root_media_assets")

    auto = assets.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))
    dot = assets.detect(docs, _docs(docs), Config(link_root="."))

    assert [(finding.line, finding.message.endswith("/assets/missing.png")) for finding in auto] == [(5, True)]
    assert [finding.line for finding in dot] == [3, 5]


# --- DS116 ----------------------------------------------------------------------------------


def test_ds116_repository_reference_is_not_an_escape_but_parent_of_link_root_is(
    asset_case: Callable[[str, str], AssetCase],
):
    """
    [Integration] link root ds116: ``/src/app.py`` is clean, ``/../outside.md`` and ``../src/app.py`` escape.

    Scenario:
        Given repo/.git and repo/docs/README.md with /src/app.py, /../outside.md, ../src/app.py
          and a /vendor/notes.md link (vendor not yet a symlink)
        When DS116 runs with the scan root at repo/docs
        Then only the link-root escape and the relative scan-root escape are reported.

    Boundaries:
        - Focus: DS116 containment bounded by the link root for "/" targets only
        - Fixtures/params: asset_case
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - _classify with link_root and the relative branch of the resolver
    """
    _repo, docs = _materialize(asset_case, "ds101", case="link_root_path_boundaries")

    findings = path_boundaries.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))

    assert _summary(findings) == [
        ("DS116", 4, "reference escapes the documentation root: /../outside.md"),
        ("DS116", 5, "reference escapes the documentation root: ../src/app.py"),
    ]


def test_ds116_symlink_out_of_link_root_is_reported_and_not_followed_by_ds101(
    asset_case: Callable[[str, str], AssetCase], tmp_path: Path
):
    """
    [Integration] link root ds101 ds116: a ``/`` target through a symlink leaving the link root is DS116's.

    Scenario:
        Given repo/vendor as a symlink to a directory outside the repository
        When DS116 and DS101 run with the scan root at repo/docs
        Then DS116 reports the symlink escape for /vendor/notes.md and DS101 does not report it.

    Boundaries:
        - Focus: escapes_via_symlink / contained_path with the link root as boundary
        - Fixtures/params: asset_case, tmp_path
        - Scope: assertions and setup in this test case only

    On failure, first check:
        - The boundary used for "/" targets in path_boundaries._classify and links.check_document
    """
    repo, docs = _materialize(asset_case, "ds101", case="link_root_path_boundaries")
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (repo / "vendor").symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    ds116 = path_boundaries.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))
    ds101 = links.detect(docs, _docs(docs), Config(), link_root=_engine_root(docs))

    assert (6, "reference resolves through a symlink that escapes the documentation root: /vendor/notes.md") in [
        (finding.line, finding.message) for finding in ds116
    ]
    assert all("/vendor/notes.md" not in finding.message for finding in ds101)
