"""Unit tests for the ``link_root`` option and site-root-absolute (``/``) resolution.

Covers :func:`docsentinel.config.validate_link_root`, the load-time option,
:func:`docsentinel.link_root.resolve_link_root` / :func:`link_root_for`, the
shared resolver :func:`docsentinel.markdown_blocks.resolve_local_reference` plus the
DS116 gate with a link root, the separator-aware containment check for a ``/`` root,
and the bounded DS101 anchor read. Filesystem layouts are tiny ``tmp_path`` trees built
inline; no assets are loaded.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from docsentinel import Config, ConfigError, load_config
from docsentinel import link_root as link_root_module
from docsentinel.config import validate_link_root
from docsentinel.detectors import links, path_boundaries
from docsentinel.link_root import link_root_for, resolve_invoker_link_root, resolve_link_root
from docsentinel.markdown_blocks import ReferenceStatus, ResolvedReference, resolve_local_reference


def _skip_if_git_above(path: Path):
    """Skip when ``path`` or an ancestor already holds ``.git`` (the fallback is then untestable).

    :param path: The directory whose ancestors must be free of ``.git``.
    """
    for directory in (path, *path.parents):
        if (directory / ".git").exists() or (directory / ".git").is_symlink():
            pytest.skip(f"tmp directory sits inside a git checkout at {directory}")


def _repo(tmp_path: Path, *, git: str = "dir") -> tuple[Path, Path]:
    """Build ``repo/docs`` under ``tmp_path`` with a ``.git`` marker of the given kind.

    :param tmp_path: The pytest scratch directory.
    :param git: ``"dir"`` for a ``.git`` directory, ``"file"`` for a ``.git`` file,
        ``"none"`` for no marker.
    :returns: ``(repo, docs)`` absolute paths.
    """
    repo = tmp_path / "repo"
    docs = repo / "docs"
    docs.mkdir(parents=True)
    if git == "dir":
        (repo / ".git").mkdir()
    elif git == "file":
        (repo / ".git").write_text("gitdir: ../.git/worktrees/repo\n", encoding="utf-8")
    return repo, docs


# --- resolve_link_root: auto -------------------------------------------------------------


def test_auto_link_root_uses_ancestor_with_git_directory(tmp_path: Path):
    """
    [Unit] link root: auto resolves to the nearest ancestor holding a ``.git`` directory.

    Scenario:
        Given repo/.git as a directory and a scan root at repo/docs
        When resolve_link_root runs with the default config
        Then the repository directory is returned.

    Boundaries:
        - Focus: the .git ancestor walk
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - _git_ancestor in docsentinel.link_root
        - The default Config.link_root value ("auto")
    """
    repo, docs = _repo(tmp_path, git="dir")

    assert resolve_link_root(docs, Config()) == repo


def test_auto_link_root_accepts_git_file_for_worktrees(tmp_path: Path):
    """
    [Unit] link root: a ``.git`` file (worktree or submodule) marks the repository root.

    Scenario:
        Given repo/.git as a regular file and a scan root at repo/docs
        When resolve_link_root runs with link_root = "auto"
        Then the repository directory is returned.

    Boundaries:
        - Focus: .git file detection
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - That the walk tests for any .git entry, not only directories
    """
    repo, docs = _repo(tmp_path, git="file")

    assert resolve_link_root(docs, Config(link_root="auto")) == repo


def test_auto_link_root_includes_the_scan_root_itself(tmp_path: Path):
    """
    [Unit] link root: a ``.git`` directly in the scan root makes the scan root the link root.

    Scenario:
        Given a scan root that itself holds .git inside an outer checkout
        When resolve_link_root runs with the default config
        Then the scan root is returned, not the outer checkout.

    Boundaries:
        - Focus: nearest-ancestor semantics including the scan root
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - The walk order (scan root first, then parents)
    """
    _repo_dir, docs = _repo(tmp_path, git="dir")
    (docs / ".git").mkdir()

    assert resolve_link_root(docs, Config()) == docs


def test_auto_link_root_falls_back_to_scan_root_without_git(tmp_path: Path):
    """
    [Unit] link root: with no ``.git`` above the scan root, auto keeps the historical scan root.

    Scenario:
        Given repo/docs with no .git marker anywhere above it
        When resolve_link_root runs with the default config
        Then the scan root is returned.

    Boundaries:
        - Focus: the byte-identical fallback
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - Whether the pytest tmp directory sits inside a git checkout
    """
    _skip_if_git_above(tmp_path)
    _repo_dir, docs = _repo(tmp_path, git="none")

    assert resolve_link_root(docs, Config()) == docs


# --- resolve_link_root: explicit values -----------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(".", "docs"), ("./", "docs"), ("..", "repo"), ("sub/..", "docs"), ("../docs/..", "repo")],
)
def test_explicit_link_root_names_scan_root_or_ancestor(tmp_path: Path, value: str, expected: str):
    """
    [Unit] link root: explicit relative values resolve lexically to the scan root or a bounded ancestor.

    Scenario:
        Given a scan root at repo/docs with repo/.git as the ceiling
        When resolve_link_root runs with an explicit link_root
        Then the lexically normalised directory is returned.

    Boundaries:
        - Focus: explicit value normalisation
        - Fixtures/params: tmp_path, value, expected
        - Scope: this test case only

    On failure, first check:
        - os.path.normpath handling in resolve_link_root
    """
    repo, docs = _repo(tmp_path, git="dir")
    by_name = {"docs": docs, "repo": repo, "tmp": tmp_path}

    assert resolve_link_root(docs, Config(link_root=value)) == by_name[expected]


@pytest.mark.parametrize("value", ["adr", "../other", "../docs-sibling", "../../repo/src"])
def test_explicit_link_root_rejects_non_ancestors(tmp_path: Path, value: str):
    """
    [Unit] link root: a subdirectory or sibling is not an ancestor and fails closed.

    Scenario:
        Given a scan root at repo/docs with existing sibling and child directories
        When resolve_link_root runs with a non-ancestor link_root
        Then ConfigError is raised.

    Boundaries:
        - Focus: the ancestor check
        - Fixtures/params: tmp_path, value
        - Scope: this test case only

    On failure, first check:
        - The _within(base, candidate) comparison in resolve_link_root
    """
    repo, docs = _repo(tmp_path, git="dir")
    (docs / "adr").mkdir()
    (repo / "other").mkdir()
    (repo / "docs-sibling").mkdir()
    (repo / "src").mkdir()

    with pytest.raises(ConfigError, match="scan root or one of its ancestors"):
        resolve_link_root(docs, Config(link_root=value))


def test_explicit_link_root_rejects_missing_directory(tmp_path: Path):
    """
    [Unit] link root: a link root directory that does not exist fails closed.

    Scenario:
        Given a scan root path that does not exist on disk
        When resolve_link_root runs with link_root = "."
        Then ConfigError reports the missing directory.

    Boundaries:
        - Focus: the existence check after the lexical ancestor check
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - The os.stat / S_ISDIR check in resolve_link_root
    """
    with pytest.raises(ConfigError, match="does not exist"):
        resolve_link_root(tmp_path / "gone", Config(link_root="."))


@pytest.mark.parametrize("value", [5, None, True, ["."], "", "/abs", "..\\..", "C:/repo", "..\x00", "\u202e.."])
def test_injected_link_root_with_invalid_value_fails_closed(tmp_path: Path, value: object):
    """
    [Unit] link root: an injected Config with a wrong type or unsafe string fails closed.

    Scenario:
        Given a hand-built Config whose link_root bypassed load_config
        When resolve_link_root runs
        Then ConfigError is raised before any filesystem decision.

    Boundaries:
        - Focus: lexical re-validation for injected configs
        - Fixtures/params: tmp_path, value
        - Scope: this test case only

    On failure, first check:
        - validate_link_root in docsentinel.config
    """
    _repo_dir, docs = _repo(tmp_path, git="dir")

    with pytest.raises(ConfigError, match="link_root"):
        resolve_link_root(docs, Config(link_root=value))  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["../..", "../../..", "../" * 40, "../../x/..", "../../tmp/.."])
def test_explicit_link_root_above_the_git_ancestor_is_refused(tmp_path: Path, value: str):
    """
    [Unit] link root: an explicit value above the nearest ``.git`` ancestor fails closed (audit HIGH).

    Scenario:
        Given repo/.git and a scan root at repo/docs
        When resolve_link_root runs with a value resolving above repo, up to the filesystem root "/"
          or through a normalising "x/.." detour
        Then ConfigError is raised before any stat of the candidate.

    Boundaries:
        - Focus: the repository ceiling on explicit link_root values
        - Fixtures/params: tmp_path, value
        - Scope: this test case only

    On failure, first check:
        - The repository bound in _bounded_config_candidate
    """
    _repo_dir, docs = _repo(tmp_path, git="dir")

    with pytest.raises(ConfigError, match="filesystem root|above the enclosing git repository root"):
        resolve_link_root(docs, Config(link_root=value))


@pytest.mark.parametrize("marker", ["pyproject.toml", "docsentinel.toml", "doc_sentinel.toml"])
def test_explicit_ancestor_without_git_needs_a_project_marker(tmp_path: Path, marker: str):
    """
    [Unit] link root: without ``.git`` a configured ancestor is accepted only if it directly holds a marker.

    Scenario:
        Given repo/docs with no .git above it
        When resolve_link_root runs with ".." before and after a project marker is created in repo
        Then the marker-less ancestor fails closed and the marked one resolves.

    Boundaries:
        - Focus: the project-marker allowlist
        - Fixtures/params: tmp_path, marker
        - Scope: this test case only

    On failure, first check:
        - _has_project_marker in _bounded_config_candidate
    """
    _skip_if_git_above(tmp_path)
    repo, docs = _repo(tmp_path, git="none")

    with pytest.raises(ConfigError, match="pyproject.toml, docsentinel.toml or doc_sentinel.toml"):
        resolve_link_root(docs, Config(link_root=".."))
    (repo / marker).write_text("", encoding="utf-8")
    assert resolve_link_root(docs, Config(link_root="..")) == repo
    assert resolve_link_root(docs, Config(link_root=".")) == docs


def test_marker_inside_the_scan_tree_does_not_admit_an_ancestor(tmp_path: Path):
    """
    [Unit] link root: a project marker in the scan root or below never vouches for an ancestor.

    Scenario:
        Given repo/docs without .git, with docs/pyproject.toml and docs/sub/docsentinel.toml, and a marker
          two levels up in tmp only
        When resolve_link_root runs with ".." (repo, marker-less)
        Then it fails closed: only the exact named directory's own markers count.

    Boundaries:
        - Focus: exact-directory marker semantics
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - That _has_project_marker checks the candidate directory itself
    """
    _skip_if_git_above(tmp_path)
    _repo_dir, docs = _repo(tmp_path, git="none")
    (docs / "pyproject.toml").write_text("", encoding="utf-8")
    (docs / "sub").mkdir()
    (docs / "sub" / "docsentinel.toml").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")

    with pytest.raises(ConfigError, match="only if it directly contains"):
        resolve_link_root(docs, Config(link_root=".."))


def test_filesystem_root_is_refused_even_with_a_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] link root: a configured value resolving to ``/`` fails closed whatever markers exist.

    Scenario:
        Given repo/docs without .git and os.path.lexists patched to report every marker as present
        When resolve_link_root runs with a value climbing to "/"
        Then ConfigError names the filesystem root.

    Boundaries:
        - Focus: the unconditional filesystem-root refusal
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: this test case only

    On failure, first check:
        - _is_filesystem_root ordering in _bounded_config_candidate
    """
    _repo_dir, docs = _repo(tmp_path, git="none")
    real_lexists = os.path.lexists
    monkeypatch.setattr(
        link_root_module.os.path,
        "lexists",
        lambda path: (
            os.path.basename(path) != ".git" and (os.path.basename(path).endswith(".toml") or real_lexists(path))
        ),
    )

    with pytest.raises(ConfigError, match="filesystem root"):
        resolve_link_root(docs, Config(link_root="../" * 40))


def test_home_level_git_is_not_trusted_as_link_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] link root: a ``.git`` at the home directory or above (dotfiles repo) never widens the link root.

    Scenario:
        Given Path.home() patched to a symlink alias of tmp_path, tmp_path/.git, and repo/docs without its own .git
        When resolve_link_root runs with "auto", ".", and ".."
        Then auto falls back to the scan root, "." resolves, and ".." fails closed; the alias proves the
          comparison is by inode (samestat), not by string.

    Boundaries:
        - Focus: _is_home_or_above and _trusted_repository
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: this test case only

    On failure, first check:
        - os.path.samestat use in _is_home_or_above
    """
    _repo_dir, docs = _repo(tmp_path, git="none")
    (tmp_path / ".git").mkdir()
    alias = tmp_path.parent / f"{tmp_path.name}-home-alias"
    try:
        alias.symlink_to(tmp_path, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: alias))

    try:
        assert resolve_link_root(docs, Config()) == docs
        assert resolve_link_root(docs, Config(link_root=".")) == docs
        with pytest.raises(ConfigError, match="home directory"):
            resolve_link_root(docs, Config(link_root=".."))
    finally:
        alias.unlink()


def test_repository_below_home_is_still_trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] link root: a ``.git`` strictly below the home directory keeps working for auto and "..".

    Scenario:
        Given Path.home() patched to tmp_path and repo/.git below it
        When resolve_link_root runs with "auto" and ".."
        Then both resolve to repo.

    Boundaries:
        - Focus: the dotfiles refusal does not catch ordinary repositories
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: this test case only

    On failure, first check:
        - That _is_home_or_above compares the repository against home and its ancestors only
    """
    repo, docs = _repo(tmp_path, git="dir")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    assert resolve_link_root(docs, Config()) == repo
    assert resolve_link_root(docs, Config(link_root="..")) == repo


def test_invoker_link_root_accepts_absolute_and_cwd_relative_ancestors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] link root: the trusted ``--link-root`` value is absolute or CWD-relative, realpath-resolved.

    Scenario:
        Given repo/docs without .git, and a symlink alias pointing at repo
        When resolve_invoker_link_root runs with an absolute ancestor, a CWD-relative path and the alias
        Then each resolves to the canonical ancestor, with no .git or home requirement.

    Boundaries:
        - Focus: resolve_invoker_link_root happy paths
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: this test case only

    On failure, first check:
        - os.path.realpath(os.path.abspath(value)) in resolve_invoker_link_root
    """
    repo, docs = _repo(tmp_path, git="none")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(repo, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks unavailable: {error}")
    monkeypatch.chdir(docs)

    assert resolve_invoker_link_root(docs, str(tmp_path)) == tmp_path
    assert resolve_invoker_link_root(docs, "..") == repo
    assert resolve_invoker_link_root(docs, ".") == docs
    assert resolve_invoker_link_root(docs, alias) == repo


@pytest.mark.parametrize("value", ["/", "adr", "../missing", "", "../..\x00"])
def test_invoker_link_root_refuses_root_non_ancestor_missing_and_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
):
    """
    [Unit] link root: the trusted value still fails closed for ``/``, non-ancestors, missing or empty paths.

    Scenario:
        Given repo/docs (with an existing docs/adr subdirectory) as the CWD
        When resolve_invoker_link_root runs with "/", a child, a missing sibling, "" or a NUL-bearing path
        Then ConfigError is raised.

    Boundaries:
        - Focus: resolve_invoker_link_root refusals
        - Fixtures/params: tmp_path, monkeypatch, value
        - Scope: this test case only

    On failure, first check:
        - The existence, ancestor and filesystem-root checks in resolve_invoker_link_root
    """
    _repo_dir, docs = _repo(tmp_path, git="none")
    (docs / "adr").mkdir()
    monkeypatch.chdir(docs)

    with pytest.raises(ConfigError, match="--link-root"):
        resolve_invoker_link_root(docs, value)


def test_link_root_for_is_lexical_and_never_walks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] link root: the detector-side helper decides with zero filesystem access.

    Scenario:
        Given repo/.git and every os probe patched to fail the test when called
        When link_root_for runs with "auto", "." and "sub/.."
        Then each maps to the scan root (the engine passes a found repository root itself), and no
          os probe ran.

    Boundaries:
        - Focus: detectors never touch a path outside the scan root to pick the link root
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: this test case only

    On failure, first check:
        - That link_root_for does not call _git_ancestor or os.stat
    """
    _repo_dir, docs = _repo(tmp_path, git="dir")

    def forbidden(*_args: object, **_kwargs: object) -> bool:
        """Fail the test on any filesystem probe.

        :param _args: Ignored positional arguments.
        :param _kwargs: Ignored keyword arguments.
        :returns: Never returns.
        :raises AssertionError: Always.
        """
        raise AssertionError("link_root_for touched the filesystem")

    monkeypatch.setattr(link_root_module.os.path, "lexists", forbidden)
    monkeypatch.setattr(link_root_module.os, "stat", forbidden)

    assert link_root_for(docs, Config()) == docs
    assert link_root_for(docs, Config(link_root=".")) == docs
    assert link_root_for(docs, Config(link_root="sub/..")) == docs


@pytest.mark.parametrize("value", ["adr", "../other", 7, "/abs", "..", "../" * 40])
def test_link_root_for_rejects_invalid_or_non_ancestor_values(tmp_path: Path, value: object):
    """
    [Unit] link root: the detector-side helper fails closed for any value not meaning the scan root.

    Scenario:
        Given a hand-built Config with a non-ancestor, wrong-typed, absolute, or ancestor link_root
          (an ancestor needs the engine's .git ceiling, which a filesystem-free detector cannot check)
        When link_root_for runs
        Then ConfigError is raised.

    Boundaries:
        - Focus: lexical fail-closed validation in detectors
        - Fixtures/params: tmp_path, value
        - Scope: this test case only

    On failure, first check:
        - _explicit_candidate and validate_link_root
    """
    _repo_dir, docs = _repo(tmp_path, git="dir")

    with pytest.raises(ConfigError, match="link_root"):
        link_root_for(docs, Config(link_root=value))  # type: ignore[arg-type]


# --- load-time validation -------------------------------------------------------------------


def test_link_root_defaults_to_auto_and_loads_from_toml(tmp_path: Path):
    """
    [Unit] config: link_root defaults to "auto" and loads from docsentinel.toml and pyproject.

    Scenario:
        Given no config, then a docsentinel.toml, then a [tool.doc_sentinel] table
        When load_config runs
        Then the default is "auto" and the configured values are kept.

    Boundaries:
        - Focus: option registration and loading
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - _CONFIG_OPTIONS and _load_extra_options in config.py
    """
    assert load_config(tmp_path).link_root == "auto"
    standalone = tmp_path / "standalone"
    standalone.mkdir()
    (standalone / "docsentinel.toml").write_text('link_root = "."\n', encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text('[tool.doc_sentinel]\nlink_root = ".."\n', encoding="utf-8")

    assert load_config(standalone).link_root == "."
    assert load_config(project).link_root == ".."


@pytest.mark.parametrize("raw", ["link_root = 1", 'link_root = ""', 'link_root = "/repo"', "link_root = ['.']"])
def test_link_root_invalid_toml_value_is_config_error(tmp_path: Path, raw: str):
    """
    [Unit] config: a lexically invalid link_root in TOML is a ConfigError at load.

    Scenario:
        Given a docsentinel.toml with a wrong-typed, empty or absolute link_root
        When load_config runs
        Then ConfigError is raised.

    Boundaries:
        - Focus: load-time lexical validation
        - Fixtures/params: tmp_path, raw
        - Scope: this test case only

    On failure, first check:
        - validate_link_root is called from _load_extra_options
    """
    (tmp_path / "docsentinel.toml").write_text(raw + "\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="link_root"):
        load_config(tmp_path)


def test_validate_link_root_accepts_auto_and_relative_paths():
    """
    [Unit] config: validate_link_root returns accepted values unchanged.

    Scenario:
        Given "auto", ".", ".." and "../.."
        When validate_link_root runs
        Then each value is returned as is.

    Boundaries:
        - Focus: validate_link_root happy path
        - Fixtures/params: none
        - Scope: this test case only

    On failure, first check:
        - The lexical rules in validate_link_root
    """
    for value in ("auto", ".", "..", "../.."):
        assert validate_link_root(value) == value


# --- resolve_local_reference with a link root ------------------------------------------------


def test_slash_target_inside_link_root_outside_scan_root_resolves(tmp_path: Path):
    """
    [Unit] resolver: ``/src/x.py`` resolves under the link root even outside the scan root.

    Scenario:
        Given scan root repo/docs and link root repo
        When resolve_local_reference resolves "/src/x.py" and "/docs/adr/README.md#a"
        Then both are RESOLVED under repo with repo as the containment boundary.

    Boundaries:
        - Focus: site-root-absolute join onto the link root
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - The decoded.startswith("/") branch of resolve_local_reference
    """
    repo, docs = tmp_path / "repo", tmp_path / "repo" / "docs"

    source = resolve_local_reference(docs, "README.md", "/src/x.py", link_root=repo)
    adr = resolve_local_reference(docs, "README.md", "/docs/adr/README.md#a", link_root=repo)

    assert source.status is ReferenceStatus.RESOLVED
    assert source.path == repo / "src" / "x.py"
    assert source.boundary == repo
    assert (adr.path, adr.fragment, adr.boundary) == (docs / "adr" / "README.md", "a", repo)


@pytest.mark.parametrize("target", ["/../x.md", "/docs/../../x.md", "/%2e%2e/x.md"])
def test_slash_target_past_link_root_is_outside_root(tmp_path: Path, target: str):
    """
    [Unit] resolver: ``..`` in a ``/`` target is bounded by the link root.

    Scenario:
        Given scan root repo/docs and link root repo
        When resolve_local_reference resolves a "/" target that climbs above repo
        Then the status is OUTSIDE_ROOT.

    Boundaries:
        - Focus: lexical normalisation bounded by the link root
        - Fixtures/params: tmp_path, target
        - Scope: this test case only

    On failure, first check:
        - _normalize_relative applied to the stripped "/" target
    """
    repo, docs = tmp_path / "repo", tmp_path / "repo" / "docs"

    reference = resolve_local_reference(docs, "README.md", target, link_root=repo)

    assert reference.status is ReferenceStatus.OUTSIDE_ROOT
    assert reference.path is None


def test_relative_targets_ignore_the_link_root(tmp_path: Path):
    """
    [Unit] resolver: relative targets keep resolving against the document inside the scan root.

    Scenario:
        Given scan root repo/docs and link root repo
        When resolve_local_reference resolves "adr/x.md", "../src/x.py" and "#top"
        Then the first is under docs, the second is OUTSIDE_ROOT as before, the third is the document.

    Boundaries:
        - Focus: link_root has no effect on relative targets
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - The relative branch still uses base = root
    """
    repo, docs = tmp_path / "repo", tmp_path / "repo" / "docs"

    nested = resolve_local_reference(docs, "guide/README.md", "../adr/x.md", link_root=repo)
    escape = resolve_local_reference(docs, "README.md", "../src/x.py", link_root=repo)
    fragment = resolve_local_reference(docs, "README.md", "#top", link_root=repo)

    assert (nested.status, nested.path, nested.boundary) == (ReferenceStatus.RESOLVED, docs / "adr" / "x.md", docs)
    assert escape.status is ReferenceStatus.OUTSIDE_ROOT
    assert (fragment.path, fragment.boundary) == (docs / "README.md", docs)


def test_resolver_without_link_root_keeps_scan_root_join(tmp_path: Path):
    """
    [Unit] resolver: omitting link_root reproduces the historical scan-root join.

    Scenario:
        Given a scan root and no link_root argument
        When resolve_local_reference resolves "/docs/x.md" and "/../x.md"
        Then the first joins onto the scan root and the second is OUTSIDE_ROOT, with equality unaffected.

    Boundaries:
        - Focus: backward compatibility of the default
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - The link_root None default and ResolvedReference.boundary compare=False
    """
    reference = resolve_local_reference(tmp_path, "README.md", "/docs/x.md")

    assert reference == ResolvedReference(ReferenceStatus.RESOLVED, tmp_path / "docs" / "x.md", "")
    assert reference.boundary == tmp_path
    assert resolve_local_reference(tmp_path, "README.md", "/../x.md").status is ReferenceStatus.OUTSIDE_ROOT


# --- DS116 gate with a link root ------------------------------------------------------------


def test_ds116_gate_and_text_bound_slash_targets_by_link_root(tmp_path: Path):
    """
    [Unit] path boundaries: ``/`` targets inside the link root are not DS116 escapes.

    Scenario:
        Given scan root repo/docs and link root repo
        When is_ds116_owned and check_text inspect "/src/x.py" and "/../x.md"
        Then only "/../x.md" is owned and reported as an escape.

    Boundaries:
        - Focus: is_ds116_owned and check_text with link_root
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - link_root forwarding in _classify and is_ds116_owned
    """
    repo, docs = tmp_path / "repo", tmp_path / "repo" / "docs"
    docs.mkdir(parents=True)
    text = "[a](/src/x.py)\n[b](/../x.md)\n"

    assert not path_boundaries.is_ds116_owned(docs, "README.md", "/src/x.py", link_root=repo)
    assert path_boundaries.is_ds116_owned(docs, "README.md", "/../x.md", link_root=repo)
    findings = path_boundaries.check_text(text, "README.md", docs, Config(), link_root=repo)
    assert [(finding.line, finding.message) for finding in findings] == [
        (2, "reference escapes the documentation root: /../x.md")
    ]


# --- separator-aware containment and the bounded anchor read ---------------------------------


def test_containment_check_handles_a_filesystem_root_boundary(tmp_path: Path):
    """
    [Unit] path boundaries: a boundary of ``/`` contains every absolute path (audit LOW, no ``//``).

    Scenario:
        Given the filesystem root "/" as a containment boundary
        When _within and escapes_via_symlink check paths below it
        Then they are contained, not reported as escapes.

    Boundaries:
        - Focus: the separator-aware prefix in path_boundaries._within
        - Fixtures/params: tmp_path
        - Scope: this test case only

    On failure, first check:
        - Whether _within builds root + os.sep for a root that already ends in os.sep
    """
    assert path_boundaries._within("/x", "/")
    assert path_boundaries._within("/", "/")
    assert path_boundaries._within("/a/b", "/a")
    assert not path_boundaries._within("/ab", "/a")
    assert not path_boundaries.escapes_via_symlink(Path("/"), tmp_path / "missing" / "file.md")


def test_linked_anchor_read_is_bounded_and_skips_undecodable_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] links: anchors of a linked file are read within a cap; oversized or non-UTF-8 files are skipped.

    Scenario:
        Given a small UTF-8 file, a file over a lowered cap, and a non-UTF-8 file
        When _linked_anchors reads each
        Then the first yields its anchors and the others yield None (skip the anchor check).

    Boundaries:
        - Focus: _MAX_ANCHOR_SOURCE_CHARS and the decode-error skip
        - Fixtures/params: tmp_path, monkeypatch
        - Scope: this test case only

    On failure, first check:
        - _linked_anchors in detectors/links.py
    """
    small = tmp_path / "small.md"
    small.write_text("# Title\n", encoding="utf-8")
    big = tmp_path / "big.md"
    big.write_text("# Title\n" + "x" * 100, encoding="utf-8")
    binary = tmp_path / "binary.md"
    binary.write_bytes(b"# Title\n\xff\xfe\n")
    monkeypatch.setattr(links, "_MAX_ANCHOR_SOURCE_CHARS", 50)

    assert links._linked_anchors(small) == {"title"}
    assert links._linked_anchors(big) is None
    assert links._linked_anchors(binary) is None
