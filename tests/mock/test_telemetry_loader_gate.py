"""Mock tests for the template loader file gate (Milestone 0007 Story 02.0 Task 01, M9-M11).

``os.open`` (and, where stated, ``os.stat``/``os.fstat``) is replaced so each test proves
a refused template is refused **before** any open, or that a size lie between ``stat``
and ``read`` is caught rather than silently truncated.
"""

import os
import stat
from pathlib import Path

import pytest

from docsentinel.telemetry import loader
from docsentinel.telemetry.loader import MAX_TEMPLATE_BYTES, TemplateError, load_template

_VALID = '{"template_version": 1, "name": "mini", "type": "text", "lines": []}'


@pytest.fixture
def no_open(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace ``os.open`` so any call is recorded and fails the read."""
    calls: list[str] = []

    def refuse(path: object, *_args: object, **_kwargs: object) -> int:
        """Record the attempted open and fail the test."""
        calls.append(os.fspath(path))  # type: ignore[arg-type]
        raise AssertionError("os.open must not be called for a refused template")

    monkeypatch.setattr(loader.os, "open", refuse)
    return calls


@pytest.fixture
def scan_root(tmp_path: Path) -> Path:
    """Return a scan root with an outside sibling directory holding a valid template."""
    root = tmp_path / "root"
    (root / "templates").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "mini.json").write_text(_VALID, encoding="utf-8")
    return root


@pytest.mark.parametrize("templates_dir", ["../outside", "/etc", "templates/../../outside", "..%2foutside"])
def test_out_of_root_templates_dir_is_refused_without_open(scan_root: Path, no_open: list[str], templates_dir: str):
    """
    [Unit] loader gate (mock): verifies a ``report_templates_dir`` outside the root is refused without opening it.

    Scenario:
        Given ``report_templates_dir`` set to a ``..`` escape, an absolute path, a nested escape or a
        percent-encoded escape
        When a template name is loaded through it
        Then TemplateError is raised, ``os.open`` is never called, and the resolved path is not echoed.

    Boundaries:
        - Focus: M10 containment on the directory (DS115 gate reuse)
        - Fixtures/params: one escaping directory per case
        - Mocks: ``os.open`` raises if called

    On failure, first check:
        - ``loader._check_contained`` and its call order in ``_load_by_name``
    """
    with pytest.raises(TemplateError, match="escapes the scan root") as caught:
        load_template("mini", root=scan_root, templates_dir=templates_dir)
    assert no_open == []
    assert str(scan_root.parent) not in str(caught.value)


@pytest.mark.parametrize("source", ["../outside/mini.json", "templates/../../outside/mini.json"])
def test_traversal_name_is_a_path_and_refused_without_open(scan_root: Path, no_open: list[str], source: str):
    """
    [Unit] loader gate (mock): verifies a ``../`` "name" is treated as a path and refused by containment (M9/M10).

    Scenario:
        Given a config-named template source containing ``..``
        When it is loaded with ``from_config=True``
        Then it fails the name pattern, is gated as a path, and is refused without ``os.open``.

    Boundaries:
        - Focus: M9 name pattern, M10 containment of the final path
        - Fixtures/params: two traversal spellings
        - Mocks: ``os.open`` raises if called

    On failure, first check:
        - ``NAME_PATTERN`` and the ``from_config`` branch of ``load_template``
    """
    with pytest.raises(TemplateError, match="escapes the scan root"):
        load_template(source, root=scan_root, from_config=True)
    assert no_open == []


def test_symlink_out_file_and_directory_are_refused_without_open(scan_root: Path, no_open: list[str]):
    """
    [Unit] loader gate (mock): verifies an in-root symlink pointing outside is refused before any open.

    Scenario:
        Given ``templates/mini.json`` symlinked to an outside file, and ``linked`` symlinked to the outside dir
        When the name is loaded through ``templates`` and through ``linked``
        Then both are refused by ``escapes_via_symlink`` and ``os.open`` is never called.

    Boundaries:
        - Focus: M10 symlink-out on the final joined path and on the directory
        - Fixtures/params: none
        - Mocks: ``os.open`` raises if called

    On failure, first check:
        - The ``escapes_via_symlink`` step of ``_check_contained``
    """
    outside = scan_root.parent / "outside"
    (scan_root / "templates" / "mini.json").symlink_to(outside / "mini.json")
    (scan_root / "linked").symlink_to(outside, target_is_directory=True)
    for templates_dir in ("templates", "linked"):
        with pytest.raises(TemplateError, match="escapes the scan root"):
            load_template("mini", root=scan_root, templates_dir=templates_dir)
    assert no_open == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need POSIX")
@pytest.mark.parametrize("from_config", [True, False])
def test_fifo_is_refused_without_open(scan_root: Path, no_open: list[str], from_config: bool):
    """
    [Unit] loader gate (mock): verifies a FIFO template is refused by ``stat`` before it could block an open.

    Scenario:
        Given ``templates/mini.json`` is a FIFO
        When it is loaded as a config-named path, and as an argv path
        Then "not a regular file" is raised and ``os.open`` is never called.

    Boundaries:
        - Focus: M11 regular-file gate (config and argv paths alike)
        - Fixtures/params: config-named and argv source
        - Mocks: ``os.open`` raises if called

    On failure, first check:
        - The pre-open ``os.stat`` in ``loader._read_gated``
    """
    fifo = scan_root / "templates" / "mini.json"
    os.mkfifo(fifo)
    source = "templates/mini.json" if from_config else str(fifo)
    with pytest.raises(TemplateError, match="not a regular file"):
        load_template(source, root=scan_root, from_config=from_config)
    assert no_open == []


def test_oversized_file_is_refused_without_open(scan_root: Path, no_open: list[str]):
    """
    [Unit] loader gate (mock): verifies a file over MAX_TEMPLATE_BYTES is refused by ``stat`` before any open.

    Scenario:
        Given an in-root template of MAX + 1 bytes
        When it is loaded
        Then "larger than" is raised and ``os.open`` is never called.

    Boundaries:
        - Focus: M11 size gate
        - Fixtures/params: none
        - Mocks: ``os.open`` raises if called

    On failure, first check:
        - The ``st_size`` check in ``loader._read_gated``
    """
    big = scan_root / "templates" / "mini.json"
    big.write_bytes(b" " * (MAX_TEMPLATE_BYTES + 1))
    with pytest.raises(TemplateError, match="larger than"):
        load_template("templates/mini.json", root=scan_root, from_config=True)
    assert no_open == []


def test_growth_after_stat_is_rejected_not_truncated(scan_root: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] loader gate (mock): verifies a file that is larger than its ``stat``/``fstat`` size is rejected, never truncated.

    Scenario:
        Given a MAX + 1 byte file whose ``stat`` and ``fstat`` are mocked to report a small size
        When it is loaded
        Then the MAX + 1 read detects the growth and "larger than" is raised.

    Boundaries:
        - Focus: M11 "read MAX + 1 and reject" (TOCTOU growth)
        - Fixtures/params: none
        - Mocks: ``os.stat`` and ``os.fstat`` report ``st_size = 10`` for the template

    On failure, first check:
        - The ``len(data) > MAX_TEMPLATE_BYTES`` check after the read
    """
    target = scan_root / "templates" / "mini.json"
    target.write_bytes(_VALID.encode() + b" " * MAX_TEMPLATE_BYTES)
    real_stat, real_fstat = os.stat, os.fstat

    def small(result: os.stat_result) -> os.stat_result:
        """Return ``result`` with ``st_size`` forced to 10."""
        fields = list(result)
        fields[stat.ST_SIZE] = 10
        return os.stat_result(fields)

    def fake_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        """Report a small size for the template only."""
        result = real_stat(path, *args, **kwargs)  # type: ignore[arg-type]
        return small(result) if Path(os.fspath(path)) == target else result  # type: ignore[arg-type]

    monkeypatch.setattr(loader.os, "stat", fake_stat)
    monkeypatch.setattr(loader.os, "fstat", lambda fd: small(real_fstat(fd)))
    with pytest.raises(TemplateError, match="larger than"):
        load_template("templates/mini.json", root=scan_root, from_config=True)


def test_special_file_swapped_in_after_stat_is_caught_by_fstat(scan_root: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] loader gate (mock): verifies the post-open ``fstat`` re-checks the file type (TOCTOU swap).

    Scenario:
        Given a regular template whose post-open ``fstat`` is mocked to report a FIFO
        When it is loaded
        Then "not a regular file" is raised.

    Boundaries:
        - Focus: M11 ``fstat`` after ``O_NONBLOCK`` open
        - Fixtures/params: none
        - Mocks: ``os.fstat`` reports ``S_IFIFO``

    On failure, first check:
        - The ``fstat`` block in ``loader._read_gated``
    """
    (scan_root / "templates" / "mini.json").write_text(_VALID, encoding="utf-8")
    real_fstat = os.fstat

    def as_fifo(fd: int) -> os.stat_result:
        """Report the opened descriptor as a FIFO."""
        fields = list(real_fstat(fd))
        fields[stat.ST_MODE] = stat.S_IFIFO | 0o644
        return os.stat_result(fields)

    monkeypatch.setattr(loader.os, "fstat", as_fifo)
    with pytest.raises(TemplateError, match="not a regular file"):
        load_template("templates/mini.json", root=scan_root, from_config=True)


def test_config_named_open_uses_nofollow_and_nonblock(scan_root: Path, monkeypatch: pytest.MonkeyPatch):
    """
    [Unit] loader gate (mock): verifies a config-named file is opened ``O_NOFOLLOW | O_NONBLOCK`` and an argv one is not
    ``O_NOFOLLOW``.

    Scenario:
        Given an in-root valid template
        When it is loaded as config-named and as an argv path
        Then the recorded ``os.open`` flags carry ``O_NONBLOCK`` both times and ``O_NOFOLLOW`` only for config.

    Boundaries:
        - Focus: M11 open flags
        - Fixtures/params: none
        - Mocks: ``os.open`` wrapped to record its flags

    On failure, first check:
        - The ``flags`` computation in ``loader._read_gated``
    """
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        pytest.skip("POSIX open flags unavailable")
    path = scan_root / "templates" / "mini.json"
    path.write_text(_VALID, encoding="utf-8")
    flags: list[int] = []
    real_open = os.open

    def record(target: object, mode: int, *args: object) -> int:
        """Record the open flags, then open for real."""
        flags.append(mode)
        return real_open(target, mode, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(loader.os, "open", record)
    assert load_template("templates/mini.json", root=scan_root, from_config=True).origin == "path"
    load_template(str(path))
    assert flags[0] & os.O_NOFOLLOW and flags[0] & os.O_NONBLOCK
    assert not flags[1] & os.O_NOFOLLOW and flags[1] & os.O_NONBLOCK
