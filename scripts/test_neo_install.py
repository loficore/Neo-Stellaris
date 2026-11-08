"""Host-side fence for ``neo_install`` — the one-click player entry point.

This file is what the installer promises, expressed as functions that can be
checked with no game, no Windows, and no network:

* the **version gate** is a sha256 → tag lookup, and the 4.4.4 digest in the
  table is the same one ``docs/offline-tooling.md`` records;
* every failure is **one line** ``NEO_PLAY fail reason=<tag>`` and the traceback
  only appears behind ``--debug``;
* the install plan has **two halves** — the official mod (descriptor /
  ``common`` / ``events`` / ``localisation`` into the Paradox mod folder, plus a
  ``dlc_load.json`` entry) and the runtime bundle (``neo/`` into
  ``C:/temp/neo_mods/<id>/``).  A plan that only does the second half installs a
  mod the engine never loads: that is the failure this test class exists for.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "windows"))

import neo_install as neo  # pyright: ignore[reportMissingImports]


# ---------------------------------------------------------------------------
# version gate
# ---------------------------------------------------------------------------

def test_version_tag_is_read_from_sha256():
    assert neo.version_tag("a" * 64) == "unsupported"
    assert neo.version_tag(neo.SUPPORTED_SHA256["4.4.4"]) == "4.4.4"


def test_supported_table_carries_the_documented_444_digest():
    """The gate is only as good as the constant — pin it to the source of truth."""
    doc = (HERE.parent / "docs" / "offline-tooling.md").read_text(encoding="utf-8")
    assert neo.SUPPORTED_SHA256["4.4.4"] in doc


def test_require_supported_raises_the_version_tag():
    with pytest.raises(neo.NeoPlayError) as exc:
        neo.require_supported("b" * 64)
    assert exc.value.tag == "version_unsupported"


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

def test_resolve_paths_uses_defaults_and_reports_missing_exe(tmp_path):
    with pytest.raises(neo.NeoPlayError) as exc:
        neo.resolve_paths(exe=None, game_root=tmp_path / "nope")
    assert exc.value.tag == "game_not_found"


def test_resolve_paths_reports_a_missing_dll(tmp_path, monkeypatch):
    # The repo's own build output is a valid fallback (`zig-out/bin/*.dll`), so a
    # test that asserts "missing" has to point REPO somewhere with no build —
    # otherwise it passes before `just build` and fails after it.
    monkeypatch.setattr(neo, "REPO", tmp_path / "norepo")
    exe = tmp_path / "stellaris.exe"
    exe.write_bytes(b"MZ")
    with pytest.raises(neo.NeoPlayError) as exc:
        neo.resolve_paths(exe=exe, game_root=tmp_path, dll=tmp_path / "gone.dll")
    assert exc.value.tag == "dll_missing"


def test_resolve_paths_prefers_the_explicit_exe(tmp_path):
    exe = tmp_path / "stellaris.exe"
    exe.write_bytes(b"MZ")
    dll = tmp_path / "sqjs.dll"
    dll.write_bytes(b"MZ")
    mod = _make_mod(tmp_path / "proj", "neo_events")
    paths = neo.resolve_paths(exe=exe, game_root=tmp_path, dll=dll, mod=mod,
                              temp_root=tmp_path / "temp",
                              docs_mod_root=tmp_path / "mods")
    assert paths.exe == exe
    assert paths.mod_id == "neo_events"
    assert paths.entry == "main.js"


# ---------------------------------------------------------------------------
# mod discovery / manifest
# ---------------------------------------------------------------------------

def test_find_mod_reports_missing(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(neo.NeoPlayError) as exc:
        neo.find_mod(tmp_path)
    assert exc.value.tag == "mod_missing"


def test_find_mod_picks_the_newest_descriptor(tmp_path):
    older = _make_mod(tmp_path / "older", "older")
    newer = _make_mod(tmp_path / "newer", "newer")
    # mtime is the tie-breaker; force a clear order instead of sleeping.
    import os
    os.utime(older / "descriptor.mod", (1_000_000, 1_000_000))
    os.utime(newer / "descriptor.mod", (2_000_000, 2_000_000))
    assert neo.find_mod(tmp_path) == newer


def test_manifest_rejects_missing_id(tmp_path):
    mod = _make_mod(tmp_path / "proj", None)
    with pytest.raises(neo.NeoPlayError) as exc:
        neo.read_manifest(mod)
    assert exc.value.tag == "manifest_invalid"


def test_manifest_reports_a_missing_bundle(tmp_path):
    mod = _make_mod(tmp_path / "proj", "neo_events")
    (mod / "neo" / "main.js").unlink()
    with pytest.raises(neo.NeoPlayError) as exc:
        neo.read_manifest(mod)
    assert exc.value.tag == "bundle_missing"


# ---------------------------------------------------------------------------
# install plan — both halves
# ---------------------------------------------------------------------------

def test_install_plan_covers_the_official_half_too(tmp_path):
    mod = _make_mod(tmp_path / "proj", "neo_events")
    paths = neo.resolve_paths(
        exe=_touch(tmp_path / "stellaris.exe"), game_root=tmp_path,
        dll=_touch(tmp_path / "sqjs.dll"), mod=mod,
        temp_root=tmp_path / "temp", docs_mod_root=tmp_path / "mods")
    steps = neo.install_plan(paths)
    roles = {step.role for step in steps}
    assert {"dll", "neo", "descriptor", "dlc_load"} <= roles
    # every official directory that exists in the project is carried over
    official_dsts = [step.dst for step in steps if step.role == "official"]
    assert any(str(p).endswith(str(pathlib.PurePosixPath("mods/neo_events/events")))
               for p in official_dsts)
    assert any(str(p).endswith(str(pathlib.PurePosixPath("mods/neo_events/common")))
               for p in official_dsts)
    # the runtime half lands in C:/temp/neo_mods/<id>/neo
    neo_step = next(step for step in steps if step.role == "neo")
    assert str(neo_step.dst).replace("\\", "/").endswith("temp/neo_mods/neo_events/neo")


def test_descriptor_text_points_at_the_mod_folder():
    text = neo.descriptor_text("neo_events")
    assert 'path="mod/neo_events"' in text
    assert "supported_version" in text


def test_enable_mod_is_idempotent_and_keeps_other_entries():
    load = {"enabled_mods": ["mod/other.mod"]}
    once = neo.enable_mod(load, "mod/neo_events.mod")
    twice = neo.enable_mod(once, "mod/neo_events.mod")
    assert twice["enabled_mods"] == ["mod/other.mod", "mod/neo_events.mod"]
    assert load["enabled_mods"] == ["mod/other.mod"]      # input not mutated


def test_enable_mod_starts_from_an_empty_document():
    assert neo.enable_mod({}, "mod/x.mod")["enabled_mods"] == ["mod/x.mod"]


def test_apply_plan_writes_both_halves(tmp_path):
    """The non-dry-run path: files land, the .mod points home, dlc_load lists it."""
    mod = _make_mod(tmp_path / "proj", "neo_events")
    paths = neo.resolve_paths(
        exe=_touch(tmp_path / "stellaris.exe"), game_root=tmp_path,
        dll=_touch(tmp_path / "sqjs.dll"), mod=mod,
        temp_root=tmp_path / "temp", docs_mod_root=tmp_path / "mods")
    neo.apply_plan(neo.install_plan(paths))

    assert (tmp_path / "temp" / "sqjs.dll").is_file()
    assert (paths.runtime_root / "mod.json").is_file()
    assert (paths.official_root / "events" / "x.txt").is_file()
    descriptor = (tmp_path / "mods" / "neo_events.mod").read_text(encoding="utf-8")
    assert 'path="mod/neo_events"' in descriptor
    load = json.loads((tmp_path / "mods" / "dlc_load.json").read_text(encoding="utf-8"))
    assert load["enabled_mods"] == ["mod/neo_events.mod"]


# ---------------------------------------------------------------------------
# receipts
# ---------------------------------------------------------------------------

def test_receipts_are_one_line():
    ok = neo.receipt_ok(dll_sha16="0123456789abcdef", mod_id="neo_events", pid=4242)
    assert ok == "NEO_PLAY ok dll=0123456789abcdef mod=neo_events pid=4242"
    assert neo.receipt_fail("game_not_found") == "NEO_PLAY fail reason=game_not_found"
    assert "\n" not in ok and "\n" not in neo.receipt_fail("x")


def test_every_failure_tag_in_the_module_is_declared():
    """A tag nobody listed is a tag the player cannot look up."""
    for tag in ("game_not_found", "version_unsupported", "dll_missing", "dll_locked",
                "mod_missing", "manifest_invalid", "bundle_missing", "python_missing",
                "bridge_failed", "internal"):
        assert tag in neo.FAILURE_TAGS
        assert neo.receipt_fail(tag).endswith(f"reason={tag}")


def test_the_bat_file_only_reports_declared_tags():
    """``neo.bat`` prints its own tag when Python is absent; keep it in the table."""
    import re
    text = (HERE / "windows" / "neo.bat").read_text(encoding="utf-8")
    tags = set(re.findall(r"reason=([a-z_]+)", text))
    assert tags, "neo.bat prints no NEO_PLAY line at all"
    assert tags <= set(neo.FAILURE_TAGS), tags - set(neo.FAILURE_TAGS)


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _dry_run_args(tmp_path, mod):
    return [
        "--exe", str(_touch(tmp_path / "stellaris.exe")),
        "--dll", str(_touch(tmp_path / "sqjs.dll")),
        "--mod", str(mod),
        "--temp-root", str(tmp_path / "temp"),
        "--docs-mod-root", str(tmp_path / "mods"),
        "--dry-run",
    ]


def test_dry_run_prints_exactly_one_line(tmp_path, capsys, monkeypatch):
    mod = _make_mod(tmp_path / "proj", "neo_events")
    exe = _touch(tmp_path / "stellaris.exe")
    monkeypatch.setitem(neo.SUPPORTED_SHA256, "test", neo.sha256_file(exe))
    code = neo.main(_dry_run_args(tmp_path, mod))
    out = capsys.readouterr()
    assert code == 0
    assert out.out.count("\n") == 1
    assert out.out.startswith("NEO_PLAY ok")
    assert "mod=neo_events" in out.out
    assert out.err == ""


def test_failure_is_one_line_and_has_no_traceback(tmp_path, capsys):
    code = neo.main(["--exe", str(tmp_path / "gone.exe"),
                     "--dll", str(_touch(tmp_path / "sqjs.dll")),
                     "--mod", str(_make_mod(tmp_path / "proj", "neo_events")),
                     "--temp-root", str(tmp_path / "temp"),
                     "--docs-mod-root", str(tmp_path / "mods"),
                     "--dry-run"])
    out = capsys.readouterr()
    assert code == 2
    assert out.out.strip() == "NEO_PLAY fail reason=game_not_found"
    assert "Traceback" not in out.err


def test_version_failure_writes_nothing(tmp_path, capsys):
    mod = _make_mod(tmp_path / "proj", "neo_events")
    code = neo.main(_dry_run_args(tmp_path, mod))
    out = capsys.readouterr()
    assert code == 2
    assert out.out.strip() == "NEO_PLAY fail reason=version_unsupported"
    assert not (tmp_path / "mods").exists()


def test_debug_prints_the_traceback(tmp_path, capsys):
    code = neo.main(["--exe", str(tmp_path / "gone.exe"),
                     "--dll", str(_touch(tmp_path / "sqjs.dll")),
                     "--mod", str(_make_mod(tmp_path / "proj", "neo_events")),
                     "--temp-root", str(tmp_path / "temp"),
                     "--docs-mod-root", str(tmp_path / "mods"),
                     "--dry-run", "--debug"])
    out = capsys.readouterr()
    assert code == 2
    assert "Traceback" in out.err


def test_a_locked_dll_maps_to_dll_locked(tmp_path, monkeypatch, capsys):
    """A file held open by a running game is `dll_locked`, not a traceback."""
    mod = _make_mod(tmp_path / "proj", "neo_events")
    exe = _touch(tmp_path / "stellaris.exe")
    monkeypatch.setitem(neo.SUPPORTED_SHA256, "test", neo.sha256_file(exe))

    def boom(*_args, **_kwargs):
        raise PermissionError(13, "The process cannot access the file")

    monkeypatch.setattr(neo.shutil, "copy2", boom)
    code = neo.main(_dry_run_args(tmp_path, mod)[:-1])   # dry_run off
    out = capsys.readouterr()
    assert code == 2
    assert out.out.strip() == "NEO_PLAY fail reason=dll_locked"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _touch(path: pathlib.Path) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ")
    return path


def _make_mod(root: pathlib.Path, mod_id):
    """A minimal project: manifest, bundle, descriptor, and the script dirs."""
    (root / "common" / "on_actions").mkdir(parents=True)
    (root / "events").mkdir()
    (root / "localisation" / "english").mkdir(parents=True)
    (root / "neo").mkdir()
    (root / "descriptor.mod").write_text('name="Neo"\n', encoding="utf-8")
    (root / "common" / "on_actions" / "x.txt").write_text("", encoding="utf-8")
    (root / "events" / "x.txt").write_text("", encoding="utf-8")
    (root / "localisation" / "english" / "x.yml").write_text("l_english:\n", encoding="utf-8")
    (root / "neo" / "main.js").write_text("// bundle\n", encoding="utf-8")
    manifest = {"entry": "main.js", "scope": ["system"]}
    if mod_id is not None:
        manifest["id"] = mod_id
    (root / "neo" / "mod.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def test_copy_or_replace_is_a_noop_for_the_same_path(tmp_path):
    """C1 live shot: --dll already in the temp root must not fail as dll_locked."""
    import importlib.util
    import pathlib as _p

    here = _p.Path(__file__).with_name("windows") / "neo_install.py"
    import sys

    spec = importlib.util.spec_from_file_location("neo_install_mod", here)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["neo_install_mod"] = mod  # dataclasses resolves annotations via sys.modules
    spec.loader.exec_module(mod)

    target = tmp_path / "sqjs.dll"
    target.write_bytes(b"x")
    mod._copy_or_replace(target, target)  # must not raise
    assert target.read_bytes() == b"x"
