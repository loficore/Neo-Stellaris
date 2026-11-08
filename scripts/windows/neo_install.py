#!/usr/bin/env python3
"""neo_install.py — the one-click player entry point: install the mod, inject, play.

Double-click ``neo.bat`` (or run this with no arguments).  The whole contract is
one line on stdout:

    NEO_PLAY ok dll=<sha16> mod=<id> pid=<pid>
    NEO_PLAY fail reason=<tag>

``pid=0`` means "the game was not started by this run" (``--dry-run``, or
``--no-launch`` with no game running) — it is not an error.

**What it installs — two halves, and both are needed.**

1. *The official half.* A normal Stellaris mod is parsed by the Clausewitz
   script engine, so ``descriptor.mod`` / ``common/`` / ``events/`` /
   ``localisation/`` have to reach the Paradox mod folder, a
   ``<id>.mod`` descriptor has to point at it, and ``dlc_load.json`` has to list
   it.  Without this half the engine never loads the mod and the runtime bundle
   is inert — a plan that only copies ``neo/`` looks like it worked and does
   nothing.
2. *The runtime half.* ``<project>/neo/`` goes to ``C:/temp/neo_mods/<id>/neo/``
   (the fixed location the injected loader reads) and the DLL to
   ``C:/temp/<basename>``.

**Version gate (fail-closed).** The exe's sha256 must be in
``SUPPORTED_SHA256``; anything else is ``version_unsupported`` and **nothing is
written** — a wrong-version install is how a save gets hurt.  The digest is the
one ``docs/offline-tooling.md`` records for 4.4.4.

**Failure surface.** Every failure is one line with a tag from ``FAILURE_TAGS``;
the traceback is printed only under ``--debug``.  ``dll_locked`` covers the
common case of a game (or an old injector) still holding the DLL.

**Not exercised offline.** ``launch_and_inject`` is the only part that needs
Windows: it asks ``session_bridge`` to run the launcher in the interactive
desktop session (an SSH/double-click shell can land in session 0, where the game
window does not exist), then runs ``c2_boot_inject`` which waits for
``stellaris.exe`` and injects.  Everything above it is pure and tested by
``scripts/test_neo_install.py``.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import traceback

EXIT_OK = 0
EXIT_FAIL = 2

HERE = pathlib.Path(__file__).resolve().parent
# Deployed as ``C:/temp/neo_install.py`` the tree has no grandparent; the repo
# layout is only used for *defaults* (examples/, zig-out/), never for the
# explicit ``--mod`` / ``--dll`` path, so fall back to HERE instead of crashing
# at import time (C1 live shot, 2026-11-08).
REPO = HERE.parents[1] if len(HERE.parents) > 1 else HERE

#: ``game version -> sha256 of stellaris.exe``.  Source of truth for the digest:
#: ``docs/offline-tooling.md`` 「前置条件」.  Adding a row is the *only* way to
#: make a new build playable — the gate has no override flag on purpose.
SUPPORTED_SHA256 = {
    "4.4.4": "9242c40abb78b53e88039ead1270ad82eb003959fb2d413c856d280ea02b1a56",
}

#: Every tag ``receipt_fail`` may print.  A tag outside this set would be one the
#: player cannot look up in ``docs/runtime-js-sdk.md``.
FAILURE_TAGS = (
    "game_not_found",
    "version_unsupported",
    "dll_missing",
    "dll_locked",
    "mod_missing",
    "manifest_invalid",
    "bundle_missing",
    "python_missing",
    "bridge_failed",
    "internal",
)

#: Where the engine keeps mods (``<Documents>/Paradox Interactive/Stellaris/mod``).
DOCS_MOD_DEFAULT = pathlib.Path(os.path.expanduser("~")) / "Documents" / \
    "Paradox Interactive" / "Stellaris" / "mod"

#: The loader's fixed root for runtime bundles (``<root>/<id>/neo/{mod.json,main.js}``).
TEMP_ROOT_DEFAULT = pathlib.Path(os.environ.get("NEO_TEMP_ROOT", r"C:\temp"))

#: Default exe candidates, in order.  ``--exe`` and ``NS_STELLARIS_EXE`` win.
EXE_CANDIDATES = (
    pathlib.Path(r"C:\Program Files (x86)\Steam\steamapps\common\Stellaris\stellaris.exe"),
    pathlib.Path(r"D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe"),
    pathlib.Path(r"C:\Program Files\Steam\steamapps\common\Stellaris\stellaris.exe"),
)

#: Official-mod entries carried from the project into the Paradox mod folder.
#: A whitelist, not a filter: a new top-level directory has to be added here
#: deliberately (the same rule `neo pack` uses).
OFFICIAL_ENTRIES = ("descriptor.mod", "common", "events", "localisation", "README.md")

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")


class NeoPlayError(Exception):
    """A failure with a player-facing ``tag``."""

    def __init__(self, tag, detail=""):
        if tag not in FAILURE_TAGS:
            raise ValueError(f"undeclared failure tag {tag!r}")
        super().__init__(detail or tag)
        self.tag = tag
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class Paths:
    exe: pathlib.Path
    dll: pathlib.Path
    mod: pathlib.Path
    mod_id: str
    entry: str
    temp_root: pathlib.Path
    docs_mod_root: pathlib.Path

    @property
    def runtime_root(self):
        return self.temp_root / "neo_mods" / self.mod_id / "neo"

    @property
    def official_root(self):
        return self.docs_mod_root / self.mod_id

    @property
    def mod_file(self):
        """The ``mod/<id>.mod`` token ``dlc_load.json`` wants (forward slashes)."""
        return f"mod/{self.mod_id}.mod"


@dataclasses.dataclass(frozen=True)
class Step:
    """One install action.  ``src is None`` means "generated by this tool".

    ``note`` carries the generated content's argument: the mod id for the
    ``<id>.mod`` descriptor, the ``mod/<id>.mod`` token for ``dlc_load.json``.
    It is on the step so ``apply_plan`` needs no second argument.
    """

    role: str
    src: object
    dst: pathlib.Path
    note: str = ""


# ---------------------------------------------------------------------------
# version gate
# ---------------------------------------------------------------------------

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def version_tag(sha256):
    """``sha256 -> version`` (``"unsupported"`` when no row matches)."""
    for tag, digest in SUPPORTED_SHA256.items():
        if digest == sha256:
            return tag
    return "unsupported"


def require_supported(sha256):
    tag = version_tag(sha256)
    if tag == "unsupported":
        raise NeoPlayError("version_unsupported", f"sha256 {sha256} is not in SUPPORTED_SHA256")
    return tag


# ---------------------------------------------------------------------------
# path resolution
# ---------------------------------------------------------------------------

def _first_existing(candidates):
    for candidate in candidates:
        if candidate is not None and pathlib.Path(candidate).is_file():
            return pathlib.Path(candidate)
    return None


def resolve_exe(exe=None, game_root=None):
    """``--exe`` -> ``NS_STELLARIS_EXE`` -> ``<game_root>/stellaris.exe`` -> defaults.

    An explicit ``game_root`` **restricts** the search to that root: it is how a
    test (and a player pointing at a second Steam library) says "look here, not
    everywhere".  No root and no hit is ``game_not_found``.
    """
    if exe is not None:
        found = _first_existing([exe])
    elif game_root is not None:
        found = _first_existing([pathlib.Path(game_root) / "stellaris.exe"])
    else:
        found = _first_existing([os.environ.get("NS_STELLARIS_EXE"), *EXE_CANDIDATES])
    if found is None:
        raise NeoPlayError("game_not_found", "stellaris.exe not found")
    return found


def resolve_dll(dll=None):
    """``--dll`` -> ``NEO_DLL`` -> next to this script -> the repo's build output."""
    candidates = [dll, os.environ.get("NEO_DLL"), HERE / "stellaris_quickjs.dll"]
    candidates.extend(sorted((REPO / "zig-out" / "bin").glob("*.dll")) if (REPO / "zig-out").is_dir() else [])
    found = _first_existing(candidates)
    if found is None:
        raise NeoPlayError("dll_missing", "no stellaris_quickjs.dll found")
    return found


def find_mod(root):
    """Newest project under ``root`` that carries ``descriptor.mod``.

    "Newest" is the mtime of ``descriptor.mod`` (a rebuild touches the bundle,
    not the descriptor; this is a *project* picker, not a freshness check), with
    the directory name as the tie-breaker so two runs on one tree agree.
    """
    root = pathlib.Path(root)
    if not root.is_dir():
        raise NeoPlayError("mod_missing", f"{root} does not exist")
    found = [p.parent for p in root.glob("*/descriptor.mod")]
    if not found:
        raise NeoPlayError("mod_missing", f"no */descriptor.mod under {root}")
    found.sort(key=lambda d: ((d / "descriptor.mod").stat().st_mtime, d.name))
    return found[-1]


def read_manifest(mod_root):
    """``(id, entry)`` from ``<mod>/neo/mod.json``; fail-closed on everything else."""
    mod_root = pathlib.Path(mod_root)
    manifest_path = mod_root / "neo" / "mod.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NeoPlayError("manifest_invalid", f"{manifest_path}: {exc}") from exc
    mod_id = manifest.get("id")
    if not isinstance(mod_id, str) or not _ID_RE.match(mod_id):
        raise NeoPlayError("manifest_invalid", f"{manifest_path}: id must match [a-z0-9][a-z0-9_]{{0,63}}")
    entry = manifest.get("entry") or "main.js"
    if not isinstance(entry, str) or "/" in entry or "\\" in entry:
        raise NeoPlayError("manifest_invalid", f"{manifest_path}: entry must be a bare filename")
    if not (mod_root / "neo" / entry).is_file():
        raise NeoPlayError("bundle_missing", f"{mod_root / 'neo' / entry} is missing — run `neo build`")
    return mod_id, entry


def resolve_paths(*, exe=None, game_root=None, dll=None, mod=None,
                  temp_root=None, docs_mod_root=None):
    exe_path = resolve_exe(exe, game_root)
    dll_path = resolve_dll(dll)
    temp = pathlib.Path(temp_root) if temp_root is not None else TEMP_ROOT_DEFAULT
    docs = pathlib.Path(docs_mod_root) if docs_mod_root is not None else DOCS_MOD_DEFAULT
    if mod is not None:
        mod_root = pathlib.Path(mod)
        if not (mod_root / "descriptor.mod").is_file():
            raise NeoPlayError("mod_missing", f"{mod_root} has no descriptor.mod")
    else:
        mod_root = _find_mod_anywhere()
    mod_id, entry = read_manifest(mod_root)
    return Paths(exe=exe_path, dll=dll_path, mod=mod_root, mod_id=mod_id, entry=entry,
                 temp_root=temp, docs_mod_root=docs)


def _find_mod_anywhere():
    for root in (HERE / "mods", REPO / "examples"):
        try:
            return find_mod(root)
        except NeoPlayError:
            continue
    raise NeoPlayError("mod_missing", "no project found next to this script or under examples/")


# ---------------------------------------------------------------------------
# install plan
# ---------------------------------------------------------------------------

def descriptor_text(mod_id, name=None):
    """The ``<id>.mod`` the launcher reads.  ``path`` uses forward slashes."""
    display = name or mod_id
    return (
        f'version="0.1.0"\n'
        f'name="{display}"\n'
        f'tags={{\n\t"runtime-js"\n}}\n'
        f'path="mod/{mod_id}"\n'
        f'supported_version="4.4.*"\n'
    )


def enable_mod(load, mod_file):
    """Return a copy of ``dlc_load.json`` with ``mod_file`` enabled, idempotently."""
    updated = dict(load)
    enabled = list(updated.get("enabled_mods") or [])
    if mod_file not in enabled:
        enabled.append(mod_file)
    updated["enabled_mods"] = enabled
    return updated


def install_plan(paths):
    """Every step, in apply order.  Pure: nothing here touches the disk."""
    steps = [
        Step("dll", paths.dll, paths.temp_root / paths.dll.name),
        Step("neo", paths.mod / "neo", paths.runtime_root),
    ]
    for name in OFFICIAL_ENTRIES:
        source = paths.mod / name
        if source.exists():
            steps.append(Step("official", source, paths.official_root / name))
    steps.append(Step("descriptor", None, paths.docs_mod_root / f"{paths.mod_id}.mod",
                      paths.mod_id))
    # ``dlc_load.json`` lives at ``<Stellaris>/dlc_load.json`` — the *parent* of
    # the ``mod/`` folder, not inside it (C1 live shot, 2026-11-08: writing it
    # under ``mod/`` left the mod disabled and the game merely ignored it).
    steps.append(Step("dlc_load", None, paths.docs_mod_root.parent / "dlc_load.json",
                      paths.mod_file))
    return steps


def apply_plan(steps, dry_run=False):
    """Execute a plan; ``dry_run`` returns the same list without writing."""
    if dry_run:
        return steps
    for step in steps:
        try:
            if step.role == "descriptor":
                step.dst.parent.mkdir(parents=True, exist_ok=True)
                step.dst.write_text(descriptor_text(step.note), encoding="utf-8")
            elif step.role == "dlc_load":
                _merge_dlc_load(step.dst, step.note)
            elif step.role == "official" and pathlib.Path(step.src).is_dir():
                shutil.copytree(step.src, step.dst, dirs_exist_ok=True)
            elif step.role == "official":
                step.dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(step.src, step.dst)
            else:
                _copy_or_replace(step.src, step.dst)
        except PermissionError as exc:
            tag = "dll_locked" if step.role == "dll" else "internal"
            raise NeoPlayError(tag, f"{step.dst}: {exc}") from exc
        except OSError as exc:
            raise NeoPlayError("internal", f"{step.dst}: {exc}") from exc
    return steps


def _copy_or_replace(src, dst):
    src = pathlib.Path(src)
    dst = pathlib.Path(dst)
    if src.resolve() == dst.resolve():
        # The DLL is already sitting where the loader expects it (C1 shot,
        # 2026-11-08).  Copying a file onto itself is a PermissionError on
        # Windows, which would surface as a bogus ``dll_locked``.
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)


def _merge_dlc_load(path, mod_file):
    try:
        load = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        load = {}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(enable_mod(load, mod_file), indent="\t"), encoding="utf-8")


# ---------------------------------------------------------------------------
# receipts
# ---------------------------------------------------------------------------

def receipt_ok(dll_sha16, mod_id, pid):
    return f"NEO_PLAY ok dll={dll_sha16} mod={mod_id} pid={pid}"


def receipt_fail(tag):
    return f"NEO_PLAY fail reason={tag}"


def next_steps(mod_id):
    """The three steps the *player* still owns after a successful install.

    "One click" is not true and never was: the Stellaris launcher keeps its own
    playset database and rewrites ``dlc_load.json`` when the player applies it,
    so the mod has to be ticked in the launcher.  Injection is a separate entry
    point (``neo.bat``).  This text is the contract, printed to stderr so the
    one-line stdout receipt stays machine-readable.
    """
    return [
        f"NEXT 1) 打开启动器 → 播放集 → 勾选 {mod_id}（启动器会重写 dlc_load.json）",
        "NEXT 2) 运行 neo.bat（安装 + 启动 + 注入；或手动跑 c2_boot_inject.py）",
        "NEXT 3) 进游戏后确认 C:/temp/neo_js.log 出现 NEO_JS_INIT_OK",
    ]


# ---------------------------------------------------------------------------
# launch + inject (Windows only, not exercised offline)
# ---------------------------------------------------------------------------

def game_pid():
    """The running ``stellaris.exe`` pid, or ``None``."""
    try:
        import psutil  # Windows-only dependency, lazily imported
    except ImportError:
        return None
    for proc in psutil.process_iter(["name", "pid"]):
        if (proc.info.get("name") or "").lower() == "stellaris.exe":
            return proc.info["pid"]
    return None


def _launch_once(wait_s):
    """Ask the interactive-desktop channel to start the game."""
    import session_bridge  # deployed beside this file on the Windows box

    rc = session_bridge.run_interactive("python", f"{HERE / 'launch_stellaris.py'}", timeout=wait_s)
    if rc != 0:
        raise NeoPlayError("bridge_failed", f"launch_stellaris rc={rc}")


def _inject_once(dll, timeout_s):
    """Wait for ``stellaris.exe`` and inject; ``c2_boot_inject`` owns the settle."""
    import c2_boot_inject  # deployed beside this file on the Windows box

    rc = c2_boot_inject.main([str(dll), "--timeout-s", str(timeout_s)])
    if rc != 0:
        raise NeoPlayError("bridge_failed", f"c2_boot_inject rc={rc}")


def launch_and_inject(paths, *, wait_s=600.0, timeout_s=60.0):
    """Launch (if needed) and inject; return the pid (0 = "not started by us").

    Two channels, both already on the box: ``session_bridge`` runs the launcher
    in the interactive desktop session (a shell that lands in session 0 cannot
    see the game window), and ``c2_boot_inject`` waits for ``stellaris.exe`` and
    injects before its settle window.  A game that is already running is only
    injected — the mod files installed a moment ago need a restart to load, so
    the caller is the one who decides whether "already running" is what it wants.
    """
    pid = game_pid()
    try:
        if pid is None:
            _launch_once(wait_s)
        # Inject the **copy** in the loader root: it is the file whose sha we printed,
        # and `C:/temp/<basename>` is the wire name the whole channel uses.
        _inject_once(paths.temp_root / paths.dll.name, timeout_s)
    except NeoPlayError:
        raise
    except Exception as exc:  # the channel is foreign code; keep the one-line promise
        raise NeoPlayError("bridge_failed", str(exc)) from exc
    return game_pid() or 0


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(add_help=True, description=__doc__.splitlines()[0])
    parser.add_argument("--exe", default=None, help="stellaris.exe (default: NS_STELLARIS_EXE, then Steam paths)")
    parser.add_argument("--game-root", default=None, help="look for stellaris.exe only here")
    parser.add_argument("--dll", default=None, help="injected DLL (default: next to this script)")
    parser.add_argument("--mod", default=None, help="authoring project (default: newest under examples/)")
    parser.add_argument("--temp-root", default=None, help=r"loader root (default C:\temp)")
    parser.add_argument("--docs-mod-root", default=None, help="Paradox mod folder")
    parser.add_argument("--dry-run", action="store_true", help="plan and gate, write nothing, launch nothing")
    parser.add_argument("--no-launch", action="store_true", help="do not start the game; inject only")
    parser.add_argument("--wait-s", type=float, default=600.0, help="how long the launcher may take")
    parser.add_argument("--timeout-s", type=float, default=60.0, help="how long to wait for stellaris.exe")
    parser.add_argument("--debug", action="store_true", help="print the traceback on failure")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        paths = resolve_paths(exe=args.exe, game_root=args.game_root, dll=args.dll,
                              mod=args.mod, temp_root=args.temp_root,
                              docs_mod_root=args.docs_mod_root)
        require_supported(sha256_file(paths.exe))
        steps = install_plan(paths)
        if args.debug:
            for step in steps:
                print(f"[neo] {step.role}: {step.src} -> {step.dst}", file=sys.stderr)
        apply_plan(steps, dry_run=args.dry_run)
        pid = 0
        if not args.dry_run and not args.no_launch:
            pid = launch_and_inject(paths, wait_s=args.wait_s, timeout_s=args.timeout_s)
    except NeoPlayError as exc:
        if args.debug:
            traceback.print_exc()
        print(receipt_fail(exc.tag))
        return EXIT_FAIL
    except Exception:  # noqa: BLE001 - the one-line promise beats the exception type
        if args.debug:
            traceback.print_exc()
        print(receipt_fail("internal"))
        return EXIT_FAIL
    print(receipt_ok(sha256_file(paths.dll)[:16], paths.mod_id, pid))
    if not args.dry_run:
        # Dry-run is a plan preview; a real install owns the reminder.
        for line in next_steps(paths.mod_id):
            print(line, file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
