# Install

A runtime JS mod has two halves, and both are required. The **official half**
(`descriptor.mod`, `common/`, `events/`, `localisation/`) is an ordinary
Stellaris mod. The **runtime half** is a `neo/` directory that the injected
QuickJS host reads from a fixed path. Install only the first half and you get a
mod that loads and then does nothing — that failure mode is exactly what this
page exists to prevent.

The one-click installer does both. This page covers it first, then the manual
route for when something goes wrong.

## What you need

- **Windows x86_64** and **Stellaris 4.4.4**. The host's version gate is a
  sha256 of `stellaris.exe`, so a different patch is refused rather than
  half-supported.
- **The developer preview package** — `neo-stellaris-preview-<version>.zip`
  from [the latest release](https://github.com/loficore/Neo-Stellaris/releases/latest).
  It contains `stellaris_quickjs.dll`, `inject.exe`, the TypeScript SDK
  (`sdk/`), two worked examples (`examples/`), `INSTALL.md` (this page, offline),
  `LICENSE`, `THIRD-PARTY-NOTICES.md` and the QuickJS licence.
- **Node.js 24** — only on the machine you *author* on, and only for
  `neo new/build/check/pack`. Playing an already-built mod needs no Node.

## Verify the download

Every release ships a `SHA256SUMS` file with three lines: the DLL, `inject.exe`
and the zip itself.

```bash
sha256sum -c SHA256SUMS
# stellaris_quickjs.dll: OK
# neo-stellaris-preview-<version>.zip: OK
```

The zip's own hash cannot be checked from inside the zip — compare that line
against the release page. If a hash does not match, do not install: the DLL is
injected into the game process and the shipped bytes are the bytes that were
gated.

## Install with the one-click installer

`neo_install.py` plus its `neo.bat` wrapper is the player entry point. Copy both
next to the game (or into `C:/temp/`), then double-click `neo.bat`. It installs
both halves, injects the runtime and launches the game. It always prints exactly
one line:

```
NEO_PLAY ok dll=8c774e60b36c2969 mod=neo_events pid=4242
NEO_PLAY fail reason=version_unsupported
```

`pid=0` means *this run did not start the game* (a dry run, or `--no-launch`
with nothing running). It is not an error.

From a shell, the same file takes flags:

```bash
python C:/temp/neo_install.py --dry-run --debug            # print the plan, write nothing
python C:/temp/neo_install.py --mod C:/temp/mods/my_mod    # install that project and launch
python C:/temp/neo_install.py --no-launch                  # install only
```

### What it puts where

| Half | Destination |
|---|---|
| official mod (`descriptor.mod`, `common/`, `events/`, `localisation/`) | `<Documents>/Paradox Interactive/Stellaris/mod/<id>/`, plus a `<id>.mod` descriptor pointing at it and a `dlc_load.json` entry |
| runtime (`<project>/neo/`) | `C:/temp/neo_mods/<id>/neo/` — the fixed path the injected loader reads |
| the host | `stellaris_quickjs.dll` → `C:/temp/`, loaded by `inject.exe` |

The `dlc_load.json` entry is the *playset* half: without it the engine never
loads the mod, no matter how correct the files are. If you install by hand you
have to add it yourself (see [Manual install](#manual-install)).

### Failure tags

Each tag is a single word because the player gets one line:

| Tag | Meaning |
|---|---|
| `game_not_found` | `stellaris.exe` not at `--exe`, `NS_STELLARIS_EXE`, `--game-root`, or the Steam defaults |
| `version_unsupported` | the exe's sha256 is not the supported 4.4.4 digest — **nothing is written** |
| `dll_missing` | no `stellaris_quickjs.dll` next to the script, in `NEO_DLL`, or in `zig-out/bin` |
| `dll_locked` | the copy hit a sharing/permission error — usually a running game holding the old DLL |
| `mod_missing` | no project directory (`descriptor.mod` absent) |
| `manifest_invalid` | `neo/mod.json` unreadable, or `id` outside `[a-z0-9][a-z0-9_]{0,63}` |
| `bundle_missing` | `neo/<entry>` is absent — run `neo build` first |
| `python_missing` | printed by `neo.bat` when neither `python` nor `py -3` exists |
| `bridge_failed` | the launch/inject channel returned non-zero |
| `internal` | anything else; `--debug` prints the traceback |

**One thing no installer can do:** mod files are read at game start, so a game
that is already running when you install will not see them. The installer
launches the game when nothing is running; if you used `--no-launch`, restart it
yourself before expecting the events.

## Manual install

Use this when you are developing the host itself, or when a tag above points at
something the installer handles but you want to see it happen.

1. **Unpack.** Keep the zip's layout; `sdk/` and `examples/` are relative to
   each other.
2. **Build the bundle.** `neo/main.js` must exist before you install:

   ```bash
   cd sdk && npm ci
   node dist/cli.js build --dir ../examples/neo_events
   node dist/cli.js check --dir ../examples/neo_events
   ```

3. **Copy the runtime half.** The project's `neo/` directory goes to
   `C:/temp/neo_mods/<id>/neo/`, so that `neo/mod.json` and `neo/main.js` are
   directly inside it. The `<id>` is the manifest's `id` field, and it is also
   the loader's directory name — they must agree.
4. **Copy the official half.** Put the project's `descriptor.mod`, `common/`,
   `events/` and `localisation/` into
   `<Documents>/Paradox Interactive/Stellaris/mod/<id>/`, and write a
   `<id>.mod` file next to that directory which `path=`s to it.
5. **Enable it in the playset.** Add `mod/<id>.mod` to `enabled_mods` in
   `dlc_load.json` (the launcher rewrites this file from its own registry, so
   doing it through the launcher UI is usually easier and always sticks).
6. **Inject before the script parser runs.** Start the game through Steam, then
   run `inject.exe` against the process and load `stellaris_quickjs.dll`. The
   host is loaded once per process and is never unloaded.

## Did it work?

In `C:/temp/neo_js.log` you should see the host's own lines:

```
NEO_JS_LOAD id=neo_events entry=main.js
NEO_JS_CALL ...            # once per system, once per monthly pulse
NEO_JS_LOG NEO_EVENT_PICK source=js system=82 pick=2 ...
```

A run **without** the injection logs `neo_action` as an unknown effect. That is
expected for a runtime-JS mod, and it is the fastest way to tell "the DLL is not
in" from "the JS is broken".

If the host loaded but your handler never ran, the chain to check is
`on_actions` → hidden event → `every_system`/`every_country` → `neo_action`; the
dispatch is driven by *official script*, not by a timer inside the host.
[Your first mod](/guide/first-mod) walks through that chain, and
[Known limits](/guide/known-limits) lists what the preview deliberately does not
do yet.
