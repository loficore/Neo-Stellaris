# Runtime JS SDK — developer preview (Phase 2)

> **Status: blocked.** This page is the manifest for the preview package and the
> trial script for issue #39. The package is **not built or published** yet.
>
> The Phase 2 live safety shot (C2) has run: multi-mod isolation **passed** (one good
> mod kept running while three bad ones were disabled, host alive both times). The flag
> APIs did **not** pass: two P2-1b shots on 2026-11-08 showed the install-time premint
> works (`id=19345`, inside u16) but the write/read land on a structure that is not the
> engine's star-flag store (official `has_star_flag` 0 hits against a 139-hit control;
> the autosave contains no `neo_hub`). Flags are therefore **not part of the preview
> surface** until the real keyword record is re-derived — see
> `evidence/logs/runtime_js_p2_1b_flags_4_4_4.log` and the status note in
> [runtime-js-sdk.md](runtime-js-sdk.md).

## What the preview is

A zip for authors who want to try **runtime JS mods** before the SDK is
published anywhere. It is built from this tree, needs no npm registry, and
contains exactly:

| Path | What it is |
|---|---|
| `sdk/` | the TypeScript SDK (`api.def`, `src/`, `dist/`, `package-lock.json`, tests) |
| `sdk/templates/neo-mod/` | the `neo new` project template |
| `examples/chokepoint/` | the worked example (graph betweenness → `neo_score`) |
| `docs/runtime-js-sdk.md` | API, `neo new/build/check/pack`, manifest format |
| `docs/runtime-js-preview.md` | this page |
| `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv` | the keyword table `neo check`'s flag-name gate compares against |
| `zig-out/bin/stellaris_quickjs.dll` | the injected host, built by the same gate as CI |
| `zig-out/bin/inject.exe` | the injector the Phase 1 shot used |
| `SHA256SUMS` | hashes of the two binaries |

It does **not** contain `node_modules/`, a mod project's `dist/` staging tree,
or `.git/` — `neo pack` builds a mod artifact from a whitelist, so those cannot
leak in by accident.

## What it is not

Not a Workshop mod, and not installable by subscribing to anything. A runtime JS
mod is inert without the injected host: the script parser logs `neo_action` as an
unknown effect until the DLL is injected, and `neo/main.js` only runs because the
host `JS_Eval`s it from `C:/temp/neo_mods/<id>/neo/`.

## Trying it (issue #39)

1. **Node 24** on the machine you author on. `cd sdk && npm ci` (exact versions
   from the committed lockfile; no other install step exists).
2. **Scaffold + check offline:**
   ```bash
   node dist/cli.js new my-mod --id my_mod --name "My Mod"
   node dist/cli.js check --dir my-mod      # real QuickJS, mock host
   node dist/cli.js pack  --dir my-mod --out my_mod.zip
   ```
   `NEO_CHECK ok … handler=1 calls=6` is the offline green. It proves the bundle
   type-checks, avoids Node/browser globals, registers exactly one `onSystem`
   handler, survives the flag-name gate (literal names, no official-keyword
   collisions) and speaks the frozen native contract. It cannot prove engine
   behaviour.
3. **Live (4.4.4, Windows, x86_64 only):** copy `my-mod` to
   `C:/temp/neo_mods/my_mod/` so that `neo/mod.json` and `neo/main.js` are inside
   it, put `stellaris_quickjs.dll` next to the game and inject it before the
   script parser runs. The generated `common/on_actions/` + `events/` pair drives
   `every_system` once a month; a run without injection logs `neo_action` as an
   unknown effect, which is expected.
4. **Report** the `NEO_JS_*` lines from `C:/temp/neo_js.log` (call/write/log
   counts, and any `NEO_JS_ERROR` / `NEO_JS_TIMEOUT` / `NEO_API_MISMATCH`), the
   game version, the campaign and whether the host survived. Flag users should
   also copy the install-time `NEO_JS_PREMINT` / `NEO_JS_PREMINT_FAIL` lines —
   they are the only way to tell "name never declared" (`no_premint`) from
   "install ran too late" (`reason=range`). A zero count means "did not happen",
   not "fixed" — say which.
5. **Do not** report `neo check` alone as a live result. The two gates are
   different by design.

## Known limitations of the preview

- **v1.1 API is shallow**: `s.id`, `s.degree`, `s.neighbors`, `s.setVariable`,
  `s.setStarFlag`, `s.hasStarFlag`, `graph.betweenness`, `graph.isChokepoint`,
  `log`, `apiVersion`. `s.name` and `s.variable()` are deferred until a static
  read path is resolved; they are absent from `api.def` rather than guessed.
  Flag names are string literals only, must be declared in `neo/mod.json`'s
  `flags` (at most 32 names, 1–15 lowercase bytes each), and the build rejects
  names that collide case-insensitively with an official keyword. The host mints
  those names at **install** time, before the script parser runs, so the id stays
  inside the engine's 16-bit flag key; an undeclared name fails closed with
  `no_premint`. This premint path has **no live reading yet** (C2 is blocked).
- **System scope only** — no country / fleet / planet / pop scopes.
- **No `onMonthly` hook**: the monthly driver is the generated
  `on_action` → hidden event → `every_system` chain, i.e. the official script
  path.
- **Multi-mod support is the host's Phase 2 work**: up to 8 isolated sessions,
  one bad mod disables only itself. The SDK side (`neo new`/`pack`) is ready;
  the live safety reading is C2 and is **blocked**.
- **The DLL is a Debug build** (the shipped bytes are the gated bytes). It is
  injection-only and is never `FreeLibrary`d.
- **No Workshop distribution, no hot reload, no build-time TS → `.txt`** — those
  are Phase 3 candidates, not preview promises.

## What "done" would look like

The preview moves from *blocked* to *published* only when:

- C2 lands one named live shot with a good mod and one bad mod (throw / timeout /
  over-permission) in the same process: the good mod's counters keep growing, the
  bad mod's `NEO_JS_ERROR` / `NEO_JS_TIMEOUT` / `WRITE_REJECT` reach the log, its
  session is disabled, the host survives, and the game is killed afterwards;
- `just sdk-test` and `just check-full` are green on the exact commit the package
  is built from;
- the zip is assembled from that commit (release job / `zip` over the manifest
  above), and `SHA256SUMS` matches `sha256sum` of the two binaries.
