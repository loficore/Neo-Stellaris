# Runtime JS SDK (v1.1 — system scope)

Authoring SDK for **runtime JS mods**: TypeScript compiled by `neo build`, evaluated by the
injected QuickJS host on the game's main thread, once per system.

> **Status (2026-11-07).** v1 is live-accepted (Phase 1 C1, below). v1.1 is the SDK half of
> Phase 2 and is **additive**: `API_VERSION` stays `1`; the new members are `System.neighbors`,
> `System.setStarFlag` and `System.hasStarFlag`, plus the `neo new` / `neo pack` authoring
> commands. The host half (the three natives, one QuickJS session per mod, per-session
> isolation) lands on `feat/runtime-js-p2-host`; until it merges, a bundle that reads
> `s.neighbors` or the flag calls checks green offline but has no native in the game. The
> Phase 2 live safety shot (C2) and the developer preview publication (C3) are **blocked** —
> nothing here claims either reading.
>
> `s.name` and `s.variable()` are **not in the contract**. They are deferred until the Track A
> static spike resolves an official body/read path; a guessed native name would be worse than a
> missing one, so `api.def` does not mention them. `setStarFlag`/`hasStarFlag` are in: the write
> goes through the official `set_star_flag` body, the read through the official flag container,
> and the **name → flag id** resolution through the engine's own flag-name table (below).
>
> **Flag keyspace fix (2026-11-08, static + host change; no live reading yet).** The two P2-1b
> shots (2026-11-08) showed the install-time premint worked (`NEO_JS_PREMINT name=neo_hub
> id=19345`, inside u16) and the write returned ok, yet an official `has_star_flag = neo_hub`
> produced **0** hits while its control produced **139**, and the autosave contained `neo_hub`
> **0** times. Static re-derivation (`evidence/analysis/flag_store_4_4_4.md`) found the actual
> defect: **the id space was wrong**, not the container. Official flags are keyed by the engine's
> own flag-name table (`0x326D110`, `0x326D118` counter, insert `0x1BCF030`,
> name append `0x158300`), a different object from the lexer token table (`0x37347A0`,
> `0x1D13270`) that `setStarFlag` used to mint from — so the two numbers could never match.
> The host now resolves through the flag table: write = `flag_ids.ensure` (may insert),
> read = `flag_ids.lookup` (**never** inserts); 16-bit ids are the table's own numbering, so the
> install-time premint is gone (`NEO_JS_PREMINT*` lines no longer exist) and the failure tag is
> `no_flag_token`. A fresh live shot is still required before these two calls count as usable:
> the offline reading (`§6` of the evidence volume) pins the insert primitive and the counter
> owner, but nothing here re-runs the game.


## What this is not

This is **not** a Workshop mod. A normal Stellaris mod is parsed by the Clausewitz
script engine; a runtime JS mod needs the injected DLL (the QuickJS host) to load it.
Without the injected loader the files described here are inert.

## Prerequisites

- Node.js **24** (the pinned toolchain; `sdk/package.json` declares `engines.node >= 24`).
- A clone of this repository (the SDK is not published to npm in v1 — see
  [Distribution](#distribution)).
- For actually running a mod: Stellaris 4.4.4 on Windows plus the injected DLL.

## Quick start

```bash
cd sdk
npm ci                       # exact versions from sdk/package-lock.json

# Scaffold a new project, then build + check it untouched
node dist/cli.js new ../my-mod --id my_mod --name "My Mod"
node dist/cli.js build --dir ../my-mod
node dist/cli.js check --dir ../my-mod

# Package it: build + check, stage dist/my_mod/, then write ../my_mod.zip
node dist/cli.js pack --dir ../my-mod --out ../my_mod.zip

# The bundled example still works the same way
node dist/cli.js build --dir ../examples/chokepoint
node dist/cli.js check --dir ../examples/chokepoint
```

`npm link` (from `sdk/`) installs the `neo` command globally, after which the commands are
`neo new <dir> --id <id> [--name <name>]`, `neo build --dir <project>`,
`neo check --dir <project>` and `neo pack --dir <project> [--out <zip>]`.

A passing check prints exactly one line and exits `0`:

```
NEO_CHECK ok dir=/abs/path/examples/chokepoint handler=1 calls=6
```

A failure prints `NEO_CHECK fail: <reason>` and exits `2`.

## Project layout

```
my-mod/
├── tsconfig.json        # maps @neo/runtime at the SDK source
├── src/main.ts          # the mod
├── neo/mod.json         # manifest (read by the loader)
├── neo/main.js          # build output, not committed
├── descriptor.mod       # launcher metadata
├── common/on_actions/   # monthly driver (on_monthly_pulse -> the event)
└── events/              # hidden event: every_system { neo_action = { } }
```

`neo new` writes exactly the template in `sdk/templates/neo-mod/`; the acceptance promise is
that the generated tree passes `neo build` and `neo check` with no hand edits
(`sdk/test/new.test.mjs`).

`tsconfig.json` has to point `@neo/runtime` at the SDK's `src/runtime.ts`; v1 does not publish a
package to a registry, so there is no `node_modules` install step for the SDK itself. `neo new`
resolves that path relative to the generated directory:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "baseUrl": ".",
    "paths": { "@neo/runtime": ["../../sdk/src/runtime.ts"] }
  },
  "include": ["src/**/*.ts"]
}
```

The example (`examples/chokepoint`) is a complete, buildable project:

```ts
import { onSystem, graph, log } from "@neo/runtime";

onSystem((s) => {
  const b = graph.betweenness(s);
  if (b >= 200) {
    s.setVariable("neo_score", b);
    if (!s.hasStarFlag("neo_hub")) {
      s.setStarFlag("neo_hub");
    }
    log(`NEO_HUB ${s.id} ${b}`);
  }
});
```

## API (v1.1 — additive over the frozen v1 surface)

| Export | Signature | Notes |
|---|---|---|
| `onSystem` | `(handler: (s: System) => void) => void` | Registers the per-system handler. Call it exactly once — the host keeps one handler per session. |
| `System.id` | `number` | The engine system id for this call. The only handle the SDK retains. |
| `System.degree` | `number` | Hyperlane degree, read on each access (not cached). |
| `System.neighbors` | `readonly number[]` | Neighbour system ids, read on each access; the host returns a fresh array, capped (64) with a truncation log line. Needs `graph.read`. |
| `System.setVariable` | `(name: string, value: number) => void` | Writes through the official `set_variable` body for the current system. |
| `System.setStarFlag` | `(name: string) => void` | Sets the official star flag `name` through the `set_star_flag` body. Needs `flag.write`. The name is resolved to a u16 id by the engine's **flag-name table** (`flag_ids.ensure`); a name the table has never seen is inserted at first use (that is what the engine does when a script writes the same literal), then the u16 goes into the official body. **No live reading since the keyspace fix** — the 2026-11-08 pair of shots was taken with the old (token-id) resolution; see the status note. The name must be a **string literal** of 1–15 lowercase bytes and must not collide with an official keyword — see the build-time gate below. Failure to get an id is `no_flag_token`; the handler never falls back to a lexer token. |
| `System.hasStarFlag` | `(name: string) => boolean` | Reads the official star flag `name` from the flag container. Needs `flag.read`. **Read-only:** the name is resolved with `flag_ids.lookup`, which never inserts — a name with no id in the flag table reads `false` and logs `reason=no_flag_token`. A name that *has* an id but is absent from the container (or whose container cannot be read) also reads `false` (fail-closed). Same literal rules as the write. |
| `graph.betweenness` | `(s: System) => number` | Graph score for the system (same source as the C5-SCORE path). |
| `graph.isChokepoint` | `(s: System) => boolean` | `betweenness(s) >= 200` — the T2 threshold; a constant, not a tuning knob in v1. |
| `log` | `(message: string) => void` | Appends `NEO_JS_LOG <text>` to `C:/temp/neo_js.log`. |
| `apiVersion` | `() => number` | Returns the host's contract version; v1.x is `1`. |

### Native contract

The SDK is a shim over ten globals installed by the host. `sdk/api.def` is the single source of
truth (`version: 1`); the TypeScript surface, the mock host, and the Zig host must all match it.
The seven v1 names come first, unchanged; the v1.1 additions are appended **after** them in the
host's own order (`neighbors`, `set_flag`, `has_flag`). The host side of the additions is Track
A's (A2), so the Python fence allows them to be declared before they are implemented, and that
allowance is deleted at integration.

| Native | Params | Returns |
|---|---|---|
| `__neo_register_system` | `function` | `void` |
| `__neo_system_degree` | `u32` | `u32` |
| `__neo_system_set_var` | `u32`, `string`, `f64` | `void` |
| `__neo_graph_betweenness` | `u32` | `u32` |
| `__neo_graph_is_chokepoint` | `u32` | `bool` |
| `__neo_log` | `string` | `void` |
| `__neo_api_version` | — | `u32` |
| `__neo_system_neighbors` | `u32` | `array<u32>` |
| `__neo_system_set_flag` | `u32`, `string` | `void` |
| `__neo_system_has_flag` | `u32`, `string` | `bool` |


## Manifest

`neo/mod.json` — the loader reads a fixed location, `C:/temp/neo_mods/<id>/neo/{mod.json,main.js}`:

```json
{
  "id": "chokepoint",
  "entry": "main.js",
  "scope": ["system"],
  "permissions": ["graph.read", "flag.read", "flag.write", "variable.write", "log"],
  "engine": "4.4.4",
  "runtime": ">=0.1",
  "flags": ["neo_hub"]
}
```

- `id` — directory name and log tag. Required.
- `entry` — the bundle filename the loader evaluates. Required.
- `scope` — v1 accepts `["system"]` only. Required.
- `permissions` — any of `graph.read`, `variable.write`, `flag.read`, `flag.write`, `log`. A
  native whose permission is absent is refused by the host, and an unknown permission disables
  the mod at load. `degree`, `neighbors`, `betweenness` and `isChokepoint` are `graph.read`;
  `setStarFlag` is `flag.write`; `hasStarFlag` is `flag.read`.
- `engine` / `runtime` — compatibility strings; a mismatch disables the mod with a log line.
- `flags` — **optional** (the 7th field; an old manifest without it still loads). A
  **build-time collision gate**, not a runtime authority: `neo build` records the bundle's
  `setStarFlag("…")` literals here and `neo check` refuses a list that no longer matches, so an
  author cannot ship a write against an official keyword unnoticed. **The host no longer reads
  this field** — at runtime the name is resolved by the engine's flag-name table on first use.
  At most **32** names; each name is 1–15 bytes, all-lowercase, does not start with `-` or a
  digit. Missing `flags` behaves like `[]` and only means the build-time gate has nothing to
  compare.

Phase 1 loaded exactly one runtime mod. Phase 2 (Track A) loads up to **8** mods from
`C:/temp/neo_mods/<id>/`, one QuickJS context/session each: a throwing, spinning, or
over-reaching mod disables only its own session (`NEO_JS_ERROR` / `NEO_JS_TIMEOUT` /
`WRITE_REJECT`) and the other sessions keep receiving `onSystem`. Zero mods logs
`NEO_JS_NO_MOD`; more than 8 are refused with a log line. The single-mod output shape is
unchanged from Phase 1. **The multi-mod half is not in this branch and has no live reading** —
the C2 safety shot is blocked.

## `neo new`

`neo new <dir> --id <id> [--name <name>]` copies `sdk/templates/neo-mod/` (substituting the id,
the display name, and the relative `@neo/runtime` path) and prints
`NEO_NEW ok dir=<abs> id=<id> files=<n>`. It refuses a non-empty target, an id outside
`[a-z0-9][a-z0-9_]{0,63}` (the id is a manifest id, a loader directory name *and* a Clausewitz
event namespace), and a display name containing a quote or control character. The generated tree
is exactly the template: `src/main.ts`, `neo/mod.json`, `tsconfig.json`, `descriptor.mod`,
`common/on_actions/<id>_on_actions.txt`, `events/<id>_events.txt`, `README.md`. The generated
manifest declares `["graph.read", "flag.read", "flag.write", "log"]` and its `onSystem` example
demonstrates the flag read/write pair.

## `neo build` and `neo check`

`neo build --dir <project> [--outfile <file>]`

1. `tsc --noEmit -p <project>` — type errors, including a missing export from `@neo/runtime`,
   fail the build.
2. esbuild bundles `src/main.ts` as `--bundle --format=iife --platform=neutral --target=es2020`.
   The output has no `import`, no `require`, and no module loader dependency.
3. Writes `<project>/neo/<manifest entry>` (default `neo/main.js`).
4. Records the bundle's `setStarFlag("…")` literals in `<project>/neo/mod.json`'s `flags`
   (deduped, sorted; every other manifest field is preserved). A project without a manifest is
   not given one — the build prints `NEO_BUILD warn: no neo/mod.json, flags not recorded` on
   stderr and the flag calls will fail closed at runtime. `neo build` does **not** consult the
   keyword table (that is `neo check`'s gate); it only records names.

`neo check --dir <project>` performs the same type-check and bundle in memory, then:

1. statically rejects `require(`, `process.`, `window.`, `document.`, and dynamic `import(`
   (none of those exist in the host context);
2. runs the **flag-name gate** over the bundle (see below);
3. refuses a manifest whose `flags` list no longer matches the bundle's literals:
   `flags: manifest flags are stale; run "neo build" (bundle has ["neo_hub"], manifest has [])`.
   A missing `flags` field counts as `[]` (old manifests stay loadable, but a bundle that mints
   names needs the list);
4. evaluates the bundle in a **real QuickJS runtime** (`quickjs-emscripten`, the same engine
   family the host embeds) with the mock host installed;
5. asserts that exactly one `onSystem` handler registered, that the handler runs for a fake
   system id `7` without throwing, and that `__neo_api_version()` matches `api.def`.

The mock host (`sdk/src/mock-host.ts`) records every native call; a passing example check reports
`calls=6` (`betweenness`, `set_var`, `has_flag`, `set_flag`, `log`, `api_version`). `neo check` is
the last gate before a bundle is shippable, but it cannot prove engine behaviour — that is the
live acceptance shot.

### Flag-name gate (build time)

`s.setStarFlag(name)` is checked before the bundle runs, because a flag name that matches an
official keyword would address engine behaviour instead of a flag (the Phase 1 `Add_Modifier`
hazard, one layer down). Two rules:

- **string literal only** — v1 has no build-time answer for a computed name, so
  `s.setStarFlag(someVariable)` fails with a message that says literals are required;
- **no official-keyword collision** — each literal is compared case-insensitively against the
  `keywords` column of `evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`; a hit fails the
  check.

The gate reads the author's `setStarFlag("…")` call site, not the native
`__neo_system_set_flag(id, name)` call: the SDK shim always forwards its own parameter, so the
native call is dynamic in every bundle. `hasStarFlag("…")` literals are **not** keyword-gated: a
read never writes anything, so a computed or unusual read name just fails closed at runtime
(`no_flag_token`, `false`). Because the keyword table is required, `neo check` needs the
repository's `evidence/` directory (the developer preview ships that one TSV for exactly this
reason); a missing table fails the check with the path it tried.

### Flag ids (resolved at first use)

A flag name is turned into the engine's **u16 flag id** by the engine's own flag-name table, on
the game's main thread, at the first `setStarFlag`/`hasStarFlag` call for that name:

| Step | Write (`setStarFlag`) | Read (`hasStarFlag`) |
|---|---|---|
| hash | `0x1C9E350` (seed 0) | same |
| probe the 0x40-stride bucket table at `0x326D110` | yes | yes |
| miss | insert with `0x1BCF030` (assigns the table's next id, appends the name to the reverse vector with `0x158300`) | **stop and return `false`** |

So the write may register a new name (exactly what the engine does when a script writes the same
literal), and the read never registers anything — one read cannot pollute the flag table. The
insert primitive and the counter owner were pinned offline (`evidence/analysis/flag_store_4_4_4.md`
§6): `0x1BCF030` increments the table's own size field, `0x158300` deep-copies the name, so the
caller's buffer only has to live for the call.

Why the token table is not used any more: `set_star_flag` keeps its key in a **u16** cell
(`[obj+0xC0]`), but the official script path resolves the name through the flag-name table. The
lexer token table (`0x1D13270` / `0x37347A0`) is a different object with a different numbering, so
a token id can never equal the id the engine's `has_star_flag` computes — that is exactly what the
two 2026-11-08 shots measured (write ok, own read-back true, official trigger 0 hits, nothing in
the save). The keyspace is what changed; the container (`scope → +0x5F8`, `+0x10` u16 array,
`+0x1C` count) and the write body (`0x180F8E0`) are unchanged.

16-bit ids are **the flag table's own numbering** (dense, assigned by its size field), not the
lexer pool, so there is no install-time mint any more: `C2NeoInstall` does not touch flags, and
the `NEO_JS_PREMINT` / `NEO_JS_PREMINT_FAIL` lines no longer exist in any build.

Failure codes:

| Line | Meaning |
|---|---|
| `NEO_JS_WRITE_REJECT … reason=no_flag_token kind=flag` | the flag table gave no id (module base unresolved, illegal name, counter `0`, or the `0xFFFF` sentinel). The flag is **not** written. |
| `NEO_JS_FLAG_REJECT … reason=no_flag_token` | the read name has no id in the flag table; the call returns `false` |
| `NEO_JS_FLAG_REJECT … reason=no_permission` | the session lacks `flag.read`; that session is disabled |

Boundaries:

- `0xFFFF` (and `0`, which the module also treats as unusable) is a **hard failure**, never a
  successful write: the official writer returns immediately on `id == 0xFFFF`;
- names are 1–15 bytes (the engine string object's inline capacity); longer names are rejected
  before the table is touched;
- a positive name→id cache in the host avoids re-hashing the same name every system/month; a
  *miss* is never cached (an official script may register the name later);
- `0x1D13270` is still the C1 keyword mint and is untouched — the flag path simply no longer uses
  it.

**No live reading for this design yet.** The write + official-trigger + save shot (Task C of the
plan) has not been run; until it is, the static reading in `flag_store_4_4_4.md` §6 is the only
evidence behind the resolution path.

## `neo pack`

`neo pack --dir <project> [--out <zip>]`

1. Runs `neo build` (so `neo/<entry>` exists) and `neo check`; a failing check aborts the pack
   with `NEO_PACK fail: pack: neo check failed: …` and writes no archive.
2. Stages `<project>/dist/<id>/` from a **whitelist**: `descriptor.mod`, `common/**`, `events/**`,
   `neo/mod.json`, `neo/<entry>`, and a `README.md` (the author's own README, if any, plus the
   known-limitation block).
3. Writes a store-only zip (fixed 1980-01-01 timestamps, entries sorted) — the same inputs
   produce the same bytes — to `--out` or `<project>/dist/<id>.zip`.
4. Reads the archive back and compares every entry with what it staged before reporting
   `NEO_PACK ok dir=<abs> out=<zip> entries=<n>`.

`node_modules/`, `dist/` and `.git/` are excluded by construction (they are never in the
whitelist), not by a filter that can silently miss one. The packaged README always carries the
"this is not a Workshop mod / inert without the injected host" limitation.

## Live acceptance (2026-11-07, 4.4.4)

Phase 1 C1 passed in one live shot (pid 3848, DLL sha256 `8c774e60b36c2969c6b792b34dffd19ac301e16cc7fbc41c581bca9ab4febe7f`):

- 27 monthly passes; `NEO_JS_CALL = 21,276 = 788 × 27`; the engine-side `Neo: system` lines are 21,276 as well.
- `NEO_JS_WRITE = 405 = 15 × 27` (`neo_score`); `NEO_JS_LOG = 405`; `NEO_JS_ERROR` / `NEO_JS_TIMEOUT` / `NEO_API_MISMATCH` = 0 / 0 / 0; host alive throughout.
- The 15 written ids are exactly the baked table's T2 set (`score >= 200`). The earlier plan estimate of 135 was wrong: the table has 15 T2, 70 T1 and 702 T0.
- Game time 2270.07.01 → 2272.10.1. `--act log` wrote no `neo_mark`; the JS `setVariable` wrote `neo_score`. The latest autosave is `autosave_2272.07.01.sav`.
- Boundaries: one example, one campaign, one runtime mod. Exception/timeout paths were not triggered (0 is "did not happen", not "fixed"). `betweenness` reads the baked table, not the live re-score. No uninstall after load.

Full reading: `evidence/logs/runtime_js_phase1_4_4_4.log`; issue #55. The example has since
gained the v1.1 `hasStarFlag`/`setStarFlag` demo (guarded, so the per-pass write cadence is
unchanged); the reading above is the Phase 1 bundle's and has **not** been re-taken.

### Phase 2 C2 (multi-mod safety + flags)

Two live shots (pid 25040 on `ce0fc76e…`, pid 25752 on `939d21f1…`), one campaign, four runtime
mods (1 good + `bad_throw` / `bad_timeout` / `bad_perm`), `--act log --rule 1:0`:

- **Isolation passed.** Each bad mod failed exactly once on its first dispatch and was disabled;
  the good mod kept running (4 and 5 monthly passes; `NEO_JS_CALL` 3,152 and 3,940 = 788 × n;
  `neo_score` writes 15/pass). Host alive in both, `taskkill` at the end.
- **Star flags failed live, and the reason is structural.** `setStarFlag("neo_hub")` is rejected
  with `reason=no_flag_token_range raw=68639`: the engine mints the name to token id **68,639**,
  while `set_star_flag` stores the flag key in a **u16** cell (`[obj+0xC0]`). New names in this
  install are minted past the 16-bit boundary (`[db+0x84]` = 18,817 static max + ≈49.8k dynamic
  names), so **no freshly minted name can be used as a flag key**. `hasStarFlag` fails on the
  same mint (`NEO_JS_FLAG_REJECT … reason=no_token raw=68639`).
- Which means the v1.1 flag APIs are **not usable as specified**; they are not merely unproven.
  Options (defer / truncate to u16 / restrict to pre-existing low ids) are recorded in
  `evidence/logs/runtime_js_phase2_safety_4_4_4.log` and left as an explicit decision, not
  silently picked.
- Reading: `evidence/logs/runtime_js_phase2_safety_4_4_4.log`; #59, #60.

**P2-1b response (2026-11-07): move the mint, not the id space** — a build-time `flags` list and
an install-time mint into the lexer token pool. The two P2-1b shots (2026-11-08) then showed the
mint working (`id=19345`, inside u16) while the flag was still invisible to the official trigger
and absent from the save: the id space itself was wrong.

**Flag keyspace fix (2026-11-08, static + host change).** The resolution now uses the engine's own
flag-name table (`0x326D110` / `0x326D118` / `0x1BCF030` / `0x158300` / `0x1C9E350`) instead of the
lexer token table, so the id the host writes is the id the official script computes. The
install-time premint was removed; `neo/mod.json`'s `flags` survives as a build-time collision gate
only. See [Flag ids (resolved at first use)](#flag-ids-resolved-at-first-use) and
`evidence/analysis/flag_store_4_4_4.md` §6. **No live reading of the fixed path yet** — Task C has
not run, so this remains an offline-pinned design.

## Limits (host-enforced)

- Context memory **16 MiB**, stack **1 MiB**.
- **10 ms** interrupt budget per handler invocation; exceeding it logs `NEO_JS_TIMEOUT` and
  disables the mod.
- A JS exception logs `NEO_JS_ERROR` and disables the mod. The game keeps running; the DLL is
  never unloaded (`FreeLibrary` is forbidden — patched engine objects would jump into a dead
  page).

## Known limitations (v1.1 non-goals)

- No `s.name` and no `s.variable()` read. They stay out of `api.def` until Track A's static spike
  resolves an official body/read path for each one; a deferred name is simply absent, never
  guessed.
- Star flags resolve through the engine's flag-name table at first use (see
  [Flag ids (resolved at first use)](#flag-ids-resolved-at-first-use)); the write may register a
  new name, the read never does. There is no install-time premint and no declared-name requirement
  at runtime. The earlier live failure (`raw=68639`) is addressed by construction, **not yet
  proven live** — the flag shot (Task C) has not run. Limits: names are 1–15 lowercase bytes, must
  be string literals, and may not collide with an official keyword (build-time gate); a
  `0xFFFF`/`0` id from the table is a hard failure (`no_flag_token`).
- No country / fleet / planet / pop scopes; system scope only.
- No `onMonthly` or any global tick hook. The monthly driver is a generated `on_action` + hidden
  `event` pair, i.e. the official script path.
- No `dlc_load.json` parsing and no inter-mod JS calls; the Phase 2 host loads up to 8 isolated
  sessions, not a module graph.
- `log` writes `C:/temp/neo_js.log`, not the official `game.log`.
- The SDK is TypeScript-source distributed only (see below).

## Distribution

Experimental, source-only. `@neo/runtime` is not published to npm in v1; clone the repository and
map the package with `paths` as shown above. Phase 1 live acceptance passed on 2026-11-07 (see
above); the distribution remains experimental and injection-based.

Phase 2 adds a **developer preview package** (SDK + templates + example + docs, zipped by
`neo pack`/the release job) for issue #39 testers — see
[docs/runtime-js-preview.md](runtime-js-preview.md). Publishing it is blocked on the C2 safety
shot; the preview is explicitly not a Workshop upload.

## Running the gate

```bash
just sdk-test     # cd sdk && npm ci && npm test
```

`sdk-test` type-checks the SDK, builds the example, runs `neo new` → `neo build` → `neo check` on
a generated project, and packs it twice to prove the artifact is byte-identical. CI runs the same
commands (`actions/setup-node` with Node 24) next to the Zig gate; the Zig gate
(`just check-full`) stays Node-free so a local run needs no npm registry, but it does run the
Python contract fence (`scripts/test_runtime_js_contract.py`) that pins `sdk/api.def` against
`src/dll/c2/neo_js_host.zig`.
