# SDK reference

The runtime JS SDK is the authoring surface for **runtime JS mods**: TypeScript
that `neo build` compiles into a single bundle, which the injected QuickJS host
evaluates on the game's main thread — once per system and once per country.

The frozen contract is
[`sdk/api.def`](https://github.com/loficore/Neo-Stellaris/blob/main/sdk/api.def)
(`version: 1`). The TypeScript surface here, the mock host used by `neo check`,
and the Zig host that ships in the DLL all have to match it; this page describes
that contract, not a design proposal.

The contract is additive and versioned: `API_VERSION` stays `1`, and members are
only ever appended. `s.name` and `s.variable()` are **absent on purpose** — see
[Absent by design](#absent-by-design).

## Prerequisites

- Node.js **24** for authoring (`sdk/package.json` declares `engines.node >= 24`).
- The SDK source: either the repository clone or the `sdk/` directory from the
  developer preview zip. Neither publishes to a registry in v1.
- For actually running a mod: Stellaris 4.4.4 on Windows x86_64 plus the injected
  DLL — see [Install](/guide/install).

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

`neo new` writes exactly the template in
[`sdk/templates/neo-mod/`](https://github.com/loficore/Neo-Stellaris/tree/main/sdk/templates/neo-mod);
the acceptance promise is that the generated tree passes `neo build` and
`neo check` with no hand edits.

`tsconfig.json` has to point `@neo/runtime` at the SDK's `src/runtime.ts`; there
is no registry install for the SDK itself. `neo new` resolves that path relative
to the generated directory:

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

The example
([`examples/chokepoint`](https://github.com/loficore/Neo-Stellaris/tree/main/examples/chokepoint))
is a complete, buildable project:

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

## API

| Export | Signature | Notes |
|---|---|---|
| `onSystem` | `(handler: (s: System) => void) => void` | Registers the per-system handler. Call it exactly once — the host keeps one handler per session. |
| `System.id` | `number` | The engine system id for this call. The only handle the SDK retains. |
| `System.degree` | `number` | Hyperlane degree, read on each access (not cached). |
| `System.neighbors` | `readonly number[]` | Neighbour system ids, read on each access; the host returns a fresh array, capped at 64 with a truncation log line. Needs `graph.read`. |
| `System.setVariable` | `(name: string, value: number) => void` | Writes through the official `set_variable` body for the current system. |
| `System.setStarFlag` | `(name: string) => void` | Sets the official star flag `name` through the `set_star_flag` body. Needs `flag.write`. The name is resolved to a `u16` id by the engine's flag-name table; a name the table has never seen is inserted at first use (what the engine does when a script writes the same literal). The name must be a **string literal** of 1–15 lowercase bytes and must not collide with an official keyword. Failure to get an id is `no_flag_token`. |
| `System.hasStarFlag` | `(name: string) => boolean` | Reads the official star flag `name` from the flag container. Needs `flag.read`. **Read-only:** the name is resolved with a lookup that never inserts — a name with no id reads `false` and logs `reason=no_flag_token`. A name that has an id but is absent from the container (or whose container cannot be read) also reads `false` (fail-closed). Same literal rules as the write. |
| `onCountry` | `(handler: (c: Country) => void) => void` | Registers the per-country handler. Needs `"country"` in the manifest's `scope`; a system-only bundle that calls it logs `NEO_JS_REGISTER_REJECT … scope=country` and stays inert (the session is **not** disabled). |
| `Country.id` | `number` | The engine country id for this call: the **low 24 bits** of the dispatched scope's `+0x10` (the high 8 bits are an engine type tag — C3 read `0x01000002 → 2`). The only handle the SDK retains. |
| `Country.opinionOf` | `(targetId: number) => number \| null` | Engine `opinion` keyword: one `int32` cell of the matrix, key `target * n + self` (both ids are masked to their low 24 bits — `SCOPE_ID_MASK` in `offsets.country`; the host masks them itself, the engine does not; pass `Country.id` as-is). **`null` = fail-closed**, never `0`: not computed (engine sentinel `0x7fffffff`), either id out of range, matrix not built (main menu / no campaign), session without `opinion.read`, or the id not matching the dispatched country. Every refusal also logs `NEO_JS_OPINION_REJECT … reason=<tag>`. **Read-only:** the cell is a lazily filled engine cache and the host never calls its calculator. |
| `Country.theirOpinionOf` | `(targetId: number) => number \| null` | Engine `their_opinion` keyword — the **transpose** of `opinionOf` (`self * n + target`). Same fail-closed rules. Which of the two means "our opinion of them" is **not** established; see [Known limits](/guide/known-limits). |
| `graph.betweenness` | `(s: System) => number` | Graph score for the system (the same source as the chokepoint score path). |
| `graph.isChokepoint` | `(s: System) => boolean` | `betweenness(s) >= 200` — a constant threshold, not a tuning knob in v1. |
| `log` | `(message: string) => void` | Appends `NEO_JS_LOG <text>` to `C:/temp/neo_js.log`. |
| `apiVersion` | `() => number` | Returns the host's contract version; v1.x is `1`. |

## Native contract

The SDK is a shim over thirteen globals installed by the host. `sdk/api.def` is
the single source of truth; the TypeScript surface, the mock host and the Zig
host must all match it. The seven v1 names come first, unchanged; the v1.1
additions are appended after them in the host's own order.

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
| `__neo_register_country` | `function` | `void` |
| `__neo_country_opinion` | `u32`, `u32` | `i32 \| null` (`undefined` = refused) |
| `__neo_country_their_opinion` | `u32`, `u32` | `i32 \| null` (`undefined` = refused) |

The `u32` in the first column of the system natives is the **system id**; the
country pair takes `(self, target)`. "Refused" is the host's fail-closed answer
and is deliberately distinct from a computed `0`.

## Manifest

`neo/mod.json` — the loader reads a fixed location,
`C:/temp/neo_mods/<id>/neo/{mod.json,main.js}`:

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
- `scope` — `"system"`, `"country"`, or `["system","country"]` (the string forms
  and the 1–2-element array forms are both accepted; each name at most once). A
  bundle only receives the scopes it declares. Required.
- `permissions` — any of `graph.read`, `variable.write`, `variable.read`,
  `flag.read`, `flag.write`, `log`, `opinion.read`. A native whose permission is
  absent is refused by the host, and an unknown permission disables the mod at
  load. `degree`, `neighbors`, `betweenness` and `isChokepoint` are `graph.read`;
  `setStarFlag` is `flag.write`; `hasStarFlag` is `flag.read`;
  `opinionOf` / `theirOpinionOf` are `opinion.read`.
- `engine` / `runtime` — compatibility strings; a mismatch disables the mod with
  a log line.
- `flags` — **optional** (an old manifest without it still loads). A
  **build-time collision gate**, not a runtime authority: `neo build` records the
  bundle's `setStarFlag("…")` literals here and `neo check` refuses a list that
  no longer matches, so an author cannot ship a write against an official
  keyword unnoticed. **The host no longer reads this field** — at runtime the name
  is resolved by the engine's flag-name table on first use. At most **32** names;
  each name is 1–15 bytes, all lowercase, does not start with `-` or a digit.
  Missing `flags` behaves like `[]`.

The host loads up to **8** mods from `C:/temp/neo_mods/<id>/`, one QuickJS
context/session each: a throwing, spinning or over-reaching mod disables only its
own session and the others keep receiving `onSystem`. Zero mods logs
`NEO_JS_NO_MOD`.

## `neo new`

`neo new <dir> --id <id> [--name <name>]` copies `sdk/templates/neo-mod/`
(substituting the id, the display name, and the relative `@neo/runtime` path) and
prints `NEO_NEW ok dir=<abs> id=<id> files=<n>`.

It refuses a non-empty target, an id outside `[a-z0-9][a-z0-9_]{0,63}` (the id is
a manifest id, a loader directory name *and* a Clausewitz event namespace), and a
display name containing a quote or control character. The generated tree is
exactly the template: `src/main.ts`, `neo/mod.json`, `tsconfig.json`,
`descriptor.mod`, `common/on_actions/<id>_on_actions.txt`,
`events/<id>_events.txt`, `README.md`. The generated manifest declares
`["graph.read", "flag.read", "flag.write", "log"]` and its `onSystem` example
demonstrates the flag read/write pair.

## `neo build` and `neo check`

`neo build --dir <project> [--outfile <file>]`

1. `tsc --noEmit -p <project>` — type errors, including a missing export from
   `@neo/runtime`, fail the build.
2. esbuild bundles `src/main.ts` as `--bundle --format=iife --platform=neutral
   --target=es2020`. The output has no `import`, no `require`, and no module
   loader dependency.
3. Writes `<project>/neo/<manifest entry>` (default `neo/main.js`).
4. Records the bundle's `setStarFlag("…")` literals in `<project>/neo/mod.json`'s
   `flags` (deduped, sorted; every other manifest field is preserved). A project
   without a manifest is not given one — the build prints
   `NEO_BUILD warn: no neo/mod.json, flags not recorded` on stderr and the flag
   calls will fail closed at runtime. `neo build` does **not** consult the keyword
   table (that is `neo check`'s gate); it only records names.

`neo check --dir <project>` performs the same type-check and bundle in memory,
then:

1. statically rejects `require(`, `process.`, `window.`, `document.`, and dynamic
   `import(` (none of those exist in the host context);
2. runs the **flag-name gate** over the bundle (see below);
3. refuses a manifest whose `flags` list no longer matches the bundle's literals:
   `flags: manifest flags are stale; run "neo build" (bundle has ["neo_hub"], manifest has [])`.
   A missing `flags` field counts as `[]`;
4. evaluates the bundle in a **real QuickJS runtime** (`quickjs-emscripten`, the
   same engine family the host embeds) with the mock host installed;
5. asserts that exactly one `onSystem` handler registered, that the handler runs
   for a fake system id `7` without throwing, and that `__neo_api_version()`
   matches `api.def`.

A passing check prints exactly one line and exits `0`:

```
NEO_CHECK ok dir=/abs/path/examples/chokepoint handler=1 calls=6
```

A failure prints `NEO_CHECK fail: <reason>` and exits `2`.

The mock host (`sdk/src/mock-host.ts`) records every native call; `calls=` is
that count for the fake system, `handler=` is the number of registered handlers.
Both are shape checks — a different `calls` number is fine, `handler=1` is not.

### Flag-name gate (build time)

`s.setStarFlag(name)` is checked before the bundle runs, because a flag name that
matches an official keyword would address engine behaviour instead of a flag (the
same hazard as the old `Add_Modifier` collision, one layer down). Two rules:

- **string literal only** — v1 has no build-time answer for a computed name, so
  `s.setStarFlag(someVariable)` fails with a message that says literals are
  required;
- **no official-keyword collision** — each literal is compared
  case-insensitively against the `keywords` column of
  [`evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`](https://github.com/loficore/Neo-Stellaris/blob/main/evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv);
  a hit fails the check.

The gate reads the author's `setStarFlag("…")` call site, not the native
`__neo_system_set_flag(id, name)` call: the SDK shim always forwards its own
parameter, so the native call is dynamic in every bundle. `hasStarFlag("…")`
literals are **not** keyword-gated: a read never writes anything, so a computed or
unusual read name just fails closed at runtime (`no_flag_token`, `false`).

Because the keyword table is required, `neo check` needs the repository's
`evidence/` directory (the preview package ships that one TSV for exactly this
reason); a missing table fails the check with the path it tried.

### Flag ids (resolved at first use)

A flag name is turned into the engine's **`u16` flag id** by the engine's own
flag-name table, on the game's main thread, at the first `setStarFlag` /
`hasStarFlag` call for that name:

| Step | Write (`setStarFlag`) | Read (`hasStarFlag`) |
|---|---|---|
| hash the name | yes | yes |
| probe the flag-name table's bucket array | yes | yes |
| miss | insert and assign the table's next id | **stop and return `false`** |

So the write may register a new name (exactly what the engine does when a script
writes the same literal), and the read never registers anything — one read cannot
pollute the flag table.

Why not the lexer token table: `set_star_flag` keeps its key in a `u16` cell, but
the official script path resolves the name through the **flag-name table**. The
lexer token table is a different object with a different (and much wider)
numbering, so a token id can never equal the id the engine's `has_star_flag`
computes. The keyspace is what changed; the container and the write body are
unchanged.

16-bit ids are the flag table's own numbering (dense, assigned by its size
field), not the lexer pool, so there is no install-time mint: the host does not
touch flags at install, and the `NEO_JS_PREMINT*` lines no longer exist in any
build.

Failure codes:

| Line | Meaning |
|---|---|
| `NEO_JS_WRITE_REJECT … reason=no_flag_token kind=flag` | the flag table gave no id (module base unresolved, illegal name, counter `0`, or the `0xFFFF` sentinel). The flag is **not** written. |
| `NEO_JS_FLAG_REJECT … reason=no_flag_token` | the read name has no id in the flag table; the call returns `false` |
| `NEO_JS_FLAG_REJECT … reason=no_permission` | the session lacks `flag.read`; that session is disabled |

Boundaries:

- `0xFFFF` (and `0`, which the module also treats as unusable) is a **hard
  failure**, never a successful write: the official writer returns immediately on
  `id == 0xFFFF`;
- names are 1–15 bytes (the engine string object's inline capacity); longer names
  are rejected before the table is touched;
- a positive name→id cache in the host avoids re-hashing the same name every
  system/month; a *miss* is never cached (an official script may register the
  name later).

**This resolution path has no live reading yet.** The static derivation is in
[`evidence/analysis/flag_store_4_4_4.md`](https://github.com/loficore/Neo-Stellaris/blob/main/evidence/analysis/flag_store_4_4_4.md)
§6; treat the two flag calls as unproven, as described in
[Known limits](/guide/known-limits).

## `neo pack`

`neo pack --dir <project> [--out <zip>]`

1. Runs `neo build` (so `neo/<entry>` exists) and `neo check`; a failing check
   aborts the pack with `NEO_PACK fail: pack: neo check failed: …` and writes no
   archive.
2. Stages `<project>/dist/<id>/` from a **whitelist**: `descriptor.mod`,
   `common/**`, `events/**`, `neo/mod.json`, `neo/<entry>`, and a `README.md`
   (the author's own README, if any, plus the known-limitation block).
3. Writes a store-only zip (fixed 1980-01-01 timestamps, entries sorted) — the
   same inputs produce the same bytes — to `--out` or `<project>/dist/<id>.zip`.
4. Reads the archive back and compares every entry with what it staged before
   reporting `NEO_PACK ok dir=<abs> out=<zip> entries=<n>`.

`node_modules/`, `dist/` and `.git/` are excluded by construction (they are never
in the whitelist), not by a filter that can silently miss one. The packaged
README always carries the "this is not a Workshop mod / inert without the injected
host" limitation.

## Absent by design

- **No `s.name`, no `s.variable()`.** They stay out of `api.def` until an official
  body/read path is resolved for each one; a deferred name is simply absent,
  never guessed.
- **No fleet, planet or pop scopes.** A dispatch with any other scope is logged
  and dropped: `NEO_SCOPE_OTHER mask=0x<mm> id=<n>` (read-only).
- **No `onMonthly` and no global tick hook.** The monthly driver is a generated
  `on_action` + hidden `event` pair — the official script path.
- **No `dlc_load.json` parsing and no inter-mod JS calls.** The host loads up to 8
  isolated sessions, not a module graph.
- **`log` writes `C:/temp/neo_js.log`**, not the official `game.log`.
- **The SDK is distributed as TypeScript source**, not as a registry package.

## Host-enforced limits

| Limit | Value |
|---|---|
| Context memory | 16 MiB |
| Stack | 1 MiB |
| Interrupt budget per handler invocation | 10 ms → `NEO_JS_TIMEOUT`, session disabled |
| JavaScript exception | `NEO_JS_ERROR`, session disabled |

The game keeps running when a session is disabled; the DLL is never unloaded
(`FreeLibrary` is forbidden — patched engine objects would jump into a dead page).
The full list, including the Debug-build consequence, is on
[Known limits](/guide/known-limits).

## Distribution

Experimental, source-only. `@neo/runtime` is not published to npm in v1: clone the
repository (or unpack the developer preview package) and map the package with
`paths` as shown above.

The preview package is assembled by `scripts/pack_preview.py` from an explicit
manifest (DLL, injector, SDK, examples, licences) and ships a `SHA256SUMS`
covering both binaries and the zip itself.
