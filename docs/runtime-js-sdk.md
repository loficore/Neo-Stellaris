# Runtime JS SDK (v1 — system scope)

Authoring SDK for **runtime JS mods**: TypeScript compiled by `neo build`, evaluated by the
injected QuickJS host on the game's main thread, once per system.

> **Status.** The SDK side (this document, `sdk/`, `examples/`) is complete and covered by
> `npm test`. The end-to-end acceptance — the injected host loading a real bundle in a real
> campaign — is the Phase 1 C1 shot and is **blocked** pending the Track A host and a named
> live session. Nothing below claims a live reading.

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

# Build the bundled example to examples/chokepoint/neo/main.js
node dist/cli.js build --dir ../examples/chokepoint

# Type-check, bundle, and run it in a real QuickJS context with the mock host
node dist/cli.js check --dir ../examples/chokepoint
```

`npm link` (from `sdk/`) installs the `neo` command globally, after which the two commands are
`neo build --dir <project>` and `neo check --dir <project>`.

A passing check prints exactly one line and exits `0`:

```
NEO_CHECK ok dir=/abs/path/examples/chokepoint handler=1 calls=4
```

A failure prints `NEO_CHECK fail: <reason>` and exits `2`.

## Project layout

```
my-mod/
├── tsconfig.json        # maps @neo/runtime at the SDK source
├── src/main.ts          # the mod
└── neo/mod.json         # manifest (read by the loader)
```

`tsconfig.json` has to point `@neo/runtime` at the SDK's `src/runtime.ts`; v1 does not publish a
package to a registry, so there is no `node_modules` install step for the SDK itself:

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
    log(`NEO_HUB ${s.id} ${b}`);
  }
});
```

## API (v1, frozen)

| Export | Signature | Notes |
|---|---|---|
| `onSystem` | `(handler: (s: System) => void) => void` | Registers the per-system handler. Call it exactly once — the host keeps one handler. |
| `System.id` | `number` | The engine system id for this call. The only handle the SDK retains. |
| `System.degree` | `number` | Hyperlane degree, read on each access (not cached). |
| `System.setVariable` | `(name: string, value: number) => void` | Writes through the official `set_variable` body for the current system. |
| `graph.betweenness` | `(s: System) => number` | Graph score for the system (same source as the C5-SCORE path). |
| `graph.isChokepoint` | `(s: System) => boolean` | `betweenness(s) >= 200` — the T2 threshold; a constant, not a tuning knob in v1. |
| `log` | `(message: string) => void` | Appends `NEO_JS_LOG <text>` to `C:/temp/neo_js.log`. |
| `apiVersion` | `() => number` | Returns the host's contract version; v1 is `1`. |

### Native contract

The SDK is a shim over seven globals installed by the host. `sdk/api.def` is the single source of
truth (`version: 1`); the TypeScript surface, the mock host, and the Zig host must all match it.

| Native | Params | Returns |
|---|---|---|
| `__neo_register_system` | `function` | `void` |
| `__neo_system_degree` | `u32` | `u32` |
| `__neo_system_set_var` | `u32`, `string`, `f64` | `void` |
| `__neo_graph_betweenness` | `u32` | `u32` |
| `__neo_graph_is_chokepoint` | `u32` | `bool` |
| `__neo_log` | `string` | `void` |
| `__neo_api_version` | — | `u32` |

## Manifest

`neo/mod.json` — the loader reads a fixed location, `C:/temp/neo_mods/<id>/neo/{mod.json,main.js}`:

```json
{
  "id": "chokepoint",
  "entry": "main.js",
  "scope": ["system"],
  "permissions": ["graph.read", "variable.write", "log"],
  "engine": "4.4.4",
  "runtime": ">=0.1"
}
```

- `id` — directory name and log tag. Required.
- `entry` — the bundle filename the loader evaluates. Required.
- `scope` — v1 accepts `["system"]` only. Required.
- `permissions` — any of `graph.read`, `variable.write`, `log`. A native whose permission is
  absent is refused by the host, and an unknown permission disables the mod at load.
- `engine` / `runtime` — compatibility strings; a mismatch disables the mod with a log line.

Exactly one runtime mod is supported in v1. Zero mods, more than one, a bad manifest, a missing
`main.js`, or an API-version mismatch all log a reason and leave the game running without JS.

## `neo build` and `neo check`

`neo build --dir <project> [--outfile <file>]`

1. `tsc --noEmit -p <project>` — type errors, including a missing export from `@neo/runtime`,
   fail the build.
2. esbuild bundles `src/main.ts` as `--bundle --format=iife --platform=neutral --target=es2020`.
   The output has no `import`, no `require`, and no module loader dependency.
3. Writes `<project>/neo/<manifest entry>` (default `neo/main.js`).

`neo check --dir <project>` performs the same type-check and bundle in memory, then:

1. statically rejects `require(`, `process.`, `window.`, `document.`, and dynamic `import(`
   (none of those exist in the host context);
2. evaluates the bundle in a **real QuickJS runtime** (`quickjs-emscripten`, the same engine
   family the host embeds) with the mock host installed;
3. asserts that exactly one `onSystem` handler registered, that the handler runs for a fake
   system id `7` without throwing, and that `__neo_api_version()` matches `api.def`.

The mock host (`sdk/src/mock-host.ts`) records every native call; a passing example check reports
`calls=4` (`betweenness`, `set_var`, `log`, `api_version`). `neo check` is the last gate before a
bundle is shippable, but it cannot prove engine behaviour — that is the live acceptance shot.

## Limits (host-enforced)

- Context memory **16 MiB**, stack **1 MiB**.
- **10 ms** interrupt budget per handler invocation; exceeding it logs `NEO_JS_TIMEOUT` and
  disables the mod.
- A JS exception logs `NEO_JS_ERROR` and disables the mod. The game keeps running; the DLL is
  never unloaded (`FreeLibrary` is forbidden — patched engine objects would jump into a dead
  page).

## Known limitations (v1 non-goals)

- No `s.name`, `s.neighbors`, `s.variable()` reads, or star flags.
- No country / fleet / planet / pop scopes; system scope only.
- No `onMonthly` or any global tick hook.
- One runtime mod, no multi-mod composition, no `dlc_load.json` parsing.
- `log` writes `C:/temp/neo_js.log`, not the official `game.log`.
- The SDK is TypeScript-source distributed only (see below).

## Distribution

Experimental, source-only. `@neo/runtime` is not published to npm in v1; clone the repository and
map the package with `paths` as shown above. Treat everything here as unstable until the Phase 1
live acceptance produces a reading.

## Running the gate

```bash
just sdk-test     # cd sdk && npm ci && npm test
```

CI runs the same two commands (`actions/setup-node` with Node 24) next to the Zig gate; the Zig
gate (`just check-full`) stays Node-free so a local run needs no npm registry.
