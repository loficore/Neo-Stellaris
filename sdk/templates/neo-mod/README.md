# {{NAME}}

A runtime JavaScript mod for **Stellaris 4.4.4**, authored with the Neo-Stellaris
runtime JS SDK.  `id` = `{{ID}}`.

This is **not** a Workshop mod: the TypeScript in `src/main.ts` is bundled to
`neo/main.js`, and that bundle only runs when the injected QuickJS host loads it
(`C:/temp/neo_mods/{{ID}}/neo/`).  Without the injection the files are inert.

## Layout

```
src/main.ts        the mod (onSystem handler)
neo/mod.json       manifest: id / entry / scope / permissions / engine / runtime
neo/main.js        build output (generated)
descriptor.mod     launcher metadata
common/on_actions/ monthly driver
events/            hidden event that runs every_system
```

## Build, check, pack

```bash
neo build --dir .     # tsc --noEmit, then bundle src/main.ts -> neo/main.js
neo check --dir .     # run the bundle in a real QuickJS with the mock host
neo pack --dir . --out {{ID}}.zip
```

`neo check` is the last offline gate: it proves the bundle type-checks, avoids
Node/browser globals, registers exactly one `onSystem` handler, and speaks the
frozen native contract.  It cannot prove engine behaviour — only a live game can.

## Limits

- `s.id`, `s.degree`, `s.neighbors`, `s.setVariable`, `s.setStarFlag`,
  `s.hasStarFlag`, `graph.*`, `log`.
- Flag names must be **string literals** and must not collide with an official
  keyword; `neo check` enforces both at build time.
- A handler runs with a 10 ms interrupt budget; one exception or timeout
  disables this mod only.
- Permissions are declared in `neo/mod.json`; an undeclared capability is
  refused by the host instead of silently ignored.
