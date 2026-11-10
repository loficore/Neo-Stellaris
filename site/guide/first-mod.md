# Your first mod

This walks a new runtime JS mod from an empty directory to a zip you can install.
It assumes you have unpacked the developer preview package (or cloned the
repository) and that you are authoring on a machine with **Node.js 24**.

The SDK lives in `sdk/` in both cases; every command below is run from the
package root unless it says otherwise.

## 1. Install the SDK's own dependencies

```bash
cd sdk
npm ci        # exact versions from sdk/package-lock.json
```

The SDK is not published to a registry, so this is the only install step. It
pulls the TypeScript compiler and the QuickJS build that `neo check` runs your
bundle in.

If you want the short command name, `npm link` from `sdk/` installs `neo`
globally. Without it, replace `neo` with `node dist/cli.js` everywhere below.

## 2. Scaffold

```bash
neo new ../my-mod --id my_mod --name "My Mod"
# NEO_NEW ok dir=/abs/path/my-mod id=my_mod files=7
```

`neo new` refuses a non-empty target directory, an id outside
`[a-z0-9][a-z0-9_]{0,63}` (the id is a manifest id, a loader directory name
*and* a Clausewitz event namespace at once), and a display name containing a
quote or control character.

The generated tree is exactly the template in `sdk/templates/neo-mod/`:

```
my-mod/
├── src/main.ts          # your mod — the only file you usually edit
├── neo/mod.json         # manifest (read by the loader)
├── neo/main.js          # build output, not committed
├── tsconfig.json        # maps @neo/runtime at the SDK source
├── descriptor.mod       # launcher metadata
├── common/on_actions/   # monthly driver
├── events/              # hidden event: random_system { every_system { neo_action = { } } }
└── README.md
```

The acceptance promise is that this tree passes `neo build` and `neo check`
with no hand edits.

## 3. Write the handler

`src/main.ts` is bundled into the game — it can only use `@neo/runtime` and
plain JavaScript built-ins (no `process`, `window`, `document`, `require` or
dynamic `import`; `neo check` rejects those statically).

```ts
import { log, onSystem } from "@neo/runtime";

// Runs once per system, once per monthly pulse. Keep it cheap.
onSystem((s) => {
  if (s.degree >= 4) {
    s.setVariable("neo_hub", s.degree);
    log(`NEO_HUB ${s.id} degree=${s.degree}`);
  }
});
```

Rules that will bite if you skip them:

- **`onSystem` is called exactly once.** The host keeps one handler per session;
  a second `onSystem(...)` call replaces nothing and is a bug in your mod.
- **`s.id` is the only handle you keep.** Objects are per-invocation; caching a
  `System` across calls is not supported.
- **Flag names are string literals**, 1–15 lowercase bytes, and may not collide
  case-insensitively with an official keyword. `neo check` enforces both.
- **Writes go through official engine bodies.** `s.setVariable` is
  `set_variable`; `s.setStarFlag` is `set_star_flag`. Your script reads them
  back with the official triggers — that is the whole integration model.

The full member list is the [SDK reference](/reference/sdk).

## 4. Build and check

```bash
neo build --dir ../my-mod
# NEO_BUILD ok dir=/abs/path/my-mod out=/abs/path/my-mod/neo/main.js

neo check --dir ../my-mod
# NEO_CHECK ok dir=/abs/path/my-mod handler=1 calls=6
```

`build` type-checks with `tsc`, bundles with esbuild into one IIFE (no module
loader in the host), writes `neo/<entry>`, and records the bundle's
`setStarFlag("…")` literals into the manifest's `flags` field.

`check` type-checks and bundles in memory, then runs the bundle in a **real
QuickJS runtime** against a mock host, and asserts that exactly one `onSystem`
handler registered, that it survives a fake system id `7`, and that
`__neo_api_version()` matches `sdk/api.def`. A failure prints
`NEO_CHECK fail: <reason>` and exits `2`.

`calls=` counts native calls the mock host saw. It is a shape check, not a
budget: `calls=6` means your handler exercised six natives on the fake system,
and a different number is fine.

**`neo check` cannot prove engine behaviour.** It proves the bundle
type-checks, avoids host-less globals, registers one handler, passes the
flag-name gate, and speaks the frozen native contract. Whether the game calls it
is the live question, and it is answered by the log lines below.

## 5. Package and install

```bash
neo pack --dir ../my-mod --out ../my_mod.zip
# NEO_PACK ok dir=/abs/path/my-mod out=/abs/path/my_mod.zip entries=9
```

`pack` runs `build` and `check` first, stages a whitelist
(`descriptor.mod`, `common/**`, `events/**`, `neo/mod.json`, `neo/<entry>`,
`README.md`), and writes a deterministic zip: fixed timestamps, sorted entries,
same inputs → same bytes. A failing check aborts the pack and writes no archive.

Install the result with `neo.bat` / `neo_install.py`, or by hand — see
[Install](/guide/install).

## 6. What "it worked" looks like

The driver is a pair of generated script files, and it is worth reading them
before you blame the JavaScript:

```text
# common/on_actions/my_mod_on_actions.txt
on_monthly_pulse = {
	events = { my_mod.1 }
}
```

```text
# events/my_mod_events.txt
namespace = my_mod

event = {
	id = my_mod.1
	hide_window = yes
	is_triggered_only = yes

	immediate = {
		random_system = {
			every_system = {
				neo_action = { }
			}
		}
	}
}
```

Two details are load-bearing:

- **`every_system` must be entered from a system scope.** From a no-scope event
  body it iterates once; wrapped in `random_system` it iterates over every
  system (788 in a default galaxy).
- **`neo_action` takes an empty block.** `neo_action = yes` is a parse error:
  the registered effect parses an assignment block.

With the host injected, one monthly pulse gives you, in `C:/temp/neo_js.log`:

```
NEO_JS_CALL ...
NEO_JS_LOG NEO_HUB 82 degree=5
NEO_JS_WRITE ... kind=variable name=neo_hub
```

Without the injection the same pulse logs `neo_action` as an unknown effect in
`error.log` — the script half is fine, the host is missing.

A zero count is "did not happen", not "fixed": `NEO_JS_ERROR = 0` means no
handler threw, not that the error path works.

## 7. Iterate

Edit `src/main.ts`, re-run `neo build` (or `pack`), and reinstall the `neo/`
half. The bundle in `neo/main.js` is generated: `neo check` does **not** compare
the committed bundle with the source, so a stale bundle passes every gate and
behaves like the edit you forgot.

There is no hot reload. Mod files are read at game start; the runtime half is
read by the host when it loads. A changed bundle needs a restart.

## Troubleshooting

| Symptom | Look at |
|---|---|
| `NEO_CHECK fail: …` | the message names the rule: a banned global, a stale `flags` list, a computed flag name, or a missing `@neo/runtime` export |
| `neo_action` logged as an unknown effect in `error.log` | the DLL is not injected — expected for a runtime mod without the host |
| the host loaded, no `NEO_JS_CALL` at all | the `on_actions` → event → `every_system` chain did not fire; check the playset entry and that the event id matches the namespace |
| `NEO_JS_FLAG_REJECT … reason=no_flag_token` | the name has no id in the engine's flag table; see [Known limits](/guide/known-limits) — flag reads are not proven live |
| the whole game process disappears | the DLL is a Debug build and a safety check aborted it; read [Known limits](/guide/known-limits) before re-running |
