# Known limits

Read this before you install anything. Everything below is a real boundary of
the preview, not a roadmap item — the API surface is frozen at what
[`sdk/api.def`](https://github.com/loficore/Neo-Stellaris/blob/main/sdk/api.def)
declares, and the parts that have no live reading yet are marked as such
instead of being promised.

## The DLL is a Debug build

The shipped `stellaris_quickjs.dll` is compiled with the compiler's own Debug
mode, because every live reading this project has taken was taken against
exactly those bytes. Switch to a release build and "the bytes we shipped" stops
being "the bytes we verified", which would cost another round of real-machine
gates for no user-visible gain.

The consequence is the important part: **a failed internal safety check aborts
the game process.** The host's own invariants (a type check, an allocator
assertion, a bounds check) are compiled *into* the code that runs inside
`stellaris.exe`, so a trip is an `abort()` — the whole game goes down with it,
not just your mod. A mod that throws a JavaScript exception is fine; the host
disables that one session and the game keeps running. A host that trips a safety
check is not.

Two more things follow from the same shape: the DLL is **injection-only** and is
never unloaded, because patched engine objects would jump into an unmapped page
after a `FreeLibrary`. Do not try to unload it.

## Star flags have no live reading yet

`System.setStarFlag` and `System.hasStarFlag` are in the contract, and the
build-time gate around them is real: `neo check` refuses a computed flag name
and refuses a name that collides case-insensitively with an official keyword.

What is **not** proven is the runtime behaviour. The flag key space was
re-derived statically after two live shots showed the write succeeding while
the official `has_star_flag` trigger matched nothing and the save contained
nothing. The host now resolves names through the engine's own flag-name table
(a `u16` id) instead of the lexer token table (a `u32` id) — the two numbers
could never match, which is exactly what the shots measured.

So, today:

- a write **may** register a new name (that is what the engine does when a
  script writes the same literal), and a read **never** registers anything;
- a name with no id in the flag table reads `false` and logs
  `reason=no_flag_token`; `0xFFFF` and `0` are hard failures, never a
  successful write;
- names are 1–15 lowercase bytes and must be string literals.

Treat the two flag calls as unproven: a mod that depends on them can pass every
offline gate and still not observe the flag in the official script path.

## Country scope is read-only, and its direction is only half known

`onCountry` and `Country.opinionOf` / `Country.theirOpinionOf` read one `int32`
cell of the engine's opinion matrix. There is **no writer**: the cell is a
lazily filled cache and filling it would be a write into engine state, so
`Country` has no setter.

Two boundaries on the read side:

1. `opinionOf` and `theirOpinionOf` read **transposed** cells of one matrix —
   that much is solid — but *which* of them means "our opinion of them" is not
   established. The names are the engine's keywords, not a claim about
   direction. Read the diagonal if you need a value that does not depend on the
   answer.
2. The value's unit and scale have no independent reference: the number is the
   engine's own `int32`, unscaled.

The **id convention** has been measured: the C3 reconnaissance recorded 39
countries, and the low 24 bits of `scope+0x10` ran `0..39` with 23 missing — so
the host now applies `SCOPE_ID_MASK` before handing `Country.id` to the bundle.
The opinion **values** themselves still have no live reading in either
direction.

Everything else country-side — resource stockpiles, income containers, the
energy index — is not in the contract.

## No hot reload, no Workshop, no build-time script generation

- **No hot reload.** Mod files are read at game start; the runtime half is read
  when the host loads. A changed bundle needs a restart. (The only development
  loop that exists is: edit → `neo build` → reinstall → restart.)
- **Not a Workshop mod.** There is nothing to subscribe to. The `descriptor.mod`
  half makes the engine load your files; the `neo/` half makes the host read
  your bundle. Both are yours to distribute.
- **No build-time TypeScript → `.txt`.** The bundle is JavaScript evaluated by
  the host, not Clausewitz script text. Converting one into the other is a
  different product decision, not a missing feature.

## The scopes that do not exist

Only two scopes are dispatched: **system** and **country**. A dispatch that
arrives with any other scope is logged and dropped:

```
NEO_SCOPE_OTHER mask=0x<mm> id=<n>
```

So there are no fleet, planet or pop scopes. There is also **no `onMonthly`
hook** and no global tick hook: the monthly driver is the generated
`on_action` → hidden event → `every_system` / `every_country` chain, i.e. the
ordinary official script path.

A bundle only receives the scopes it declares in the manifest. A system-only
bundle that calls `onCountry` logs `NEO_JS_REGISTER_REJECT … scope=country` and
stays inert — the session is not disabled.

## The surface that is deliberately absent

`s.name` and `s.variable()` are **not** in the contract. They are deferred until
an official read path is resolved for each one; a guessed native name would be
worse than a missing one, so `api.def` does not mention them and the SDK does
not expose them.

## Host-enforced limits

| Limit | Value | What happens at the limit |
|---|---|---|
| Context memory | 16 MiB | allocation failure inside the handler |
| Stack | 1 MiB | same |
| Time per handler invocation | 10 ms | `NEO_JS_TIMEOUT` is logged and **the mod is disabled** |
| JavaScript exception | — | `NEO_JS_ERROR` is logged and **the mod is disabled** |
| Concurrent runtime mods | 8 | more than 8 are refused with a log line; zero mods logs `NEO_JS_NO_MOD` |

Disabling means *that session only*: the other sessions keep receiving their
dispatch. A mod that throws every time is disabled after its first failure, so
the game keeps running.

## Logging

`log(...)` appends `NEO_JS_LOG <text>` to `C:/temp/neo_js.log` — **not** to the
official `game.log`. The official log is written by the official script half
(the `log` effect inside an event option).

Useful lines:

| Line | Meaning |
|---|---|
| `NEO_JS_CALL` | the handler ran for one scope |
| `NEO_JS_WRITE … kind=variable` | a variable write went through the official body |
| `NEO_JS_ERROR` | the handler threw; the session was disabled |
| `NEO_JS_TIMEOUT` | the handler exceeded 10 ms; the session was disabled |
| `NEO_JS_OPINION_REJECT … reason=<tag>` | a country opinion read was refused |
| `NEO_JS_FLAG_REJECT … reason=no_flag_token` | a flag name had no id in the flag table |

## What the offline gates do and do not prove

`neo check` runs your bundle in a real QuickJS runtime against a mock host. It
proves: the bundle type-checks, contains no host-less globals, registers
exactly one handler, passes the flag-name gate, and calls natives with the
shapes `api.def` declares.

It does not prove: that the engine calls your handler, that the values you read
are the ones you expect, that your writes are visible to the official script
path, or that anything works in a campaign at all. Those questions are answered
by the live log lines, not by a green check.

The same split applies to the whole preview: the gates are offline and
mechanical, and the live behaviour is only as good as the last real reading.
Where a reading is missing, this page says so instead of promising.
