---
layout: home

hero:
  name: Neo-Stellaris
  text: Runtime JavaScript mods for Stellaris
  tagline: Write your mod's logic in TypeScript. An injected QuickJS host runs it on the game's main thread, once per system and once per country.
  actions:
    - theme: brand
      text: Download the preview
      link: https://github.com/loficore/Neo-Stellaris/releases/latest
    - theme: alt
      text: Read the SDK reference
      link: /reference/sdk

features:
  - title: TypeScript, not script text
    details: Graph maths, cross-scope aggregation and per-object state are awkward in the Clausewitz DSL. Write them as ordinary TypeScript with a small, frozen native surface.
  - title: The official script stays official
    details: The host writes engine state; your mod's own events, on_actions and triggers do the rest. No custom file format, no replacement event engine.
  - title: Checked before it ships
    details: "`neo check` bundles your code, runs it in a real QuickJS runtime against a mock host, and refuses flag names that collide with an official keyword."
---

## The 60-second path

1. **Download** `neo-stellaris-preview-<version>.zip` from
   [the latest release](https://github.com/loficore/Neo-Stellaris/releases/latest)
   and unpack it anywhere. It contains the injected host DLL, the injector, the
   TypeScript SDK and two worked examples — no npm registry needed for the
   download itself.
2. **Install** it: the DLL goes next to `stellaris.exe` and the mod's `neo/`
   directory goes to `C:/temp/neo_mods/<id>/`. The one-click installer
   (`neo.bat`) does both halves for you — see [Install](/guide/install) for the
   manual route and the failure tags.
3. **Write** a handler. This is a complete runtime mod body:

```ts
import { log, onSystem } from "@neo/runtime";

onSystem((s) => {
  log(`system ${s.id} has degree ${s.degree}`);
});
```

Then `neo build` → `neo check` → `neo pack`, and install the result. The full
walkthrough, including the generated `on_actions`/`events` pair that drives the
handler once a month, is [Your first mod](/guide/first-mod).

::: warning Read the limits before you play
The shipped DLL is a **Debug** build: a failed internal safety check aborts the
game process instead of the mod. Star-flag writes have no live reading yet and
country scope is read-only. All of that is on [Known limits](/guide/known-limits)
— it takes a minute and it is the difference between a demo and a broken save.
:::

## What this is not

Not a Workshop mod. A runtime JS mod is inert without the injected host: the
script parser sees `neo_action` as an unknown effect, and `neo/main.js` only
runs because the host evaluates it from `C:/temp/neo_mods/<id>/neo/`. There is
no subscription that installs any of this, and there is no hot reload.

The rest of this site is the author-facing half only: [Install](/guide/install),
[Your first mod](/guide/first-mod), [Examples](/guide/examples),
[Known limits](/guide/known-limits) and the [SDK reference](/reference/sdk).
