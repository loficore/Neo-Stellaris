# Neo Events — slice 1 of the community-mechanic bet

A complete, ordinary Stellaris mod whose *choice* is made at run time by the
injected QuickJS host instead of by script text: once a month the host hands
every system to `neo/main.js`, which writes `neo_event_pick` = 0 / 1 / 2 on
system 82 from the hyperlane graph, and the official script fires the matching
event on the player country.

Nothing in this directory needs a special file format. `descriptor.mod`,
`common/on_actions/`, `events/`, `localisation/english/` are the usual
Clausewitz shapes; the only foreign name is the `neo_action` effect, which the
injected host registers. Without the injection the parser reports it as an
unknown effect — that is expected for a runtime-JS mod.

## Build it

```bash
cd <repo>
node sdk/dist/cli.js build --dir examples/neo_events     # writes neo/main.js
node sdk/dist/cli.js check --dir examples/neo_events     # NEO_CHECK ok … handler=1
```

`neo/main.js` is committed so the mod can be installed without Node, but it is
**generated** from `src/main.ts`: edit the source, then rebuild. `neo check`
does not compare the two.

## Install / play

Double-click `neo.bat` (shipped next to `neo_install.py`), or:

```bash
python C:/temp/neo_install.py --mod C:/temp/neo_events --dry-run --debug   # look first
python C:/temp/neo_install.py --mod C:/temp/neo_events                     # install + launch
```

It prints one line, `NEO_PLAY ok dll=<sha16> mod=neo_events pid=<pid>` or
`NEO_PLAY fail reason=<tag>`. The tag table is in `site/reference/sdk.md`.

## What "it worked" means

An event window with one clickable option appears inside one monthly pulse; the
option writes `NEO_EVENT_PICK <n>` to `game.log` and `neo_event_last = <n>` to
the country. `C:/temp/neo_js.log` has the other half of the pair:
`NEO_EVENT_PICK source=js system=82 pick=<n> …`. The two numbers must agree.

`neo_event_done` stops the demo after one firing per campaign — a window that
reopens every month says nothing new and keeps the game paused.
