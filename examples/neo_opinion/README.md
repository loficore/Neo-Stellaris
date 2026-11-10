# Neo Opinion — the read-only country contract

A complete, ordinary Stellaris mod whose *reading* is done at run time by the
injected QuickJS host instead of by script text: once a month the host hands
every non-AI country to `neo/main.js`, which reads one cell of the engine's
opinion matrix and writes it to `C:/temp/neo_js.log`.

Nothing in this directory needs a special file format. `descriptor.mod`,
`common/on_actions/`, `events/` are the usual Clausewitz shapes; the only
foreign name is the `neo_action` effect, which the injected host registers.
Without the injection the parser reports it as an unknown effect — that is
expected for a runtime-JS mod.

## What it reads

| SDK | Engine keyword | Value |
|---|---|---|
| `c.opinionOf(targetId)` | `opinion` | int32 from `base[(target * n) + self]` |
| `c.theirOpinionOf(targetId)` | `their_opinion` | int32 from `base[(self * n) + target]` |

The two are **transposed cells of one matrix** (that part is A-level,
`evidence/analysis/country_fields_4_4_4.md` §2.3). *Which* of them means "our
opinion of them" is **B-level**: the names are the engine's keywords, and the
contract does not claim a human-readable direction. The example therefore reads
the diagonal (`c.opinionOf(c.id)`), which is well-defined under either reading —
a single-country campaign has no asymmetric pair to tell the two apart.

`null` is the only failure value, and it is not `0`: not computed (the engine
sentinel `0x7fffffff`), either id outside the matrix, the matrix not built (main
menu / no campaign loaded), the session missing `opinion.read`, or the JS id not
matching the country being dispatched. Each one also logs
`NEO_JS_OPINION_REJECT self=<n> target=<n> reason=<tag>` next to the read.

**There is no writer.** The matrix is a lazily-filled engine cache; filling a
cell means calling the engine's own calculator (`0x743bb0`), which writes. That
is out of scope for this contract, and `Country` has no setter.

## Build it

```bash
cd <repo>
node sdk/dist/cli.js build --dir examples/neo_opinion     # writes neo/main.js
node sdk/dist/cli.js check --dir examples/neo_opinion     # NEO_CHECK ok … handler=1
```

`neo/main.js` is committed so the mod can be installed without Node, but it is
**generated** from `src/main.ts`: edit the source, then rebuild. `neo check`
does not compare the two.

## Install / play

Double-click `neo.bat` (shipped next to `neo_install.py`), or:

```bash
python C:/temp/neo_install.py --mod C:/temp/neo_opinion --dry-run --debug   # look first
python C:/temp/neo_install.py --mod C:/temp/neo_opinion                     # install + launch
```

It prints one line, `NEO_PLAY ok dll=<sha16> mod=neo_opinion pid=<pid>` or
`NEO_PLAY fail reason=<tag>`. The tag table is in `site/reference/sdk.md`.

## What "it worked" means

One `NEO_JS_CALL_COUNTRY id=<n>` per non-AI country per monthly pulse, and for
each of them one line from the bundle:

```
NEO_OPINION_SELF id=<n> value=<int32|null>
```

- `value=<int32>` — the matrix cell was already computed; the number is the
  engine's own int32, **not** rescaled (the contract has no independent
  reference for a scale, see the docs' known limitations).
- `value=null` — a refused read. The same dispatch has a
  `NEO_JS_OPINION_REJECT` line naming the reason. On a fresh campaign
  `not_computed` is the expected reading: the engine only fills a cell when one
  of its own triggers asks for it, and this mod never asks the engine to fill.

A missing `NEO_JS_CALL_COUNTRY` means the country dispatch never arrived (the
event / on_action chain), not that the read failed.
