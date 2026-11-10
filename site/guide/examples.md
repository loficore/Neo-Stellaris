# Examples

The preview package ships two complete mods. Both are ordinary Stellaris mods —
`descriptor.mod`, `common/on_actions/`, `events/`, `localisation/` — with one
foreign name: the `neo_action` effect, which the injected host registers.
Without the injection the script parser reports `neo_action` as an unknown
effect, and that log line is expected.

## `neo_events` — JS decides, the official script fires

The shape that works for a runtime mod: **JavaScript writes an official state
value, official script reads it back and fires a real event.**

```ts
import { graph, log, onSystem } from "@neo/runtime";

const DRIVER_SYSTEM = 82;
const driver = { id: DRIVER_SYSTEM } as unknown as Parameters<typeof graph.betweenness>[0];

onSystem((s) => {
  const betweenness = graph.betweenness(driver);
  const pick = betweenness >= 200 ? 2 : 1;
  s.setVariable("neo_event_pick", pick);
  if (s.id === DRIVER_SYSTEM) {
    log(`NEO_EVENT_PICK source=js system=${s.id} pick=${pick} betweenness=${betweenness}`);
  }
});
```

The official half then fires the matching event on the player country:

```
on_monthly_pulse                       (common/on_actions/neo_events_on_actions.txt)
  └─ neo_events.100 (hidden, events/neo_events.txt)
       ├─ random_system { every_system { neo_action = { } } }
       │    └─ the injected host calls onSystem once per system
       │       └─ JS writes neo_event_pick = 0 | 1 | 2  on system 82
       └─ every_country { limit = { is_ai = no … }
            any_system { check_variable = { which = neo_event_pick value = 1 } }
            └─ country_event = { id = neo_events.2 } }
```

Two things are load-bearing here and both are easy to get wrong:

- `every_system` must be wrapped in `random_system` when the event has no
  system scope; from a no-scope event body it iterates once, not 788 times.
- The event must land on a **country the player controls**. An event fired at an
  AI country never draws a window, so the example fires on `is_ai = no` and
  reads the system variable through `any_system` instead of firing on `owner`.

**What you should see:** an event window with one clickable option, once per
monthly pulse. The option writes `NEO_EVENT_PICK <n>` to `game.log` and
`neo_event_last = <n>` to the country; the other half of the pair is
`NEO_EVENT_PICK source=js system=82 pick=<n>` in `C:/temp/neo_js.log`. The two
numbers must agree — a mismatch is a real defect, not a demo quirk.

Build and check it:

```bash
cd sdk && npm ci
node dist/cli.js build --dir ../examples/neo_events   # writes neo/main.js
node dist/cli.js check --dir ../examples/neo_events   # NEO_CHECK ok … handler=1
```

Full source and README:
[examples/neo_events](https://github.com/loficore/Neo-Stellaris/tree/main/examples/neo_events).

## `neo_opinion` — the read-only country contract

The same shape, but the reading is done at run time instead of by script text:
once a month the host hands every non-AI country to the bundle, which reads one
cell of the engine's opinion matrix.

```ts
import { log, onCountry } from "@neo/runtime";

onCountry((c) => {
  const self = c.opinionOf(c.id);
  log(`NEO_OPINION_SELF id=${c.id} value=${self === null ? "null" : self}`);
});
```

| SDK | Engine keyword | Cell |
|---|---|---|
| `c.opinionOf(targetId)` | `opinion` | `base[(target * n) + self]` |
| `c.theirOpinionOf(targetId)` | `their_opinion` | `base[(self * n) + target]` |

The two are transposed cells of **one** matrix. Which of them means "our
opinion of them" is not established, so the example reads the diagonal
(`c.opinionOf(c.id)`), which is well defined either way — a single-country
campaign has no asymmetric pair to tell the two apart.

`null` is the only failure value, and it is not `0`. It means one of: the cell
was never computed (the engine's `0x7fffffff` sentinel), an id is out of range,
the matrix does not exist yet (main menu, or no campaign loaded), the session
lacks the `opinion.read` permission, or the id does not match the country being
dispatched. Every refusal also logs `NEO_JS_OPINION_REJECT … reason=<tag>`.

**There is no writer.** The matrix is a lazily filled engine cache; filling a
cell means calling the engine's own calculator, which writes. That is out of
scope, and `Country` has no setter.

Build and check it:

```bash
node dist/cli.js build --dir ../examples/neo_opinion
node dist/cli.js check --dir ../examples/neo_opinion   # NEO_CHECK ok … handler=1
```

Full source and README:
[examples/neo_opinion](https://github.com/loficore/Neo-Stellaris/tree/main/examples/neo_opinion).

## More in the repository

The repository also carries a third, smaller sample —
[examples/chokepoint](https://github.com/loficore/Neo-Stellaris/tree/main/examples/chokepoint) —
which scores the hyperlane graph and writes the score as a system variable. It
is the simplest possible shape: one `onSystem` handler, one variable write, one
log line, and no event half at all.

The `neo new` template
([`sdk/templates/neo-mod`](https://github.com/loficore/Neo-Stellaris/tree/main/sdk/templates/neo-mod))
is a fourth starting point: a registered handler that reads the neighbour list
and demonstrates the flag read/write pair.
