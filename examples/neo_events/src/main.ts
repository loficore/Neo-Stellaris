import { gameDate, gameTick, graph, log, onSystem } from "@neo/runtime";

// Slice 1: the JS decision the official script cannot express.
//
// The engine calls this once per system, once a month (the `neo_action` effect
// inside `events/neo_events.txt`).  The pick is derived from the *graph*, not
// from anything the event file knows.  Every system gets the same value: the
// official half reads it with `any_system { check_variable … }`, and leaving
// systems without the variable would make `check_variable` log an error for
// each of them (4.4.4 semantics).
const DRIVER_SYSTEM = 82;
// Only `.id` is read by the shim, so a bare id is enough to ask the graph about
// the driver system from any handler invocation.
const driver = { id: DRIVER_SYSTEM } as unknown as Parameters<typeof graph.betweenness>[0];

onSystem((s) => {
  const betweenness = graph.betweenness(driver);
  const pick = betweenness >= 200 ? 2 : 1;
  s.setVariable("neo_event_pick", pick);
  if (s.id === DRIVER_SYSTEM) {
    // The world clock is readable from any handler: `gameDate()` is the engine's
    // own `"YYYY.MM.DD"` (month/day already 1-based) and `gameTick()` is the
    // absolute day index since the epoch — the unit the official script compares
    // against when it schedules a follow-up (`days > 30`-style arithmetic).
    // Both are `null` before a campaign is loaded; the template prints that as
    // `null` rather than pretending it is day 0.
    log(`NEO_DATE ${gameDate()} tick=${gameTick()}`);
    log(`NEO_EVENT_PICK source=js system=${s.id} pick=${pick} betweenness=${betweenness}`);
  }
});
