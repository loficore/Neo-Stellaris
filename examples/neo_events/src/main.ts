import { graph, log, onSystem } from "@neo/runtime";

// Slice 1: the JS decision the official script cannot express.
//
// The engine calls this once per system, once a month (the `neo_action` effect
// inside `events/neo_events.txt`).  The pick is derived from the *graph*, not
// from anything the event file knows: a system on a top-15 chokepoint gets 2,
// a junction gets 1, everything else 0.  The official half then reads the
// number back with `any_system { check_variable … }` and fires the matching
// event — so which event appears is decided here, in JS, at runtime.
const DRIVER_SYSTEM = 82;

onSystem((s) => {
  const betweenness = graph.betweenness(s);
  const pick = betweenness >= 200 ? 2 : s.degree >= 2 ? 1 : 0;

  // Only one system carries the value: 788 monthly writes of a variable that
  // nothing else reads is just save bloat.  82 is the demo's fixed driver (the
  // saving is only `neo_event_pick`; `neo_event_last` is written by the event).
  if (s.id !== DRIVER_SYSTEM) return;

  s.setVariable("neo_event_pick", pick);
  log(`NEO_EVENT_PICK source=js system=${s.id} pick=${pick} betweenness=${betweenness}`);
});
