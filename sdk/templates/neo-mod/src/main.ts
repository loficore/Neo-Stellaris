import { log, onSystem } from "@neo/runtime";

// The host calls this once per system, once a month (the event in `events/`
// drives it).  Keep it cheap: it runs for every system on every pass.
onSystem((s) => {
  const neighbors = s.neighbors;
  log(`NEO_HELLO ${s.id} degree=${s.degree} neighbors=${neighbors.length}`);
});
