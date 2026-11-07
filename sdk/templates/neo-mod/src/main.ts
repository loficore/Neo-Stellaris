import { log, onSystem } from "@neo/runtime";

// The host calls this once per system, once a month (the event in `events/`
// drives it).  Keep it cheap: it runs for every system on every pass.
onSystem((s) => {
  const neighbors = s.neighbors;
  if (!s.hasStarFlag("neo_greeted")) {
    // Flag names are string literals on purpose: `neo check` refuses computed
    // names and names that collide with an official keyword.
    s.setStarFlag("neo_greeted");
    log(`NEO_HELLO ${s.id} degree=${s.degree} neighbors=${neighbors.length}`);
  }
});
