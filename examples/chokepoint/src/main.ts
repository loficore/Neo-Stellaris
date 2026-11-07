import { onSystem, graph, log } from "@neo/runtime";

onSystem((s) => {
  const b = graph.betweenness(s);
  if (b >= 200) {
    s.setVariable("neo_score", b);
    // Flags persist in the save, so the write is guarded by the read.  Both names
    // are literals: `neo check` rejects computed names and official-keyword
    // collisions at build time.
    if (!s.hasStarFlag("neo_hub")) {
      s.setStarFlag("neo_hub");
    }
    log(`NEO_HUB ${s.id} ${b}`);
  }
});
