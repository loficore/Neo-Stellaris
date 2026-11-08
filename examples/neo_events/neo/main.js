"use strict";
(() => {
  // sdk/src/runtime.ts
  function onSystem(fn) {
    __neo_register_system((id) => {
      fn({
        id,
        get degree() {
          return __neo_system_degree(id);
        },
        get neighbors() {
          return __neo_system_neighbors(id);
        },
        setVariable(name, value) {
          __neo_system_set_var(id, name, value);
        },
        setStarFlag(name) {
          __neo_system_set_flag(id, name);
        },
        hasStarFlag(name) {
          return __neo_system_has_flag(id, name);
        }
      });
    });
  }
  var graph = {
    betweenness(s) {
      return __neo_graph_betweenness(s.id);
    },
    isChokepoint(s) {
      return __neo_graph_is_chokepoint(s.id);
    }
  };
  function log(message) {
    __neo_log(message);
  }

  // examples/neo_events/src/main.ts
  var DRIVER_SYSTEM = 82;
  onSystem((s) => {
    const betweenness = graph.betweenness(s);
    const pick = betweenness >= 200 ? 2 : s.degree >= 2 ? 1 : 0;
    if (s.id !== DRIVER_SYSTEM) return;
    s.setVariable("neo_event_pick", pick);
    log(`NEO_EVENT_PICK source=js system=${s.id} pick=${pick} betweenness=${betweenness}`);
  });
})();
