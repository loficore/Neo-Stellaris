"use strict";
(() => {
  // sdk/src/runtime.ts
  function onCountry(fn) {
    __neo_register_country((id) => {
      fn({
        id,
        opinionOf: (targetId) => intOrNull(__neo_country_opinion(id, targetId)),
        theirOpinionOf: (targetId) => intOrNull(__neo_country_their_opinion(id, targetId))
      });
    });
  }
  function intOrNull(v) {
    return typeof v === "number" ? v : null;
  }
  function log(message) {
    __neo_log(message);
  }

  // examples/neo_opinion/src/main.ts
  onCountry((c) => {
    const self = c.opinionOf(c.id);
    log(`NEO_OPINION_SELF id=${c.id} value=${self === null ? "null" : self}`);
  });
})();
