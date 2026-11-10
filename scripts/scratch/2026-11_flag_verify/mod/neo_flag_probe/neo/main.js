"use strict";
// Flag-keyspace probe — runtime half (Stellaris 4.4.4, one-shot).
//
// The question this bundle answers: does our native `__neo_system_has_flag` /
// `__neo_system_set_flag` resolve flag names through the SAME engine table the
// official `has_star_flag` / `set_star_flag` use?
//
// Three actions, one system handler, nothing else:
//   1. read the flag the official script wrote (`neo_probe`) — log only when
//      true, else this would be 788 lines a month;
//   2. on system 82 only: write `neo_probe2`, read it back, log the readback
//      (a `present=false` here would be evidence the write misses its own read);
//   3. every other system does nothing — the probe must not write engine state
//      anywhere it was not asked to.
//
// Hand-written on purpose: no SDK, no npm, no build step. The names live in
// constants so a typo cannot slip into one call site only; `neo_probe` /
// `neo_probe2` are checked against the official keyword table before the shot
// (scripts/c1_preflight.py + a grep over the keyword TSV).
(() => {
  var OFFICIAL_FLAG = "neo_probe";   // written by events/neo_flag.txt step 1
  var OUR_FLAG = "neo_probe2";       // written below, read by step 4
  var DRIVER_SYSTEM = 82;            // the one system we write on

  __neo_log("NEO_FLAG_SESSION_READY");

  __neo_register_system(function (id) {
    // 1. do we see the flag the official script set?
    if (__neo_system_has_flag(id, OFFICIAL_FLAG)) {
      __neo_log("NEO_FLAG_READ name=" + OFFICIAL_FLAG +
                " present=true id=" + id);
    }

    // 2. write ours on one system, then read it back through the same API.
    if (id === DRIVER_SYSTEM) {
      __neo_system_set_flag(id, OUR_FLAG);
      __neo_log("NEO_FLAG_READ name=" + OUR_FLAG + " present=" +
                (__neo_system_has_flag(id, OUR_FLAG) ? "true" : "false") +
                " id=" + id);
    }

    // 3. everything else: nothing.
  });
})();
