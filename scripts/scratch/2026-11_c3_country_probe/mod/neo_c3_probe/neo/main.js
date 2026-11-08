"use strict";
// C3 country-probe — read-only.
//
// The bundle exists so the host has an active session with `scope: ["country"]`
// (state = ready ⇒ `onCountry` counts every dispatch and `noteOtherScope` runs).
// The handler is deliberately empty: every field readout happens in the host's
// read-only diagnostic (`NEO_C3_*`), not in JS — the probe must not write engine
// state and must not call engine functions.
(() => {
  __neo_log("NEO_C3_SESSION_READY");

  __neo_register_country(() => {
    // deliberately empty — read-only probe
  });
})();
