"use strict";
// R7 — country id 24-bit mask probe (runtime half, Stellaris 4.4.4, one-shot).
//
// The question this bundle answers: after the host masks `scope+0x10` down to
// the engine's 24-bit country id (high 8 bits are a type tag — C3 read
// 0x01000002 / 0x04000015 / 0x06000014), does the handler see the masked id,
// and does the opinion reader accept that same masked id as `self`?
//
// One handler, two actions:
//   1. log the id the host handed us — the R7 criterion is "every
//      `NEO_JS_CALL_COUNTRY id=` is in 0..39", i.e. no 8-hex-digit magnitudes;
//   2. read the opinion row the dispatched country holds toward country 0 and
//      log it. A numeric `op=` is the only evidence that the masked `self`
//      survives the `scope_mismatch` check; `op=undefined` is a negative
//      reading, not an error.
//
// Hand-written on purpose: no SDK, no npm, no build step (same rule as the
// flag probe). The probe writes nothing — no engine memory, no variables.
(() => {
  var TARGET = 0;   // the human country: C3's single measurable column

  __neo_log("NEO_CID_SESSION_READY");

  __neo_register_country(function (id) {
    __neo_log("COUNTRY id=" + id + " op=" + __neo_country_opinion(id, TARGET));
  });
})();
