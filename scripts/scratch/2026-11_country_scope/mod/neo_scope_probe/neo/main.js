"use strict";
// C2 country-scope probe — read-only.
//
// This bundle exists so the host has at least one active session (state =
// ready) and therefore emits `NEO_JS_CALL` for the control group. The handler
// itself does nothing: the probe must not write engine state.
(() => {
  function onSystem(fn) {
    __neo_register_system((id) => {
      fn({ id });
    });
  }

  __neo_log("NEO_C2_SESSION_READY");

  onSystem(() => {
    // deliberately empty — read-only probe
  });
})();
