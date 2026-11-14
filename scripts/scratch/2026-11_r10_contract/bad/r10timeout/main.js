"use strict";
// R10 bad bundle #1 — the timeout path.  An unbounded loop inside the handler:
// the host's 10 ms interrupt budget must fire and disable **this session only**
// (`NEO_JS_TIMEOUT` + `NEO_JS_DISABLED mod=r10timeout reason=budget`).
globalThis.__neo_register_system(function (id) { while (true) {} });
