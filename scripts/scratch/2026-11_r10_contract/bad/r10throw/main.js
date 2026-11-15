"use strict";
// R10 bad bundle #2 — the exception path.  The thrown message is the marker: the
// host's `NEO_JS_ERROR id=<id> mod=r10throw <message>` line must carry it verbatim.
globalThis.__neo_register_system(function (id) { throw new Error("R10_INTENTIONAL"); });
