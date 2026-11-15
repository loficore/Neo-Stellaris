// api_tests.zig — test root for the api/ read path.
//
// `api/gamestate.zig` reads the engine through `hooking/windows.zig`; a module
// rooted at `src/dll/api` cannot reach `../hooking` (Zig rejects imports that
// escape the module path). Rooting here keeps every import inside `src/dll` and
// avoids main.zig's QuickJS C linkage — the same reason `c2_tests.zig` and
// `scripted_tests.zig` exist.
//
// The tests themselves live next to the code they exercise (`api/gamestate.zig`,
// and the C3-FIELD channel's own module), as they did when this module was rooted
// there; this file only has to make the files reachable.

const std = @import("std");

const gamestate = @import("api/gamestate.zig");
const field_read = @import("api/field_read.zig");

comptime {
    _ = gamestate;
    _ = field_read;
}

test {
    _ = std.testing.refAllDecls(@This());
}
