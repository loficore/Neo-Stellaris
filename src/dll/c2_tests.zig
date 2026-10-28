// c2_tests.zig — test root for the c2/ read-only guards.
//
// The probes live in src/dll/c2 and import ../shared/offsets.zig and ../hooking/*, which a
// module rooted at src/dll/c2 cannot reach (Zig rejects imports escaping the module path).
// Rooting here keeps every import inside src/dll and avoids main.zig's QuickJS C linkage —
// the same reason `scripted_tests.zig` exists for src/dll/scripted.

const std = @import("std");

const trigger_eval = @import("c2/trigger_eval_probe.zig");

comptime {
    _ = trigger_eval;
}

test {
    _ = std.testing.refAllDecls(@This());
}
