// scripted_tests.zig — test root for the detour modules.
//
// exec_hook.zig and lookup_hook.zig import ../hooking/*, which a module rooted at
// src/dll/scripted cannot reach (Zig rejects imports escaping the module path). Rooting
// here keeps every import inside src/dll and avoids main.zig's QuickJS C linkage.

const std = @import("std");

const lookup = @import("scripted/lookup_hook.zig");
const exec = @import("scripted/exec_hook.zig");
const detour = @import("hooking/detour.zig");
const windows = @import("hooking/windows.zig");

comptime {
    _ = lookup;
    _ = exec;
    _ = detour;
    _ = windows;
}

test {
    _ = std.testing.refAllDecls(@This());
}
