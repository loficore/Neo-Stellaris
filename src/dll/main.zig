// main.zig — DLL root source file.
//
// This module is the compilation root for the stellaris_quickjs shared library.
// It imports the exports module so that exported symbols (PushCApplicationPtr,
// DllMain) are reachable from the compilation root and linked into the final DLL.

const std = @import("std");

// Pull in the exports — reachable from root means the linker includes them.
pub const exports = @import("exports.zig");

// QuickJS runtime integration.
pub const quickjs = @import("quickjs/runtime.zig");
