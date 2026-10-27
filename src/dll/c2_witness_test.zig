// Native tests for the C4 slot[2] instantiate witness guard. Root lives at
// src/dll/ because Zig imports may not escape the module root (same reason as
// c2_exec_test.zig).

const witness = @import("c2/instantiate_witness_probe.zig");

comptime {
    _ = witness;
}
