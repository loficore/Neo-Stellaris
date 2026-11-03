// c2_tests.zig — test root for the c2/ read-only guards.
//
// The probes live in src/dll/c2 and import ../shared/offsets.zig and ../hooking/*, which a
// module rooted at src/dll/c2 cannot reach (Zig rejects imports escaping the module path).
// Rooting here keeps every import inside src/dll and avoids main.zig's QuickJS C linkage —
// the same reason `scripted_tests.zig` exists for src/dll/scripted.

const std = @import("std");

const trigger_eval = @import("c2/trigger_eval_probe.zig");
const per_system = @import("c2/per_system_probe.zig");
const neo_effect = @import("c2/neo_effect.zig");
const neo_vtable = @import("c2/neo_vtable.zig");
const neo_dispatch = @import("c2/neo_dispatch.zig");
const neo_state = @import("c2/neo_state.zig");
const chokepoint_dynamic = @import("c2/chokepoint_dynamic.zig");
const graph_fixture = @import("c2/graph_fixture.zig");

comptime {
    _ = trigger_eval;
    _ = per_system;
    _ = neo_effect;
    _ = neo_vtable;
    _ = neo_dispatch;
    _ = neo_state;
    _ = chokepoint_dynamic;
    _ = graph_fixture;
}

test {
    _ = std.testing.refAllDecls(@This());
}

// ---------------------------------------------------------------------------
// chokepoint_dynamic: pure Brandes + Tarjan graph metrics
// ---------------------------------------------------------------------------

const cd = chokepoint_dynamic;
const fx = graph_fixture;

test "chokepoint_dynamic: three-node chain centre outranks the ends" {
    var scores: [3]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;
    var edges = [_]cd.Edge{ .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 2 } };
    try cd.analyze(std.testing.allocator, &edges, 3, .{
        .scores = &scores,
        .articulation = &art,
        .bridge_endpoint = &bri,
    });
    // Brandes on a 3-chain: only the pair {0,2} runs through node 1, and the
    // denominator is (3-1)(3-2)/2 = 1, so score[1] = round(1000 * (1 / 1)) = 1000.
    try std.testing.expectEqual(@as(u16, 1000), scores[1]);
    try std.testing.expectEqual(@as(u16, 0), scores[0]);
    try std.testing.expectEqual(@as(u16, 0), scores[2]);
    try std.testing.expect(scores[1] > scores[0]);
    try std.testing.expect(scores[1] > scores[2]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0 }, &art);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1 }, &bri);
}

test "chokepoint_dynamic: self-loops and duplicate edges are ignored" {
    var scores: [3]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;

    // One real edge plus a reversed duplicate plus a self-loop must measure the
    // same as the single-edge graph (all three outputs).
    var noisy = [_]cd.Edge{ .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 0 }, .{ .a = 1, .b = 1 } };
    var clean = [_]cd.Edge{.{ .a = 0, .b = 1 }};
    var ns: [3]u16 = undefined;
    var na: [3]u8 = undefined;
    var nb: [3]u8 = undefined;
    try cd.analyze(std.testing.allocator, &noisy, 3, .{
        .scores = &ns,
        .articulation = &na,
        .bridge_endpoint = &nb,
    });
    try cd.analyze(std.testing.allocator, &clean, 3, .{
        .scores = &scores,
        .articulation = &art,
        .bridge_endpoint = &bri,
    });
    try std.testing.expectEqualSlices(u16, &scores, &ns);
    try std.testing.expectEqualSlices(u8, &art, &na);
    try std.testing.expectEqualSlices(u8, &bri, &nb);

    // The same noise bolted onto the 3-chain leaves the chain result intact.
    var chain = [_]cd.Edge{ .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 2 } };
    var chain_noisy = [_]cd.Edge{
        .{ .a = 0, .b = 1 },
        .{ .a = 1, .b = 2 },
        .{ .a = 1, .b = 0 },
        .{ .a = 1, .b = 1 },
    };
    var cs: [3]u16 = undefined;
    var ca: [3]u8 = undefined;
    var cb: [3]u8 = undefined;
    var xs: [3]u16 = undefined;
    var xa: [3]u8 = undefined;
    var xb: [3]u8 = undefined;
    try cd.analyze(std.testing.allocator, &chain, 3, .{
        .scores = &cs,
        .articulation = &ca,
        .bridge_endpoint = &cb,
    });
    try cd.analyze(std.testing.allocator, &chain_noisy, 3, .{
        .scores = &xs,
        .articulation = &xa,
        .bridge_endpoint = &xb,
    });
    try std.testing.expectEqualSlices(u16, &cs, &xs);
    try std.testing.expectEqualSlices(u8, &ca, &xa);
    try std.testing.expectEqualSlices(u8, &cb, &xb);
}

test "chokepoint_dynamic: an empty edge list is error.NoEdges" {
    var scores: [3]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;
    try std.testing.expectError(error.NoEdges, cd.analyze(
        std.testing.allocator,
        &[_]cd.Edge{},
        3,
        .{ .scores = &scores, .articulation = &art, .bridge_endpoint = &bri },
    ));
}

test "chokepoint_dynamic: an endpoint outside the system range is an error" {
    var scores: [3]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;
    var edges = [_]cd.Edge{.{ .a = 0, .b = 3 }};
    try std.testing.expectError(error.EndpointOutOfRange, cd.analyze(
        std.testing.allocator,
        &edges,
        3,
        .{ .scores = &scores, .articulation = &art, .bridge_endpoint = &bri },
    ));
}

test "chokepoint_dynamic: an isolated system counts toward the denominator and scores 0" {
    // n = system_count = 4 (this module's contract), NOT len(adjacency) = 3:
    // the denominator is (4-1)(4-2)/2 = 3, so score[1] = round(1000 * (1 / 3)) = 333.
    // The offline tool normalises by len(adjacency) = 3 and would print 1000 here —
    // the two agree only when every system has degree >= 1 (true for the fixture).
    var scores: [4]u16 = undefined;
    var art: [4]u8 = undefined;
    var bri: [4]u8 = undefined;
    var edges = [_]cd.Edge{ .{ .a = 0, .b = 1 }, .{ .a = 1, .b = 2 } };
    try cd.analyze(std.testing.allocator, &edges, 4, .{
        .scores = &scores,
        .articulation = &art,
        .bridge_endpoint = &bri,
    });
    try std.testing.expectEqualSlices(u16, &.{ 0, 333, 0, 0 }, &scores);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0, 0 }, &art);
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1, 0 }, &bri);
}

test "chokepoint_dynamic: output slices shorter than system_count are error.LengthMismatch" {
    var scores: [2]u16 = undefined;
    var art: [3]u8 = undefined;
    var bri: [3]u8 = undefined;
    var edges = [_]cd.Edge{.{ .a = 0, .b = 1 }};
    try std.testing.expectError(error.LengthMismatch, cd.analyze(
        std.testing.allocator,
        &edges,
        3,
        .{ .scores = &scores, .articulation = &art, .bridge_endpoint = &bri },
    ));
}

test "chokepoint_dynamic: synthetic fixture matches the offline scores" {
    const alloc = std.testing.allocator;
    const edges = try alloc.alloc(cd.Edge, fx.EDGE_COUNT);
    defer alloc.free(edges);
    for (fx.edges, 0..) |e, i| edges[i] = .{ .a = e[0], .b = e[1] };

    var scores: [fx.SYSTEM_COUNT]u16 = undefined;
    var art: [fx.SYSTEM_COUNT]u8 = undefined;
    var bri: [fx.SYSTEM_COUNT]u8 = undefined;
    try cd.analyze(alloc, edges, fx.SYSTEM_COUNT, .{
        .scores = &scores,
        .articulation = &art,
        .bridge_endpoint = &bri,
    });
    try std.testing.expectEqualSlices(u16, &fx.expected_scores, &scores);
    try std.testing.expectEqualSlices(u8, &fx.expected_articulation, &art);
    try std.testing.expectEqualSlices(u8, &fx.expected_bridge_endpoint, &bri);
}
