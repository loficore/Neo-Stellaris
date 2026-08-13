// id_mapper.zig — Effect ID-to-name mapping system.
//
// Maps numeric effect IDs (as found in CEffect objects at offset +0xFF0)
// to human-readable effect names. The mapping is loaded from game data
// files (common/scripted_effects/*.txt) and supplemented with hardcoded
// IDs for built-in effects.
//
// The engine uses a dispatch switch at 0x14180B050 that reads the effect
// ID and jumps to the corresponding handler. This mapper provides the
// reverse lookup: given an ID, what effect does it represent?

const std = @import("std");
const offsets = @import("offsets");

/// Maximum length for effect name strings.
/// Effects in Stellaris typically have short names (< 64 bytes).
pub const MAX_EFFECT_NAME_LEN: usize = 128;

/// Error types for the ID mapper.
pub const MapperError = error{
    /// The requested effect ID is not mapped.
    UnknownId,
    /// Failed to read game data file.
    FileReadError,
    /// Game data file has invalid format.
    InvalidFormat,
    /// Memory allocation failed.
    OutOfMemory,
};

/// Effect ID mapper with bidirectional lookup.
///
/// Usage:
///   var mapper = EffectIdMapper.init(allocator);
///   defer mapper.deinit();
///
///   // Load from game data (optional, for scripted effects)
///   mapper.loadFromGameData("/path/to/stellaris/common/scripted_effects/") catch {};
///
///   // Look up effect name by ID
///   if (mapper.getNameById(45)) |name| {
///       std.debug.print("Effect 45 is: {s}\n", .{name});
///   }
pub const EffectIdMapper = struct {
    /// Primary mapping: effect ID → name string.
    /// Names are stored as slices into allocated memory (owned by this struct).
    id_to_name: std.AutoHashMap(i32, []const u8),

    /// Reverse mapping: name → effect ID.
    /// Useful for looking up an ID when you only have the name.
    name_to_id: std.StringHashMap(i32),

    /// Allocator used for all allocations.
    allocator: std.mem.Allocator,

    /// Count of loaded mappings (for diagnostics).
    count: u32,

    /// Initialize a new EffectIdMapper.
    pub fn init(allocator: std.mem.Allocator) EffectIdMapper {
        return .{
            .id_to_name = std.AutoHashMap(i32, []const u8).init(allocator),
            .name_to_id = std.StringHashMap(i32).init(allocator),
            .allocator = allocator,
            .count = 0,
        };
    }

    /// Deinitialize and free all resources.
    pub fn deinit(self: *EffectIdMapper) void {
        // Free all stored name strings
        var it = self.id_to_name.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.id_to_name.deinit();
        self.name_to_id.deinit();
    }

    /// Register a mapping from effect ID to name.
    /// If the ID or name already exists, the old mapping is replaced.
    pub fn register(self: *EffectIdMapper, id: i32, name: []const u8) !void {
        // Allocate and copy the name string
        const owned_name = try self.allocator.dupe(u8, name);

        // Remove old mapping if it exists
        if (self.id_to_name.fetchRemove(id)) |kv| {
            self.allocator.free(kv.value);
            _ = self.name_to_id.remove(kv.value);
        }
        if (self.name_to_id.fetchRemove(name)) |kv| {
            _ = self.id_to_name.remove(kv.value);
        }

        // Insert new mapping
        try self.id_to_name.put(id, owned_name);
        try self.name_to_id.put(owned_name, id);
        self.count += 1;
    }

    /// Look up effect name by ID.
    /// Returns null if the ID is not mapped.
    pub fn getNameById(self: EffectIdMapper, id: i32) ?[]const u8 {
        return self.id_to_name.get(id);
    }

    /// Look up effect ID by name.
    /// Returns null if the name is not mapped.
    pub fn getIdByName(self: EffectIdMapper, name: []const u8) ?i32 {
        return self.name_to_id.get(name);
    }

    /// Get a formatted string for an effect ID.
    /// Returns "effect_name (ID)" if mapped, or "unknown_effect (ID)" if not.
    pub fn formatId(self: EffectIdMapper, id: i32, buf: []u8) ![]const u8 {
        if (self.getNameById(id)) |name| {
            return std.fmt.bufPrint(buf, "{s} ({d})", .{ name, id }) catch error.NoSpaceLeft;
        } else {
            return std.fmt.bufPrint(buf, "unknown_effect ({d})", .{id}) catch error.NoSpaceLeft;
        }
    }

    /// Load effect mappings from game data files.
    ///
    /// This function scans the given directory for .txt files containing
    /// scripted effect definitions. Each file may contain one or more
    /// effect blocks like:
    ///
    ///   my_effect = {
    ///       # effect body
    ///   }
    ///
    /// The effect names are extracted and assigned sequential IDs starting
    /// from the scripted effect base (4081).
    ///
    /// Note: This is a stub implementation. Full parsing requires the
    /// Clausewitz text format parser (not yet implemented).
    pub fn loadFromGameData(self: *EffectIdMapper, path: []const u8) !void {
        // TODO: Implement actual file parsing when text parser is available.
        //
        // High-level algorithm:
        // 1. Scan directory for *.txt files
        // 2. For each file, parse the Clausewitz text format
        // 3. Extract top-level key-value pairs (effect names)
        // 4. Register each with assignSequentialId()
        //
        // For now, just validate the path exists (stub)
        _ = path;

        // Load hardcoded built-in effect names
        try self.loadBuiltInEffects();
    }

    /// Load hardcoded built-in effect names.
    /// These are the effects handled by the switch-case at 0x14180B050.
    fn loadBuiltInEffects(self: *EffectIdMapper) !void {
        // Register known built-in effects with their IDs.
        // The IDs are derived from the case values in the dispatch switch.
        //
        // This list is not exhaustive — the full list has 254+159+166 cases.
        // These are the most commonly used effects for initial testing.

        const built_in_effects = [_]struct { id: i32, name: []const u8 }{
            .{ .id = 0, .name = "add_monthly_income" },
            .{ .id = 1, .name = "set_name" },
            .{ .id = 2, .name = "add_opinion" },
            .{ .id = 3, .name = "setGMEModerate" },
            .{ .id = 4, .name = "set_country_flag" },
            .{ .id = 5, .name = "set_country_color" },
            .{ .id = 6, .name = "set_federation_name" },
            .{ .id = 7, .name = "set_sector_name" },
            .{ .id = 8, .name = "set_star_name" },
            .{ .id = 9, .name = "set_ship_name" },
            .{ .id = 10, .name = "set_planet_name" },
            .{ .id = 11, .name = "set_pop_name" },
            .{ .id = 12, .name = "set_leader_name" },
            .{ .id = 13, .name = "set_army_name" },
            .{ .id = 14, .name = "set_fleet_name" },
            .{ .id = 15, .name = "set_station_name" },
            .{ .id = 20, .name = "add_resource" },
            .{ .id = 21, .name = "add_minerals" },
            .{ .id = 22, .name = "add_energy" },
            .{ .id = 23, .name = "add_influence" },
            .{ .id = 24, .name = "add_unity" },
            .{ .id = 25, .name = "add_alloys" },
            .{ .id = 26, .name = "add_consumer_goods" },
            .{ .id = 27, .name = "add_food" },
            .{ .id = 28, .name = "add_volatile_motes" },
            .{ .id = 29, .name = "add_rare_crystals" },
            .{ .id = 30, .name = "add_exotic_gases" },
            .{ .id = 31, .name = "add zro" },
            .{ .id = 32, .name = "add_dark_matter" },
            .{ .id = 33, .name = "add_living_metal" },
            .{ .id = 40, .name = "create_fleet" },
            .{ .id = 41, .name = "create_army" },
            .{ .id = 42, .name = "create_pop" },
            .{ .id = 43, .name = "create_leader" },
            .{ .id = 44, .name = "create_ship" },
            .{ .id = 45, .name = "create_country" },
            .{ .id = 50, .name = "destroy_fleet" },
            .{ .id = 51, .name = "destroy_army" },
            .{ .id = 52, .name = "destroy_ship" },
            .{ .id = 60, .name = "set_ethos" },
            .{ .id = 61, .name = "set_government" },
            .{ .id = 62, .name = "set_ruler" },
            .{ .id = 70, .name = "add_modifier" },
            .{ .id = 71, .name = "remove_modifier" },
            .{ .id = 80, .name = "add_trait" },
            .{ .id = 81, .name = "remove_trait" },
            .{ .id = 82, .name = "set_species" },
            .{ .id = 89, .name = "set_planet_size" },
            .{ .id = 90, .name = "terraform" },
            .{ .id = 100, .name = "add_research_option" },
            .{ .id = 101, .name = "add_technology" },
            .{ .id = 150, .name = "set_relation_flag" },
            .{ .id = 151, .name = "set_default_fire_rate" },
            .{ .id = 156, .name = "set_country_type" },
            .{ .id = 200, .name = "set_controller" },
            .{ .id = 201, .name = "transfer_texture_to" },
            .{ .id = 250, .name = "set_empire_name" },
            .{ .id = 300, .name = "set_military_power" },
        };

        for (built_in_effects) |effect| {
            try self.register(effect.id, effect.name);
        }
    }

    /// Assign a sequential ID to a scripted effect name.
    /// Used when loading from game data files.
    pub fn assignSequentialId(self: *EffectIdMapper, name: []const u8) !i32 {
        const id = offsets.known_effect_ids.SCRIPTED_EFFECT_BASE + @as(i32, @intCast(self.count));
        try self.register(id, name);
        return id;
    }

    /// Get the total number of registered effects.
    pub fn getCount(self: EffectIdMapper) u32 {
        return self.count;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "init and deinit" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try std.testing.expectEqual(@as(u32, 0), mapper.count);
}

test "register and lookup" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(42, "test_effect");
    try std.testing.expectEqual(@as(?i32, 42), mapper.getIdByName("test_effect"));
    try std.testing.expectEqualStrings("test_effect", mapper.getNameById(42) orelse unreachable);
}

test "lookup unknown ID returns null" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try std.testing.expectEqual(@as(?[]const u8, null), mapper.getNameById(999));
}

test "format ID with name" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(42, "test_effect");

    var buf: [128]u8 = undefined;
    const result = try mapper.formatId(42, &buf);
    try std.testing.expectEqualStrings("test_effect (42)", result);
}

test "format unknown ID" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    var buf: [128]u8 = undefined;
    const result = try mapper.formatId(999, &buf);
    try std.testing.expectEqualStrings("unknown_effect (999)", result);
}

test "sequential ID assignment" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    const id1 = try mapper.assignSequentialId("effect_a");
    const id2 = try mapper.assignSequentialId("effect_b");
    const id3 = try mapper.assignSequentialId("effect_c");

    try std.testing.expectEqual(offsets.known_effect_ids.SCRIPTED_EFFECT_BASE, id1);
    try std.testing.expectEqual(offsets.known_effect_ids.SCRIPTED_EFFECT_BASE + 1, id2);
    try std.testing.expectEqual(offsets.known_effect_ids.SCRIPTED_EFFECT_BASE + 2, id3);

    try std.testing.expectEqualStrings("effect_a", mapper.getNameById(id1) orelse unreachable);
    try std.testing.expectEqualStrings("effect_b", mapper.getNameById(id2) orelse unreachable);
    try std.testing.expectEqualStrings("effect_c", mapper.getNameById(id3) orelse unreachable);
}

test "replace existing mapping" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(42, "old_name");
    try mapper.register(42, "new_name");

    try std.testing.expectEqualStrings("new_name", mapper.getNameById(42) orelse unreachable);
    try std.testing.expectEqual(@as(?i32, 42), mapper.getIdByName("new_name"));
    try std.testing.expectEqual(@as(?i32, null), mapper.getIdByName("old_name"));
}

test "load built-in effects" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.loadBuiltInEffects();

    // Should have loaded multiple built-in effects
    try std.testing.expect(mapper.count > 0);

    // Verify some known effects exist
    try std.testing.expect(mapper.getNameById(0) != null); // add_monthly_income
    try std.testing.expect(mapper.getNameById(20) != null); // add_resource
    try std.testing.expect(mapper.getNameById(45) != null); // create_country
}

test "getCount returns correct count" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try std.testing.expectEqual(@as(u32, 0), mapper.getCount());

    try mapper.register(1, "effect_a");
    try std.testing.expectEqual(@as(u32, 1), mapper.getCount());

    try mapper.register(2, "effect_b");
    try std.testing.expectEqual(@as(u32, 2), mapper.getCount());
}

test "register with negative ID" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(-1, "negative_effect");
    try std.testing.expectEqual(@as(?i32, -1), mapper.getIdByName("negative_effect"));
    try std.testing.expectEqualStrings("negative_effect", mapper.getNameById(-1) orelse unreachable);
}

test "register with zero ID" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(0, "zero_effect");
    try std.testing.expectEqual(@as(?i32, 0), mapper.getIdByName("zero_effect"));
    try std.testing.expectEqualStrings("zero_effect", mapper.getNameById(0) orelse unreachable);
}

test "register many effects" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    // Register 100 effects
    var i: i32 = 0;
    while (i < 100) : (i += 1) {
        var name_buf: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "effect_{d}", .{i}) catch unreachable;
        try mapper.register(i, name);
    }

    try std.testing.expectEqual(@as(u32, 100), mapper.getCount());

    // Verify some
    try std.testing.expectEqualStrings("effect_0", mapper.getNameById(0) orelse unreachable);
    try std.testing.expectEqualStrings("effect_50", mapper.getNameById(50) orelse unreachable);
    try std.testing.expectEqualStrings("effect_99", mapper.getNameById(99) orelse unreachable);
}

test "formatId: known ID" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(42, "test_effect");

    var buf: [256]u8 = undefined;
    const result = try mapper.formatId(42, &buf);
    try std.testing.expectEqualStrings("test_effect (42)", result);
}

test "formatId: unknown ID" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    var buf: [256]u8 = undefined;
    const result = try mapper.formatId(999, &buf);
    try std.testing.expectEqualStrings("unknown_effect (999)", result);
}

test "formatId: negative ID" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(-5, "neg_effect");

    var buf: [256]u8 = undefined;
    const result = try mapper.formatId(-5, &buf);
    try std.testing.expectEqualStrings("neg_effect (-5)", result);
}

test "replace mapping: old name becomes invalid" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(10, "old_name");
    try std.testing.expectEqual(@as(?i32, 10), mapper.getIdByName("old_name"));

    try mapper.register(10, "new_name");
    try std.testing.expectEqual(@as(?i32, null), mapper.getIdByName("old_name"));
    try std.testing.expectEqual(@as(?i32, 10), mapper.getIdByName("new_name"));
}

test "assignSequentialId: sequential IDs are unique" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    const id1 = try mapper.assignSequentialId("eff1");
    const id2 = try mapper.assignSequentialId("eff2");
    const id3 = try mapper.assignSequentialId("eff3");

    try std.testing.expect(id1 != id2);
    try std.testing.expect(id2 != id3);
    try std.testing.expect(id1 != id3);
}

test "loadFromGameData: stub does not crash" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    // loadFromGameData is a stub that calls loadBuiltInEffects
    try mapper.loadFromGameData("/nonexistent/path");
    try std.testing.expect(mapper.count > 0);
}

test "getNameById: returns owned slice" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(1, "owned_name");
    const name = mapper.getNameById(1) orelse unreachable;

    // The returned slice should be valid
    try std.testing.expectEqual(@as(usize, 10), name.len);
    try std.testing.expectEqualStrings("owned_name", name);
}

test "getIdByName: returns null for empty string" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(1, "test");
    try std.testing.expectEqual(@as(?i32, null), mapper.getIdByName(""));
}

test "getIdByName: returns null for unmatched name" {
    var mapper = EffectIdMapper.init(std.testing.allocator);
    defer mapper.deinit();

    try mapper.register(1, "test_effect");
    try std.testing.expectEqual(@as(?i32, null), mapper.getIdByName("test_effec"));
    try std.testing.expectEqual(@as(?i32, null), mapper.getIdByName("test_effect "));
}
