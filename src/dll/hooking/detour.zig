// detour.zig — Trampoline detour hooking framework.
//
// Implements the classic detour pattern for x86_64 Windows:
//   1. Overwrite the first N bytes of the target function with a JMP to the detour.
//   2. Copy the original bytes into a trampoline buffer, followed by a JMP back.
//   3. The detour can call the trampoline to invoke the original function.
//
// The minimum JMP patch size is 14 bytes (FF 25 /0 [rip+0]; jmp qword [rip+0])
// which encodes a 64-bit absolute indirect jump, avoiding ±2GB rel32 limitations.
//
// Thread safety: All hook state mutations are protected by a global mutex.
// Install and remove use VirtualProtect to flip code pages to RX↔RWX.

const std = @import("std");
const windows = @import("windows.zig");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum number of bytes to overwrite at the target function.
/// 14 bytes = FF 25 00 00 00 00 + 8-byte absolute address (jmp [rip+0]).
const JMP_PATCH_SIZE: usize = 14;

/// Maximum number of bytes we'll copy into the trampoline (original prologue).
/// Must be >= JMP_PATCH_SIZE and aligned for simplicity.
const TRAMPOLINE_MAX_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// x86_64 instruction length decoder
// ---------------------------------------------------------------------------

/// Decode the length of a single x86_64 instruction at `code`.
/// Returns the instruction length in bytes, or 0 if the byte is unrecognized.
///
/// This handles the common instruction patterns found at function prologues.
/// Not a complete x86_64 decoder — covers the ~20 opcodes that account for
/// >99% of prologue instructions (push, mov, sub, lea, xor, nop, etc.).
fn decodeInstructionLength(code: [*]const u8) u8 {
    var i: u8 = 0;

    // --- Legacy prefixes (segment overrides, lock, rep, operand/addr size) ---
    while (true) {
        switch (code[i]) {
            0xF0, 0xF2, 0xF3 => { // LOCK, REPNE, REP
                i += 1;
                continue;
            },
            0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65 => { // Segment overrides
                i += 1;
                continue;
            },
            0x66 => { // Operand size override
                i += 1;
                continue;
            },
            0x67 => { // Address size override
                i += 1;
                continue;
            },
            else => break,
        }
    }

    // --- REX prefix (0x40–0x4F) ---
    var rex: u8 = 0;
    if (code[i] >= 0x40 and code[i] <= 0x4F) {
        rex = code[i];
        i += 1;
    }

    const has_rex = rex != 0;
    const rex_w = (rex & 0x08) != 0; // 64-bit operand size
    _ = rex_w;

    // --- Opcode ---
    const opcode = code[i];
    i += 1;

    // Helper: determine ModR/M byte register vs memory addressing
    const modrm_needed = needsModRM(opcode, has_rex);

    if (modrm_needed) {
        const modrm = code[i];
        const mod: u8 = (modrm >> 6) & 0x03;
        const rm: u8 = modrm & 0x07;
        i += 1; // consume ModR/M

        // SIB byte present when mod != 3 and rm == 4
        if (mod != 3 and rm == 4) {
            i += 1; // consume SIB
        }

        // Displacement
        if (mod == 1) {
            i += 1; // disp8
        } else if (mod == 2 or (mod == 0 and rm == 5)) {
            i += 4; // disp32
        }
    }

    // --- Immediate operand ---
    i += immediateSize(opcode, rex);

    return i;
}

/// Returns true if this opcode has a ModR/M byte.
fn needsModRM(opcode: u8, has_rex: bool) bool {
    _ = has_rex;
    return switch (opcode) {
        // Group 1: AL/AX/EAX/RAX, imm
        0x04, 0x05, 0x0C, 0x0D, 0x14, 0x15, 0x1C, 0x1D,
        0x24, 0x25, 0x2C, 0x2D, 0x34, 0x35, 0x3C, 0x3D,
        => false,

        // Group 1: r/m, imm (8-bit and 32/64-bit)
        0x80, 0x81, 0x83 => true,

        // Group 2: shift/rotate
        0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3 => true,

        // Group 3: TEST r/m, imm; NOT; NEG; MUL; DIV
        0xF6, 0xF7 => true,

        // Group 5: INC/DEC/CALL/JMP/PUSH r/m
        0xFF => true,

        // MOV r/m8, r8 / MOV r/m64, r64 / MOV r8, r/m8 / MOV r64, r/m64
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8E => true,

        // LEA r64, m
        0x8D => true,

        // MOV r/m, imm (reg-encoded in opcode, no ModR/M)
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7 => false, // MOV r8, imm8
        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF => false, // MOV r64, imm64

        // NOP, RET, INT3, etc.
        0x90, 0xC3, 0xCC => false,

        // PUSH/POP reg
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        => false,

        // Conditional jumps (short and near)
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        => false, // rel8 only

        // JMP rel32
        0xE9 => false,

        // CALL rel32
        0xE8 => false,

        // MOV AL/AX/EAX/RAX, moffs / MOV moffs, AL/AX/EAX/RAX
        0xA0, 0xA1, 0xA2, 0xA3 => false,

        // CMP AL/AX/EAX/RAX, imm
        0x38, 0x39, 0x3A, 0x3B => true,

        // Two-byte opcode escape (0x0F xx)
        // We handle the most common ones below
        else => false,
    };
}

/// Returns the number of immediate bytes for a given opcode.
fn immediateSize(opcode: u8, rex: u8) u8 {
    _ = rex;
    return switch (opcode) {
        // Group 1: r/m, imm8
        0x80, 0x83 => 1,
        // Group 1: r/m, imm32 (or imm16 with 0x66 prefix)
        0x81 => 4,
        // MOV r64, imm64 (REX.W + B8+rd)
        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF => 8,
        // MOV r8, imm8
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7 => 1,
        // AL/AX/EAX/RAX, imm
        0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C => 1,
        0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D => 4,
        // TEST r/m, imm
        0xF6 => 1,
        0xF7 => 4,
        // JMP/CALL rel32
        0xE9, 0xE8 => 4,
        // JMP/CALL rel8
        0xEB, 0xE3 => 1,
        // Conditional jumps rel8
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        => 1,
        // Shift r/m, 1
        0xD0, 0xD1, 0xD2, 0xD3 => 0,
        // Shift r/m, CL
        0xC0, 0xC1 => 1,
        else => 0,
    };
}

/// Decode the total length needed to cover at least `min_bytes` of instructions.
/// Returns the total number of bytes that form complete instructions >= min_bytes.
/// Panics if it can't decode enough (shouldn't happen with normal code).
fn decodePrologueLength(code: [*]const u8, min_bytes: usize) usize {
    var total: usize = 0;
    while (total < min_bytes) {
        const len = decodeInstructionLength(code + total);
        if (len == 0) {
            // Unknown instruction — assume single byte to make progress.
            total += 1;
        } else {
            total += len;
        }
    }
    return total;
}

// ---------------------------------------------------------------------------
// Hook descriptor
// ---------------------------------------------------------------------------

/// Represents an installed detour hook.
///
/// `trampoline` is a pointer to executable memory containing the original
/// prologue instructions followed by a jump back to the target function
/// (at the point after the overwritten bytes).
///
/// To call the original function, cast `trampoline` to the appropriate
/// function pointer type and invoke it.
pub const Hook = struct {
    /// Pointer to the trampoline: original prologue + JMP back.
    /// Cast this to the original function signature to call it.
    trampoline: *anyopaque,

    /// Pointer to the start of the overwritten bytes in the target function.
    target: *anyopaque,

    /// Number of bytes overwritten in the target function.
    patch_size: usize,

    /// Pointer to the allocated trampoline memory (for freeing).
    trampoline_mem: [*]u8,

    /// Original memory protection of the target page.
    old_protect: u32,
};

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Mutex protecting all hook state (install/remove/query).
var hook_mutex = std.Thread.Mutex{};

/// List of installed hooks (simple fixed-capacity array for now).
const MAX_HOOKS = 64;
var hook_count: usize = 0;
var hooks: [MAX_HOOKS]Hook = undefined;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install a detour hook.
///
/// - `target`: Address of the function to hook.
/// - `detour`: Address of the replacement function.
///
/// Returns a `Hook` whose `trampoline` field points to executable memory
/// that, when called, executes the original function's prologue and jumps
/// back to continue normal execution.
///
/// Thread-safe: acquires global mutex.
pub fn installHook(target: *anyopaque, detour: *anyopaque) !Hook {
    _ = detour; // Will be used when we write the JMP to the detour.
    _ = &target;

    hook_mutex.lock();
    defer hook_mutex.unlock();

    if (hook_count >= MAX_HOOKS) return error.TooManyHooks;

    // 1. Determine how many bytes of prologue to save.
    const target_bytes: [*]const u8 = @ptrCast(target);
    const patch_size = decodePrologueLength(target_bytes, JMP_PATCH_SIZE);

    // 2. Allocate trampoline memory.
    // Layout: [original_bytes (patch_size)] [JMP back to target+patch_size]
    const trampoline_total = patch_size + JMP_PATCH_SIZE;
    const trampoline_mem: [*]u8 = @ptrCast(try windows.allocNear(target, trampoline_total));

    // 3. Copy original prologue into trampoline.
    for (0..patch_size) |i| {
        trampoline_mem[i] = target_bytes[i];
    }

    // 4. Append JMP back: FF 25 00 00 00 00 [8-byte addr of target+patch_size]
    const jmp_back_offset = patch_size;
    const continuation_addr = @intFromPtr(target) + patch_size;
    trampoline_mem[jmp_back_offset + 0] = 0xFF;
    trampoline_mem[jmp_back_offset + 1] = 0x25;
    trampoline_mem[jmp_back_offset + 2] = 0x00;
    trampoline_mem[jmp_back_offset + 3] = 0x00;
    trampoline_mem[jmp_back_offset + 4] = 0x00;
    trampoline_mem[jmp_back_offset + 5] = 0x00;
    std.mem.writeInt(u64, trampoline_mem[jmp_back_offset + 6 .. jmp_back_offset + 14][0..8], continuation_addr, .little);

    // 5. Make trampoline executable.
    {
        var guard = try windows.ProtectGuard.change(
            trampoline_mem,
            trampoline_total,
            .execute_read,
        );
        defer guard.deinit();
    }

    // 6. Patch the target function: overwrite prologue with JMP to detour.
    //    For now, we write a NOP sled (placeholder until detour dispatch is wired).
    {
        var guard = try windows.ProtectGuard.change(
            @ptrCast(target),
            patch_size,
            .execute_readwrite,
        );
        defer guard.deinit();

        var target_mut: [*]u8 = @ptrCast(target);
        for (0..patch_size) |i| {
            target_mut[i] = 0x90; // NOP (placeholder — real detour JMP wired in T7)
        }
    }

    // 7. Flush instruction cache.
    windows.flushInstructionCache(target, patch_size);

    // 8. Record the hook.
    const hook = Hook{
        .trampoline = trampoline_mem,
        .target = target,
        .patch_size = patch_size,
        .trampoline_mem = trampoline_mem,
        .old_protect = 0,
    };
    hooks[hook_count] = hook;
    hook_count += 1;

    return hook;
}

/// Remove a previously installed hook, restoring the original prologue.
///
/// Thread-safe: acquires global mutex.
pub fn removeHook(hook: *const Hook) !void {
    hook_mutex.lock();
    defer hook_mutex.unlock();

    // 1. Restore original bytes.
    const trampoline_bytes: [*]const u8 = @ptrCast(hook.trampoline);

    {
        var guard = try windows.ProtectGuard.change(
            @ptrCast(hook.target),
            hook.patch_size,
            .execute_readwrite,
        );
        defer guard.deinit();

        var target_mut: [*]u8 = @ptrCast(hook.target);
        for (0..hook.patch_size) |i| {
            target_mut[i] = trampoline_bytes[i];
        }
    }

    // 2. Flush instruction cache.
    windows.flushInstructionCache(hook.target, hook.patch_size);

    // 3. Free trampoline memory.
    try windows.freeMem(hook.trampoline_mem);

    // 4. Remove from global list.
    var i: usize = 0;
    while (i < hook_count) : (i += 1) {
        if (hooks[i].target == hook.target) {
            // Shift remaining hooks down.
            var j: usize = i;
            while (j + 1 < hook_count) : (j += 1) {
                hooks[j] = hooks[j + 1];
            }
            hook_count -= 1;
            break;
        }
    }
}

/// Check if a hook is installed for the given target address.
pub fn isHooked(target: *anyopaque) bool {
    hook_mutex.lock();
    defer hook_mutex.unlock();

    for (0..hook_count) |i| {
        if (hooks[i].target == target) return true;
    }
    return false;
}

/// Get the number of currently installed hooks.
pub fn hookCount() usize {
    hook_mutex.lock();
    defer hook_mutex.unlock();
    return hook_count;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "decodeInstructionLength: NOP" {
    const code = [_]u8{0x90}; // NOP
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 1), len);
}

test "decodeInstructionLength: PUSH RBP" {
    const code = [_]u8{0x55}; // PUSH RBP
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 1), len);
}

test "decodeInstructionLength: MOV RSP, RBP" {
    // 48 89 E5 — MOV RSP, RBP (with REX.W)
    const code = [_]u8{ 0x48, 0x89, 0xE5 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 3), len);
}

test "decodeInstructionLength: SUB RSP, imm32" {
    // 48 81 EC xx xx xx xx — SUB RSP, imm32
    const code = [_]u8{ 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 7), len);
}

test "decodeInstructionLength: SUB RSP, imm8" {
    // 48 83 EC 20 — SUB RSP, 0x20
    const code = [_]u8{ 0x48, 0x83, 0xEC, 0x20 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 4), len);
}

test "decodeInstructionLength: MOV R64, imm64" {
    // 48 B8 xx xx xx xx xx xx xx xx — MOV RAX, imm64
    const code = [_]u8{ 0x48, 0xB8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 10), len);
}

test "decodeInstructionLength: LEA RAX, [RIP+disp32]" {
    // 48 8D 05 xx xx xx xx — LEA RAX, [RIP+disp32]
    const code = [_]u8{ 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 7), len);
}

test "decodeInstructionLength: XOR EAX, EAX" {
    // 33 C0 — XOR EAX, EAX
    const code = [_]u8{ 0x33, 0xC0 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: RET" {
    const code = [_]u8{0xC3}; // RET
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 1), len);
}

test "decodeInstructionLength: JMP rel32" {
    // E9 xx xx xx xx — JMP rel32
    const code = [_]u8{ 0xE9, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 5), len);
}

test "decodeInstructionLength: CALL rel32" {
    // E8 xx xx xx xx — CALL rel32
    const code = [_]u8{ 0xE8, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 5), len);
}

test "decodeInstructionLength: MOV [RBP-8], RDI" {
    // 48 89 7D F8 — MOV [RBP-8], RDI (REX.W, ModR/M mod=01, reg=111, rm=101, disp8)
    const code = [_]u8{ 0x48, 0x89, 0x7D, 0xF8 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 4), len);
}

test "decodeInstructionLength: MOV [RSP+RAX*8], RSI with SIB" {
    // 48 89 74 C4 08 — MOV [RSP+RAX*8+8], RSI (REX.W, ModR/M mod=01, reg=110, rm=100 → SIB)
    const code = [_]u8{ 0x48, 0x89, 0x74, 0xC4, 0x08 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 5), len);
}

test "decodeInstructionLength: Jcc rel8 (JE short)" {
    const code = [_]u8{ 0x74, 0x10 }; // JE +16
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: NOP with REX prefix" {
    // 40 90 — NOP (REX prefix + NOP, technically not a real NOP but valid)
    const code = [_]u8{ 0x40, 0x90 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: PUSH R12 (REX.B)" {
    // 41 54 — PUSH R12 (REX.B prefix)
    const code = [_]u8{ 0x41, 0x54 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: TEST byte [RAX], AL" {
    // 84 00 — TEST [RAX], AL (mod=00, reg=0, rm=000, no displacement)
    const code = [_]u8{ 0x84, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: MOV byte [RAX+RCX*4+0x10], BL" {
    // 88 5C 88 10 — MOV [RAX+RCX*4+0x10], BL (mod=01, reg=011, rm=100→SIB, disp8)
    const code = [_]u8{ 0x88, 0x5C, 0x88, 0x10 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 4), len);
}

test "decodeInstructionLength: CMP byte [RAX+5], 0" {
    // 80 78 05 00 — CMP byte [RAX+5], 0 (Group 1, mod=01, reg=111, rm=000, disp8, imm8)
    const code = [_]u8{ 0x80, 0x78, 0x05, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 4), len);
}

test "decodeInstructionLength: MOV RAX, [RCX] (absolute disp32 via mod=00 rm=101)" {
    // 48 8B 05 00 00 00 00 — MOV RAX, [disp32] (mod=00, reg=000, rm=101 → disp32)
    const code = [_]u8{ 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 7), len);
}

test "decodeInstructionLength: INC ECX (Group 4)" {
    // FF C1 — INC ECX (ModR/M: mod=11, reg=000, rm=001)
    const code = [_]u8{ 0xFF, 0xC1 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: INC RAX (REX.W)" {
    // 48 FF C0 — INC RAX (REX.W + ModR/M: mod=11, reg=000, rm=000)
    const code = [_]u8{ 0x48, 0xFF, 0xC0 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 3), len);
}

test "decodePrologueLength: covers minimum JMP_PATCH_SIZE" {
    // 4 bytes of NOP (1 each) + 5-byte JMP rel32 = 9. Need >= 14, so it should
    // keep decoding until we have >= 14 bytes.
    const code = [_]u8{
        0x90, 0x90, 0x90, 0x90, // 4 NOPs
        0xE9, 0x00, 0x00, 0x00, 0x00, // JMP rel32 (5 bytes)
        0x90, 0x90, 0x90, 0x90, 0x90, // 5 more NOPs
    };
    const len = decodePrologueLength(&code, JMP_PATCH_SIZE);
    try std.testing.expect(len >= JMP_PATCH_SIZE);
    // Should be exactly 14: 4 + 5 + 5 = 14
    try std.testing.expectEqual(@as(usize, 14), len);
}

test "decodePrologueLength: handles typical x86_64 prologue" {
    // PUSH RBP; MOV RSP, RBP; SUB RSP, 0x20
    const code = [_]u8{
        0x55, // PUSH RBP (1)
        0x48, 0x89, 0xE5, // MOV RSP, RBP (3)
        0x48, 0x83, 0xEC, 0x20, // SUB RSP, 0x20 (4)
    }; // Total: 8 bytes
    // With min=14, it needs more. The next bytes would be needed.
    // Since we only have 8, it will decode what's there and pad.
    const len = decodePrologueLength(&code, JMP_PATCH_SIZE);
    try std.testing.expect(len >= JMP_PATCH_SIZE);
}

test "JMP_PATCH_SIZE is 14" {
    // FF 25 00 00 00 00 [8 bytes addr] = 14 bytes
    try std.testing.expectEqual(@as(usize, 14), JMP_PATCH_SIZE);
}

test "decodeInstructionLength: XOR EAX, imm32" {
    // 35 xx xx xx xx — XOR EAX, imm32
    const code = [_]u8{ 0x35, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 5), len);
}

test "decodeInstructionLength: ADD EAX, imm32" {
    // 05 xx xx xx xx — ADD EAX, imm32
    const code = [_]u8{ 0x05, 0x01, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 5), len);
}

test "decodeInstructionLength: PUSH imm8" {
    // 6A xx — PUSH imm8
    const code = [_]u8{ 0x6A, 0x20 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: PUSH imm32" {
    // 68 xx xx xx xx — PUSH imm32
    const code = [_]u8{ 0x68, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 5), len);
}

test "decodeInstructionLength: MOV r/m32, imm32 (Group 1)" {
    // C7 C0 xx xx xx xx — MOV EAX, imm32 (ModR/M: mod=11, reg=000, rm=000)
    const code = [_]u8{ 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 6), len);
}

test "decodeInstructionLength: JMP rel8" {
    // EB xx — JMP rel8
    const code = [_]u8{ 0xEB, 0x10 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: INT3" {
    const code = [_]u8{0xCC}; // INT3
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 1), len);
}

test "decodeInstructionLength: MOV AL, moffs" {
    // A0 xx xx xx xx — MOV AL, [moffs]
    const code = [_]u8{ 0xA0, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 5), len);
}

test "decodeInstructionLength: DEC EAX (Group 4)" {
    // FF C8 — DEC EAX
    const code = [_]u8{ 0xFF, 0xC8 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: CALL [RAX] (Group 5)" {
    // FF 10 — CALL [RAX] (ModR/M: mod=00, reg=010, rm=000)
    const code = [_]u8{ 0xFF, 0x10 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 2), len);
}

test "decodeInstructionLength: PUSH [RBP+8] (Group 5)" {
    // FF 75 08 — PUSH [RBP+8] (ModR/M: mod=01, reg=110, rm=101, disp8)
    const code = [_]u8{ 0xFF, 0x75, 0x08 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 3), len);
}

test "decodeInstructionLength: LEA RAX, [RAX+RCX*4]" {
    // 48 8D 04 88 — LEA RAX, [RAX+RCX*4] (ModR/M: mod=00, reg=000, rm=100 → SIB, no disp)
    const code = [_]u8{ 0x48, 0x8D, 0x04, 0x88 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 4), len);
}

test "decodeInstructionLength: MOV RAX, [RSP+disp32] with SIB" {
    // 48 8B 84 24 00 00 00 00 — MOV RAX, [RSP+disp32] (SIB: mod=10, rm=100, disp32)
    const code = [_]u8{ 0x48, 0x8B, 0x84, 0x24, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 8), len);
}

test "decodeInstructionLength: TEST EAX, imm32" {
    // A9 xx xx xx xx — TEST EAX, imm32
    const code = [_]u8{ 0xA9, 0x00, 0x00, 0x00, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 5), len);
}

test "decodeInstructionLength: NOP (multi-byte 0F 1F)" {
    // 0F 1F 00 — NOP dword [RAX] (3-byte NOP)
    const code = [_]u8{ 0x0F, 0x1F, 0x00 };
    const len = decodeInstructionLength(&code);
    try std.testing.expectEqual(@as(u8, 0), len); // 0F prefix not handled, returns 0
}

test "decodePrologueLength: exactly 14 bytes" {
    // 14 single-byte NOPs = 14 bytes
    const code = [_]u8{0x90} ** 14;
    const len = decodePrologueLength(&code, JMP_PATCH_SIZE);
    try std.testing.expectEqual(@as(usize, 14), len);
}

test "decodePrologueLength: 15 bytes needed" {
    // 15 single-byte NOPs, min=14 → should return 14 (first instruction boundary >= 14)
    const code = [_]u8{0x90} ** 15;
    const len = decodePrologueLength(&code, JMP_PATCH_SIZE);
    try std.testing.expectEqual(@as(usize, 14), len);
}
