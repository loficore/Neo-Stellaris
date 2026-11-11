// capability.zig — 运行时能力自检(v1:只报告)。
//
// 这一模块回答一个问题:**「我们写下来的那 7 条结构断言,在这个版本上还成立吗?」**
// 它不是版本兼容判据(见 spec §7),也**不改变** `neo_action` / `neo_effect` / 写路径的任何行为
// —— 现有指纹门(`exec_hook` 32 B / `neo_dispatch` 19 B)仍是执行面**唯一**的 fail-closed。
//
// 七项检查(spec §3.1),顺序即导出矩阵的顺序:
//   `scope` `token` `descriptor` `graph` `state` `vtable` `fingerprint`
//
// 判读纪律(全局约束,与 spec §2 的决定一一对应):
//   * **读不到 = `fail` + 原因码**,不得降级成 `skip`;`skip` 只用于「没有 system scope」;
//   * `presence_only` 只用于 `class_info` / `docstring` 的**存在性**,不许当 `ok`;
//   * `state` 是唯一有副作用的一项,只写一个变量 `neo_cap_probe`,结束必须写 0;
//   * `scope` 必须排在 `state` **之前**判,否则 country scope 会把国家 id 写进变量还报 ok。

const std = @import("std");

const gg = @import("galaxy_graph.zig");
const offsets = @import("../shared/offsets.zig");
const neo_dispatch = @import("neo_dispatch.zig");
const exec_hook = @import("../scripted/exec_hook.zig");

const kr = offsets.keyword_reg;

/// 七项检查。
pub const CHECK_COUNT: usize = 7;

/// 矩阵顺序即导出矩阵顺序(驱动侧 `CHECK_IDS` 与它逐字相同,围栏钉住)。
pub const Check = enum(u8) { scope, token, descriptor, graph, state, vtable, fingerprint };

pub const CHECK_NAMES = [_][]const u8{
    "scope", "token", "descriptor", "graph", "state", "vtable", "fingerprint",
};

/// `0 = skip`、`1 = ok`、`2 = fail`、`3 = presence_only`(spec §3.2)。
pub const Status = enum(u8) { skip = 0, ok = 1, fail = 2, presence_only = 3 };

/// 稳定的小整数原因码。驱动侧有一份同名同值的表,两份不一致就是围栏红。
pub const Reason = enum(u8) {
    none = 0,
    unreadable = 1,
    mismatch = 2,
    no_scope = 3,
    out_of_range = 4,
    write_rejected = 5,
    not_cleared = 6,
};

/// 导出矩阵的字节数:每项 `u32 status, u32 reason`。
pub const STATS_SIZE: usize = CHECK_COUNT * 8;
/// 布局版本:驱动侧第一格的对账值。改语义就改它。
pub const LAYOUT_VERSION: u32 = 1;

fn statusName(s: Status) []const u8 {
    return switch (s) {
        .skip => "skip",
        .ok => "ok",
        .fail => "fail",
        .presence_only => "presence",
    };
}

fn reasonName(r: Reason) []const u8 {
    return switch (r) {
        .none => "none",
        .unreadable => "unreadable",
        .mismatch => "mismatch",
        .no_scope => "no_scope",
        .out_of_range => "out_of_range",
        .write_rejected => "write_rejected",
        .not_cleared => "not_cleared",
    };
}

/// 一次自检的结果矩阵。默认全 `skip` —— 「没跑」与「跑了且都过」必须能分开。
pub const Report = struct {
    statuses: [CHECK_COUNT]Status = [_]Status{.skip} ** CHECK_COUNT,
    reasons: [CHECK_COUNT]Reason = [_]Reason{.none} ** CHECK_COUNT,
    /// 跑过至少一次(与 `ran` 分开:`state_cleared` 只说那一次写有没有收回)。
    ran: bool = false,
    /// `state` 项的第二次写(写 0)成功收回。写过的进程被杀时这里会是 false。
    state_cleared: bool = false,

    pub fn set(self: *Report, check: Check, status: Status, reason: Reason) void {
        const i = @intFromEnum(check);
        self.statuses[i] = status;
        self.reasons[i] = reason;
    }

    pub fn statusOf(self: Report, check: Check) Status {
        return self.statuses[@intFromEnum(check)];
    }

    pub fn reasonOf(self: Report, check: Check) Reason {
        return self.reasons[@intFromEnum(check)];
    }

    /// `skip` 与 `presence_only` 都不是失败 —— 它们各自有独立的语义(spec §3.1/§3.4)。
    pub fn failCount(self: Report) usize {
        var n: usize = 0;
        for (self.statuses) |s| {
            if (s == .fail) n += 1;
        }
        return n;
    }

    /// 一行 `NEO_CAP …`,字段顺序 = `Check` 的枚举顺序。
    /// `fail` 带 `(reason)`;`skip`/`presence_only` 各自有自己的词,不许写成 `ok`。
    pub fn line(self: Report, buf: []u8) []const u8 {
        const head = "NEO_CAP";
        if (buf.len < head.len) return "";
        @memcpy(buf[0..head.len], head);
        var w: usize = head.len;
        for (CHECK_NAMES, 0..) |name, idx| {
            const status = self.statuses[idx];
            const piece = if (status == .fail)
                std.fmt.bufPrint(buf[w..], " {s}={s}({s})", .{
                    name, statusName(status), reasonName(self.reasons[idx]),
                })
            else
                std.fmt.bufPrint(buf[w..], " {s}={s}", .{ name, statusName(status) });
            const written = piece catch return "";
            w += written.len;
        }
        return buf[0..w];
    }
};

var current: Report = .{};

/// 测试缝:换掉矩阵内容。生产路径只有 `maybeRun`/`reset` 写 `current`。
pub fn storeForTest(r: Report) void {
    current = r;
}

/// 当前矩阵(只读快照)。
pub fn snapshot() Report {
    return current;
}

/// 两个布局词:`[version = 1, CHECK_COUNT]`。返回写下的词数(2)。
pub fn layoutInto(out: *[2]u32) u32 {
    out.* = .{ LAYOUT_VERSION, CHECK_COUNT };
    return 2;
}

/// 写满 `CHECK_COUNT × 8 B` 返回 0;缓冲短于 `STATS_SIZE` 返回 -1 且**一个字节都不写**
/// (短缓冲是拒读,不是截断 —— Review Focus 4)。
pub fn statsInto(out: []u8) i32 {
    if (out.len < STATS_SIZE) return -1;
    var i: usize = 0;
    while (i < CHECK_COUNT) : (i += 1) {
        std.mem.writeInt(u32, out[i * 8 ..][0..4], @intFromEnum(current.statuses[i]), .little);
        std.mem.writeInt(u32, out[i * 8 + 4 ..][0..4], @intFromEnum(current.reasons[i]), .little);
    }
    return 0;
}

/// 清矩阵与 `ran` 标志。**不碰任何 hook**(本模块没有 hook),也不重置引擎侧任何东西。
pub fn reset() void {
    current = .{};
}

// ---------------------------------------------------------------------------
// Task 2 — 四项 scope-free 检查(token / descriptor / vtable / fingerprint)
// ---------------------------------------------------------------------------

/// 检查里唯一用到的官方 keyword:自检问的是「这条 id ↔ 名字的对应关系在这一版上还读得回来吗」。
/// 两个值都是 4.4.4 的静态事实(§17),不是我们从别处抄来的运行时常量。
pub const PROBE_KEYWORD_ID: u32 = 10104;
pub const PROBE_KEYWORD_NAME = "add_modifier";

/// 静态 descriptor 数组的槽数(§17:9,863)。**不是** id 上界 —— 槽号 ≠ id
/// (`add_modifier` 的 id 是 10104,落在槽 1149),所以下面按槽扫、不按 id 索引。
pub const DESCRIPTOR_SLOTS: usize = 9863;

/// `[db + 0x70]` = token 名字表基址;`[基址 + id*0x30]` 是那个 id 的 name holder(§30.2)。
const TOKEN_DB_NAME_TABLE: usize = 0x70;

/// 一个 descriptor 槽里够判名字的窗口:`+0x00` 的 id 与 `+0x20` 起的内联串
/// (`add_modifier` 13 B 带 NUL,16 B 足够;窗口故意开小,好让 9,863 槽各只读一次)。
const DESCRIPTOR_WINDOW: usize = kr.TOKEN_STR_INLINE + 16;

/// 一次自检的全部外部输入。`mem` 是唯一的读通道(生产侧 = `ReadProcessMemory`,
/// 测试侧 = 合成镜像);`write_var` 是唯一的写通道(生产侧 = `writeSystemVariable`)。
pub const Env = struct {
    mem: gg.Memory,
    module_base: usize,
    /// 当前战役的星系条数(`[[0x3260BB0]+0x59C]`,与驱动 `--systems` 同源)。读不到就传 0 ——
    /// `graph` 检查随之 `fail(unreadable)`,这是对的。
    systems: u32,
    /// 当次逐系统派发的 scope;0 = 这一发没有 system scope(3 项 `skip`)。
    scope: u64 = 0,
    /// `(scope, name, value) -> 写成功?`。`null` = 没有注入写通道 ⇒ `state` 记 `fail(write_rejected)`。
    write_var: ?*const fn (scope: u64, name: []const u8, value: u32) bool = null,
};

pub fn readU32(env: Env, addr: usize) ?u32 {
    var buf: [4]u8 = undefined;
    if (!env.mem.read(env.mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(u32, &buf, .little);
}

pub fn readU64(env: Env, addr: usize) ?u64 {
    var buf: [8]u8 = undefined;
    if (!env.mem.read(env.mem.ctx, addr, buf.len, &buf)) return null;
    return std.mem.readInt(u64, &buf, .little);
}

/// 逐字节读到 NUL 止。**逐字节**是因为名字是内存派生的短串:一次跨页读会在页边界翻成
/// 「读不到」,而逐字节最多读到那一页为止,不会把「名字在下一页」误判成不存在。
/// 缓冲写满仍无 NUL ⇒ `null`(那不是我们要判的名字)。
pub fn readCStr(env: Env, addr: usize, buf: []u8) ?[]const u8 {
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        const at = gg.addAddr(addr, i) orelse return null;
        var one: [1]u8 = undefined;
        if (!env.mem.read(env.mem.ctx, at, 1, &one)) return null;
        if (one[0] == 0) return buf[0..i];
        buf[i] = one[0];
    }
    return null;
}

const NameRead = union(enum) { ok: []const u8, bad, unreadable };

/// name holder(0x38 B)里的名字。判据用**引擎自己的那一条**(`0x1d152fb`,与
/// `keyword_registry.NameHolder.charsPtr` 同一口径):`cap`(`+0x28`) < 0x10 ⇒ 字符就是
/// `+0x10` 那 16 字节本身;否则 `[+0x10]` 是 char*。
fn holderName(env: Env, entry: usize, buf: []u8) NameRead {
    const cap_at = gg.addAddr(entry, kr.HOLDER_STR_CAP) orelse return .unreadable;
    const cap = readU64(env, cap_at) orelse return .unreadable;
    const size_at = gg.addAddr(entry, kr.HOLDER_STR_SIZE) orelse return .unreadable;
    const size = readU64(env, size_at) orelse return .unreadable;
    if (size == 0 or size >= buf.len) return .bad;
    const n: usize = @intCast(size);

    if (cap < @as(u64, kr.SSO_MAX)) {
        if (n > kr.SSO_MAX) return .bad;
        const chars = gg.addAddr(entry, kr.HOLDER_NAME) orelse return .unreadable;
        if (!env.mem.read(env.mem.ctx, chars, n, buf[0..n])) return .unreadable;
        return .{ .ok = buf[0..n] };
    }

    const ptr_at = gg.addAddr(entry, kr.HOLDER_NAME) orelse return .unreadable;
    const chars = readU64(env, ptr_at) orelse return .unreadable;
    const addr = std.math.cast(usize, chars) orelse return .bad;
    if (addr == 0) return .bad;
    const s = readCStr(env, addr, buf) orelse return .unreadable;
    return .{ .ok = s };
}

fn checkToken(env: Env, r: *Report) void {
    const db = gg.addAddr(env.module_base, kr.RVA_TOKEN_DB_OBJECT) orelse
        return r.set(.token, .fail, .out_of_range);
    const table_at = gg.addAddr(db, TOKEN_DB_NAME_TABLE) orelse
        return r.set(.token, .fail, .out_of_range);
    const table = readU64(env, table_at) orelse return r.set(.token, .fail, .unreadable);
    const base = std.math.cast(usize, table) orelse return r.set(.token, .fail, .mismatch);
    if (base == 0) return r.set(.token, .fail, .unreadable);

    const entry = gg.elemAddr(base, PROBE_KEYWORD_ID, kr.HOLDER_SIZE, 0) orelse
        return r.set(.token, .fail, .out_of_range);
    var buf: [64]u8 = undefined;
    switch (holderName(env, entry, &buf)) {
        .unreadable => return r.set(.token, .fail, .unreadable),
        .bad => return r.set(.token, .fail, .mismatch),
        .ok => |name| if (!std.mem.eql(u8, name, PROBE_KEYWORD_NAME)) {
            return r.set(.token, .fail, .mismatch);
        },
    }
    r.set(.token, .ok, .none);
}

/// `buf` 里第一个 NUL 之前的部分;没有 NUL ⇒ `null`(这个名字判不了)。
fn cstrPrefix(buf: []const u8) ?[]const u8 {
    const end = std.mem.indexOfScalar(u8, buf, 0) orelse return null;
    return buf[0..end];
}

/// 按槽扫,不按 id 索引 —— 槽号 ≠ id。找到名字后再断言同槽的 `+0x00` 就是那个 id;
/// 找不到、或 id 不等,都是 `fail(mismatch)`。
fn checkDescriptor(env: Env, r: *Report) void {
    const base = gg.addAddr(env.module_base, kr.RVA_DESCRIPTOR_ARRAY) orelse
        return r.set(.descriptor, .fail, .out_of_range);
    var slot: usize = 0;
    while (slot < DESCRIPTOR_SLOTS) : (slot += 1) {
        const addr = gg.elemAddr(base, slot, kr.TOKEN_STRIDE, 0) orelse
            return r.set(.descriptor, .fail, .out_of_range);
        var buf: [DESCRIPTOR_WINDOW]u8 = undefined;
        if (!env.mem.read(env.mem.ctx, addr, buf.len, &buf)) {
            return r.set(.descriptor, .fail, .unreadable);
        }
        const name = cstrPrefix(buf[kr.TOKEN_STR_INLINE..]) orelse continue;
        if (!std.mem.eql(u8, name, PROBE_KEYWORD_NAME)) continue;
        const id = std.mem.readInt(u32, buf[kr.TOKEN_ID..][0..4], .little);
        if (id != PROBE_KEYWORD_ID) return r.set(.descriptor, .fail, .mismatch);
        return r.set(.descriptor, .ok, .none);
    }
    r.set(.descriptor, .fail, .mismatch);
}

fn checkVtable(env: Env, r: *Report) void {
    const slot_at = gg.addAddr(env.module_base, kr.DONOR_EFFECT_VTABLE + kr.EFFECT_VTBL_EXECUTE) orelse
        return r.set(.vtable, .fail, .out_of_range);
    const slot1 = readU64(env, slot_at) orelse return r.set(.vtable, .fail, .unreadable);
    const expected = gg.addAddr(env.module_base, kr.RVA_EFFECT_DONOR_EXECUTE) orelse
        return r.set(.vtable, .fail, .out_of_range);
    if (slot1 != @as(u64, expected)) return r.set(.vtable, .fail, .mismatch);
    r.set(.vtable, .ok, .none);
}

fn checkFingerprint(env: Env, r: *Report) void {
    const addr = gg.addAddr(env.module_base, neo_dispatch.RVA_DISPATCH) orelse
        return r.set(.fingerprint, .fail, .out_of_range);
    var code: [neo_dispatch.EXPECTED_CODE.len]u8 = undefined;
    if (!env.mem.read(env.mem.ctx, addr, code.len, &code)) {
        return r.set(.fingerprint, .fail, .unreadable);
    }
    const bytes_ok = std.mem.eql(u8, &code, &neo_dispatch.EXPECTED_CODE);
    // 本通道自己的 detour 就跑在这个地址上:它活着时目标头 14 B 是**我们的** JMP,
    // 指纹按定义不再成立。那时唯一还成立的事实是「钩子还在原处」(`verify() == 0`)——
    // 这不是放宽,而是把「我们改过的字节」换成一个同样可判的断言。
    const hooked_ok = neo_dispatch.isInstalled() and neo_dispatch.verify() == 0;
    if (!bytes_ok and !hooked_ok) return r.set(.fingerprint, .fail, .mismatch);

    // `exec_hook` 的那一半只在它这一进程真的解析过时才断言:`-3` = 从未解析、`-2` = 非 Windows,
    // 两者都是「这一发里它没参与」—— 记 `fail` 就是把仪器缺席读成漂移。
    const eh = exec_hook.verifyState();
    if (eh != 0 and eh != -2 and eh != -3 and !exec_hook.isInstalled()) {
        return r.set(.fingerprint, .fail, .mismatch);
    }
    r.set(.fingerprint, .ok, .none);
}

/// 四项不需要 scope 的检查。读的顺序固定,好让日志里第一个失败项的原因码稳定
/// (矩阵本身按 `Check` 枚举序写,与执行顺序无关)。
pub fn runFree(env: Env) Report {
    var r = Report{};
    checkToken(env, &r);
    checkDescriptor(env, &r);
    checkVtable(env, &r);
    checkFingerprint(env, &r);
    return r;
}

// ---------------------------------------------------------------------------
// Tests (written first — Task 1 Step 1)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "Report.set folds statuses and failCount ignores skip/presence_only" {
    var r = Report{};
    r.set(.scope, .ok, .none);
    r.set(.state, .fail, .write_rejected);
    try std.testing.expectEqual(@as(usize, 1), r.failCount());
    try std.testing.expectEqual(Status.fail, r.statuses[4]);
    try std.testing.expectEqual(Reason.write_rejected, r.reasons[4]);
}

test "line prints all seven checks in enum order" {
    var buf: [256]u8 = undefined;
    var r = Report{};
    r.set(.scope, .ok, .none);
    r.set(.token, .ok, .none);
    r.set(.descriptor, .ok, .none);
    r.set(.graph, .ok, .none);
    r.set(.state, .ok, .none);
    r.set(.vtable, .presence_only, .none);
    r.set(.fingerprint, .fail, .mismatch);
    try std.testing.expectEqualStrings(
        "NEO_CAP scope=ok token=ok descriptor=ok graph=ok state=ok vtable=presence fingerprint=fail(mismatch)",
        r.line(&buf),
    );
}

test "statsInto writes 8 bytes per check and refuses a short buffer" {
    var r = Report{};
    r.set(.graph, .fail, .out_of_range);
    storeForTest(r);
    var buf: [STATS_SIZE]u8 = undefined;
    try std.testing.expectEqual(@as(i32, 0), statsInto(&buf));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, buf[24..28], .little));
    try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, buf[28..32], .little));
    var small: [16]u8 = undefined;
    try std.testing.expectEqual(@as(i32, -1), statsInto(&small));
}

// ---------------------------------------------------------------------------
// Task 2 — 四项 scope-free 检查的合成内存(零游戏、零 Windows API)
// ---------------------------------------------------------------------------

const FakeRegion = struct { start: usize, bytes: []u8 };

/// 合成镜像:`[start, start+bytes.len)` 内的地址可读,其余一律 `false` ——
/// 与生产侧 `ReadProcessMemory` 同一个 bool 契约(读不到不是「空」)。
const FakeMem = struct {
    regions: [4]FakeRegion = undefined,
    count: usize = 0,

    fn read(ctx: *anyopaque, addr: usize, len: usize, buf: []u8) bool {
        const self: *FakeMem = @ptrCast(@alignCast(ctx));
        for (self.regions[0..self.count]) |rg| {
            if (addr < rg.start) continue;
            const off = addr - rg.start;
            if (off + len <= rg.bytes.len) {
                @memcpy(buf, rg.bytes[off..][0..len]);
                return true;
            }
        }
        return false;
    }

    fn add(self: *FakeMem, start: usize, bytes: []u8) void {
        self.regions[self.count] = .{ .start = start, .bytes = bytes };
        self.count += 1;
    }

    fn env(self: *FakeMem, module_base: usize, systems: u32) Env {
        return .{
            .mem = .{ .ctx = @ptrCast(self), .read = FakeMem.read },
            .module_base = module_base,
            .systems = systems,
        };
    }
};

const TEST_MODULE: usize = 0x1_0000_0000;
const TEST_HOLDER: usize = 0x2_0000_0000;

fn putU32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .little);
}

fn putU64(buf: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], v, .little);
}

fn putName(buf: []u8, off: usize, name: []const u8) void {
    @memcpy(buf[off..][0..name.len], name);
    buf[off + name.len] = 0;
}

test "token check reads add_modifier's name back from the id table" {
    const alloc = testing.allocator;
    var db = [_]u8{0} ** 0x80;
    const entry_off = PROBE_KEYWORD_ID * kr.HOLDER_SIZE;
    const holder = try alloc.alloc(u8, entry_off + kr.HOLDER_SIZE);
    defer alloc.free(holder);
    @memset(holder, 0);

    putU64(&db, TOKEN_DB_NAME_TABLE, TEST_HOLDER);
    // §20 / `NameHolder.charsPtr`:cap < 0x10 ⇒ 字符就是 +0x10 那 16 字节本身。
    putName(holder, entry_off + kr.HOLDER_NAME, PROBE_KEYWORD_NAME);
    putU64(holder, entry_off + kr.HOLDER_STR_SIZE, PROBE_KEYWORD_NAME.len);
    putU64(holder, entry_off + kr.HOLDER_STR_CAP, kr.SSO_MAX - 1);

    var mem = FakeMem{};
    mem.add(TEST_MODULE + kr.RVA_TOKEN_DB_OBJECT, &db);
    mem.add(TEST_HOLDER, holder);

    const rep = runFree(mem.env(TEST_MODULE, 0));
    try testing.expectEqual(Status.ok, rep.statusOf(.token));
}

test "token check fails when the read-back name is another keyword" {
    const alloc = testing.allocator;
    var db = [_]u8{0} ** 0x80;
    const entry_off = PROBE_KEYWORD_ID * kr.HOLDER_SIZE;
    const holder = try alloc.alloc(u8, entry_off + kr.HOLDER_SIZE);
    defer alloc.free(holder);
    @memset(holder, 0);

    putU64(&db, TOKEN_DB_NAME_TABLE, TEST_HOLDER);
    putName(holder, entry_off + kr.HOLDER_NAME, "add_modifief");
    putU64(holder, entry_off + kr.HOLDER_STR_SIZE, PROBE_KEYWORD_NAME.len);
    putU64(holder, entry_off + kr.HOLDER_STR_CAP, kr.SSO_MAX - 1);

    var mem = FakeMem{};
    mem.add(TEST_MODULE + kr.RVA_TOKEN_DB_OBJECT, &db);
    mem.add(TEST_HOLDER, holder);

    const rep = runFree(mem.env(TEST_MODULE, 0));
    try testing.expectEqual(Status.fail, rep.statusOf(.token));
    try testing.expectEqual(Reason.mismatch, rep.reasonOf(.token));
}

test "descriptor check scans slots for the inline name and asserts the id" {
    const alloc = testing.allocator;
    const array = try alloc.alloc(u8, DESCRIPTOR_SLOTS * kr.TOKEN_STRIDE);
    defer alloc.free(array);
    @memset(array, 0);

    // 槽号 ≠ id:名字放在槽 3,id 写 10104(§17 的 closed-chain 一行读的就是这种错位)。
    const slot_off = 3 * kr.TOKEN_STRIDE;
    putU32(array, slot_off + kr.TOKEN_ID, PROBE_KEYWORD_ID);
    putName(array, slot_off + kr.TOKEN_STR_INLINE, PROBE_KEYWORD_NAME);

    var mem = FakeMem{};
    mem.add(TEST_MODULE + kr.RVA_DESCRIPTOR_ARRAY, array);

    const rep = runFree(mem.env(TEST_MODULE, 0));
    try testing.expectEqual(Status.ok, rep.statusOf(.descriptor));
}

test "descriptor check fails when the slot carries another id" {
    const alloc = testing.allocator;
    const array = try alloc.alloc(u8, DESCRIPTOR_SLOTS * kr.TOKEN_STRIDE);
    defer alloc.free(array);
    @memset(array, 0);

    const slot_off = 7 * kr.TOKEN_STRIDE;
    putU32(array, slot_off + kr.TOKEN_ID, PROBE_KEYWORD_ID + 1);
    putName(array, slot_off + kr.TOKEN_STR_INLINE, PROBE_KEYWORD_NAME);

    var mem = FakeMem{};
    mem.add(TEST_MODULE + kr.RVA_DESCRIPTOR_ARRAY, array);

    const rep = runFree(mem.env(TEST_MODULE, 0));
    try testing.expectEqual(Status.fail, rep.statusOf(.descriptor));
    try testing.expectEqual(Reason.mismatch, rep.reasonOf(.descriptor));
}

test "vtable check requires slot1 of the donor table to be donor Execute" {
    var table = [_]u8{0} ** 0x10;
    putU64(&table, kr.EFFECT_VTBL_EXECUTE, TEST_MODULE + kr.RVA_EFFECT_DONOR_EXECUTE);

    var mem = FakeMem{};
    mem.add(TEST_MODULE + kr.DONOR_EFFECT_VTABLE, &table);
    const rep = runFree(mem.env(TEST_MODULE, 0));
    try testing.expectEqual(Status.ok, rep.statusOf(.vtable));

    putU64(&table, kr.EFFECT_VTBL_EXECUTE, TEST_MODULE + kr.RVA_EFFECT_DONOR_EXECUTE + 1);
    var bad_mem = FakeMem{};
    bad_mem.add(TEST_MODULE + kr.DONOR_EFFECT_VTABLE, &table);
    const bad = runFree(bad_mem.env(TEST_MODULE, 0));
    try testing.expectEqual(Status.fail, bad.statusOf(.vtable));
    try testing.expectEqual(Reason.mismatch, bad.reasonOf(.vtable));
}

test "fingerprint check compares 19 bytes at module+RVA_DISPATCH" {
    var code = neo_dispatch.EXPECTED_CODE;

    var mem = FakeMem{};
    mem.add(TEST_MODULE + neo_dispatch.RVA_DISPATCH, &code);
    const rep = runFree(mem.env(TEST_MODULE, 0));
    try testing.expectEqual(Status.ok, rep.statusOf(.fingerprint));

    code[7] ^= 0xFF;
    var bad_mem = FakeMem{};
    bad_mem.add(TEST_MODULE + neo_dispatch.RVA_DISPATCH, &code);
    const bad = runFree(bad_mem.env(TEST_MODULE, 0));
    try testing.expectEqual(Status.fail, bad.statusOf(.fingerprint));
    try testing.expectEqual(Reason.mismatch, bad.reasonOf(.fingerprint));
}
