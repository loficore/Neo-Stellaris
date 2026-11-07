// flag_ids.zig — flag 名 → 官方 u16 flag id(`0x326D110` 那张表)。
//
// 为什么不是 lexer token:P2-1b 的两发实机(evidence/logs/runtime_js_p2_1b_flags_4_4_4.log)
// 证明 `0x1D13270` 发的 token id 与官方脚本解析 flag 名得到的号**永不相等**。两套号来自
// 两个不同对象(token DB `0x37347A0` 步长 0x30 vs 这张表步长 0x40、各自有发号器);
// 拿 token id 去写 `+0x5F8` 的后果是「写返回 ok、自己读回 true、官方 0 命中」。
// 逐字读数见 evidence/analysis/flag_store_4_4_4.md §2.3 与 §6。
//
// 两条路径必须分开(计划 Review Focus #1):
//   lookup — 只读。哈希 + 桶扫描(`0x1C9E350` + 0x40 步长表),未命中返回 null,**不插表**。
//   ensure — 未命中才调官方 `0x1BCF030`(它自己递增 `0x326D118`,§6.3)插表,再调
//            `0x158300` 把名字追加进反查 vector(深拷贝,§6.4)。1..15 字节。
//
// 号的空间:这张表自己的 size 字段就是下一个 id(稠密、从 0 起),16 位上限来自表本身,
// 与 lexer token 池无关 —— 所以安装期预发号不再需要。
//
// 只走官方例程:哈希 `0x1C9E350`、插入 `0x1BCF030`、追加 `0x158300`。不写引擎内存、
// 不伪造表结构(AGENTS 约束 1/5);名字对象在**我们自己**的栈上,引擎按值拷走。

const std = @import("std");
const builtin = @import("builtin");
const windows = @import("../hooking/windows.zig");
const flag_offsets = @import("../shared/offsets.zig").flag_ids;

const is_windows = builtin.os.tag == .windows;

// 桶布局(§6.2):0x40 步长,哈希 + 探测距离 + 0x30 B 引擎串 + u16 id。
pub const BUCKET_STRIDE: usize = 0x40;
pub const BUCKET_HASH_OFF: usize = 0x00;
pub const BUCKET_DIB_OFF: usize = 0x04;
pub const BUCKET_CHARS_OFF: usize = 0x18;
pub const BUCKET_LEN_OFF: usize = 0x28;
pub const BUCKET_CAP_OFF: usize = 0x30;
pub const BUCKET_ID_OFF: usize = 0x38;

/// 名字上限 = MSVC SSO 边界(15 B):超过就要堆分配,那条路不在本模块的纪律里。
pub const MAX_NAME: usize = 15;
/// 容量 `< 0x10` ⇒ 字符内联在对象里(`cmp qword [bucket+0x30],0x10`)。
pub const INLINE_CAP: usize = 0x10;
/// `0xFFFF` 是引擎的「发不出来」哨兵(§6.3),`0` 在本模块同样按失败处理。
pub const SENTINEL: u16 = 0xFFFF;

/// 探测上界:引擎的 tail = log2(capacity)+2(`0x1BCF400`),插入在探测距离 > tail 时
/// 扩容;正常表永远到不了 capacity+64。它只防「表被写坏」时的无限扫描。
pub const MAX_EXTRA_PROBE: usize = 0x40;

pub const HashFn = *const fn ([*]const u8, usize) callconv(.c) u32;

/// 插入的读数:`created = false` 表示表里本来就有这个名字(此时**不许**再 append,
/// 否则反查 vector 会多一条没有 id 指的记录)。§6.1 的 `{bucket_ptr, inserted}`。
/// `ok = false` 是「插入没成功」;`callconv(.c)` 不许返回非指针 optional,所以用
/// 显式 ok 位而不是 `?InsertOutcome`。
pub const InsertOutcome = extern struct {
    id: u16,
    created: bool,
    ok: bool,

    const failure = InsertOutcome{ .id = 0, .created = false, .ok = false };
};

pub const InsertFn = *const fn (hash: u32, chars: [*]const u8, len: usize, candidate: u16) callconv(.c) InsertOutcome;
pub const AppendFn = *const fn (chars: [*]const u8, len: usize) callconv(.c) void;

/// 表的一趟快照:桶基址 / 下一个 id 的地址 / 掩码 / 三个官方例程。
/// 生产侧每次操作都重读 `0x326D110`/`0x326D11C`(扩容会换桶数组与掩码);
/// 测试侧由 `setTableForTest` 塞一份假表。
pub const Table = struct {
    buckets: usize,
    next_id: *u16,
    mask: u32,
    hash: HashFn,
    insert: InsertFn,
    append: AppendFn,
};

// ---------------------------------------------------------------------------
// Test seam
// ---------------------------------------------------------------------------

var test_table: ?Table = null;
var test_fake: ?*FakeTable = null;

/// 注入/撤掉假表。两种调用都清缓存 —— 缓存是按名字记的,换表就作废。
pub fn setTableForTest(t: ?Table) void {
    test_table = t;
    if (t == null) test_fake = null;
    resetCache();
}

fn activeTable() ?Table {
    if (test_table) |t| return t;
    if (comptime !is_windows) return null;
    const base = engineBase() orelse return null;
    const map = std.math.add(usize, base, flag_offsets.RVA_MAP) catch return null;
    const buckets = readU64(map + 0x08) orelse return null;
    const mask = readU32(map + 0x14) orelse return null;
    if (buckets == 0) return null;
    return .{
        .buckets = buckets,
        // size 字段(`0x326D118`)的低 16 位就是下一个 id;递增由插入函数自己做。
        .next_id = @ptrFromInt(map + 0x10),
        .mask = mask,
        .hash = engineHash,
        .insert = engineInsert,
        .append = engineAppend,
    };
}

fn engineBase() ?usize {
    if (comptime !is_windows) return null;
    const p = windows.moduleFunction(0) catch return null;
    return @intFromPtr(p);
}

// ---------------------------------------------------------------------------
// 缓存(只缓存**命中**)
// ---------------------------------------------------------------------------

/// 为什么没有负缓存:一个读到的「不存在」在官方脚本稍后 `set_star_flag` 之后会变成
/// 「存在」,缓存它会让读路径永远看不到那个 flag(fail-open 的反面)。命中的 id 则
/// 永不改变 —— 这张表只增不删,id 由 size 字段稠密分配。
const CacheEntry = struct {
    name: [MAX_NAME]u8,
    len: u8,
    id: u16,
};

pub const CACHE_SLOTS: usize = 64;
var cache: [CACHE_SLOTS]CacheEntry = undefined;
var cache_len: usize = 0;

pub fn resetCache() void {
    cache_len = 0;
}

fn cacheGet(name: []const u8) ?u16 {
    var i: usize = 0;
    while (i < cache_len) : (i += 1) {
        if (cache[i].len == name.len and std.mem.eql(u8, cache[i].name[0..name.len], name)) return cache[i].id;
    }
    return null;
}

fn cachePut(name: []const u8, id: u16) void {
    if (name.len == 0 or name.len > MAX_NAME) return;
    if (cacheGet(name) != null) return;
    if (cache_len >= CACHE_SLOTS) return;
    var e = &cache[cache_len];
    @memcpy(e.name[0..name.len], name);
    e.len = @intCast(name.len);
    e.id = id;
    cache_len += 1;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// 只读解析。命中返回 id(可以是 0 —— 0 是这张表合法的第一个号),否则 null。
/// **不插表**、不递增计数器:读一个不存在的名字不许给它发号(计划 Global Constraints)。
pub fn lookup(name: []const u8) ?u16 {
    if (name.len == 0 or name.len > MAX_NAME) return null;
    if (cacheGet(name)) |id| return id;
    const t = activeTable() orelse return null;
    const id = lookupIn(t, name) orelse return null;
    cachePut(name, id);
    return id;
}

/// 写路径专用的解析:未命中时**插入**。新号 = 表自己的 size 字段(调用前读),
/// 递增由官方插入例程做(§6.3 判 (a));插完才把名字追加进反查 vector(§6.4)。
pub fn ensure(name: []const u8) ?u16 {
    if (name.len == 0 or name.len > MAX_NAME) return null;
    if (cacheGet(name)) |id| return id;
    const t = activeTable() orelse return null;
    const id = ensureIn(t, name) orelse return null;
    cachePut(name, id);
    return id;
}

/// 纯逻辑:给定一张表快照做只读查找(测试与 `lookup` 共用)。
pub fn lookupIn(t: Table, name: []const u8) ?u16 {
    if (name.len == 0 or name.len > MAX_NAME) return null;
    if (t.buckets == 0) return null;
    const h = t.hash(name.ptr, name.len);
    var idx: usize = @as(usize, h) & @as(usize, t.mask);
    var dist: usize = 1;
    // 桶数组 = capacity + tail + 1 槽(§6.5);正常表在第一个空槽就停。
    const limit = @as(usize, t.mask) + 1 + MAX_EXTRA_PROBE;
    var steps: usize = 0;
    while (steps < limit) : (steps += 1) {
        const slot = bucketAddr(t.buckets, idx) orelse return null;
        var raw: [BUCKET_STRIDE]u8 = undefined;
        if (!readBytes(slot, &raw)) return null;
        // robin-hood 不变量:探测距离小于当前距离 ⇒ 后面的槽不可能装着这个名字。
        if (@as(usize, raw[BUCKET_DIB_OFF]) < dist) return null;
        const len = std.mem.readInt(u32, raw[BUCKET_LEN_OFF..][0..4], .little);
        if (len == name.len) {
            const cap = std.mem.readInt(u64, raw[BUCKET_CAP_OFF..][0..8], .little);
            const chars_addr = if (cap >= INLINE_CAP)
                std.mem.readInt(u64, raw[BUCKET_CHARS_OFF..][0..8], .little)
            else
                slot + BUCKET_CHARS_OFF;
            if (chars_addr != 0) {
                var got: [MAX_NAME]u8 = undefined;
                if (readBytes(chars_addr, got[0..name.len]) and
                    std.mem.eql(u8, got[0..name.len], name))
                    return std.mem.readInt(u16, raw[BUCKET_ID_OFF..][0..2], .little);
            }
        }
        idx += 1;
        dist += 1;
    }
    return null;
}

/// 纯逻辑版的 `ensure`。`0`/`0xFFFF` 一律失败(硬失败,不当写成功)。
pub fn ensureIn(t: Table, name: []const u8) ?u16 {
    if (name.len == 0 or name.len > MAX_NAME) return null;
    if (lookupIn(t, name)) |id| return id;
    const candidate = t.next_id.*;
    if (candidate == 0 or candidate == SENTINEL) return null;
    const h = t.hash(name.ptr, name.len);
    const outcome = t.insert(h, name.ptr, name.len, candidate);
    if (!outcome.ok) return null;
    if (outcome.id == 0 or outcome.id == SENTINEL) return null;
    // 官方插入自己会再扫一遍:若它报「本来就有」,这里**不许** append ——
    // 否则反查 vector 会多一条没有 id 指的记录(§6.4 的 size/index 对应关系)。
    if (outcome.created) t.append(name.ptr, name.len);
    return outcome.id;
}

// ---------------------------------------------------------------------------
// 引擎例程(生产侧;宿主测试从不解析模块基址)
// ---------------------------------------------------------------------------

/// 官方串对象的形状(§6.2/§6.4):0x30 B = 16 B 头 + 16 B 内联字符 + u64 长度 +
/// u64 容量。`0x15F590` / `0x15F770` / `0x1BCF7A0` 三处构造逐字一致。
const EngineString = extern struct {
    hdr0: u64,
    hdr1: u64,
    chars: [16]u8,
    size: u64,
    cap: u64,

    fn init(name: []const u8) EngineString {
        var s = EngineString{
            .hdr0 = 0,
            .hdr1 = 0,
            .chars = [_]u8{0} ** 16,
            .size = name.len,
            .cap = 0x0f,
        };
        @memcpy(s.chars[0..name.len], name);
        return s;
    }
};

comptime {
    if (@sizeOf(EngineString) != 0x30) @compileError("engine string must be 0x30 bytes");
    if (@offsetOf(EngineString, "chars") != 0x10) @compileError("engine string chars at +0x10");
    if (@offsetOf(EngineString, "size") != 0x20) @compileError("engine string size at +0x20");
    if (@offsetOf(EngineString, "cap") != 0x28) @compileError("engine string cap at +0x28");
}

fn bucketAddr(buckets: usize, index: usize) ?usize {
    const off = std.math.mul(usize, index, BUCKET_STRIDE) catch return null;
    return std.math.add(usize, buckets, off) catch null;
}

fn readBytes(addr: usize, out: []u8) bool {
    if (addr == 0 or out.len == 0) return false;
    if (comptime is_windows) return windows.readProcessMemory(addr, out);
    // 宿主测试:假表就在本进程地址空间里,直接读(生产侧走上面的 ReadProcessMemory)。
    const p: [*]const u8 = @ptrFromInt(addr);
    @memcpy(out, p[0..out.len]);
    return true;
}

fn readU16(addr: usize) ?u16 {
    var buf: [2]u8 = undefined;
    if (!readBytes(addr, &buf)) return null;
    return std.mem.readInt(u16, &buf, .little);
}

fn readU32(addr: usize) ?u32 {
    var buf: [4]u8 = undefined;
    if (!readBytes(addr, &buf)) return null;
    return std.mem.readInt(u32, &buf, .little);
}

fn readU64(addr: usize) ?u64 {
    var buf: [8]u8 = undefined;
    if (!readBytes(addr, &buf)) return null;
    return std.mem.readInt(u64, &buf, .little);
}

/// `0x1C9E350`:`hash(seed=0, chars, len)`;调用方读 `edx`/`r9d` 的分别是地址与长度
/// (`0x1c9e350 mov ebx, r8d` / `mov r9d, r8d` / `xor ecx, ecx` 在调用点)。
fn engineHash(chars: [*]const u8, len: usize) callconv(.c) u32 {
    const base = engineBase() orelse return 0;
    const addr = std.math.add(usize, base, flag_offsets.RVA_NAME_HASH) catch return 0;
    const f: *const fn (u32, [*]const u8, u32) callconv(.c) u32 = @ptrFromInt(addr);
    return f(0, chars, @intCast(len));
}

/// `0x1BCF030` 逐字签名(§6.1):`(rcx 不用, rdx=出参 {bucket,inserted}, r8d=哈希,
/// r9=&引擎串, [rsp+0x20]=&候选 id)`。计数器由它自己递增,本函数不碰。
fn engineInsert(hash: u32, chars: [*]const u8, len: usize, candidate: u16) callconv(.c) InsertOutcome {
    if (len == 0 or len > MAX_NAME) return InsertOutcome.failure;
    const base = engineBase() orelse return InsertOutcome.failure;
    const addr = std.math.add(usize, base, flag_offsets.RVA_MAP_EMPLACE) catch return InsertOutcome.failure;
    var name = EngineString.init(chars[0..len]);
    var out: [16]u8 = [_]u8{0} ** 16; // { qword bucket_ptr; u8 inserted; 7 B pad }
    var id = candidate;
    const f: *const fn (usize, *[16]u8, u32, *const EngineString, *const u16) callconv(.c) void = @ptrFromInt(addr);
    f(0, &out, hash, &name, &id);
    const bucket = std.mem.readInt(u64, out[0..8], .little);
    if (bucket == 0) return InsertOutcome.failure;
    const bucket_id = readU16(bucket + BUCKET_ID_OFF) orelse return InsertOutcome.failure;
    if (bucket_id == 0 or bucket_id == SENTINEL) return InsertOutcome.failure;
    return .{ .id = bucket_id, .created = out[8] != 0, .ok = true };
}

/// `0x158300`:`append(vector, index, &name)`,索引取 vector 自己的计数
/// (`[0x2A00DF4]`),名字被**深拷贝**进元素(§6.4)⇒ 栈上对象安全。
fn engineAppend(chars: [*]const u8, len: usize) callconv(.c) void {
    if (len == 0 or len > MAX_NAME) return;
    const base = engineBase() orelse return;
    const fn_addr = std.math.add(usize, base, flag_offsets.RVA_NAME_APPEND) catch return;
    const vector = std.math.add(usize, base, flag_offsets.RVA_NAME_VECTOR) catch return;
    const index = readU32(vector + 0x14) orelse return;
    var name = EngineString.init(chars[0..len]);
    const f: *const fn (usize, u32, *const EngineString) callconv(.c) usize = @ptrFromInt(fn_addr);
    _ = f(vector, index, &name);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "lookup finds an existing name and never inserts" {
    var fake = FakeTable.init(&.{ "neo_hub", "neo_tier1" });
    setTableForTest(fake.table());
    defer setTableForTest(null);
    try testing.expectEqual(@as(?u16, 0), lookup("neo_hub"));
    try testing.expectEqual(@as(?u16, 1), lookup("neo_tier1"));
    try testing.expectEqual(@as(?u16, null), lookup("absent"));
    try testing.expectEqual(@as(usize, 0), fake.insert_calls);
}

test "ensure inserts on miss and returns the counter value" {
    var fake = FakeTable.init(&.{"neo_hub"});
    setTableForTest(fake.table());
    defer setTableForTest(null);
    try testing.expectEqual(@as(?u16, 0), ensure("neo_hub"));
    try testing.expectEqual(@as(?u16, 1), ensure("neo_probe"));
    try testing.expectEqual(@as(?u16, 1), ensure("neo_probe")); // cached, no second insert
    try testing.expectEqual(@as(usize, 1), fake.insert_calls);
}

test "ensure treats 0xFFFF and 0 as failure" {
    var exhausted = FakeTable.initExhausted(); // next_id = 0xFFFF
    setTableForTest(exhausted.table());
    try testing.expectEqual(@as(?u16, null), ensure("neo_probe"));

    var zero = FakeTable.initWithNextId(0);
    setTableForTest(zero.table());
    defer setTableForTest(null);
    try testing.expectEqual(@as(?u16, null), ensure("neo_probe"));
}

// ---------------------------------------------------------------------------
// FakeTable:同一套桶布局的纯 Zig 实现,让 `lookup` 的真实扫描代码在宿主上跑
// ---------------------------------------------------------------------------

/// 假表用真正的 0x40 步长桶布局(哈希 / DIB / 0x30 B 串 / u16 id),所以 `lookup`
/// 走的是生产代码路径,而不是另一份「假 lookup」。插入是标准 robin-hood 落位
/// (探测距离 1 起、空槽 DIB=0),与 §6 的引擎算法同形。
pub const FakeTable = struct {
    pub const SLOTS: usize = 64;
    pub const MASK: u32 = SLOTS - 1;
    const MEM_SLOTS: usize = SLOTS + MAX_EXTRA_PROBE;

    memory: [MEM_SLOTS * BUCKET_STRIDE]u8 = [_]u8{0} ** (MEM_SLOTS * BUCKET_STRIDE),
    next_id: u16 = 1,
    placed: usize = 0,
    insert_calls: usize = 0,
    append_calls: usize = 0,

    pub fn init(names: []const []const u8) FakeTable {
        var f = FakeTable{};
        for (names, 0..) |n, i| _ = f.place(n, @intCast(i));
        // 空表也从一个非 0 号开始:活进程里这张表在启动时已经装了几千个名字,
        // id 0 不会出现在「第一次插入」上(见 ensure 的 0 = 失败口径)。
        f.next_id = if (f.placed == 0) 1 else @intCast(f.placed);
        return f;
    }

    pub fn initExhausted() FakeTable {
        var f = FakeTable{};
        f.next_id = SENTINEL;
        return f;
    }

    pub fn initWithNextId(next: u16) FakeTable {
        var f = FakeTable{};
        f.next_id = next;
        return f;
    }

    pub fn table(self: *FakeTable) Table {
        test_fake = self;
        return .{
            .buckets = @intFromPtr(&self.memory),
            .next_id = &self.next_id,
            .mask = MASK,
            .hash = fakeHash,
            .insert = fakeInsert,
            .append = fakeAppend,
        };
    }

    const PlaceResult = enum { inserted, exists, full };

    fn place(self: *FakeTable, name: []const u8, id: u16) PlaceResult {
        if (name.len == 0 or name.len > MAX_NAME) return .full;
        const h = fnv1a(name);
        var idx: usize = @as(usize, h) & MASK;
        var dist: usize = 1;
        while (idx < MEM_SLOTS) : (dist += 1) {
            const slot = idx * BUCKET_STRIDE;
            const dib = self.memory[slot + BUCKET_DIB_OFF];
            if (dib == 0) {
                @memset(self.memory[slot..][0..BUCKET_STRIDE], 0);
                std.mem.writeInt(u32, self.memory[slot + BUCKET_HASH_OFF ..][0..4], h, .little);
                self.memory[slot + BUCKET_DIB_OFF] = @intCast(dist);
                std.mem.writeInt(u32, self.memory[slot + BUCKET_LEN_OFF ..][0..4], @intCast(name.len), .little);
                std.mem.writeInt(u64, self.memory[slot + BUCKET_CAP_OFF ..][0..8], 0x0f, .little);
                @memcpy(self.memory[slot + BUCKET_CHARS_OFF ..][0..name.len], name);
                std.mem.writeInt(u16, self.memory[slot + BUCKET_ID_OFF ..][0..2], id, .little);
                self.placed += 1;
                return .inserted;
            }
            const len = std.mem.readInt(u32, self.memory[slot + BUCKET_LEN_OFF ..][0..4], .little);
            if (len == name.len and
                std.mem.eql(u8, self.memory[slot + BUCKET_CHARS_OFF ..][0..name.len], name))
                return .exists;
            idx += 1;
        }
        return .full;
    }

    fn findId(self: *FakeTable, name: []const u8) ?u16 {
        var slot: usize = 0;
        while (slot < MEM_SLOTS * BUCKET_STRIDE) : (slot += BUCKET_STRIDE) {
            if (self.memory[slot + BUCKET_DIB_OFF] == 0) continue;
            const len = std.mem.readInt(u32, self.memory[slot + BUCKET_LEN_OFF ..][0..4], .little);
            if (len != name.len) continue;
            if (std.mem.eql(u8, self.memory[slot + BUCKET_CHARS_OFF ..][0..name.len], name))
                return std.mem.readInt(u16, self.memory[slot + BUCKET_ID_OFF ..][0..2], .little);
        }
        return null;
    }
};

fn fnv1a(name: []const u8) u32 {
    var h: u32 = 0x811C9DC5;
    for (name) |b| {
        h ^= b;
        h *%= 0x01000193;
    }
    return h;
}

fn fakeHash(chars: [*]const u8, len: usize) callconv(.c) u32 {
    return fnv1a(chars[0..len]);
}

fn fakeInsert(hash: u32, chars: [*]const u8, len: usize, candidate: u16) callconv(.c) InsertOutcome {
    _ = hash;
    const f = test_fake orelse return InsertOutcome.failure;
    f.insert_calls += 1;
    const name = chars[0..len];
    switch (f.place(name, candidate)) {
        .inserted => {
            f.next_id = candidate +% 1;
            return .{ .id = candidate, .created = true, .ok = true };
        },
        .exists => return .{ .id = f.findId(name) orelse return InsertOutcome.failure, .created = false, .ok = true },
        .full => return InsertOutcome.failure,
    }
}

fn fakeAppend(chars: [*]const u8, len: usize) callconv(.c) void {
    _ = chars;
    _ = len;
    const f = test_fake orelse return;
    f.append_calls += 1;
}
