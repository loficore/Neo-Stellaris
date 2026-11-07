// neo_vtable.zig — C5-ADD 的 body:一个星系一行 `Neo: system <id>`。
//
// **这个模块不装任何东西。** 2026-11-02 第一发否定了「换对象 vtable」那条路
// (§93.2:解析出来的 effect 树不经谓词,`pred_patched=0`),现在的挂载点是
// `neo_dispatch.zig` 在逐系统派发入口 `0x3B0F80` 上的 token detour,它在 token
// 命中时直接调本模块的 `runBody`。
//
// body 只做四件事:读 scope 的 `+0x10`(星系 id)→ 规则筛 → 在栈上合成一个
// `0xF0` 零块、把文案写成 `+0x38` 的 MSVC 短串 → 调官方 `log` 的实现
// `0x185BF60`。`0x185BF60` 只读 `+0x38`/`+0xd0`/`+0xe0`,**不读 `[self]`**,
// 所以不需要虚表;那三格之外的内容它看不到。
//
// C5-WRITE/C5-SCORE 在规则筛之后多走一步 `--act write`:用同一个官方
// `set_variable` body 写 `neo_mark = id` 与 `neo_score = scores[id]`(两个栈上
// 合成对象),值都按 1e-5 定点编码。
//
// 不写引擎内存、不改对象 `[self]`、不 FreeLibrary。

const std = @import("std");
const graph_trigger = @import("../scripted/graph_trigger.zig");
const builtin = @import("builtin");
const offsets = @import("../shared/offsets.zig");
const windows = @import("../hooking/windows.zig");
const neo_effect = @import("neo_effect.zig");
const neo_state = @import("neo_state.zig");
const chokepoint_table = @import("chokepoint_table.zig");
const neo_js_host = @import("neo_js_host.zig");
const keyword_registry = @import("../scripted/keyword_registry.zig");

const is_windows = builtin.os.tag == .windows;

/// §80.2 的 scope 形状(`0x7f7f20` 那一类指针):`+0x08` mask、`+0x10` id。
pub const SCOPE_MASK_OFF: usize = 0x08;
pub const SCOPE_ID_OFF: usize = 0x10;

/// §90.4 — 我们自己要调的那个官方 `log` 实现。
pub const RVA_LOG_EFFECT_EXEC: usize = offsets.keyword_reg.RVA_LOG_EFFECT_EXEC;

/// C5-WRITE — `set_variable` 的 per-scope body(`0x25EA560` 的 slot[9]/`+0x48`)。
pub const RVA_STATE_BODY: usize = 0x188E1D0;
/// 同一个类的 vtable;官方 `create` 把它写进 `[obj+0]`。
pub const RVA_STATE_VTABLE: usize = 0x25EA560;

/// Phase 2 A1 — `set_star_flag` 的 `+0x48` body(`0x26049B0` 的 slot[9])。
/// 它自己经 `[vptr+0xE0]` 把 scope 解析成系统 flag 容器,再调官方写手 `0x1bce180`。
pub const RVA_STAR_FLAG_BODY: usize = 0x180F8E0;

/// `[obj+0]` 必须是**绝对地址**:body 第一件事是 `mov rax,[rdi]; call [rax+0xE0]`
/// (0x180F930 / 0x180F937),所以这里存的是 base + RVA 之后的值,不是常量本身。
/// 2026-11-07 C2 实机前这一格写的是裸 RVA —— 只要 body 真跑起来就会跳进未映射页;
/// 这一发因 mint 先失败而没跑到,缺陷由静态读回确认(见 evidence 卷 C2 一节)。
pub const RVA_STAR_FLAG_VTABLE: usize = 0x26049B0;

/// 每个进程最多 mint 多少个 flag 名字的 token id。静态 holder 永不释放
/// (`keyword_registry.getToken` 的寿命警告);超过就 fail-closed。
pub const MAX_MINTED_FLAGS: usize = 64;

pub const RULE_HITS: usize = 64;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var log_effect_addr: usize = 0;
var state_body_addr: usize = 0;
var state_vtable_addr: usize = 0;
var star_flag_body_addr: usize = 0;
var star_flag_vtable_addr: usize = 0;

/// 最近一次 flag 名 mint 的**原始**返回值(0 = mint 失败)。诊断用:
/// `set_star_flag` 的对象把 id 存成 u16,而 token 空间是 u32 —— 若引擎发回来的
/// id 超过 0xFFFF,这里能把它读到,而不是笼统一个 `no_flag_token`。
var last_flag_mint_raw: u32 = 0;

/// 0 = 只写日志(C5-ADD 的原行为),1 = 日志 + 写两个系统变量
/// (`neo_mark = id` / `neo_score = 图分数`)。
/// 与 `rule_bits` 一样是单个原子 u32:dispatch 线程永远读不到半更新值。
var act_mode: u32 = 0;

var stat_calls: u64 = 0;
var stat_matched: u64 = 0;
var stat_log_calls: u64 = 0;
var stat_writes: u64 = 0;
var stat_skipped: u64 = 0;
var stat_score_writes: u64 = 0;
var stat_score_skipped: u64 = 0;
/// C5-PARAM: how many times `runSet` actually called the official body. The
/// pair with `setCalls()` is the spec's §8 triage (`calls>0, runs=0` = address
/// never resolved).
var stat_set_runs: u64 = 0;
var stat_null_scope: u64 = 0;
var stat_non_system_scope: u64 = 0;
var last_id: u32 = 0;

var hit_count: u64 = 0;
var hits: [RULE_HITS]u32 = undefined;

// ---------------------------------------------------------------------------
// The per-system body
// ---------------------------------------------------------------------------

fn plausible(p: usize) bool {
    return p >= 0x10000 and p <= 0x00007FFF_FFFF_0000 and (p & 7) == 0;
}

fn readU32(addr: usize, comptime off: usize) u32 {
    if (!plausible(addr)) return 0;
    const base: [*]const u8 = @ptrFromInt(addr);
    return std.mem.readInt(u32, base[off..][0..4], .little);
}

fn scopeReadable(scope: usize) bool {
    if (!plausible(scope)) return false;
    if (!is_windows) return true;
    return windows.isCommitted(scope);
}

/// §80.2/§91.7 — the `every_system` loop stamps `mask = 0x80` on the scope it
/// hands to each child.  That cell is the only *type* signal we have; an id in
/// `0..786` is an observation, `mask == 0x80` is the engine saying "system
/// scope" (review M-1).
pub fn isSystemScope(mask: u32) bool {
    return mask == 0x80;
}

/// 当次派发给我们的 scope 确实是 system scope 时返回它的 id(`+0x10`),否则 `null`。
///
/// Runtime JS(Track A)要拿它做两件事:把「JS 只拿 id」这条纪律固定下来(`onSystem`
/// 读一次),以及**在写之前核对** `setVariable(id, …)` 的 id 与当次 scope 一致 ——
/// 写走的是 scope,id 只是 JS 侧的镜像;两者不一致时拒绝写,而不是把值写进另一个星系。
pub fn systemScopeId(scope: u64) ?u32 {
    if (scope == 0) return null;
    const s: usize = @intCast(scope);
    if (!scopeReadable(s)) return null;
    if (!isSystemScope(readU32(s, SCOPE_MASK_OFF))) return null;
    return readU32(s, SCOPE_ID_OFF);
}

fn recordHit(id: u32) void {
    const nth = @atomicRmw(u64, &hit_count, .Add, 1, .monotonic);
    if (nth < RULE_HITS) hits[@intCast(nth)] = id;
}

/// C5-WRITE 的动作分支:`set_variable` 的官方 body 收 `(self, scope)`。
/// 合成对象在栈上、vtable 由我们摆;写进引擎的是**官方 body 自己**做的。
///
/// 名字与值由调用方给:Runtime JS 的 `s.setVariable(name, value)`(Track A)用的
/// 就是这一条路径,不是另一套写手。名字必须 **≤ 15 字节**(MSVC 内联串上限,
/// `neo_state.layoutNumber` 的注释),超长会被静默截断成另一个变量名 —— 所以这里
/// 直接拒绝,而不是写一个错的。
/// 返回是否真的调了 body —— 地址没解析到、名字非法时都是 `false`。
pub fn writeVariable(name: []const u8, number: u32, scope: u64) bool {
    if (state_body_addr == 0 or state_vtable_addr == 0) return false;
    if (name.len == 0 or name.len > neo_state.SSO_MAX) return false;
    var obj: [neo_state.OBJECT_SIZE]u8 align(8) = undefined;
    neo_state.layoutNumber(&obj, name, number);
    std.mem.writeInt(u64, obj[0..8], state_vtable_addr, .little);
    const body: *const fn (u64, u64) callconv(.c) void = @ptrFromInt(state_body_addr);
    body(@intFromPtr(&obj), scope);
    return true;
}

fn writeState(id: u32, scope: u64) bool {
    return writeVariable(neo_state.VAR_NAME, id, scope);
}

// ---------------------------------------------------------------------------
// Phase 2 A1/A2: `s.setStarFlag` — the official `set_star_flag` body
// ---------------------------------------------------------------------------
//
// Two official pieces, no fabrication of engine state:
//   * `0x180f8e0` (`set_star_flag`'s `+0x48` slot) reads the flag token id from
//     `[obj+0xC0]`, resolves the scope through `[vptr+0xE0]` (→ `0x397490`, which
//     for a mask-0x80 scope returns `0x393970(scope) + 0x5f8`) and calls the
//     engine's own flag writer `0x1bce180`;
//   * `0x1D13270` mints the name→token id (`keyword_registry.mintToken`), the same
//     key the script lexer uses. Nothing is inserted into a scripted db.
//
// The object is a zeroed stack block with the official vtable at `[0]` and the id
// at `+0xC0` (`neo_state.layoutStarFlag`); `[+0xE8] == 0` selects the direct-id
// branch the engine itself takes when the flag was parsed as a token.

/// Test seam: the production path resolves the engine base; Linux tests inject a
/// name→id map so the layout and the call shape stay testable without QuickJS or
/// the engine.
pub const TokenMinter = *const fn (name: []const u8) ?u32;

var token_minter: ?TokenMinter = null;

pub fn setTokenMinterForTest(m: ?TokenMinter) void {
    token_minter = m;
}

/// Static holders: `0x1D13270` may retain the chars pointer, so the backing must
/// outlive the call (`keyword_registry.getToken`). Append-only, never freed.
var mint_holders: [MAX_MINTED_FLAGS]keyword_registry.NameHolder = undefined;
var mint_holder_count: usize = 0;
var mint_names: [MAX_MINTED_FLAGS][neo_state.SSO_MAX]u8 = undefined;
var mint_name_lens: [MAX_MINTED_FLAGS]u8 = undefined;
var mint_ids: [MAX_MINTED_FLAGS]u32 = undefined;

/// 最近一次 mint 的原始 id(0 = 失败)。见 `last_flag_mint_raw` 的注释。
pub fn lastFlagMintRaw() u32 {
    return last_flag_mint_raw;
}

/// Mint the token id a flag name maps to. Lower-cased first because the engine's
/// token lookup case-folds (§25.5); names longer than the MSVC SSO limit (15 B) are
/// rejected rather than heap-allocated, same bound `setVariable` uses.
///
/// Repeat calls with the same name hit the cache: otherwise every `hasStarFlag`
/// would append a holder and exhaust `MAX_MINTED_FLAGS` after 64 evaluations.
///
/// 返回**原始 u32**:调用方自己决定 u16 是否够用(`lastFlagMintRaw` 让失败也能读回)。
pub fn mintFlagTokenRaw(name: []const u8) ?u32 {
    last_flag_mint_raw = 0;
    if (name.len == 0 or name.len > neo_state.SSO_MAX) return null;

    var lower: [neo_state.SSO_MAX]u8 = undefined;
    for (name, 0..) |ch, i| lower[i] = std.ascii.toLower(ch);
    const key = lower[0..name.len];

    var i: usize = 0;
    while (i < mint_holder_count) : (i += 1) {
        if (std.mem.eql(u8, mint_names[i][0..mint_name_lens[i]], key)) {
            last_flag_mint_raw = mint_ids[i];
            return mint_ids[i];
        }
    }
    if (mint_holder_count >= MAX_MINTED_FLAGS) return null;

    var id: u32 = 0;
    if (token_minter) |m| {
        id = m(key) orelse return null;
    } else {
        if (comptime !is_windows) return null;
        const base = @intFromPtr(windows.moduleFunction(0) catch return null);
        const eng = keyword_registry.Engine.map(base);
        mint_holders[mint_holder_count] = keyword_registry.NameHolder.inlineSso(key);
        const holder = &mint_holders[mint_holder_count];
        id = keyword_registry.mintToken(&eng, holder) catch return null;
    }
    last_flag_mint_raw = id;
    if (id == 0) return null;
    @memcpy(mint_names[mint_holder_count][0..key.len], key);
    mint_name_lens[mint_holder_count] = @intCast(key.len);
    mint_ids[mint_holder_count] = id;
    mint_holder_count += 1;
    return id;
}

/// u16 版本:`set_star_flag` 的对象只有 u16 的槽(`[obj+0xC0]`)。超界即 fail-closed
/// —— 调用方应当用 `mintFlagTokenRaw` 把原始值记进日志,否则「超界」和「没 mint 出来」
/// 在读数上无法区分。
pub fn mintFlagToken(name: []const u8) ?u16 {
    const raw = mintFlagTokenRaw(name) orelse return null;
    if (raw > std.math.maxInt(u16)) return null;
    return @intCast(raw);
}

/// `s.setStarFlag(name)` 的执行体。返回是否真的调了官方 body。
pub fn setStarFlag(flag_name: []const u8, scope: u64) bool {
    if (star_flag_body_addr == 0) return false;
    const id = mintFlagToken(flag_name) orelse return false;
    return setStarFlagId(id, scope);
}

/// 已经拿到 token id 的版本(测试与 `hasStarFlag` 共用一次 mint)。
pub fn setStarFlagId(flag_id: u16, scope: u64) bool {
    if (star_flag_body_addr == 0 or star_flag_vtable_addr == 0) return false;
    var obj: [neo_state.STAR_FLAG_OBJECT_SIZE]u8 align(8) = undefined;
    neo_state.layoutStarFlag(&obj, flag_id);
    std.mem.writeInt(u64, obj[0..8], star_flag_vtable_addr, .little);
    const body: *const fn (u64, u64) callconv(.c) void = @ptrFromInt(star_flag_body_addr);
    body(@intFromPtr(&obj), scope);
    return true;
}

/// `neo_score` 的来源。0 = 烘焙表(C5-SCORE 原行为),1 = 活体重算(M5)。
/// 单个原子 u32:dispatch 线程永远读不到半更新值,与 `act_mode` 同一条纪律。
var score_source: u32 = graph_trigger.SCORE_SOURCE_TABLE;

/// `0` 接受;`-1` = 未知来源(越界值不许静默当成 table)。
pub fn setScoreSource(mode: u32) i32 {
    if (mode > graph_trigger.SCORE_SOURCE_LIVE) return -1;
    @atomicStore(u32, &score_source, mode, .monotonic);
    return 0;
}

pub fn liveSnapshot() @TypeOf(graph_trigger.liveSnapshot()) {
    return graph_trigger.liveSnapshot();
}

/// 边集内容哈希(16 B 导出的取值面):哈希 + 这一趟读到的边数。
pub fn liveHashSnapshot() @TypeOf(graph_trigger.liveHashSnapshot()) {
    return graph_trigger.liveHashSnapshot();
}

/// verify 通路的两个计数:`verified` = 定时核对跑了且图没变;`verify_failed` =
/// 核对这一趟读失败(fail-closed:分数与哈希都不动)。它们不进 8 词统计契约。
pub fn liveVerifySnapshot() struct { verified: u64, verify_failed: u64 } {
    const s = graph_trigger.liveSnapshot().stats;
    return .{ .verified = s.verified, .verify_failed = s.verify_failed };
}

pub fn resetLiveSource() void {
    graph_trigger.resetLive();
}

pub fn scoreSource() u32 {
    return @atomicLoad(u32, &score_source, .monotonic);
}

/// C5-SCORE 的分数来源:烘焙表,或(在 live 源下)**每次求值都问活体图**。
/// live 源拿不到就返回 null(`score_skipped`),**绝不回退到烘焙表** —— 两条源混用会让
/// "这个分数是图算的还是表查的"这个判词失去意义(M5 §7)。
pub fn scoreFor(id: u32) ?u16 {
    if (scoreSource() == graph_trigger.SCORE_SOURCE_LIVE) return graph_trigger.liveScore(id);
    if (id >= chokepoint_table.SCORE_COUNT) return null;
    return chokepoint_table.scores[id];
}

/// C5-SCORE:`set_variable neo_score = scores[id]`。与 `writeState` 同形 ——
/// 同一个官方 body、同一个栈上合成对象,只有名字与值不同。
/// 返回是否真的写了;越界 id 与未解析地址都算 `false`(计 `score_skipped`)。
fn writeScore(id: u32, scope: u64) bool {
    const score = scoreFor(id) orelse return false;
    return writeVariable(neo_state.SCORE_NAME, score, scope);
}

/// C5-PARAM: the `neo_set` body. Transparent forward — the loader already
/// parsed `which` / `value` into this object through the shared class_info
/// (`set_variable`'s vtable slot[5] = `0x188E240`), so all we do is hand the
/// same object and scope to the official body (`0x188E1D0`). No engine memory
/// is written by us; the official body owns the write.
pub fn runSet(child: u64, scope: u64, a3: u64) u64 {
    _ = a3;
    if (state_body_addr == 0) return 0;
    const body: *const fn (u64, u64) callconv(.c) void = @ptrFromInt(state_body_addr);
    body(child, scope);
    _ = @atomicRmw(u64, &stat_set_runs, .Add, 1, .monotonic);
    return 0;
}

/// The per-system body. Order is load-bearing (plan Task 2 Step 3): count →
/// scope gate → read id → rule → compose → count → call. Nothing here writes
/// engine memory; the only engine call is the official `log` implementation
/// with a stack object.  Since Phase 1 Track A the same hit is then handed to
/// the Runtime JS host (`notifyHost` → `neo_js_host.onSystem`); the host owns
/// its own writes and only ever reaches the engine through the official
/// `set_variable` body.
pub fn runBody(scope: u64, a3: u64) u64 {
    _ = @atomicRmw(u64, &stat_calls, .Add, 1, .monotonic);
    if (!scopeReadable(@intCast(scope))) {
        _ = @atomicRmw(u64, &stat_null_scope, .Add, 1, .monotonic);
        return 0;
    }
    if (!isSystemScope(readU32(@intCast(scope), SCOPE_MASK_OFF))) {
        _ = @atomicRmw(u64, &stat_non_system_scope, .Add, 1, .monotonic);
        return 0;
    }
    const id = readU32(@intCast(scope), SCOPE_ID_OFF);
    @atomicStore(u32, &last_id, id, .monotonic);
    if (!neo_effect.matches(id)) return 0;
    if (log_effect_addr == 0) return 0;
    _ = @atomicRmw(u64, &stat_matched, .Add, 1, .monotonic);
    recordHit(id);

    // C5-WRITE:先写状态,再写日志 —— 两个读数在同一次命中里成对出现。
    // C5-SCORE:同一个门里再写一个 `neo_score`,它是图分数而不是 id。
    if (@atomicLoad(u32, &act_mode, .monotonic) == 1) {
        if (writeState(id, scope)) {
            _ = @atomicRmw(u64, &stat_writes, .Add, 1, .monotonic);
        } else {
            _ = @atomicRmw(u64, &stat_skipped, .Add, 1, .monotonic);
        }
        if (writeScore(id, scope)) {
            _ = @atomicRmw(u64, &stat_score_writes, .Add, 1, .monotonic);
        } else {
            _ = @atomicRmw(u64, &stat_score_skipped, .Add, 1, .monotonic);
        }
    }

    // MSVC std::string at +0x38 of a zeroed 0xF0 block — `0x185BF60` reads
    // three cells there (+0x38 text, +0xd0 empty string, +0xe0 previous length)
    // and never dereferences `[self]`, so no vtable is required.
    var obj: [0xF0]u8 = [_]u8{0} ** 0xF0;
    var text: [32]u8 = undefined;
    const line = neo_effect.formatText(&text, id);
    neo_effect.writeSso(@ptrCast(&obj[0x38]), line);

    _ = @atomicRmw(u64, &stat_log_calls, .Add, 1, .monotonic);
    const log_fn: *const fn (u64, u64, u64) callconv(.c) u64 = @ptrFromInt(log_effect_addr);
    const rc = log_fn(@intFromPtr(&obj), scope, a3);

    // Runtime JS(Phase 1 Track A):官方 `log` 之后,把同一个逐系统命中交给 host。
    // 这里是**游戏主线程**的同步区间 —— host 的 QuickJS context 就在这条路径上懒建
    // (计划 Review Focus 1);`scope` 只这一趟有效,host 不跨调用保存它。
    // 非 Windows 目标上 `notifyHost` 走空实现:c2_tests 那条 native 根不链 QuickJS,
    // 所以 `neo_js_host` 的那条 `@import` 只在 Windows 分支里被真正解析。
    notifyHost(id, scope);
    return rc;
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Resolve the engine base into the one address the body needs. The donor-vtable
/// copy this module used to build is gone: nothing ever installed it (§93.2).
pub fn resolveFromGame(game_base: usize) !void {
    const addr = game_base + RVA_LOG_EFFECT_EXEC;
    if (!plausible(addr)) return error.BadLogEffectPointer;
    log_effect_addr = addr;

    // C5-WRITE 的两个地址独立解析:拿不到就只记 `skipped`,不连累 C5-ADD 的日志路径。
    const body = game_base + RVA_STATE_BODY;
    const vtable = game_base + RVA_STATE_VTABLE;
    state_body_addr = if (plausible(body)) body else 0;
    state_vtable_addr = if (plausible(vtable)) vtable else 0;

    // Phase 2: `set_star_flag` 的 body 独立解析(fail-closed,不影响变量写)。
    const flag_body = game_base + RVA_STAR_FLAG_BODY;
    star_flag_body_addr = if (plausible(flag_body)) flag_body else 0;
    const flag_vtable = game_base + RVA_STAR_FLAG_VTABLE;
    star_flag_vtable_addr = if (plausible(flag_vtable)) flag_vtable else 0;
}

/// `0` = 只写日志 | `1` = 日志 + 写系统变量。其它值按「开」处理吗?
/// 不 —— 只有精确的 1 开写,其余一律关,免得上层传错常量时悄悄改世界。
pub fn setAct(mode: u32) void {
    @atomicStore(u32, &act_mode, mode, .monotonic);
}

/// 官方 `set_variable` body / vtable 是否已解析到。
/// Runtime JS 的 `s.setVariable` 用它在第一次写之前补一次 `resolveFromGame`
/// (它不由 `C1Run` 负责;主线程懒解析,失败就 fail-closed 不写)。
pub fn stateResolved() bool {
    return state_body_addr != 0 and state_vtable_addr != 0;
}

/// `s.setStarFlag` 的 body/vtable 是否都已解析到(与 `stateResolved` 独立)。
/// 两者缺一都不可写:`[obj+0]` 必须是绝对 vtable 地址,body 才会经 `[vptr+0xE0]` 走到
/// 官方 scope 解析。
pub fn flagsResolved() bool {
    return star_flag_body_addr != 0 and star_flag_vtable_addr != 0;
}

/// 测试专用:把 `set_star_flag` body + vtable 直接摆上。
pub fn armFlagPathForTest(body: usize, vtable: usize) void {
    star_flag_body_addr = body;
    star_flag_vtable_addr = vtable;
}

/// 测试专用:把写路径的两个地址直接摆上(生产侧只有 `resolveFromGame` 能设)。
/// 只在 Debug 测试根里被调用;不改任何引擎字节。
pub fn armWritePathForTest(body: usize, vtable: usize) void {
    state_body_addr = body;
    state_vtable_addr = vtable;
}

/// Runtime JS 的接收端。生产路径是 `neo_js_host.onSystem`;native 测试根不链
/// QuickJS,所以 `runBody` 经这一层转交 —— 测试用 `setHostHookForTest` 把它换成
/// 一个记录器,从而在 Linux 上钉住「同一 id/同一 scope、且在官方 log 之后」这条接线。
var host_hook: ?*const fn (id: u32, scope: u64) void = null;

pub fn setHostHookForTest(h: ?*const fn (id: u32, scope: u64) void) void {
    host_hook = h;
}

fn notifyHost(id: u32, scope: u64) void {
    if (host_hook) |h| {
        h(id, scope);
        return;
    }
    if (comptime is_windows) neo_js_host.onSystem(id, scope);
}

// ---------------------------------------------------------------------------
// Readouts (the stats line lives in neo_dispatch.zig, which owns the hook state)
// ---------------------------------------------------------------------------

pub fn calls() u64 {
    return @atomicLoad(u64, &stat_calls, .monotonic);
}

pub fn matched() u64 {
    return @atomicLoad(u64, &stat_matched, .monotonic);
}

pub fn logCalls() u64 {
    return @atomicLoad(u64, &stat_log_calls, .monotonic);
}

/// 我们真的调了官方 `set_variable` body 的次数(= `matched` 中开写的那部分)。
pub fn writes() u64 {
    return @atomicLoad(u64, &stat_writes, .monotonic);
}

/// 该写但 body/vtable 地址没解析到的次数 ⇒ `writes=0 skipped>0` 时查 `resolveFromGame`。
pub fn skipped() u64 {
    return @atomicLoad(u64, &stat_skipped, .monotonic);
}

/// C5-SCORE:图分数真的写进 `neo_score` 的次数。
/// 判据是 `score_writes == matched`;小于它时查越界 id 或未解析地址。
pub fn scoreWrites() u64 {
    return @atomicLoad(u64, &stat_score_writes, .monotonic);
}

/// 该写分数但没写的次数(越界 id,或 body/vtable 地址没解析到)。
pub fn scoreSkipped() u64 {
    return @atomicLoad(u64, &stat_score_skipped, .monotonic);
}

/// C5-PARAM: `runSet` really reached the official `set_variable` body.
pub fn setRuns() u64 {
    return @atomicLoad(u64, &stat_set_runs, .monotonic);
}

pub fn lastId() u32 {
    return @atomicLoad(u32, &last_id, .monotonic);
}

pub fn ruleHitsRecorded() u32 {
    return @intCast(@min(@atomicLoad(u64, &hit_count, .monotonic), RULE_HITS));
}

pub fn nullScope() u64 {
    return @atomicLoad(u64, &stat_null_scope, .monotonic);
}

pub fn nonSystemScopes() u64 {
    return @atomicLoad(u64, &stat_non_system_scope, .monotonic);
}

pub fn resetForTest() void {
    log_effect_addr = 0;
    state_body_addr = 0;
    state_vtable_addr = 0;
    star_flag_body_addr = 0;
    star_flag_vtable_addr = 0;
    last_flag_mint_raw = 0;
    token_minter = null;
    mint_holder_count = 0;
    act_mode = 0;
    stat_calls = 0;
    stat_matched = 0;
    stat_log_calls = 0;
    stat_writes = 0;
    stat_skipped = 0;
    stat_score_writes = 0;
    stat_score_skipped = 0;
    stat_set_runs = 0;
    stat_null_scope = 0;
    stat_non_system_scope = 0;
    last_id = 0;
    hit_count = 0;
    host_hook = null;
    @memset(std.mem.asBytes(&hits), 0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "set_runs starts at zero and reset clears it" {
    resetForTest();
    try std.testing.expectEqual(@as(u64, 0), setRuns());
}

var fwd_self: u64 = 0;
var fwd_scope: u64 = 0;

fn stubForward(self_ptr: u64, scope: u64) callconv(.c) void {
    fwd_self = self_ptr;
    fwd_scope = scope;
}

test "runSet forwards the same child and scope to the official body and counts the run" {
    resetForTest();
    state_body_addr = @intFromPtr(&stubForward);
    const r = runSet(0x1234_5678, 0x9ABC_DEF0, 0);
    try std.testing.expectEqual(@as(u64, 0), r);
    try std.testing.expectEqual(@as(u64, 0x1234_5678), fwd_self);
    try std.testing.expectEqual(@as(u64, 0x9ABC_DEF0), fwd_scope);
    try std.testing.expectEqual(@as(u64, 1), setRuns());
}

test "runSet does not call or count when the body address is unresolved" {
    resetForTest();
    fwd_self = 0;
    fwd_scope = 0;
    const r = runSet(0x1234_5678, 0x9ABC_DEF0, 0);
    try std.testing.expectEqual(@as(u64, 0), r);
    try std.testing.expectEqual(@as(u64, 0), fwd_self);
    try std.testing.expectEqual(@as(u64, 0), setRuns());
}

test "rule hits are recorded in call order and capped" {
    resetForTest();
    var i: u32 = 0;
    while (i < RULE_HITS + 5) : (i += 1) recordHit(100 + i);
    try std.testing.expectEqual(@as(u32, RULE_HITS), ruleHitsRecorded());
    try std.testing.expectEqual(@as(u32, 100), hits[0]);
    try std.testing.expectEqual(@as(u32, 100 + RULE_HITS - 1), hits[RULE_HITS - 1]);
}

test "resetForTest zeroes the counters but keeps nothing else" {
    resetForTest();
    stat_calls = 3;
    stat_matched = 2;
    stat_log_calls = 1;
    recordHit(7);
    resetForTest();
    try std.testing.expectEqual(@as(u64, 0), calls());
    try std.testing.expectEqual(@as(u64, 0), matched());
    try std.testing.expectEqual(@as(u64, 0), logCalls());
    try std.testing.expectEqual(@as(u32, 0), ruleHitsRecorded());
    try std.testing.expectEqual(@as(usize, 0), log_effect_addr);
}

test "the scope offsets are the ones the dispatch site documents" {
    try std.testing.expectEqual(@as(usize, 0x10), SCOPE_ID_OFF);
    try std.testing.expectEqual(@as(usize, 0x08), SCOPE_MASK_OFF);
    try std.testing.expectEqual(@as(usize, 0x185BF60), RVA_LOG_EFFECT_EXEC);
}

test "the C5-WRITE body and vtable are the load-bearing RVAs" {
    try std.testing.expectEqual(@as(usize, 0x188E1D0), RVA_STATE_BODY);
    try std.testing.expectEqual(@as(usize, 0x25EA560), RVA_STATE_VTABLE);
    resetForTest();
    try std.testing.expectEqual(@as(u64, 0), writes());
    try std.testing.expectEqual(@as(u64, 0), skipped());
}

test "the system-scope marker is 0x80" {
    try std.testing.expect(isSystemScope(0x80));
    try std.testing.expect(!isSystemScope(0));
    try std.testing.expect(!isSystemScope(0x81));
}

test "scoreFor indexes the baked table and refuses out-of-range ids" {
    try std.testing.expectEqual(@as(?u16, chokepoint_table.scores[0]), scoreFor(0));
    try std.testing.expectEqual(@as(?u16, chokepoint_table.scores[786]), scoreFor(786));
    try std.testing.expectEqual(@as(?u16, null), scoreFor(787));
}

test "the score counters start at zero after reset" {
    resetForTest();
    try std.testing.expectEqual(@as(u64, 0), scoreWrites());
    try std.testing.expectEqual(@as(u64, 0), scoreSkipped());
}

// --- writeScore's payload ---------------------------------------------------
// The score tests above only prove the table lookup; these pin what actually
// reaches the engine, because a wrong name or value is invisible until a live
// shot spends its budget (§94.6's "不能说" is about the live readout, not this).

var seen_calls: usize = 0;
var seen_names: [4][16]u8 = undefined;
var seen_values: [4]u64 = undefined;
var seen_vtables: [4]u64 = undefined;

fn stubSetVariable(self_ptr: u64, scope: u64) callconv(.c) void {
    _ = scope;
    if (seen_calls < seen_values.len) {
        const base: [*]const u8 = @ptrFromInt(self_ptr);
        @memcpy(&seen_names[seen_calls], base[neo_state.NAME_STRING_OFF..][0..16]);
        seen_values[seen_calls] = std.mem.readInt(u64, base[neo_state.VALUE_CELL_OFF..][0..8], .little);
        seen_vtables[seen_calls] = std.mem.readInt(u64, base[0..8], .little);
    }
    seen_calls += 1;
}

fn stubLog(self_ptr: u64, scope: u64, a3: u64) callconv(.c) u64 {
    _ = self_ptr;
    _ = scope;
    _ = a3;
    return 0;
}

fn armStubs() void {
    resetForTest();
    seen_calls = 0;
    state_body_addr = @intFromPtr(&stubSetVariable);
    state_vtable_addr = RVA_STATE_VTABLE;
}

test "writeScore writes neo_score with the table score in 1e-5 fixed point" {
    armStubs();
    try std.testing.expect(writeScore(0, 0));
    try std.testing.expectEqual(@as(usize, 1), seen_calls);
    try std.testing.expectEqualStrings(neo_state.SCORE_NAME, seen_names[0][0..neo_state.SCORE_NAME.len]);
    try std.testing.expectEqual(neo_state.encodeNumber(chokepoint_table.scores[0]), seen_values[0]);
    try std.testing.expectEqual(@as(u64, RVA_STATE_VTABLE), seen_vtables[0]);
}

test "writeScore refuses an out-of-range id and an unresolved body" {
    armStubs();
    try std.testing.expect(!writeScore(@intCast(chokepoint_table.SCORE_COUNT), 0));
    try std.testing.expectEqual(@as(usize, 0), seen_calls);
    state_body_addr = 0;
    try std.testing.expect(!writeScore(0, 0));
    try std.testing.expectEqual(@as(usize, 0), seen_calls);
}

test "runBody counts one score write beside the state write" {
    armStubs();
    log_effect_addr = @intFromPtr(&stubLog);
    setAct(1);
    neo_effect.setRule(1, 0);
    defer neo_effect.setRule(0, 0);

    var scope: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, scope[SCOPE_MASK_OFF..][0..4], 0x80, .little);
    std.mem.writeInt(u32, scope[SCOPE_ID_OFF..][0..4], 7, .little);
    _ = runBody(@intFromPtr(&scope), 0);

    try std.testing.expectEqual(@as(u64, 1), calls());
    try std.testing.expectEqual(@as(u64, 1), matched());
    try std.testing.expectEqual(@as(u64, 1), writes());
    try std.testing.expectEqual(@as(u64, 1), scoreWrites());
    try std.testing.expectEqual(@as(u64, 0), scoreSkipped());
    // Two calls: `neo_mark` first (C5-WRITE), then `neo_score` (C5-SCORE).
    try std.testing.expectEqual(@as(usize, 2), seen_calls);
    try std.testing.expectEqualStrings(neo_state.SCORE_NAME, seen_names[1][0..neo_state.SCORE_NAME.len]);
}

// --- Track A (Runtime JS): the generic write path and the scope id gate -------

test "writeVariable writes any script name through the official body" {
    armStubs();
    // Runtime JS's `s.setVariable('neo_score', 286)` lands on the same body the
    // C5-WRITE/C5-SCORE paths use — only the name and value come from JS.
    try std.testing.expect(writeVariable("custom_var", 286, 0));
    try std.testing.expectEqual(@as(usize, 1), seen_calls);
    try std.testing.expectEqualStrings("custom_var", seen_names[0][0.."custom_var".len]);
    try std.testing.expectEqual(neo_state.encodeNumber(286), seen_values[0]);
    try std.testing.expectEqual(@as(u64, RVA_STATE_VTABLE), seen_vtables[0]);
}

test "writeVariable refuses a name the MSVC short string would truncate" {
    armStubs();
    // 16 bytes would be silently cut to 15 by `writeSso` -> a *different* variable
    // every tick.  Reject instead of writing a wrong name.
    try std.testing.expect(!writeVariable("0123456789abcdef", 1, 0));
    try std.testing.expectEqual(@as(usize, 0), seen_calls);
    try std.testing.expect(!writeVariable("", 1, 0));
    try std.testing.expectEqual(@as(usize, 0), seen_calls);
    // 15 bytes is the boundary and must pass.
    try std.testing.expect(writeVariable("0123456789abcde", 1, 0));
    try std.testing.expectEqual(@as(usize, 1), seen_calls);
}

test "writeVariable does not write when the body is unresolved" {
    armStubs();
    state_body_addr = 0;
    try std.testing.expect(!writeVariable("neo_score", 1, 0));
    try std.testing.expectEqual(@as(usize, 0), seen_calls);
}

test "systemScopeId accepts only a 0x80 system scope and reads the id at +0x10" {
    var scope: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, scope[SCOPE_MASK_OFF..][0..4], 0x80, .little);
    std.mem.writeInt(u32, scope[SCOPE_ID_OFF..][0..4], 4242, .little);
    try std.testing.expectEqual(@as(?u32, 4242), systemScopeId(@intFromPtr(&scope)));

    // 0x81 is not the system marker (§80.2: only the `every_system` stamp is 0x80).
    std.mem.writeInt(u32, scope[SCOPE_MASK_OFF..][0..4], 0x81, .little);
    try std.testing.expectEqual(@as(?u32, null), systemScopeId(@intFromPtr(&scope)));

    // Null and implausible pointers are refused, not dereferenced.
    try std.testing.expectEqual(@as(?u32, null), systemScopeId(0));
    try std.testing.expectEqual(@as(?u32, null), systemScopeId(0x1000));
}

// --- Track A wiring: runBody -> Runtime JS host ------------------------------

var host_hook_calls: usize = 0;
var host_hook_id: u32 = 0;
var host_hook_scope: u64 = 0;
var seq: u32 = 0;
var seq_log: u32 = 0;
var seq_host: u32 = 0;

fn stubLogSeq(self_ptr: u64, scope: u64, a3: u64) callconv(.c) u64 {
    _ = self_ptr;
    _ = scope;
    _ = a3;
    seq_log = seq;
    seq += 1;
    return 0;
}

fn hostHook(id: u32, scope: u64) void {
    host_hook_calls += 1;
    host_hook_id = id;
    host_hook_scope = scope;
    seq_host = seq;
    seq += 1;
}

test "runBody hands the same id and scope to the Runtime JS host, after the official log" {
    resetForTest();
    defer {
        setHostHookForTest(null);
        resetForTest();
    }
    log_effect_addr = @intFromPtr(&stubLogSeq);
    setHostHookForTest(&hostHook);
    host_hook_calls = 0;
    host_hook_id = 0xFFFF_FFFF;
    host_hook_scope = 0;
    seq = 0;
    seq_log = 0;
    seq_host = 0;
    neo_effect.setRule(1, 0); // every system
    defer neo_effect.setRule(0, 0);

    var scope: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, scope[SCOPE_MASK_OFF..][0..4], 0x80, .little);
    std.mem.writeInt(u32, scope[SCOPE_ID_OFF..][0..4], 7, .little);
    _ = runBody(@intFromPtr(&scope), 0);

    try std.testing.expectEqual(@as(usize, 1), host_hook_calls);
    try std.testing.expectEqual(@as(u32, 7), host_hook_id);
    // The scope is passed through unchanged — the host re-reads the id from it.
    try std.testing.expectEqual(@as(u64, @intFromPtr(&scope)), host_hook_scope);
    // Order is load-bearing: the engine's own `log` line is written first.
    try std.testing.expect(seq_log < seq_host);
}

test "runBody does not reach the host when the rule rejects the system" {
    resetForTest();
    defer {
        setHostHookForTest(null);
        resetForTest();
    }
    log_effect_addr = @intFromPtr(&stubLogSeq);
    setHostHookForTest(&hostHook);
    host_hook_calls = 0;
    neo_effect.setRule(0, 0); // rule disabled => every system is rejected

    var scope: [0x20]u8 align(8) = [_]u8{0} ** 0x20;
    std.mem.writeInt(u32, scope[SCOPE_MASK_OFF..][0..4], 0x80, .little);
    std.mem.writeInt(u32, scope[SCOPE_ID_OFF..][0..4], 7, .little);
    _ = runBody(@intFromPtr(&scope), 0);

    try std.testing.expectEqual(@as(usize, 0), host_hook_calls);
}

// --- Phase 2: the set_star_flag path ---------------------------------------

var flag_calls: usize = 0;
var flag_seen_vtable: u64 = 0;
var flag_seen_id: u16 = 0;
var flag_seen_scope: u64 = 0;

fn stubFlagBody(self_ptr: u64, scope: u64) callconv(.c) void {
    const base: [*]const u8 = @ptrFromInt(self_ptr);
    flag_seen_vtable = std.mem.readInt(u64, base[0..8], .little);
    flag_seen_id = std.mem.readInt(u16, base[neo_state.STAR_FLAG_ID_OFF..][0..2], .little);
    flag_seen_scope = scope;
    flag_calls += 1;
}

fn testMinter(name: []const u8) ?u32 {
    if (std.mem.eql(u8, name, "my_flag")) return 4242;
    return null;
}

/// 测试里 vtable 故意不是裸 RVA:body 要的是绝对地址,C2 实机读数抓到的正是
/// 「裸 RVA 写进 `[obj+0]`」这一格(见 RVA_STAR_FLAG_VTABLE 的注释)。
const TEST_FLAG_VTABLE: usize = 0x140000000 + neo_state.STAR_FLAG_VTABLE;

fn armFlags() void {
    resetForTest();
    flag_calls = 0;
    star_flag_body_addr = @intFromPtr(&stubFlagBody);
    star_flag_vtable_addr = TEST_FLAG_VTABLE;
    setTokenMinterForTest(&testMinter);
}

test "setStarFlagId builds the official object and calls the +0x48 body" {
    armFlags();
    defer resetForTest();
    try std.testing.expect(setStarFlagId(4242, 0xABCD));
    try std.testing.expectEqual(@as(usize, 1), flag_calls);
    try std.testing.expectEqual(@as(u64, TEST_FLAG_VTABLE), flag_seen_vtable);
    try std.testing.expectEqual(@as(u16, 4242), flag_seen_id);
    try std.testing.expectEqual(@as(u64, 0xABCD), flag_seen_scope);
}

test "setStarFlag mints the name and forwards the minted id" {
    armFlags();
    defer resetForTest();
    try std.testing.expect(setStarFlag("my_flag", 0x1234));
    try std.testing.expectEqual(@as(usize, 1), flag_calls);
    try std.testing.expectEqual(@as(u16, 4242), flag_seen_id);
    try std.testing.expectEqual(@as(u64, 0x1234), flag_seen_scope);
}

test "setStarFlag refuses a name the minter rejects and an unresolved body" {
    armFlags();
    defer resetForTest();
    try std.testing.expect(!setStarFlag("not_mintable", 1));
    try std.testing.expectEqual(@as(usize, 0), flag_calls);

    star_flag_body_addr = 0;
    try std.testing.expect(!setStarFlag("my_flag", 1));
    try std.testing.expect(!setStarFlagId(4242, 1));
    try std.testing.expectEqual(@as(usize, 0), flag_calls);

    // body 在、vtable 不在:同样 fail-closed,而不是把 0 写进 `[obj+0]` 再跳。
    star_flag_body_addr = @intFromPtr(&stubFlagBody);
    star_flag_vtable_addr = 0;
    try std.testing.expect(!setStarFlagId(4242, 1));
    try std.testing.expectEqual(@as(usize, 0), flag_calls);
}

test "flagsResolved is independent of the set_variable path" {
    resetForTest();
    defer resetForTest();
    try std.testing.expect(!flagsResolved());
    star_flag_body_addr = @intFromPtr(&stubFlagBody);
    try std.testing.expect(!flagsResolved()); // vtable still missing
    star_flag_vtable_addr = TEST_FLAG_VTABLE;
    try std.testing.expect(flagsResolved());
    try std.testing.expect(!stateResolved());
}

test "resolveFromGame stores the star-flag vtable as base + RVA (absolute)" {
    resetForTest();
    defer resetForTest();
    const base: usize = 0x140000000;
    try resolveFromGame(base);
    try std.testing.expect(flagsResolved());
    try std.testing.expectEqual(base + RVA_STAR_FLAG_VTABLE, star_flag_vtable_addr);
    try std.testing.expect(star_flag_vtable_addr != RVA_STAR_FLAG_VTABLE);
}

test "mintFlagToken is the seam: off Windows it fails closed without an injected map" {
    resetForTest();
    defer resetForTest();
    if (builtin.os.tag == .windows) return;
    try std.testing.expectEqual(@as(?u16, null), mintFlagToken("my_flag"));
    setTokenMinterForTest(&testMinter);
    try std.testing.expectEqual(@as(?u16, 4242), mintFlagToken("my_flag"));
}

var mint_calls: usize = 0;

fn countingMinter(name: []const u8) ?u32 {
    mint_calls += 1;
    if (std.mem.eql(u8, name, "my_flag")) return 4242;
    return null;
}

test "mintFlagToken lower-cases and caches, so repeated reads do not exhaust slots" {
    resetForTest();
    defer resetForTest();
    setTokenMinterForTest(&countingMinter);
    mint_calls = 0;

    try std.testing.expectEqual(@as(?u16, 4242), mintFlagToken("my_flag"));
    try std.testing.expectEqual(@as(?u16, 4242), mintFlagToken("MY_FLAG")); // case-folded
    try std.testing.expectEqual(@as(?u16, 4242), mintFlagToken("my_flag"));
    try std.testing.expectEqual(@as(usize, 1), mint_calls);
    try std.testing.expectEqual(@as(?u16, null), mintFlagToken("0123456789abcdef")); // 16 B
}
