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
