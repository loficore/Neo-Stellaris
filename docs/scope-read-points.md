# `api/scope` 读点清单 —— `CEventScope` `+8`/`+16` 的逐条处置

`evidence/analysis/runtime_444_c1_validation.md` **§26** 实测:`0x1D08520`(`CEffect::Execute` base)在
`call [vptr+0x10]` 之前 `inc`、之后 `dec` `[arg2+8]` —— 那个 dword 是**调用深度计数器**,不是 scope type。
所以 `src/dll/api/scope.zig` 的四个 getter 与 `src/dll/shared/offsets.zig` 的 `c_event_scope` 两个字段,读的是
一个**已被证伪**的布局;而 `src/dll/api/bridge.zig` 把这四个 getter 注册成了 JS 函数。

本清单给每一个读点一条可机械核对的处置。**处置只能是诚实化,不能是改正**:§26.2 明写「真正的
`CEventScope` 是哪个对象」仍未定,`+8`/`+16` 的真相需要实机交出一个真的 `arg2` 帧指针 —— 那条线在
`docs/roadmap.md` 段4,等它自己的授权,不属于本清单。`offsets.scope_types`
(`src/dll/shared/offsets.zig:273-285`)的位标值保持 `[UNVERIFIED 3.x]`,不在这 16 行里(它不经这四个
getter)。表中的行号是 2026-10-22 标注动作**之后**重跑 grep 得到的真实行号。

处置列的合法取值只有 `改掉` / `标注未确认` / `待 Task 2`(最后一个只允许 build.zig 那一行)。
行数判据:

```bash
grep -cE '^\| `src/' docs/scope-read-points.md          # 16
grep -cE '^\| `build\.zig' docs/scope-read-points.md    # 1
```

| 读点(文件:行) | 现状 | 处置 | 证人 |
|---|---|---|---|
| `src/dll/api/scope.zig:35` | 模块级常量 `OFFSET_SCOPE_TYPE`(值 8)。改动前 doc 只写 "Byte offset to the scope type field in CEventScope",未确认字样只存在于文件头 `:7-17` 的散文里,不在这个读点身上 | 标注未确认 | §26 |
| `src/dll/api/scope.zig:40` | 模块级常量 `OFFSET_OBJECT_ID`(值 16)。改动前同上,doc 自身无未确认字样 | 标注未确认 | §26 |
| `src/dll/api/scope.zig:118` | `getScopeType` 直接读 `base + 8`;改动前 `# Returns` 写 "The scope type as an i64 bit flag",主张的正是 §26 否掉的那个语义 | 标注未确认 | §26 |
| `src/dll/api/scope.zig:137` | `getScopeObjectId` 直接读 `base + 16`;改动前 `# Returns` 写 "The object ID as an i64" | 标注未确认 | §26 |
| `src/dll/api/scope.zig:153` | `getScopeTypeName` 经 `:118` 取值再查 `offsets.scope_types`,继承同一个假偏移 | 标注未确认 | §26 |
| `src/dll/api/scope.zig:169` | `hasScopeType` 经 `:118` 取值做位与,继承同一个假偏移 | 标注未确认 | §26 |
| `src/dll/api/scope.zig:263` | 改动前是 `test "offsets: constants match expected values"`,把 8/16 钉成 "expected values" —— 独立测试步被打开后,它会把已证伪的数字当规格 | 改掉 | §26 / 本计划 Review Focus 2 |
| `src/dll/api/bridge.zig:32` | `const scope = @import("scope.zig")` — 注册面进入这四个 getter 的唯一门。本计划不改写 `bridge.zig` 任何一行(动它 = 动 JS API 表面),未确认性由清单入账 + 被调方的标注承载 | 标注未确认 | §26 |
| `src/dll/api/bridge.zig:228` | wrapper `jsGetScopeType`;`:227` 的 doc 只有签名说明(`/// JS: Stellaris.getScopeType(scope: pointer) -> number`),无未确认字样。未确认性由被调方 `scope.zig:118` 的标注与本清单承载 | 标注未确认 | §26 |
| `src/dll/api/bridge.zig:239` | wrapper `jsGetScopeObjectId`;`:238` 同样只有签名说明 | 标注未确认 | §26 |
| `src/dll/api/bridge.zig:250` | wrapper `jsGetScopeTypeName`;`:249` 同样只有签名说明 | 标注未确认 | §26 |
| `src/dll/api/bridge.zig:262` | wrapper `jsHasScopeType`;`:261` 同样只有签名说明 | 标注未确认 | §26 |
| `src/dll/api/bridge.zig:302` | `api_functions` 注册表块首行(代表 `:302-305` 四行):四个 JS 名 `getScopeType`/`getScopeObjectId`/`getScopeTypeName`/`hasScopeType` 对 mod 脚本可见。删名/改名会动 JS API 表面,不在处置范围内 | 标注未确认 | §26 |
| `src/dll/api/bridge.zig:390` | `test "api_functions: expected names present"` 的 body 只做三次 `std.mem.eql`(`getCountry`、`setVariable`、`getScopeType`),scope 四名里只有 `getScopeType` 被守住 —— 另外三个改名或删除都不会变红,所以"测试没红"不是"表面没动"的证据 | 标注未确认 | §26 |
| `src/dll/shared/offsets.zig:266` | `OFFSET_SCOPE_TYPE: usize = 8`,行尾已带 `[FALSIFIED for Execute's arg2, §26]`;但改动前 struct 体内没有一个调用方可读的编译期标志 | 标注未确认 | §26 |
| `src/dll/shared/offsets.zig:267` | `OFFSET_OBJECT_ID: usize = 16`,行尾已带 `[UNVERIFIED 3.x]` | 标注未确认 | §26 |
| `build.zig:293` | `:293-295` 的 NOTE 记下 `import of file outside module path`,`:296` 的 `test_step.dependOn(&run_api_scope_tests.step);` 仍是注释 —— `scope.zig` 的 8 条 `test` block 今天根本不在 test 图里 | 待 Task 2 | §26 |

## 计数
