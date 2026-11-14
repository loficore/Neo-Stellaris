# 2026-11_r10_contract — R10 合同探针（一次性）

计划：`docs/superpowers/plans/…r10…`（私有）。实机读数与判据在
`evidence/logs/c6_r10_4_4_4.log`；本目录只放**发出去的那三份字节**。

## 目录形状（被工具钉死，别自创）

- `descriptor.mod` + `common/` + `events/` + `neo/` = `neo_install.py --mod` 要的**官方半边**项目根；
  它会把整棵 `neo/` 复制到 `C:/temp/neo_mods/r10good/neo/`。
- `bad/r10timeout/`、`bad/r10throw/` = **只有 runtime 半边**，按 loader 的目录契约手放到
  `C:/temp/neo_mods/<id>/neo/mod.json`（loader 只枚举 `C:/temp/neo_mods/*`，
  见 `src/dll/c2/neo_js_loader.zig` 的 `MODS_ROOT`）。

## 与计划草图的两处差异（都是被 `src/` 钉死的，不是自由度）

1. **manifest 不写 `name` / `version`**。loader 的字段集是**严格 7 字段**
   （`id`/`entry`/`scope`/`permissions`/`engine`/`runtime`/`flags`，`neo_js_loader.zig:168-194`），
   多一个键 = `UnknownField` = `NEO_JS_BAD_MANIFEST`，**整个 mod 不会载入**。
   计划里的 `{"name":…,"version":…}` 会让好 mod 直接缺席。
2. **权限要带 `flag.read`**。`hasStarFlag` 走 `canReadFlag`（`neo_js_host.zig:1188`），
   缺这一位时读恒 `false` 且落 `NEO_JS_FLAG_REJECT … reason=no_permission` ——
   `before=false` 会变成假读数。

## 判据（读数在日志里，不在这个文件里）

- `n == deg`：两个 native 读同一份边容器的两个字段（`+0x59c` 计数 / `+0x590` 数据），
  不一致是布局/走查缺陷。
- `before=false` → `after=true`：`r10flag` 必须是本战役**从没出现过**的名字
  （窗口前的 autosave 里查；旧名读到 true 什么都不证明）。
