# `scripts/scratch/2026-11_flag_store/` — flag 存储再定位(一次性)

**属于哪次取证**:`evidence/analysis/flag_store_4_4_4.md`(2026-11-08,离线)。
**不是维护中的工具**,不进顶层 `scripts/`(AGENTS.md 的 scratch 约定);
它读本地 `stellaris.exe` 拷贝,不需要进程、不需要 IDA license。

## `scan_flag_keyword.py`

给定一个官方 keyword,走 `TSV → class_info → create → vptr → 每个 slot`,
按**消费形状**给每个 slot 打标(读不读 MSVC 形状的名字串 / 读不读 u16 / 按序调了谁)。

```bash
python3 scripts/scratch/2026-11_flag_store/scan_flag_keyword.py --keyword set_star_flag
python3 scripts/scratch/2026-11_flag_store/scan_flag_keyword.py --keyword has_star_flag
python3 scripts/scratch/2026-11_flag_store/scan_flag_keyword.py --create 0x1895620
python3 scripts/scratch/2026-11_flag_store/scan_flag_keyword.py --ci 0x2610e80
```

exe 路径:`NS_STELLARIS_EXE` → `/var/lofibass_ssd/data/stellaris/4.4.4/stellaris.exe`
→ `D:\SteamLibrary\...` 候选链(与 `scripts/disrva.py` 同序)。

### 输出与列映射

第 1 行是 `#` 注释(回显解出来的 `class_info / create / new / vptrs`),第 2 行是表头:

| 列 | 含义 |
|---|---|
| `slot_off` | 该槽在 vtable 里的字节偏移(`+0x48` 就是 body) |
| `slot_rva` | `vptr + slot_off` |
| `func_rva` | 槽目标的函数起点(**`.pdata` 起点**,不是随便的代码地址) |
| `func_len` | `.pdata` 区间的长度 |
| `string_reads` | 见到 MSVC 串形状的读点时打标,`地址:判据` 用 `;` 分隔;无则 `-` |
| `id_reads` | 见到 `movzx <reg>, word ptr [...]` 时打标;无则 `-` |
| `callees` | 按**指令顺序**的直接 call 目标 RVA,空格分隔 |

`string_reads` 的四个判据(与取证卷 §2 同口径):

1. `cmp qword ptr [rX + {0x18,0x28,0x30}], 0x10` —— MSVC `std::string` 的 SSO 容量门
2. 调 `0x15F770` / `0x15F590` / `0x15EA40` —— 串构造/赋值
3. 调 `0x158300` —— 把串 append 进 `0x2A00DE0` 那张反查 vector
4. 调 `0x1C9E350` —— 对串做哈希

### 输入表来源

`evidence/xrefs/keyword_behaviour_registration_4_4_4.tsv`(`scripts/thunkarrays.py` 产出)。
列序: `array_rva · index · thunk_rva · db_global_rva · token_id · keywords · class_info ·
deleter · docstring · doc_first_line · insert_fn_rva`。

**注意 TSV 的 `col[7]`(0x34c090)是全表共享的 deleting destructor,不是 `create`**;
`create` 只能从 `class_info` 的第二个 qword 读(`cinfo.py` 的口径),脚本已按此实现。

### 判读陷阱(踩过的)

* **`.pdata` 起点才是函数边界**。`vtable.py` 用 "目标 == RUNTIME_FUNCTION 起点"
  判定一个槽是函数;本脚本用同一判据。非代码槽(vtable 里很常见)会被跳过,
  所以输出行数**少于**槽数,这是对的,不是漏读。
* **两个 vptr**。`set_star_flag` 的 `create` 发布 `0x26049b0`(primary)与
  `0x25f2b08`(secondary);两个都会展开,同一个函数会在两处出现。
  **不要把 secondary 的槽偏移当成 primary 的**。
* **只读形状,不读值**。脚本不解引用 `.data`,所以「`0x326D110` 那张表现在有几个
  元素」它答不了 —— 那是实机的问题(Task C)。
* **`movzx ..., word` 会误伤**(bool/枚举读也是 word)。所以 `id_reads`
  只当"候选"看,判词要回 `disrva.py` 逐条核。
