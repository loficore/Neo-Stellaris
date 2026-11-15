# 2026-11_scope_closeout

一次性离线探针,服务 `evidence/analysis/runtime_444_scope_tables_4_4_4.md` **§8**
(§4.4 第 3 条:`[scope+0x1c]` 缓存槽的**填充方**)。只读 exe 拷贝,零实机:
不注入、不起游戏、不需要进程。

- `cell_filler_sites.py` —— 扫整个 `.text`(37,292,032 B)找 `+0x1c` / `+0x14` 的写点。
  六种形态(A/B 8 B 写、C 4 B 写、D 立即数、E 16 B 向量写、F 经 `lea` 指针写)+ 三层筛
  (mask 门 / id 同基址 / 非清零),按 `.pdata` 分桶,叶子函数退化成「解码连续段」。
  跑法:`python3 scripts/scratch/2026-11_scope_closeout/cell_filler_sites.py [--json OUT]`,
  全段约 10 s。

三个坑(第一版全踩过,留在这里省下一个人一次):

1. **`detail=True` 全段线性解码跑不完。** 第一版用它,>4 min 没出第一行;换
   `disasm_lite` + 只读 `op_str` 文本,全段 10 s。
2. **`insn.regs_write` 在本环境恒空**(同一个坑记在
   `scripts/scratch/2026-10_exec_frame_census/README.md` 第三条)。判读写一律走显式操作数
   或 `op_str` 文本,别信 capstone 的隐式寄存器集合。
3. **零值跟踪写错过一次。** 用 `R_XOR.match(op_str.replace(" ", ""))` 去比
   `^(e[a-z]+|r\d+d), \1$` —— 去掉空格后模式里的 `", "` 永远不匹配,于是 `xor eax,eax`
   从未被记成零值,自检靶 `0x394200` 的 `mov [rcx+0x1c], rax` 被判成「填充」。现在按
   `, ` 切操作数比字符串,不信任何正则的空白假设。

结论、逐字反汇编与每个被否候选的判词在 §8,**不在**这个目录里。
