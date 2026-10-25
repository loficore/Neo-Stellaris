# 2026-10_exec_frame_census

一次性离线读数,服务 §61(普查表第 1 行 `origin=incoming_arg` 的帧来源)。只读 exe 拷贝,不需要进程。

- `slot_offsets.py` —— 游程起点法。**结论是这条启发式不可用**:`.rdata` 里 vtable 紧挨排列,
  游程并成 1401/1435/1564 槽的大块,槽位偏移全是垃圾。留着是为了让下一个人不再试这条路。
- `slot_offsets2.py` —— 改用 `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` 的 1,805 个 vtable 基址
  逐槽解引用。读数:`slot_index 分布 = {2: 365}`、`orphan = 0`。
- `forwarding_wrappers.py` —— §62 的续读:把普查表 12 个 `origin=incoming_arg` 站点**逐函数**读完
  (站点目标、承载寄存器写点、有没有对帧的写、rdx 是否来自栈上 `lea`),并以第 1 行
  `0x1bcd120` 的已知读数 `mov rbx, rdx @0x1bcd131` 做自校验。

两个坑记在这里:比对时要用**槽内容 == anchor VA**(误比命中位置会得到 365 全 orphan);
map 的 key 是**模块相对 RVA**,拿去和 `.rdata` 的 VA 比之前要加 `0x140000000`。
第三个坑属于检测器本身:**别用 capstone 的 `insn.regs_write` 判 x86 读写**,本环境该属性恒空,
第一版因此把「对帧的写」读成 0 —— 一个「太干净」的 0 要先怀疑检测器。

结论与字节证据在 `evidence/analysis/runtime_444_c1_validation.md` §61–§62,不在这里。
