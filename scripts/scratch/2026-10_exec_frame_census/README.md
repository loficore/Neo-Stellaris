# 2026-10_exec_frame_census

一次性离线读数,服务 §61(普查表第 1 行 `origin=incoming_arg` 的帧来源)。只读 exe 拷贝,不需要进程。

- `slot_offsets.py` —— 游程起点法。**结论是这条启发式不可用**:`.rdata` 里 vtable 紧挨排列,
  游程并成 1401/1435/1564 槽的大块,槽位偏移全是垃圾。留着是为了让下一个人不再试这条路。
- `slot_offsets2.py` —— 改用 `evidence/xrefs/ceffect_vtable_map_4_4_4.txt` 的 1,805 个 vtable 基址
  逐槽解引用。读数:`slot_index 分布 = {2: 365}`、`orphan = 0`。

两个坑记在这里:比对时要用**槽内容 == anchor VA**(误比命中位置会得到 365 全 orphan);
map 的 key 是**模块相对 RVA**,拿去和 `.rdata` 的 VA 比之前要加 `0x140000000`。

结论与字节证据在 `evidence/analysis/runtime_444_c1_validation.md` §61,不在这里。
