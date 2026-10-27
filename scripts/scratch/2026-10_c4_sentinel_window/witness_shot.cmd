@echo off
rem 证人 shot —— §57.4 第三档要的那把哨兵证人,单行 argv,前台经 ssh 跑。
rem 形态逐字照 2026-10_live_window_donor_scope/donor_shot.cmd:同一台机、同一个 DLL、同一族靶子,
rem 只有函数换槽(donor 是 slot[1] 0x3AFD30,本枪是 slot[2] 0x3B01A0)。
rem DLL 用绝对路径 C:\temp\sqjs_c4.dll(§67 坑②:相对路径在 ssh 的 cwd 下会解析到别处)。
rem --mask 0 强制默认值:三档判据的主读数是恒计的 table_hits/unmatched,ring 只是证人 (§57.4
rem 「不要照搬 base Execute 的 1/512」)。频率窗(20 s)先跑,读完 calls 增量再决定这枪带不带 mask。
rem 顺序纪律:这枪必须在 donor 那枪之前跑完并清理成功 —— donor 的第三档资格由本枪的 calls>0 提供。
python C:\temp\c2_witness_probe.py C:\temp\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:/temp/c4_witness_probe.tsv
