@echo off
rem donor 首枪 —— 单行 argv, 前台经 ssh 跑 (§59.2: 脱作业对象的两种写法都没放出去,
rem 不要照抄 2026-10_scope_shot/c4_scope_run_v4.cmd 那份 > file 2>&1 的脱作业形态)。
rem --mask 0 是默认, 这里强制: §57.4 三档判据的主读数是恒计的 table_hits/unmatched,
rem ring 只是证人。先带 mask 就永远定不出 §57.4 要的那个频率 (§57.4「不要照搬 1/512」)。
rem 首枪之后才谈第二次点名要不要带 mask。
python C:\temp\c2_donor_probe.py C:\temp\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:\temp\c4_donor_probe.tsv
