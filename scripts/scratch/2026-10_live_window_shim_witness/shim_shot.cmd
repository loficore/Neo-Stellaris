@echo off
rem 族外证人 正式窗(本发判决读数的来源)—— §13 那七把 2,090 次 shim 里表序第一把 0xCC4220。
rem 靶不是 base Execute、不是 donor(slot[1] 0x3AFD30)、不是证人(slot[2] 0x3B01A0):它是
rem vtable 0x25460F0 的 slot[2],而那七张表与家族五张的交集是空(§71.3)。
rem 前置门①:本发之前 C4ShimProbeInstall 在本进程**从未** dispatch 过(一进程一次 install 额度;
rem           再装会答 -2,而 -2 会被读成判词)。前置门②:predicate detour 未 armed,否则模块拒装。
rem 频率窗(先跑,argv 见 Task 8 Step 1):同一条命令换 --poll-s 20 --out C:/temp/c4_shim_freq.tsv,
rem 读完 calls 增量再决定本发带不带 mask;三档判据的主读数是恒计的 h0..h6/unmatched,ring 只是证人。
rem --mask 0 强制默认值(§57.4「不要照搬 base Execute 的 1/512」);DLL 用绝对路径(§67 坑②)。
python C:\temp\c2_shim_probe.py C:\temp\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:/temp/c4_shim_probe.tsv
echo EXIT:%ERRORLEVEL%
