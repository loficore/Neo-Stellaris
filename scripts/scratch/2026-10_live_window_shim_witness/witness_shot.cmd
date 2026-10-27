@echo off
rem 族内 slot[2] 证人 —— 条件性第三发:只在 shim 正式窗拿到 calls>0 时才打。
rem 它的意义不是再问一次族内,而是把「执行确实发生」的证人与族内静默摆进同一个进程、相邻两个窗
rem (§70.3 的先例:两个 0 不能读成同一个对象两次都没被调用 —— 反过来,一个 >0 加一个 0 才分得开)。
rem argv 逐字照 §69 那次正式窗(证据卷 :6369 同族一串);只有靶与 out 不变、DLL 用绝对路径。
rem 前置门①:本发之前 C4WitnessProbeInstall 在本进程**从未** dispatch 过(§69 已用尽的那一发在
rem           pid 15500,换进程才合法)。前置门②:本发之前 C4ShimProbeUninstall rc=0 且 Verify=0
rem           (两把 guard 状态各自私有,串行合法;并行双 detour 挂同族两槽不做)。
python C:\temp\c2_witness_probe.py C:\temp\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:\temp\c4_witness_probe.tsv
echo EXIT:%ERRORLEVEL%
