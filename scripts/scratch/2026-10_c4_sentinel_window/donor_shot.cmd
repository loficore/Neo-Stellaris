@echo off
rem donor 重打 —— argv 逐字 = 取证卷 §67 的复现行(:6216),换的只有靶子顺序:
rem 这一枪排在证人之后,且只有证人那枪 `calls>0`(§57.4 第三档的前半句「执行确实发生」成立)
rem 才值得打 —— 证人安静时这一枪的安静什么都不能证明(docs/offline-tooling.md 证人节判读陷阱 1)。
rem 前置:同进程里证人必须已 Uninstall=0 且 Verify=0(两组 guard 变量各自私有,所以串行合法,
rem 并行双 detour 挂同族两槽不做)。DLL 绝对路径(§67 坑②)。
python C:\temp\c2_donor_probe.py C:\temp\sqjs_c4.dll --mask 0 --poll-s 120 --settle-s 2 --out C:/temp/c4_donor_probe.tsv
