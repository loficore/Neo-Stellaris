@echo off
rem B2 census 复采 —— **本窗口最后一发**,压在所有 [self+0] join 读数之后。
rem 理由是硬的:它武装 base Execute 0x1D08520 的 detour,一旦装上,该进程之后任何 guard 读到的
rem [self+0] 都可能来自一个热路径归我们所有的状态;顺序纪律见 docs/offline-tooling.md 的 execspy 节。
rem NS_LIVE_DLL 指到本窗口的 DLL 字节;C:\\ns\\stellaris_quickjs.dll 那份是另一份字节,两次读数
rem 只能并排讨论、不能并排比对(驱动会把 basename 作为 NS_DLL_NAME 注进 execspy.js)。
rem 硬门:hist_overflow 必须为 0。>0 ⇒ 计数不完整,只当环境样本记,不写 per-system 结论。
rem 前置门①:本发之前所有 guard 都已拆且 Verify=0。前置门②:本发之后不再安排任何 [self+0] 读数。
set NS_LIVE_DLL=C:\temp\sqjs_c4.dll
cd /d C:\temp
python C:\temp\execspy.py 60 > C:\temp\c4_census_run.txt 2>&1
echo EXIT:%ERRORLEVEL%>> C:\temp\c4_census_run.txt
