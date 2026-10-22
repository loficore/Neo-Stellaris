# 2026-10_threadhandle_matrix — §44 里 gle=5 到底是「没权限」还是「线程已死」

一次性:回答「§44 那 22 次采样**每一次**都 `SuspendThread gle=5`,是我们的句柄缺权限,还是那条线程
根本不能 suspend」。

| 文件 | 当时在回答哪个问题 |
|---|---|
| `threadhandle_matrix.py` | 在**本脚本自己 spawn 的子进程**里造一条 `kernel32!Sleep(8000)` 的远程线程,然后跑一个 2×2 矩阵:**句柄种类**(`CreateRemoteThread` 返回的 created handle vs `OpenThread` 拿到的 opened handle)× **线程状态**(sleeping 时 vs 已返回后),每格走 `c2_harness.capture_thread_state` 的同一条只读路径。 |

结果:线程活着时两种句柄都读得到 `Rip`;线程**已退出**后两种句柄都报 `ERROR_ACCESS_DENIED (5)`。
⇒ gle=5 不是我们句柄的权限问题,而是「这条线程已经不能 suspend」的形状。

**怎么跑**:`scp` 到 `C:/temp/`(要带 `c2_harness.py`,它按裸名 import),然后
`python C:/temp/threadhandle_matrix.py`。**零游戏**:目标进程是本脚本自己起的子 python,不调
`LoadLibrary`、不注入我们的 DLL。

**结论落在** `evidence/analysis/runtime_444_c1_validation.md` §44.3,逐字记录在
`evidence/logs/c2_threadstate_4_4_4.log`。

**不作为接口维护**:可以失效,但别重犯它已经踩过的口径错误 —— 第一次尝试用 `sys.executable` 起子进程,
拿到的子进程**一个可见线程都没有**,那样矩阵每一格都没有意义;脚本里那个显式解释器路径的兜底就是为这个。
