@echo off
rem scope 新形状一发 —— argv 逐字照取证卷 §68 的复现行(:6369),不新增旗标。
rem 这一发自带 §68.4 前置 ①② 的离线预备:depth-2 分档(plausible_user_ptr + 镜像界)与预算 27
rem (8 + 那 19 个没问过的),所以 self 支要么问完,要么在 #meta 里以 capped 明示没问完。
rem 前置门①:本发之前 C2ExecProbeUninstall 未装过。前置门②:C4ShimProbeVerify=0 且
rem           C4WitnessProbeVerify=0(donor/证人/scope 四把仪器不许有两个同时 armed)。
cd /d C:\temp
python C:\temp\c2_scope_probe.py C:\temp\sqjs_c4.dll --poll-s 120 --settle-s 2 --out C:\temp\c4_scope_d2_27.tsv --vtables C:\temp\ceffect_vtable_map_4_4_4.txt --census C:\temp\exec_frame_callers_4_4_4.tsv --id-names C:\temp\descriptor_oracle_4_4_4.tsv > C:\temp\c4_scope_run_27.txt 2>&1
echo EXIT:%ERRORLEVEL%>> C:\temp\c4_scope_run_27.txt
