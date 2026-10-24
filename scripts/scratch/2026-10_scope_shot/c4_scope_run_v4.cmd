@echo off
rem Detached runner for the v4 scope shot. Pattern copied from C:\temp\c4_scope_run.cmd
rem (§56.7). stdout goes to a file, not to ssh, so a reset connection cannot orphan
rem an install before Uninstall runs.
cd /d C:\temp
python C:\temp\c2_scope_probe.py C:\temp\sqjs_c4_scope_v2.dll --poll-s 120 --settle-s 2 --out C:\temp\c4_scope_probe_v4.tsv --vtables C:\temp\ceffect_vtable_map_4_4_4.txt --census C:\temp\exec_frame_callers_4_4_4.tsv --id-names C:\temp\descriptor_oracle_4_4_4.tsv > C:\temp\c4_scope_run_v4.txt 2>&1
echo EXIT:%ERRORLEVEL%>> C:\temp\c4_scope_run_v4.txt
