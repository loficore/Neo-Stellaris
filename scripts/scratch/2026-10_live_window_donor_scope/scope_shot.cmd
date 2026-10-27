@echo off
rem scope 深跟读第二次 shot —— argv 逐字照 §59.11 那次跑通的形态 (三份参考都在远端)。
rem 同样只能前台经 ssh 跑 (§59.2); DLL 与 donor_shot.cmd 是同一个文件。
rem 这一发用的是 Task 3 加进 c2_scope_probe.py 的深跟读判读面, 不改 DLL 一个字节。
python C:\temp\c2_scope_probe.py C:\temp\sqjs_c4.dll --poll-s 120 --settle-s 2 --out C:\temp\c4_scope_d2.tsv --vtables C:\temp\ceffect_vtable_map_4_4_4.txt --census C:\temp\exec_frame_callers_4_4_4.tsv --id-names C:\temp\descriptor_oracle_4_4_4.tsv
