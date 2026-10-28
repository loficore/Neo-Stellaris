@echo off
rem B2 census recensus -- the LAST shot of this window (plan Task 10 Step 2).
rem ASCII only: a UTF-8 .cmd with CJK comments is mis-parsed by a cp936 cmd.exe
rem (the 2026-10-27 census_run.cmd failed exactly that way: its rem lines were
rem executed as commands).  NS_LIVE_DLL points at this window's bytes.
set NS_LIVE_DLL=C:\temp\sqjs_c4.dll
cd /d C:\temp
python C:\temp\execspy.py 60 > C:\temp\c4_census_run.txt 2>&1
echo EXIT:%ERRORLEVEL%>> C:\temp\c4_census_run.txt
