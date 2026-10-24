# Neo-Stellaris developer index.
#
# Host-side recipes run where `just` runs.  Windows-side recipes are thin ssh
# wrappers over the deployed tools; the wire names (C:/temp/<name>.py) are
# checked by scripts/test_scripts_layout.py, not by trust.

WIN_HOST := env("NS_WIN_HOST", "Windows_Jiaolong")
WIN_TEMP := "C:/temp"

default:
    @just --list

build:
    zig build

test:
    zig build test

fence:
    python3 -m pytest scripts/test_scripts_layout.py -q

host-tests:
    cd scripts/windows && python3 -m pytest tests -q

# Score-table drift fence: regenerate src/dll/c2/chokepoint_table.zig in memory and compare.
chokepoints-check:
    python3 scripts/chokepoints_emit.py --tsv evidence/xrefs/chokepoint_scores_4_4_4.tsv --out src/dll/c2/chokepoint_table.zig --save-sha 6f271294bcfe3620a5e7da367a7f3fb0891c77315baffa28601ca48ec5d8d94e --check

check: build test fence host-tests chokepoints-check

deploy:
    scp scripts/windows/game_supervisor.py scripts/windows/launch_stellaris.py scripts/windows/keep_awake.py {{WIN_HOST}}:{{WIN_TEMP}}/

# Launch Stellaris through Steam (launcher clicks included; stays paused).
launch *args:
    ssh {{WIN_HOST}} "python {{WIN_TEMP}}/launch_stellaris.py {{args}}"

# start | stop | status | pause | unpause | want playing | policy first |
# choose 2 | speed up | click 1400 861 | console <text> |
# console_sync open|closed|auto | console_close | dismiss | close | shot | quit
game verb *args:
    ssh {{WIN_HOST}} "python {{WIN_TEMP}}/game_supervisor.py {{verb}} {{args}}"

# keep the interactive desktop awake: serve | start | stop | status | check
awake *args:
    ssh {{WIN_HOST}} "python {{WIN_TEMP}}/keep_awake.py {{args}}"

# arbitrary command on the Windows host, e.g. just win "Get-Process stellaris"
win *args:
    ssh {{WIN_HOST}} {{args}}
