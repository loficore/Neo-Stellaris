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
    # `--summary all` on purpose: without it a green run prints nothing, so a CI
    # log would show "step succeeded" with no evidence of what ran.  The judge is
    # still the exit code (see docs/offline-tooling.md: the step count only grows,
    # so never pin it as a threshold).
    zig build test --summary all

# `test_hook_teardown.py` is here because `test_scripts_layout.py` does not read Zig
# sources: without this line the "never free a trampoline" invariant is tested only
# when someone remembers to run it (2026-10-28 review M-2).
# `test_graph_fixture_emit.py` is here for the same reason: `graph-fixture-check`
# runs only the emitter's `--check` drift, never its unit tests (2026-11-03 review C).
fence:
    python3 -m pytest scripts/test_scripts_layout.py scripts/test_hook_teardown.py scripts/test_graph_fixture_emit.py -q

host-tests:
    cd scripts/windows && python3 -m pytest tests -q

# SDK gate (Track B): Node 24 + the exact versions in sdk/package-lock.json.
# `npm test` type-checks the SDK, builds the examples in a temp dir, and runs the
# bundle inside a real QuickJS context with the mock host (`neo check`).  Kept
# out of `check`/`check-full` on purpose: the Zig gate must stay runnable on a
# machine with no npm registry.
sdk-test:
    cd sdk && npm ci && npm test

# Score-table drift fence: regenerate src/dll/c2/chokepoint_table.zig in memory and compare.
chokepoints-check:
    python3 scripts/chokepoints_emit.py --tsv evidence/xrefs/chokepoint_scores_4_4_4.tsv --out src/dll/c2/chokepoint_table.zig --save-sha 6f271294bcfe3620a5e7da367a7f3fb0891c77315baffa28601ca48ec5d8d94e --check

# Graph-fixture drift fence: regenerate src/dll/c2/graph_fixture.zig in memory and compare.
graph-fixture-check:
    python3 scripts/graph_fixture_emit.py --edges evidence/xrefs/c5_campaign_edges_4_4_4.tsv --scores evidence/xrefs/chokepoint_scores_4_4_4.tsv --out src/dll/c2/graph_fixture.zig --check

check: lint build test fence host-tests chokepoints-check graph-fixture-check

# Lint gates.  Two things are pinned here and nowhere else matters:
#   * zig  — `zig fmt` is the compiler's own formatter, so the zig version pin
#            (0.16.0, in the workflow and ci/runner/Dockerfile) covers it.
#   * ruff — pinned 0.17.3 (scripts/requirements.txt + both CI install lists),
#            configured in ruff.toml.  Local prerequisite:
#            `uv tool install ruff==0.17.3` (or `pip install ruff==0.17.3`).
# `--check` means "would reformat", so both are read-only: the tree must come
# out of this recipe exactly as it went in.
lint:
    zig fmt --check .
    ruff check .

# CI 门：check + scripts/ 全量（check 只覆盖 418/1,461 条 python 测试）
check-full: check
    python3 -m pytest scripts -q -rs

# NOTE: the world-state machine is TWO files and they must travel together with
# its Windows halves — world_state.py is the pure machine (one directory up in
# the repo, bare-name on the wire), world_probe.py takes the reading, ns_world.py
# is the CLI.  Leaving any of them out makes the CLI fail on the host with an
# import error that reads like the tool is broken.
deploy:
    scp scripts/world_state.py scripts/windows/world_probe.py scripts/windows/ns_world.py scripts/windows/session_bridge.py scripts/windows/game_supervisor.py scripts/windows/launch_stellaris.py scripts/windows/keep_awake.py scripts/windows/popup_geometry.py scripts/windows/popup_identity.py scripts/windows/popup_guard.py scripts/windows/popup_ocr.py {{WIN_HOST}}:{{WIN_TEMP}}/

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
