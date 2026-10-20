# launch_stellaris — Design

**Status:** Draft, awaiting user approval.
**Created:** 2026-09-29
**Owner:** unassigned
**Spec location:** `docs/superpowers/specs/2026-09-29-launch-stellaris-design.md`
**Planned implementation:** `scripts/windows/launch_stellaris.py`
**Related context:** `AGENTS.md` §"硬性约束", `docs/superpowers/plans/2026-10-08-c2-quickjs-bootstrap.md` (style precedent for plans produced from this spec)

---

## 1. Intent & Why

When the agent detects that `stellaris.exe` has crashed, it needs a way to
launch a fresh copy of the game so the C1/C2/C3 debug loop can keep
running. Today the human part of the loop is manual: a person looks at a
frozen screen, kills anything stuck, clicks Steam, waits for the PDX
Launcher to come up, clicks through EULA / news / Play, and waits until the
real game is up. That kills the value of running the agent unattended
overnight.

This design replaces the human side of that loop with a single CLI script
that:

1. starts the game through Steam (no coordinate clicking),
2. drives the PDX Launcher UI via UI Automation (no coordinate clicking),
3. confirms that `stellaris.exe` has been alive and healthy for ≥ 30 s,
4. prints the game PID on success, exits non-zero with a typed failure on
   anything else.

Everything else (DLL injection, gmon dispatch, chokepoint instrumentation)
is **out of scope** and remains the responsibility of the calling agent.

## 2. Goals / Non-Goals / Anti-Goals

### Goals

- **G1.** Agent can run fully unattended for hours: launches fire, real
  game comes up, PID is returned; any dead-end path exits with a typed
  failure the agent can branch on.
- **G2.** Launch reliability on a single, healthy box ≥ 95% over 50
  attempts in a row. (Goal, not acceptance — the agent loop is the truth.)
- **G3.** No coordinate-based UI driving anywhere in the script.
- **G4.** Typed exit codes for every failure mode an unattended caller
  might want to branch on (Steam dead, login required, update required,
  launcher stuck, game crashed in window, JIT dialog, etc.).
- **G5.** Runs on Windows only. Does not require the game binary to be
  present on the path the script is launched from.
- **G6.** Composable with PowerShell: invoked as
  `python scripts/windows/launch_stellaris.py` from a PowerShell prompt
  and consumed by exit code + stdout PID.

### Non-Goals

- **N1.** Injecting the Neo-Stellaris DLL. The agent does this elsewhere.
- **N2.** Detecting that the game has crashed. The agent does this.
- **N3.** Verifying the agent's instrumentation is live (i.e. confirming
  that the DLL was actually injected). The agent does this.
- **N4.** Updating Stellaris. If Steam or Stellaris wants to update, the
  script reports a typed failure; the human runs the update.
- **N5.** Handling Steam Cloud sync prompts. Pre-launch environmental
  concern; if Steam asks, the script fails the run.
- **N6.** Multi-language / multi-Steam-user support. Single user, single
  language, single locale.

### Anti-Goals

- **A1.** A pixel-perfect or image-recognition launcher. We are not going
  to look at bitmaps. UIA is the only window-driving primitive.
- **A2.** A daemon / always-running service. The script is invoked per
  launch and exits. State does not persist between invocations except
  through the OS process table.
- **A3.** Working around Steam's "Steam Guard required" prompt by
  typing credentials. If Steam Guard fires, the script reports it and
  gives up.
- **A4.** Trying to fix a stuck launcher by force-killing it more than
  once per launch attempt. One kill budget per attempt.

## 3. Constraints & Preconditions

### Environmental preconditions (NOT the script's responsibility, but it
assumes they hold)

- **E1.** Windows 10/11 x64, .NET 4.x available (pywinauto UIA backend
  requires it).
- **E2.** Steam client installed and the same Windows user is logged in.
  If Steam is not running, `steam://` URI auto-launches it.
- **E3.** The Windows user has logged into Steam at least once on this
  machine, Steam Guard has been satisfied at least once, and "Remember
  credentials" is on. The script will not type credentials.
- **E4.** Windows JIT Debugger (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\Debugger`)
  is either unset or points to a non-interactive handler. If it points to
  Visual Studio or `drwtsn32`, the first crash will pop a modal dialog that
  will block the script until a human clicks "No". The script *detects*
  this and reports a typed failure; it does not silently click "No".
- **E5.** No second Steam client running under a different user account on
  the same machine. The script uses the `steam://` protocol handler
  which goes to the default-registered client.
- **E6.** `scripts/windows/launch_stellaris.py` is reachable by the
  calling agent (probably via SSH + Python interpreter on the Windows
  box).
- **E7.** **The agent invokes the script over SSH** (Q1 answer), which
  lands in a non-interactive session. This is the SSH context that the
  spec is written against — any other invocation path (RDP-attached
  shell, console session, scheduled task started by a service) needs
  its own plan. Because Session 0 and any non-interactive window
  station have no visible desktop, the script cannot reach the PDX
  Launcher window from its own process. It must bridge into the user's
  logged-on interactive session before any UIA work; see §5a
  "Session bridging".
- **E8.** **PDX Launcher must expose a UIA control tree on this box**
  for the script to drive it. This has **not yet been verified** at
  design time (Q2 answer: no prior inspection; user offered SSH access
  to `Windows_Jiaolong`). Until verified on `Windows_Jiaolong`, the
  UIA-based `LAUNCHER_DRIVE` phase is conditional. If PDX Launcher
  turns out to use a CEF / Electron / owner-drawn surface, the spec
  needs a different primitive (keyboard input to the launcher window,
  image recognition, or the launcher config pre-load approach
  originally considered) — flagged here so it does not get lost.

### Engineering constraints

- **C1.** Python 3.10+ (the project's main script language; matches
  `scripts/requirements.txt`).
- **C2.** Dependencies: `pywinauto` (UIA backend) and `psutil`. These are
  *runtime* deps on the Windows box and are not appropriate to add to
  `scripts/requirements.txt` (which is the offline analysis toolchain
  comment at top of file). Add a separate
  `scripts/windows/requirements.txt`.
- **C3.** The script does **not** import IDA, unicorn, capstone, or any
  of the offline RE stack. The Windows runtime is a separate world from
  the Linux reverse-engineering toolchain.
- **C4.** No DLL-side changes. This work is purely in
  `scripts/windows/launch_stellaris.py` and a new
  `scripts/windows/requirements.txt`.
- **C5.** The script does not patch any binary, does not write to
  `libidalib.so`, does not write any "EULA 90" registry key. (Per
  `AGENTS.md` 硬性约束 1 — same rule, different stack.)
- **C6.** Source files are committed to the repo and pull-deployed to
  the Windows host, the same way `scripts/c1_remote.py` etc. are.

## 4. Contract

### Invocation

```powershell
python scripts/windows/launch_stellaris.py
```

When invoked from the agent's SSH session (the default per E7), the
script detects that it is running in a non-interactive session and
self-bridges into the logged-on user's interactive session via
`schtasks /run /it`. Stdout, stderr, and the exit code from the
in-session run are propagated back to the SSH session through a temp
file. From the agent's perspective the call looks like a single
synchronous invocation with normal exit-code / stdout / stderr
semantics. See §5a "Session bridging" for the contract.

Optional flags (see §5 for defaults):

- `--launcher-timeout-s N` — total seconds to wait for launcher window.
- `--game-timeout-s N` — total seconds to wait for `stellaris.exe`
  process after launcher exited.
- `--observe-s N` — observation window length, default 30.
- `--bridge-timeout-s N` — session-bridge total budget, default 90 s.
- `--inner` — implementation flag; the bridge sets this on the
  re-launched copy. The agent does not pass it. A copy started with
  `--inner` skips session detection and runs the launch chain directly.
- `--app-id N` — Steam AppID, default 281990 (Stellaris, verified
  Q6).
- `--no-prekill` — skip the stale-process pre-kill (debug only).
- `--verbose` — write timeline events to stderr at INFO level (default
  INFO is enabled, DEBUG silenced).

### stdout (success)

```
<pid>281990
```

A single integer PID, the PID of `stellaris.exe`, followed by `\n`. The
caller parses this with `int(stdout.strip())`.

### stderr (always)

A one-line-per-event timeline suitable for the agent's log. Format is
plain text, not JSON, to keep it readable in `print(stderr)` debug. Each
line has shape:

```
<ISO8601-UTC>  <PHASE>  <event>=<value>  [detail...]
```

Example:

```
2026-09-29T03:14:07Z  PREKILL  killed_pids=[1234,5678]  reason=stale
2026-09-29T03:14:07Z  STEAM    uri=steam://rungameid/281990  result=sent
2026-09-29T03:14:11Z  LAUNCHER window_found=PDX Launcher  title="Stellaris"
2026-09-29T03:14:15Z  LAUNCHER button=Play  clicked=true
2026-09-29T03:14:18Z  GAME     pid=9876  parent_pid=2345
2026-09-29T03:14:48Z  OBSERVE  ok=true  alive=30.0s  jit=False  wer=False
2026-09-29T03:14:48Z  DONE     exit=0  pid=9876
```

### Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | `stellaris.exe` is alive past the observation window and clean. PID on stdout. |
| 2 | Pre-kill: could not terminate a stale `stellaris.exe` or `launcher.exe`. Likely permission. Retry won't help. |
| 11 | Steam: `steam://` URI did not produce a Steam client process within the timeout. Protocol handler probably not registered. |
| 12 | Steam: Steam Guard / login required. Human action needed. |
| 13 | Steam: Stellaris update required. Human action needed. |
| 21 | Launcher: launcher window did not appear within `--launcher-timeout-s`. |
| 22 | Launcher: required UIA control (Play, Skip, Accept, ...) not found in launcher window. UI changed or non-cooperative. |
| 23 | Launcher: clicked a control and the launcher state did not progress within 10 s. |
| 24 | Launcher: launcher exited before reaching Play state. |
| 31 | Game: `stellaris.exe` did not spawn within `--game-timeout-s` of launcher click. |
| 32 | Game: `stellaris.exe` died within the observation window. stderr includes how long it lived and the exit code. |
| 33 | Game: JIT debugger dialog detected during observation. E4 was violated; human action needed. |
| 34 | Game: Windows Error Reporting dialog detected during observation. Human action needed. |
| 99 | Internal: unexpected exception. stderr includes the traceback. |

Codes 12, 13, 33, 34 are "go look at the box" failures — the script
correctly refuses to keep banging on a stuck modal dialog.

### Timing

- Total time, wall clock best case: launcher appears fast (≈10 s), game
  launches immediately, observation window is 30 s → ~45 s.
- Total time, wall clock worst case (still on the happy path): launcher
  window up to 30 s, game launch up to 30 s, observation 30 s → ~90 s.
- Defaults are chosen so the script returns inside ~90 s on a healthy
  box and inside ~120 s on a slow one.

## 5. Launch Chain (state machine)

```
                       ┌────────────┐
                       │   START    │
                       └─────┬──────┘
                             │ detect session (psutil.Process().session_id)
                             ▼
                ┌────────────────────────┐
                │  SESSION_BRIDGE (≤ 15 s)│──── fail 41/42/43 ──► EXIT
                │  (no-op if already in   │
                │   interactive session)  │
                └───────────┬────────────┘
                            │ schtasks /IT + poll
                            ▼
                ┌────────────────────────┐
                │  PREKILL  (≤ 2 s)     │──── fail 2 ───► EXIT
                └───────────┬────────────┘
                            ▼
                ┌────────────────────────┐
                │  STEAM_SPAWN (≤ 1 s)   │──── fail 11 ──► EXIT
                └───────────┬────────────┘
                            ▼
       ┌────────────────────────────────────────┐
       │ STEAM_READY (poll for client PID)      │──── fail 12/13 ──► EXIT
       └─────────────────┬──────────────────────┘
                         ▼
            ┌────────────────────────────┐
            │ LAUNCHER_WAIT (≤ 30 s)    │──── fail 21 ──► EXIT
            └─────────────┬──────────────┘
                          ▼
            ┴────────────────────────────┐
       ┌──► LAUNCHER_DISCOVER (≤ 5 s)   │─── fail 22 ──► EXIT
       │    └─────────────────┬─────────┘
       │                      ▼
       │    ┌────────────────────────────┐
       │    │ LAUNCHER_DRIVE (≤ 60 s)    │─── fail 22/23 ──► EXIT
       │    └─────────────────┬─────────┘
       │                      ▼
       │    ┌────────────────────────────┐
       │    │ LAUNCHER_HANDOFF (≤ 30 s)  │─── fail 24/31 ──► EXIT
       │    └─────────────────┬─────────┘
       │                      ▼
       │    ┌────────────────────────────┐
       │    │ GAME_OBSERVE (≤ 30 s)      │─── fail 32/33/34 ──► EXIT
       │    └─────────────────┬─────────┘
       ▼                      ▼
     (re-                    ┌───────────┐
      drive                  │  DONE  0  │
      launcher               └─────┬─────┘
      on stuck)                    ▼
                                  EXIT
```

The only loop in the happy path is inside `LAUNCHER_DRIVE`: the script
iterates "find a known-button → click it → wait for the window state to
change" until either (a) the launcher exits (handed off to game) or (b)
10 s elapse with no state change. Iteration budget ≤ 6.

### Phase contracts

**SESSION_BRIDGE** — On entry, `psutil.Process().session_id` returns
the calling session ID. The "logged-on user's interactive session" is
found by enumerating sessions via the `kernel32` `WTSEnumerateSessions`
API and selecting the `WTSActive` session (or, as a fallback, the
session of any running `explorer.exe` instance found via
`psutil.process_iter`). If the calling session ID already equals the
target session ID, SESSION_BRIDGE is a no-op and execution continues
in this same process.

Otherwise the script:

1. Generates a one-shot task name (`stellaris-launch-<pid>-<ts>`) and a
   completion-marker temp file path (`os.environ["TEMP"]\\...`).
2. Schedules the inner copy with `/ru <username> /rl highest` so it
   runs in that user's interactive session: `schtasks /create /tn
   <name> /tr "python launch_stellaris.py --inner --marker <path>"
   /sc once /st HH:MM /ru lofibass\\13229 /rl highest /f`. The
   **legacy `schtasks.exe` on Windows 10/11 does not recognize
   `/it`** (verified on `Windows_Jiaolong`: `schtasks /Run /?` only
   lists `/I`, not `/IT`). The `/ru <user> /rl highest` pair is what
   actually constrains the task to run in the user's interactive
   session when their account is logged on at the console.
3. Runs it with `schtasks /run /tn <name> /I` — `/I` is "ignore
   schedule constraints, run now" in legacy `schtasks.exe`. Verified
   working: the inner process lands in session 1 as user
   `lofibass\13229`, not in the SSH caller's session 0.
4. Polls the marker file every 0.5 s, up to `--bridge-timeout-s`
   (default 90), for a final `DONE:<exitcode>` line. The marker also
   receives an append of stderr lines from the inner run, so the
   outer can mirror them to its own stderr to preserve a single
   timeline.
5. Cleans up: `schtasks /delete /tn <name> /f`, deletes the marker,
   exits with the inner's exit code.

Total SESSION_BRIDGE budget ≤ 15 s on a healthy box (the schtasks
create/run/delete round-trip); `--bridge-timeout-s` is the cap, not
the target.

Failure modes:
- No logged-on interactive session → exit 41.
- `schtasks` not available / not permitted → exit 42.
- Inner invocation did not complete in `--bridge-timeout-s` → exit 43.

The **inner** invocation runs the rest of the chain (PREKILL through
GAME_OBSERVE) in the interactive session. The `--inner` flag is a
contract the builder must respect — without it the script would
re-bridge itself recursively.

**PREKILL** — `taskkill /F /IM stellaris.exe /T`,
`taskkill /F /IM "Paradox Launcher.exe" /T`. If either `taskkill`
returns non-zero because of a permission error (not because the process
was missing), exit 2. Missing processes are OK and treated as success.

Note: the launcher process is named `Paradox Launcher.exe` on this box,
**not** `launcher.exe`. (Verified: `launcher.exe` was never observed;
`Paradox Launcher.exe` appears with multiple instances per launch —
PDX Launcher uses a host + helper model.)

The script is **re-entrant safe** (Q5 answer: agent retries, script
does not). PREKILL must tolerate its own previous run's targets still
being alive — Steam often holds a process lock for tens of seconds
after a hard crash, and a re-entrant call must not blow up on the
second `taskkill`. The builder should explicitly test that a second
invocation, run 5 s after a failed run, completes PREKILL without
exiting 2.

**STEAM_SPAWN** — `subprocess.Popen(['cmd','/c','start','""','steam://rungameid/<app-id>'])`,
where the empty `""` is the title argument to `start` that prevents it
from being misinterpreted. Alternative: `os.startfile()` is simpler and
goes through the same protocol handler; builder's call.

**STEAM_READY** — poll `psutil.process_iter(['name'])` for a process
named `steam.exe` with a window handle (i.e., a Steam UI is showing) up
to `--launcher-timeout-s` seconds. While polling, also scan top-level
windows via UIA for a window whose title contains "Login" / "Sign in"
or whose control tree contains a Steam Guard prompt. If found, exit 12
or 13 as appropriate. If a "Stellaris update required" / "Update" /
"Play anyway" button is visible in the Steam UI, exit 13.

**LAUNCHER_WAIT** — once Steam is ready, poll `psutil.process_iter()`
for `Paradox Launcher.exe` (case-insensitive on Windows; the actual
process image name on this box is `Paradox Launcher.exe`). When found,
attach to its main window via `pywinauto.Application(backend="uia")
.connect(path="Paradox Launcher.exe")` — **the attach is for
window-existence checks only; the control tree is not used** (see
LAUNCHER_KEYBOARD below). Window must appear within 5 s of process
appearance, otherwise exit 21.

**LAUNCHER_KEYBOARD** — *(was LAUNCHER_DISCOVER + LAUNCHER_DRIVE;
UIA-on-PDX-Launcher was verified non-cooperative on `Windows_Jiaolong`
— the window class `Chrome_WidgetWin_1` exposes only a single empty
`Pane/RootView` control to UIA; no buttons, no Play, nothing to click.
CEF/Chromium surfaces like this only render to a single canvas and do
not expose interactive elements to UIA. Falling back to coordinate clicks
would violate G3; falling back to image recognition is a last resort.
Keyboard input via the standard Windows message loop is well-defined
on CEF and is the chosen path.)*

The phase:

1. Bring the launcher window to foreground: `ctypes.windll.user32
   .SetForegroundWindow(hwnd)`. If the call fails or `GetForegroundWindow`
   does not return the launcher hwnd within 3 s, exit 22.
2. Wait 1 s for keyboard focus to settle.
3. Send `Enter` (vk=0x0D, key down + key up) via `ctypes.windll.user32
   .SendInput(INPUT(...))`. Most Paradox Launcher instances
   default-focus the Play button on first show, so this is the
   cheapest attempt.
5. Wait up to 5 s for the launcher to start handoff: either
   `Paradox Launcher.exe` exits OR `stellaris.exe` appears.
6. If still up at 5 s, send `Tab` (vk=0x09) once, then `Enter`. Wait
   5 s again for handoff.
7. Repeat step 6 up to 2 more times (3 total Tab+Enter attempts).
8. If after the full sequence the launcher is still up and no
   `stellaris.exe` appeared, exit 23 (key sequence did not advance
   the launcher).

The launcher has a small number of focusable elements and Play is one
of them; Tab navigation reaches it deterministically within a few
presses on a CEF surface. If the actual launcher variant on this box
behaves differently, the builder's first run should observe what
focused element Tab lands on (via `GetGUIThreadInfo`) and adjust the
sequence — but the structural fallback (multiple Tab presses + Enter)
should still recover. **Document whatever sequence actually works in
D1 when the first successful run lands.**

Failure modes:
- Window exists but cannot be brought to foreground → exit 22.
- Tab+Enter sequence exhausted without handoff → exit 23.

**LAUNCHER_HANDOFF** — wait for `Paradox Launcher.exe` to exit, OR
for `stellaris.exe` to appear (whichever first). If neither within 10 s
after the final `Enter` press, exit 24. Then if `stellaris.exe` did
not appear within `--game-timeout-s` of `Paradox Launcher.exe`'s exit,
exit 31.

**GAME_OBSERVE** — over `--observe-s` (default 30) seconds, every 1 s:

- `psutil.Process(pid).status()` must be `"running"` and `.is_running()`
  must be `True`. If process disappears or status changes to `"zombie"`
  or `"dead"`, exit 32 (with last-known status + exit code if any).
- `pywinauto.findwindows` (top-level only) for windows whose class
  name matches `*(JIT|Debug|DbgW)*` or whose title matches
  `*(?i)starts-with[a-z]*just-in-time debugger*`. If found, exit 33.
- Same scan for `WerFault.exe` (Windows Error Reporting) process
  appearance OR a top-level window with title
  `*(?i)*Problem reporting*` or class `WerFault*`. If found, exit 34.

After the window passes with no failure, write `<pid>\n` to stdout and
exit 0.

## 6. Failure modes — full table

(Failure modes already enumerated as the §4 exit-code table; this section
captures them as a checklist the implementation must cover, not as
extra spec.)

Each row: detection signal → exit code → stderr message key.

| Detection | Exit code | stderr key |
|------------|----------:|------------|
| No logged-on interactive session (SSH context, headless box) | 41 | `no_interactive_session` |
| `schtasks` unavailable or permission denied | 42 | `schtasks_denied` |
| Inner invocation did not complete in `--bridge-timeout-s` | 43 | `bridge_timeout` |
| `taskkill` fails with permission error | 2 | `prekill_permission` |
| `steam://` URI does not produce Steam process within 15 s | 11 | `steam_no_client` |
| UIA detects Steam login window | 12 | `steam_login_required` |
| UIA detects Stellaris update dialog | 13 | `stellaris_update_required` |
| `Paradox Launcher.exe` process appears but no window in 5 s | 21 | `launcher_window_missing` |
| LAUNCHER_KEYBOARD: window cannot be brought to foreground | 22 | `launcher_no_focus` |
| LAUNCHER_KEYBOARD: Tab+Enter sequence exhausted, no handoff | 23 | `launcher_no_advance` |
| LAUNCHER_HANDOFF: launcher exited, no `stellaris.exe` in 30 s | 31 | `game_did_not_spawn` |
| GAME_OBSERVE: `stellaris.exe` status != running | 32 | `game_exited_early` |
| GAME_OBSERVE: JIT debugger window appeared | 33 | `jit_dialog` |
| GAME_OBSERVE: WerFault window appeared | 34 | `wer_dialog` |
| Any uncaught exception | 99 | `internal_error` |

The builder should add a few more rows discovered at runtime if they
appear on the box — the table is not exhaustive.

## 7. Dependencies

Runtime (Windows box, new file `scripts/windows/requirements.txt`):

- `pywinauto>=0.6.8` — UIA backend for `Application`, `findwindows`,
  `WindowSpecification`.
- `psutil>=5.9` — `process_iter`, `Process.status`, `Process.is_running`.

These two are the *only* deps. The implementation must not introduce
others.

No build-time deps. No native extensions to compile.

## 8. Decisions / open items for the builder

The following are deliberately **left to the builder**, per the
brainstorm session that produced this spec:

- **D1.** Exact Tab/Enter sequence that successfully triggers the
  launcher handoff. The first run on `Windows_Jiaolong` should
  observe what `GetGUIThreadInfo` reports about the focused element
  after each Tab press and record the minimal sequence that works.
  The spec assumes `Enter` alone is enough, then `Tab`+`Enter` up to
  3 times; if a different sequence is required, update this section.
- **D2.** Whether to spawn the URI via `os.startfile`,
  `subprocess.Popen(['cmd','/c','start',...])`, or `subprocess.Popen(['powershell','Start-Process',...])`.
  All three use the same protocol handler; the builder picks.
- **D3.** Internal module structure (`launcher_drive.py`,
  `state_machine.py`, `observation.py`). One file is fine; multiple is
  fine. Recommend `launch_stellaris.py` as a single ~400-line module
  with private helpers, for ease of `scp`-deploy.
- **D4.** Whether to add `--dry-run` that does everything except the
  actual URI spawn and the kill. Useful for first-time setup on a new
  box.
- **D5.** Whether to write a `tests/` (host-only smoke tests; no Windows
  machine in CI). Probably yes; can be skipped if not worth.
- **D6.** Exit-code map encoding. The script's exit codes are part of
  the contract; the builder must not change them without going back to
  the spec.
- **D7.** Whether to use `schtasks /IT` (built-in, no extra tooling)
  or `psexec -i` (Sysinternals; needs to be on the box) for the
  session bridge. Either works; `schtasks` is preferred for not
  introducing a new dependency. If `schtasks /IT` fails on this box's
  Windows build for any reason, fall back to `psexec -i` if present,
  else exit 42.
- **D8.** *(resolved 2026-09-29 verification on `Windows_Jiaolong`.)*
  UIA on PDX Launcher is non-cooperative: window class
  `Chrome_WidgetWin_1` exposes only `Pane/RootView` with no
  child controls. The chosen fallback is **keyboard input via
  `SendInput`** (LAUNCHER_KEYBOARD phase). Image recognition and
  coordinate clicks remain off the table per G3.

## 9. Open questions for the user

None at this stage. The five Yours-class questions from builder-check
were resolved:

- Q1: Execution context = SSH (non-interactive). Drives E7 and the
  SESSION_BRIDGE phase (§5a).
- Q2: PDX Launcher UIA verified non-cooperative on
  `Windows_Jiaolong` (window class `Chrome_WidgetWin_1`, control tree
  is just `Pane/RootView`). Drives the LAUNCHER_KEYBOARD phase
  (§5) — keyboard fallback chosen, per user pick "A".
- Q5: Retry ownership = A (agent retries). Drives re-entrant safety
  on PREKILL (§5).
- Q6: AppID 281990 confirmed. Drives the default value of
  `--app-id`.
- The "无问题" / strict-health check from the earlier builder-check
  pass was raised again by the second builder-check and resolves to "the
  user already decided running + no JIT + no WER is enough" — kept as-is.

If the user wants to add additional failure modes, preconditions, or
phases, this section is where they go.

## 10. Next steps (after spec approval)

1. ~~Spec review → user approves → spec committed.~~ *Done
   2026-09-29.*
2. ~~**Pre-implementation verification on `Windows_Jiaolong`**.~~ *Done
   2026-09-29. Results folded into the spec above.* Verified:
   - SSH session is session 0; interactive user `lofibass\13229` is
     session 1; explorer.exe confirms session 1 is logged-on.
   - Python 3.13.2 + psutil 7.2.2 + pywinauto 0.6.9 installed and
     usable.
   - Stellaris v4.4.4 lives at `D:\SteamLibrary\steamapps\common
     \Stellaris` (NOT the default path).
   - **Bridge mechanism**: legacy `schtasks.exe` on Windows 10/11 does
     NOT recognize `/it`; the actual bridge is
     `schtasks /create /ru <user> /rl highest + schtasks /run /I`.
     Verified: inner Python process lands in session 1 as user
     `lofibass\13229`.
   - **Launcher UIA**: PDX Launcher window class is `Chrome_WidgetWin_1`;
     UIA control tree is just `Pane/RootView` with no children. UIA
     is non-cooperative. **Fallback: keyboard input via `SendInput`**
     (LAUNCHER_KEYBOARD phase).
   - **Process name**: launcher runs as `Paradox Launcher.exe`
     (multiple instances per launch), NOT `launcher.exe`.
   - **Steam client state**: `steam.exe` already running in session
     1, 7 `steamwebhelper.exe` children (healthy). Appmanifest
     `StateFlags=4` (update required, but already downloaded &
     staged).
3. Builder produces plan: `docs/superpowers/plans/YYYY-MM-DD-launch-stellaris-impl.md`,
   following the style of `docs/superpowers/plans/2026-10-08-c2-quickjs-bootstrap.md`.
4. Plan review → user approves → implement
   `scripts/windows/launch_stellaris.py` and
   `scripts/windows/requirements.txt`.
5. First-run smoke on `Windows_Jiaolong`: dry-run (verify bridge +
   pre-kill + window-attach), then a real launch triggered **over SSH**
   (the actual use case). The first real launch should record what
   `GetGUIThreadInfo` reports about the focused element after each
   Tab press, to pin down D1's exact Tab/Enter sequence.
6. After 50 successful unattended runs over SSH, this document is
   done.