"""keep_awake —— 顶住空闲,并把「桌面此刻可达不可达」变成一条可读的观测.

常驻在交互会话里,用 `SetThreadExecutionState` 的进程级断言(`ES_CONTINUOUS |
ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED`)掐掉「空闲 → 关屏 → 唤醒要求登录」这条链;
进程一退出 Windows 自动恢复原电源行为,所以不写注册表、不改电源计划。同时读**当前输入桌面名**
(`Winsta0\\Default` = 已解锁,`Winlogon` = 锁着),把判决写进 `STATUS_PATH`。

本文件是两半结构:`# pure core` 小节在任何 OS 上 import 得到(判决、时钟、记录形状),
`# Windows edge` 与 `# serve / CLI` 小节只在实机跑。纯核里的数字来自 2026-10-24 对主机的
只读现状测量(插电 3600 s 关屏、电池 180 s 即睡),它们是 Windows 边缘喂进来的契约。

**与消费端的唯一耦合是两个字符串**:状态文件的 `desktop` 值 `"unlocked"` 与 `state` 值
`"serving"` 是 `scripts/c4_wiring_probe.py` 那侧的开机前置门读的东西,没有 import 关系
(与 `supervisor_ready`/`console_gate` 同一形状)。
"""

import ctypes
import sys

# --------------------------------------------------------------------------
# pure core — importable and testable on any OS
# --------------------------------------------------------------------------

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002
ERROR_ACCESS_DENIED = 5

DESKTOP_STATES = ("unlocked", "locked", "screensaver", "wrong_session",
                  "unreadable_denied", "unreadable_error", "unknown_name")

STATUS_PATH = r"C:\temp\ns_awake_status.json"
CMD_PATH = r"C:\temp\ns_awake_cmd.txt"
CMD_SEEN_PATH = r"C:\temp\ns_awake_cmd.seen"
LOG_PATH = r"C:\temp\ns_awake_log.jsonl"
TASK_SHIM = r"C:\temp\ns_awake_task.cmd"
OUT_PATH = r"C:\temp\ns_awake.out"
TASK_NAME = "NeoStellarisKeepAwake"

DEFAULT_INTERVAL_S = 5.0
DEFAULT_ASSERT_EVERY_S = 25.0
STATUS_MAX_AGE_S = 15.0

_DESKTOP_BY_NAME = {"Default": "unlocked",
                    "Winlogon": "locked",
                    "ScreenSaver": "screensaver"}


def execution_flags() -> int:
    """The thread assertion we hold: keep the display and the system awake, continuously.

    `ES_AWAYMODE_REQUIRED` is deliberately absent — that is media-center semantics,
    power plans don't always allow it, and what we want is "don't blank the screen",
    not "pretend somebody is home".
    """
    return ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED


def classify_desktop(name, err: int, own_session: int, console_session: int) -> str:
    """One of DESKTOP_STATES for one read of the input desktop.

    Session equality is checked **before** the name: a `Default` living in somebody
    else's session is not a desktop this process can drive, and reading the name
    first would call it reachable.
    """
    if own_session != console_session:
        return "wrong_session"
    if name is None:
        if err == ERROR_ACCESS_DENIED:
            return "unreadable_denied"
        return "unreadable_error"
    return _DESKTOP_BY_NAME.get(name, "unknown_name")


def desktop_reachable(state: str) -> bool:
    return state == "unlocked"


def is_fresh(rec, now: float, max_age_s: float = STATUS_MAX_AGE_S) -> bool:
    """Whether a status record was written inside the window the gate accepts.

    `STATUS_MAX_AGE_S` is three missed ticks at the default `--interval`, so a
    single hiccup in the daemon's own clock doesn't trip the gate.
    """
    if not isinstance(rec, dict):
        return False
    try:
        epoch = float(rec["epoch"])
    except (KeyError, TypeError, ValueError):
        return False
    return now - epoch <= max_age_s


def should_reassert(asserted_at: float, now: float,
                    interval_s: float = DEFAULT_ASSERT_EVERY_S) -> bool:
    return now - asserted_at >= interval_s


def plan_tick(now: float, asserted_at: float, last_state, state: str,
              assert_every_s: float = DEFAULT_ASSERT_EVERY_S):
    """The two loop decisions of one tick: re-assert the power request? log a transition?

    The first tick has no previous state, so it is never a transition — otherwise the
    log would open with a change that never happened.
    """
    do_assert = should_reassert(asserted_at, now, assert_every_s)
    is_transition = last_state is not None and state != last_state
    return do_assert, is_transition


def build_status_record(*, pid: int, now: float, desktop_state: str,
                        desktop_detail: str, own_session: int, console_session: int,
                        assert_rc: int, asserted_at: float, state: str = "serving",
                        note: str = ""):
    """The status record the consumer reads — the key set is the wire contract."""
    return {"pid": pid, "epoch": now, "state": state, "note": note,
            "desktop": desktop_state, "desktop_detail": desktop_detail,
            "session": own_session, "console_session": console_session,
            "assert_rc": assert_rc, "asserted_at": asserted_at}


def status_line(rec, now: float) -> str:
    """One human-readable line about a status record; None reads as absent."""
    if not isinstance(rec, dict):
        return "DESKTOP=absent"
    try:
        age = f"{now - float(rec['epoch']):.1f}s"
    except (KeyError, TypeError, ValueError):
        age = "unknown"
    return (f"STATE={rec.get('state', 'unknown')} DESKTOP={rec.get('desktop', 'unknown')} "
            f"detail={rec.get('desktop_detail', 'unknown')} age={age} "
            f"pid={rec.get('pid')} assert_rc={rec.get('assert_rc')} "
            f"session={rec.get('session')}/{rec.get('console_session')}")


def task_shim_text(pythonw: str, script: str) -> str:
    """ASCII-only .cmd shim that starts the daemon under pythonw.

    Keeping the shim ASCII means a non-ASCII install path fails here loudly instead
    of producing a scheduled task that dies silently — same reason as the supervisor's.
    """
    text = ("@echo off\r\n"
            f'"{pythonw}" "{script}" serve >> "{OUT_PATH}" 2>&1\r\n')
    text.encode("ascii")
    return text


# --------------------------------------------------------------------------
# Windows edge — ctypes only, runs on the host
# --------------------------------------------------------------------------

DESKTOP_READOBJECTS = 0x0001
UDESKF_NAME = 4
NO_CONSOLE_SESSION = 0xFFFFFFFF


def _require_windows() -> None:
    if sys.platform != "win32":
        raise SystemExit("keep_awake's live half runs on Windows")


def _dll(name: str):
    """A WinDLL that keeps ctypes' per-call last-error capture alive.

    `use_last_error=True` plus `ctypes.get_last_error()` is the only reliable way to
    read GetLastError here: calling kernel32.GetLastError() goes through ctypes' own
    frames, which can overwrite it first.  ctypes caches the instance, so building it
    per call costs nothing and keeps this module importable off Windows (where
    `ctypes.WinDLL` doesn't even exist).
    """
    return ctypes.WinDLL(name, use_last_error=True)


def assert_execution() -> int:
    """Re-assert the power request; the return value is the *previous* state.

    No judgement here — the caller records the value into the status record so a
    reader can see the assertion was actually accepted.
    """
    _require_windows()
    return _dll("kernel32").SetThreadExecutionState(execution_flags())


def _win_session_ids():
    """(own, console) session ids; -1 for whichever half the API couldn't answer."""
    from ctypes import wintypes

    _require_windows()
    kernel32 = _dll("kernel32")
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    own = -1
    sid = wintypes.DWORD()
    if kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcess(), ctypes.byref(sid)):
        own = int(sid.value)
    console = int(kernel32.WTSGetActiveConsoleSessionId())
    if console == NO_CONSOLE_SESSION:
        console = -1
    return own, console


def desktop_snapshot():
    """Classify the desktop currently receiving input, with a human-readable detail.

    The session ids are read **before** `OpenInputDesktop` so the failure branch can
    carry them too — `err=5 sessions=1/1` is what a DACL refusal looks like from the
    outside, and it is a different problem than a locked screen (§54.9's lesson: a
    belief about the desktop has to say which way it failed).
    """
    import ctypes.wintypes as wintypes

    _require_windows()
    user32 = _dll("user32")
    own, console = _win_session_ids()
    user32.OpenInputDesktop.restype = ctypes.c_void_p
    user32.CloseDesktop.restype = wintypes.BOOL
    handle = user32.OpenInputDesktop(0, False, DESKTOP_READOBJECTS)
    if not handle:
        gle = ctypes.get_last_error()
        return (classify_desktop(None, gle, own, console),
                f"err={gle} sessions={own}/{console}", own, console)
    try:
        buf = ctypes.create_unicode_buffer(256)
        needed = wintypes.DWORD()
        ok = user32.GetUserObjectInformationW(
            handle, UDESKF_NAME, buf,
            ctypes.sizeof(buf) * ctypes.sizeof(ctypes.c_wchar), ctypes.byref(needed))
        if not ok:
            gle = ctypes.get_last_error()
            return (classify_desktop(None, gle, own, console),
                    f"err={gle} sessions={own}/{console}", own, console)
        name = buf.value
    finally:
        user32.CloseDesktop(handle)
    if "\\" in name:
        name = name.split("\\")[-1]   # the API usually returns the bare name; strip any Winsta0\ prefix
    return classify_desktop(name, 0, own, console), name, own, console
