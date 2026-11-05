"""Host-side fence for ``session_bridge`` — the session-0 → session-1 channel.

The bridge exists because an SSH shell on Windows lands in session 0, where no
game window is visible; a scheduled task run interactively (``/I``) inherits the
logged-on session instead.  Only the pure part is testable here: the launcher
text, which is what carries the command across.

Three properties matter and all are cheap to break:

* the task must start **no console window** — a ``.cmd`` task fired with
  ``/run /I`` pops a console on the interactive desktop, steals the foreground
  from the game, and Stellaris self-pauses on focus loss (issue #32).  The task
  therefore runs ``wscript.exe`` on a ``.vbs`` that asks for a hidden window;
* the launcher must be **ASCII** — the host parses/executes it in a cp936
  locale, so a non-ASCII path would produce a task that dies silently at run
  time instead of failing where someone can see it;
* the sentinel must be unambiguous — the exit code is echoed as ``EXIT=`` after
  the command's own output, so the reader can split on the **last** ``EXIT=``
  and never mistake a line the command printed for the result.
"""

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import session_bridge as bridge  # pyright: ignore[reportMissingImports]


def _command_cmd_will_run(text: str) -> str:
    """The command line ``cmd.exe`` ends up executing.

    Two layers sit between the file and the process: VBScript collapses every
    doubled quote inside the string literal, then ``cmd /c`` applies its own
    quote rule — with more than two quotes it strips the leading quote and
    removes the last one.  Modelling both layers is the only way a host-side
    test can say anything about what lands on the box.
    """
    assert 'CreateObject("WScript.Shell")' in text, "WSH has no WScript.Shell property"
    line = next(ln for ln in text.splitlines() if ln.startswith("sh.Run "))
    literal = line.split("sh.Run ", 1)[1].strip()
    assert literal.endswith(", 0, True"), literal
    literal = literal[: -len(", 0, True")].strip()
    assert literal.startswith('"') and literal.endswith('"'), literal
    value = literal[1:-1].replace('""', '"')       # VBScript un-doubling
    assert " /c " in value, value
    rest = value.split(" /c ", 1)[1]
    assert rest.startswith('"') and rest.endswith('"'), rest
    return rest[1:-1]                               # cmd's quote stripping


def test_the_task_starts_a_hidden_launcher_not_a_console():
    """#32: a ``.cmd`` task window takes the foreground and the game pauses."""
    args = bridge.task_create_args(
        bridge.TASK_NAME, r"C:\temp\ns_world_oneshot.vbs", r"BOX\user"
    )
    target = args[args.index("/tr") + 1]
    assert target.lower().startswith("wscript.exe"), target
    assert "//B" in target and "//Nologo" in target, target
    assert target.rstrip('"').endswith(".vbs"), target


def test_the_vbs_hides_its_window_and_waits_for_the_exit_code():
    text = bridge.vbs_text(
        r"C:\Python\python.exe",
        r"C:\temp\ns_world.py",
        "assert-ready --action install --guard shim",
        r"C:\temp\out.txt",
    )
    text.encode("ascii")  # raises here, not on the box
    assert ", 0, True" in text
    assert text.count(r"C:\temp\out.txt") == 1


def test_the_launched_command_keeps_stdout_and_the_exit_sentinel():
    """One redirect covers output *and* sentinel, so out_path stays single."""
    text = bridge.vbs_text(
        r"C:\Python\python.exe",
        r"C:\temp\ns_world.py",
        "assert-ready --action install",
        r"C:\temp\out.txt",
    )
    command = _command_cmd_will_run(text)
    assert '"C:\\Python\\python.exe" "C:\\temp\\ns_world.py" assert-ready' in command
    # stderr has no console to go to any more, so it must join stdout
    assert "2>&1" in command
    # the sentinel is evaluated AFTER the command, inside the same group that
    # carries the redirect: %ERRORLEVEL% would have been expanded too early
    assert "echo EXIT=!ERRORLEVEL!" in command
    assert command.index("echo EXIT=") > command.index("2>&1")
    assert '> "C:\\temp\\out.txt"' in command


def test_the_task_never_schedules_a_second_run():
    """A +120 s one-shot fired a second copy while the first was still running.

    2026-11-03: the bridge created the task at ``now + 120 s`` and also fired it
    with ``/run``; a long probe (or a racing delete) let the scheduled copy run
    the shim again.  For ``--launch`` that is a second game.  The start must be
    a time already past so only ``/run`` can fire it.
    """
    args = bridge.task_create_args(bridge.TASK_NAME, r"C:\temp\x.vbs", r"BOX\user")
    assert args[0] == "schtasks"
    assert args[args.index("/sc") + 1] == "once"
    assert args[args.index("/st") + 1] == bridge.PAST_START
    assert bridge.PAST_START == "00:00"


def test_launcher_without_args_still_forms_a_runnable_command():
    text = bridge.vbs_text(
        r"C:\Python\pythonw.exe", r"C:\temp\ns_world.py", "", r"C:\temp\out.txt"
    )
    command = _command_cmd_will_run(text)
    assert '"C:\\Python\\pythonw.exe" "C:\\temp\\ns_world.py"' in command
    text.encode("ascii")


def test_a_non_ascii_path_is_refused_here_not_on_the_box():
    """The failure has to happen where a human is watching the deploy."""
    try:
        bridge.vbs_text(
            r"C:\Pуthon\python.exe", r"C:\temp\x.py", "status", r"C:\temp\out.txt"
        )
    except UnicodeEncodeError:
        return
    raise AssertionError("a non-ASCII launcher must be refused at write time")


def test_run_interactive_reads_the_sentinel_back(tmp_path, monkeypatch):
    """The read half of the channel: shim written, task fired, output read back.

    The two halves are separate code paths, and only the shim text had a fence.
    A read path that cannot open the file it just asked for defeats the whole
    channel while every shim-text test stays green.
    """
    shim = tmp_path / "shim.cmd"
    out = tmp_path / "out.txt"
    monkeypatch.setattr(bridge, "SHIM_PATH", str(shim))
    monkeypatch.setattr(bridge, "OUT_PATH", str(out))

    def fake_run(argv, **kwargs):
        if "/run" in argv:
            out.write_text("hello\r\nEXIT=0\r\n", encoding="utf-8")
        return

    monkeypatch.setattr(bridge.subprocess, "run", fake_run)

    output, code = bridge.run_interactive(r"C:\temp\probe.py", "status", timeout_s=5)
    assert (output, code) == ("hello", 0)
    assert shim.exists()


def test_peel_timeout_lets_a_shot_outlast_the_default():
    """A 120 s sampling window cannot be run under a 120 s bridge timeout."""
    timeout_s, rest = bridge.peel_timeout(["--timeout-s", "600", r"C:\temp\x.py", "run"])
    assert timeout_s == 600.0
    assert rest == [r"C:\temp\x.py", "run"]


def test_peel_timeout_is_absent_by_default():
    timeout_s, rest = bridge.peel_timeout([r"C:\temp\x.py", "status"])
    assert timeout_s == bridge.DEFAULT_TIMEOUT_S
    assert rest == [r"C:\temp\x.py", "status"]


def test_the_task_name_is_its_own():
    """Firing this must not disturb the launcher's or the supervisor's task."""
    assert bridge.TASK_NAME != "NeoStellarisSupervisor"
    assert "stellaris-launch" not in bridge.TASK_NAME
