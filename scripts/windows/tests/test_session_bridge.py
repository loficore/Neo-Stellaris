"""Host-side fence for ``session_bridge`` — the session-0 → session-1 channel.

The bridge exists because an SSH shell on Windows lands in session 0, where no
game window is visible; a scheduled task run interactively (``/I``) inherits the
logged-on session instead.  Only the pure part is testable here: the shim's
text, which is what carries the command across.

Two properties matter and both are cheap to break:

* the shim must be **ASCII** — a cp936 ``cmd.exe`` parses ``.cmd`` files in the
  console code page, so a non-ASCII path would produce a task that dies
  silently at run time instead of failing where someone can see it;
* the sentinel must be unambiguous — the exit code is echoed as ``EXIT=`` after
  the command's own output, so the reader can split on the **last** ``EXIT=``
  and never mistake a line the command printed for the result.
"""

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import session_bridge as bridge  # pyright: ignore[reportMissingImports]


def test_shim_is_ascii_and_echoes_the_exit_code_after_the_command():
    text = bridge.shim_text(
        r"C:\Python\python.exe",
        r"C:\temp\ns_world.py",
        "assert-ready --action install --guard shim",
        r"C:\temp\out.txt",
    )
    text.encode("ascii")  # raises here, not on the box
    assert text.startswith("@echo off\r\n")
    assert '"C:\\Python\\python.exe" "C:\\temp\\ns_world.py" assert-ready' in text
    assert '> "C:\\temp\\out.txt" 2>&1' in text
    # the sentinel comes AFTER the output redirection, so the reader can split
    # on the last EXIT= and be sure it is the exit code.
    assert text.index("EXIT=%ERRORLEVEL%") > text.index("> ")
    assert text.count("EXIT=") == 1


def test_shim_without_args_still_forms_a_runnable_command():
    text = bridge.shim_text(
        r"C:\Python\pythonw.exe", r"C:\temp\ns_world.py", "", r"C:\temp\out.txt"
    )
    assert '"C:\\temp\\ns_world.py"\r\n' in text or '"C:\\temp\\ns_world.py" > ' in text
    text.encode("ascii")


def test_a_non_ascii_path_is_refused_here_not_on_the_box():
    """The failure has to happen where a human is watching the deploy."""
    try:
        bridge.shim_text(
            r"C:\Pуthon\python.exe", r"C:\temp\x.py", "status", r"C:\temp\out.txt"
        )
    except UnicodeEncodeError:
        return
    raise AssertionError("a non-ASCII shim must be refused at write time")


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
        return None

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
    assert bridge.TASK_NAME not in ("NeoStellarisSupervisor",)
    assert "stellaris-launch" not in bridge.TASK_NAME
