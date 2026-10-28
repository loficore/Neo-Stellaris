"""session_bridge — run one command in the interactive desktop session.

**Why this exists.** The whole project is driven over SSH, and an SSH login on
Windows lands in **session 0** — the service session, which has no interactive
desktop.  ``EnumWindows`` there sees almost nothing: on the game box a shell in
session 0 enumerates *one* top-level window while ``stellaris.exe``,
``explorer.exe`` and ``steam.exe`` are all in session 1.  So a probe run from
SSH reports ``NO_GAME`` forever, and the world-state machine — whose entire job
is to read the real window — can never take a reading.

``launch_stellaris.py`` and ``game_supervisor.py start`` already solve this by
registering a **scheduled task** and running it interactively (``/I``): a task
run that way inherits the logged-on user's session, so it can see and touch the
game window.  This tool is the same mechanism, generalised to one command:

    python C:/temp/session_bridge.py C:/temp/ns_world.py status
    python C:/temp/session_bridge.py C:/temp/ns_world.py assert-ready \
        --action install --guard shim

It writes an ASCII ``.cmd`` shim, registers a one-shot task that runs it with
output redirected to a file, fires it with ``/run /I``, waits for the
``EXIT=`` sentinel, deletes the task and prints what the command printed plus
its exit code.

**It is a channel, not a policy.** It runs what you tell it to run, in the
session where the game lives.  Nothing here decides anything; the judgement
stays in ``world_state``.

Deliberately **not** wired into the justfile as a new recipe: a ``just ns``
verb would be a second world-changing channel outside the ``game`` recipe, and
``scripts/test_scripts_layout.py``'s R-verbs fence only polices that one.  Use
``just win "python C:/temp/session_bridge.py ..."`` until a registry entry for
this channel exists on purpose.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

#: The scheduled task this tool owns.  Distinct from the launcher's and the
#: supervisor's names so firing one never disturbs the others.
TASK_NAME = "NSWorldOneShot"
SHIM_PATH = r"C:\temp\ns_world_oneshot.cmd"
OUT_PATH = r"C:\temp\ns_world_oneshot.txt"

#: How long to wait for the sentinel.  Generous: ``/run /I`` waits for the
#: Task Scheduler to pick the task up, and the task itself may take seconds.
DEFAULT_TIMEOUT_S = 120.0


def _open_file(path, mode, **kwargs):
    """``open`` that names the file when it fails.  Exception class preserved.

    Kept as a helper so the call sites can stay context managers while the
    failure is still handled: the try lives here, the ``with`` stays outside.
    """
    try:
        return open(path, mode, **kwargs)
    except OSError as exc:
        raise type(exc)(f"{path}: cannot open ({exc})") from exc


def shim_text(python: str, script: str, args: str, out_path: str) -> str:
    """The ASCII ``.cmd`` that runs one command and records its exit code.

    ASCII on purpose (the same reason ``game_supervisor.task_shim_text`` is):
    a cp936 ``cmd.exe`` parses ``.cmd`` files in the console code page, so a
    non-ASCII path would produce a task that dies silently at run time instead
    of failing here.
    """
    command = f'"{python}" "{script}"'
    if args:
        command += f" {args}"
    text = ("@echo off\r\n"
            f'{command} > "{out_path}" 2>&1\r\n'
            f'echo EXIT=%ERRORLEVEL% >> "{out_path}"\r\n')
    text.encode("ascii")          # raises here rather than on the box
    return text


def run_interactive(script: str, args: str = "", *,
                    timeout_s: float = DEFAULT_TIMEOUT_S,
                    python: str | None = None) -> tuple[str, int | None]:
    """Run ``script`` in session 1; return ``(output, exit_code)``.

    ``exit_code`` is ``None`` when the sentinel never arrived (the caller must
    treat that as "we do not know what happened", not as success).
    """
    python = python or sys.executable
    with _open_file(SHIM_PATH, "w", encoding="ascii", newline="") as fh:
        fh.write(shim_text(python, script, args, OUT_PATH))
    # A leftover sentinel would let this call read the PREVIOUS run's exit code,
    # which is the one way this channel could report a result nobody produced.
    try:
        os.remove(OUT_PATH)
    except FileNotFoundError:
        pass

    owner = f"{os.environ.get('COMPUTERNAME', '')}\\{os.environ.get('USERNAME', '')}"
    start = time.strftime("%H:%M", time.localtime(time.time() + 120))
    subprocess.run(["schtasks", "/create", "/tn", TASK_NAME, "/tr", SHIM_PATH,
                    "/sc", "once", "/st", start, "/ru", owner, "/rl", "highest",
                    "/f"], check=True, capture_output=True, text=True)
    try:
        subprocess.run(["schtasks", "/run", "/tn", TASK_NAME, "/I"],
                       check=True, capture_output=True, text=True)
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if os.path.exists(OUT_PATH):
                with _open_file(OUT_PATH, "r", encoding="utf-8",
                                errors="replace") as fh:
                    text = fh.read()
                if "EXIT=" in text:
                    body, _, tail = text.rpartition("EXIT=")
                    try:
                        return body.strip(), int(tail.strip().splitlines()[0])
                    except (ValueError, IndexError):
                        return body.strip(), None
            time.sleep(0.5)
        return "", None
    finally:
        # check=False on purpose: deleting a task that was never created must
        # not mask the result we already have.
        subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
                       check=False, capture_output=True, text=True)


def peel_timeout(args: list[str]) -> tuple[float, list[str]]:
    """Take an optional leading ``--timeout-s N`` off the front of ``args``.

    The default (120 s) fits a status read, not the shot drivers: those sample
    for ``--poll-s 120`` and only then drain, so the sentinel arrives long after
    the bridge would have given up.  A timeout here is "we do not know what
    happened", which must never be the reading a 120 s shot produces.
    """
    if len(args) >= 2 and args[0] == "--timeout-s":
        try:
            timeout_s = float(args[1])
        except ValueError as exc:
            raise SystemExit(f"--timeout-s needs a number, got {args[1]!r}") from exc
        return timeout_s, args[2:]
    return DEFAULT_TIMEOUT_S, args


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__)
        return 2
    timeout_s, args = peel_timeout(args)
    if not args:
        print(__doc__)
        return 2
    script, rest = args[0], " ".join(args[1:])
    output, code = run_interactive(script, rest, timeout_s=timeout_s)
    if output:
        print(output)
    if code is None:
        print("BRIDGE=timeout (no EXIT sentinel — treat as unknown, not success)")
        return 4
    print(f"EXIT={code}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
