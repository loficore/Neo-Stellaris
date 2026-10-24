"""Read-only campaign preflight for the C4 scope shot (host side).

Proves two things before the sampler is installed: the console path actually
delivers, and a campaign with per-system execution is loaded. Reuses
c4_wiring_probe's own command-file and marker-counting helpers so the wire
format stays the one the daemon already speaks.

    python ns_scope_pre.py V2PRE

Prints MARKERS <n> (None if game.log could not be read) and the delivery
receipt. Writes nothing but ns_game_cmd.txt.
"""

import os
import sys

import c4_wiring_probe as w


def main():
    marker = sys.argv[1] if len(sys.argv) > 1 else "V2PRE"
    log_path = os.path.expanduser(w.GAME_LOG)
    text = 'effect every_system = { log = "%s_[This.GetName]" }' % marker

    offset = w._file_size(log_path)
    print("LOG", log_path, "OFFSET", offset)
    try:
        w._send_console_or_abort(w.SUPERVISOR_CMD, text, log_path)
    except w._Abort as exc:
        print("CONSOLE_ABORT", exc.verdict, exc.detail)
        return 2
    got = w._wait_marker(log_path, offset, marker, w.PREFLIGHT_MARKERS, 30)
    print("MARKERS", got, "EXPECTED", w.PREFLIGHT_MARKERS)
    return 0 if got else 1


if __name__ == "__main__":
    sys.exit(main())
