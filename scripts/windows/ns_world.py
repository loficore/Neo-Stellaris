# ``world_state`` lives one directory up in the repo and beside this module on
# the wire (C:\\temp), so a bare import is not resolvable by a static checker;
# it IS resolvable at run time on both sides.
# pyright: reportMissingImports=false
"""ns_world — the agent's only entry point into the world-state machine.

The window discipline of this project used to live in prose: 「装那一刻前提是否
成立」 was a sentence in a document, and violating it produced no error.  This
module is the code that turns it into a refusal.  Every state-changing action
the agent can take goes through here, and the answer is **one line** plus an
exit code:

    STATE=<state> EVIDENCE=<k=v,...> NEXT=<a|b|c>

The agent reads that line and decides its next step.  It does not need to
understand a pixel, a threshold or a state name's history — and that is the
point: the reading is produced by the machine, not re-derived by the caller.

The exit codes are the second half of the interface (spec §1, §11-4):

===== ==========================================================
   0  the action is allowed / the command did what it said
   2  **refused** — the premise does not hold right now
   3  **blocked** — the attempt budget or a block marker says no
   4  **wedged** — the state lock could not be taken
===== ==========================================================

What this module does **not** do: decide anything.  Every judgement lives in
``world_state`` (the pure state machine); this module only loads the store,
calls it, saves the result and prints the line.  A judgement that lived here
would be a judgement the offline tests could not reach.

Two commands are deliberately **different** (spec §1 D3): ``quit`` exits the
game (a thin delegation to ``game_supervisor.py quit``) and ``abort`` records
that the agent has stopped trying an action.  Neither implies the other, and
``abort`` never touches the attempt budget — only ``unblock --evidence`` can
clear that (spec §7).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

#: Where the transition log lives on the Windows side.  Both the state file
#: and its history are written there (spec §3): one writer, one place.
JSONL_PATH = os.environ.get("NS_WORLD_JSONL") or r"C:\temp\ns_world.jsonl"

#: Where ``pull`` puts the history on the Linux side (spec §3).
LOCAL_JSONL = os.path.join("evidence", "logs", "world_state_4_4_4.jsonl")

#: The four exit codes.  The names are what ``exit_code_for`` speaks.
EXIT_KINDS = {"ok": 0, "refused": 2, "blocked": 3, "wedged": 4}

#: The order the evidence is written in — the order spec §10 lists the raw
#: counts in, so a reader finds each one where it expects it.
EVIDENCE_KEYS = ("pause", "console", "window", "red_px", "green_px",
                 "bright_px", "gold_px", "row_count", "option_count", "bbox")

#: The separator between the actions in ``NEXT=``.
ACTION_SEPARATOR = "|"


# ---------------------------------------------------------------------------
# The two pure functions: the line and the code
# ---------------------------------------------------------------------------

def exit_code_for(kind: str) -> int:
    """The exit code a gate outcome maps to.

    ``ok`` → 0, ``refused`` → 2, ``blocked`` → 3, ``wedged`` → 4.  An unknown
    kind is a **programming error**, not a runtime condition: it raises, so a
    new outcome cannot slip through as "some non-zero code" and leave the
    agent guessing.
    """
    try:
        return EXIT_KINDS[kind]
    except KeyError:
        raise ValueError(
            f"unknown outcome kind {kind!r} (known: {sorted(EXIT_KINDS)})") from None


def render_status(state: str, evidence: dict | None, next_actions) -> str:
    """One line: ``STATE=… EVIDENCE=… NEXT=…``.

    The line is a **protocol**, so it is built to be parsed without
    understanding the values:

    * the three verdicts come first, then the raw counts, then ``reason=``;
    * a value never contains a comma — a comma inside a value (a bbox, a
      reason) is written as ``;``, so the pairs split on ``,`` alone;
    * ``NEXT=`` is the pipe-joined list of the actions the transition table
      allows from this state; an empty list leaves the field **empty**,
      which is unambiguous ("nothing may follow") rather than a word that
      could be mistaken for a state or a window kind.
    """
    evidence = evidence or {}
    raw = evidence.get("raw") or {}
    pairs = []
    for key in EVIDENCE_KEYS:
        if key in ("pause", "console", "window"):
            section = evidence.get(key)
            if isinstance(section, dict):
                verdict = section.get("state", section.get("kind"))
                if verdict is not None:
                    pairs.append(f"{key}={_render_value(key, verdict)}")
        elif key in raw:
            pairs.append(f"{key}={_render_value(key, raw[key])}")
    reason = evidence.get("reason")
    if reason:
        pairs.append(f"reason={_render_value('reason', reason)}")
    actions = [str(a) for a in (next_actions or ()) if a]
    return (f"STATE={state} EVIDENCE={','.join(pairs)} "
            f"NEXT={ACTION_SEPARATOR.join(actions)}")


def _render_value(key: str, value) -> str:
    """One value, written so it cannot break the line's parsing."""
    if key == "bbox" and isinstance(value, (list, tuple)):
        return ";".join(str(v) for v in value)
    if value is None:
        return "none"
    return _one_line(str(value))


def _one_line(text: str) -> str:
    """Text on one line, with the protocol's separators neutralised."""
    return text.replace("\r", " ").replace("\n", " ").replace(",", ";")


# ---------------------------------------------------------------------------
# The store, the reading and the log
# ---------------------------------------------------------------------------

def _state_module():
    """The pure state machine, imported by name.

    On the wire both files sit in ``C:\\temp``; in the repo ``world_state.py``
    is one directory up.  The import happens here, not at module level, so
    importing this CLI never drags the state machine (or anything else) in —
    and a CLI that cannot find it says so, instead of failing with a bare
    traceback on a machine where the two are not side by side.
    """
    try:
        import world_state as ws

        return ws
    except ImportError:
        here = os.path.dirname(os.path.abspath(__file__))
        for candidate in (os.path.dirname(here), here):
            if candidate not in sys.path:
                sys.path.append(candidate)
        try:
            import world_state as ws

            return ws
        except ImportError as exc:
            raise RuntimeError(
                "world_state.py is not importable — it must sit beside this "
                "file (C:\\temp) or one directory above it") from exc


def _install_provider() -> None:
    """Give the lock its generation source (spec §11-4) — on Windows only.

    spec §7 names the source: the CIM creation date.  ``world_state`` is pure
    and cannot ask Windows itself, so the **entry point** installs the query.
    On Linux the provider is deliberately **not** installed: a provider that
    answers "no creation date" would short-circuit the module's own
    ``/proc`` parse and silently disable the generation check there.
    """
    if os.name != "nt":
        return
    import world_probe

    _state_module().set_process_start_time_provider(world_probe.start_time_provider)


def _live_reading():
    """One reading of the live game, or ``None`` when there is no game.

    ``None`` is not "healthy": every caller has to treat the absence of a
    reading as a refusal, because an unreadable window is not evidence of a
    good one (spec §5).
    """
    try:
        import game_supervisor as gs
        import world_probe as wp
    except ImportError:
        return None
    pid, hwnd = gs.find_game()
    if not pid or not hwnd:
        return None
    try:
        return wp.probe(hwnd, pid)
    except OSError:
        return None


def append_jsonl(record: dict, path: str | None = None) -> None:
    """Append one line to the transition log (spec §1 D4).

    The line carries the **reading**, not the state's name: a name says what
    the machine concluded, a reading says what it saw.  The log is
    append-only — a transition history that can be rewritten is not a
    history.
    """
    target = path or JSONL_PATH
    directory = os.path.dirname(target)
    line = json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
    try:
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError as exc:
        # Loud, not silent: a transition that cannot be recorded must stop the
        # caller — a log that silently drops lines is not a history.
        raise RuntimeError(f"{target}: cannot append to the transition log "
                           f"({exc})") from exc


def _store(args):
    """The state store, from the path the caller gave (or the default)."""
    ws = _state_module()
    return ws.Store.load(getattr(args, "state_path", None))


def _emit(state: str, evidence: dict | None, next_actions) -> str:
    """Print the one line and return it."""
    line = render_status(state, evidence, next_actions)
    print(line)
    return line


def _record(event: str, reading: dict | None, **extra) -> None:
    """Write one transition-log line: the event, the reading, the extras."""
    record = {"event": event, "at": time.time()}
    if reading is not None:
        record["probe"] = reading
    record.update(extra)
    append_jsonl(record)


# ---------------------------------------------------------------------------
# The subcommands
# ---------------------------------------------------------------------------

def cmd_probe(args) -> int:
    """Take a reading; write it out as the evidence file when asked.

    The file this writes is the only thing ``unblock`` accepts (spec §7): it
    carries the complete reading **and** the nonce of the block it is meant
    to clear.  A hand-written file cannot: it has no nonce (or no reading).
    """
    ws = _state_module()
    reading = _live_reading()
    if reading is None:
        _emit("NO_GAME", {"reason": "no game window to read"}, ())
        return exit_code_for("refused")

    if args.out:
        nonce = _nonce_for(args, reading)
        document = dict(reading)
        document["block_nonce"] = nonce
        document["written_at"] = time.time()
        directory = os.path.dirname(os.path.abspath(args.out))
        try:
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(document, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError as exc:
            raise RuntimeError(f"{args.out}: cannot write the evidence file "
                               f"({exc})") from exc
    state, evidence = ws.infer_state(reading)
    _emit(state, evidence, ws.legal_actions(state))
    return exit_code_for("ok")


def _nonce_for(args, reading) -> str | None:
    """The nonce of the block this evidence file is meant to clear.

    Three ways to name it, in order of how explicit they are: the caller
    says which action it is about; the file's **name** carries it
    (``ns_block_<nonce>.json``, the name spec §7 fixes); or there is exactly
    one block on record.  With none of those the file gets no nonce, and
    ``unblock`` will refuse it — which is the correct outcome, not a bug.
    """
    store = _store(args)
    action = getattr(args, "action", None)
    if action:
        marker = store.data.get("blocks", {}).get(action)
        if marker:
            return marker.get("nonce")
    name = os.path.basename(getattr(args, "out", "") or "")
    if name.startswith("ns_block_") and name.endswith(".json"):
        return name[len("ns_block_"):-len(".json")]
    blocks = store.data.get("blocks", {})
    if len(blocks) == 1:
        return next(iter(blocks.values())).get("nonce")
    return None


def cmd_status(args) -> int:
    """Report the state, the reading and the legal next actions."""
    ws = _state_module()
    now = time.time()
    store = _store(args)
    reading = _live_reading()
    if reading is None:
        _emit("NO_GAME", {"reason": "no game window to read"}, ())
        return exit_code_for("ok")

    probe = dict(reading)
    pid = reading.get("pid")
    probe["blocked"] = any(ws.block_state(store, action, now, pid=pid)
                           for action in ws.ACTIONS)
    probe["restore_incomplete"] = ws.expired_while_armed(store, now) is not None
    state, evidence = ws.infer_state(probe)
    _emit(state, evidence, ws.legal_actions(state))
    return exit_code_for("ok")


def cmd_assert_ready(args) -> int:
    """The gate: may this action be attempted right now?

    Refuses with exit code 2 (the premise does not hold) or 3 (the action is
    blocked and needs evidence to clear).  On success it issues the lease
    and prints its id — the caller then injects, and consumes the lease.
    """
    ws = _state_module()
    now = time.time()
    store = _store(args)
    reading = _live_reading()
    if reading is None:
        _emit("NO_GAME", {"reason": "no game window: the premise cannot be "
                                     "proven so the action is refused"},
              ())
        return exit_code_for("refused")
    try:
        with store.locked():
            ok, reason = ws.assert_ready(store, args.action, guard=args.guard,
                                          probe_evidence=reading, now=now)
            if ok:
                store.save()
    except TimeoutError as exc:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")
    if not ok:
        pid = reading.get("pid")
        blocked = ws.block_state(store, args.action, now, pid=pid)
        kind = "blocked" if blocked is not None else "refused"
        _emit("BLOCKED_WITH_EVIDENCE" if kind == "blocked" else "NO_GAME",
              {"raw": reading.get("raw") or {}, "reason": reason}, ())
        return exit_code_for(kind)
    _emit("GUARD_ARMED" if args.guard else "IN_GAME_RUNNING",
          {"raw": reading.get("raw") or {}, "reason": f"lease={reason}"},
          (args.action,))
    return exit_code_for("ok")


def cmd_lease(args) -> int:
    """Issue a lease for an action, against the current reading."""
    ws = _state_module()
    now = time.time()
    store = _store(args)
    reading = _live_reading()
    if reading is None:
        _emit("NO_GAME", {"reason": "no game window to read"}, ())
        return exit_code_for("refused")
    probe = dict(reading)
    state, evidence = ws.infer_state(probe)
    try:
        with store.locked():
            lease = ws.acquire(store, args.action, guard=args.guard, state=state,
                               fingerprint=ws.lease_fingerprint(evidence), now=now)
            if lease is not None:
                store.save()
    except TimeoutError as exc:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")
    if lease is None:
        _emit(state, dict(evidence, reason="no lease issued: the state is not "
                                       "IN_GAME_RUNNING or a lease is already "
                                       "outstanding"), ())
        return exit_code_for("refused")
    _emit(state, dict(evidence, reason=f"lease={lease['lease_id']}"), (args.action,))
    return exit_code_for("ok")


def cmd_consume(args) -> int:
    """Use a lease up: one lease, one use."""
    ws = _state_module()
    now = time.time()
    store = _store(args)
    try:
        with store.locked():
            consumed = ws.consume(store, args.lease, now)
            if consumed:
                store.save()
    except TimeoutError as exc:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")
    if not consumed:
        _emit("IN_GAME_RUNNING", {"reason": f"lease {args.lease!r} could not be "
                                            f"consumed (unknown, used up or expired)"},
              ())
        return exit_code_for("refused")
    _emit("IN_GAME_RUNNING", {"reason": f"lease {args.lease} consumed"}, ())
    return exit_code_for("ok")


def cmd_arm(args) -> int:
    """Record that a guard is installed against a lease."""
    ws = _state_module()
    now = time.time()
    store = _store(args)
    identity = (args.pid, args.start_time or "")
    try:
        with store.locked():
            ws.arm(store, args.guard, args.lease, identity, now)
            store.save()
    except TimeoutError as exc:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")
    except ValueError as exc:
        _emit("IN_GAME_RUNNING", {"reason": str(exc)}, ())
        return exit_code_for("refused")
    _emit("GUARD_ARMED", {"reason": f"guard {args.guard} armed on lease {args.lease}"},
          ())
    return exit_code_for("ok")


def cmd_unarm(args) -> int:
    """Record that a guard is no longer installed.

    Without this the guard stays "armed" and its lease's expiry reads as
    ``RESTORE_INCOMPLETE`` forever — spec §5's 宁可误判不可漏判, paid for by
    every uninstall path having to say so.
    """
    ws = _state_module()
    now = time.time()
    store = _store(args)
    try:
        with store.locked():
            ws.unarm(store, args.guard, now)
            store.save()
    except TimeoutError as exc:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")
    _emit("IN_GAME_RUNNING", {"reason": f"guard {args.guard} unarmed"}, ())
    return exit_code_for("ok")


def cmd_unblock(args) -> int:
    """Clear a block — but only with machine-made evidence.

    spec §7: the evidence must carry the block's nonce **and** the complete
    reading, and be newer than the block.  A hand-written or ``touch``\\ed
    file fails, so an agent cannot brush its way past a block by retrying.
    """
    ws = _state_module()
    now = time.time()
    store = _store(args)
    nonce = args.nonce
    if not nonce:
        nonce = _nonce_in_file(args.evidence) or ""
    try:
        with store.locked():
            ok, reason = ws.unblock(store, nonce, args.evidence, now)
            if ok:
                store.save()
    except TimeoutError as exc:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")
    if not ok:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": reason}, ())
        return exit_code_for("blocked")
    _emit("IN_GAME_RUNNING", {"reason": reason}, ())
    _record("unblock", None, action=args.action, nonce=nonce,
            reason=args.reason or reason)
    return exit_code_for("ok")


def _nonce_in_file(path: str) -> str | None:
    """The ``block_nonce`` an evidence file carries, if it has one."""
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    nonce = document.get("block_nonce")
    return nonce if isinstance(nonce, str) and nonce else None


def cmd_quit(args) -> int:
    """Exit the game — a thin delegation to ``game_supervisor.py quit``.

    Distinct from ``abort`` on purpose (spec §1 D3): this one changes the
    world, that one only records a decision.  Neither implies the other.
    """
    try:
        import game_supervisor as gs
    except ImportError as exc:
        _emit("NO_GAME", {"reason": f"game_supervisor is not importable: {exc}"}, ())
        return exit_code_for("refused")
    gs.cmd_send(argparse.Namespace(words=["quit"], wait_s=0.8))
    _emit("NO_GAME", {"reason": "quit sent to the game supervisor"}, ())
    _record("quit", None)
    return exit_code_for("ok")


def cmd_abort(args) -> int:
    """Record that the agent has stopped trying an action.

    It records the decision and **nothing else**: the attempt budget is the
    block, and only ``unblock --evidence`` may clear that (spec §7).  An
    abort that reset the counters would be an evidence-free way past a
    block — the very thing the design forbids (spec §2).
    """
    ws = _state_module()
    now = time.time()
    store = _store(args)
    pid = args.pid
    blocked = ws.block_state(store, args.action, now, pid=pid)
    try:
        with store.locked():
            store.data.setdefault("aborted", {})[args.action] = {
                "at": now, "reason": args.reason or ""}
            store.save()
    except TimeoutError as exc:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")
    reason = f"aborted {args.action}"
    if blocked is not None:
        reason += (f" — but it is still blocked ({blocked['attempts']} attempts "
                   f"on record): only 'unblock --evidence' can clear that")
    _emit("IN_GAME_RUNNING", {"reason": reason}, ())
    _record("abort", None, action=args.action, reason=args.reason or "",
            blocked=blocked is not None)
    return exit_code_for("ok")


def cmd_pull(args) -> int:
    """Fetch the transition log off the Windows host.

    The history is written on the Windows side (spec §3: one writer, one
    place); the Linux side pulls it.  The bytes come back base64-encoded in
    slices, because a plain download over this channel resets the connection
    past a few KB (docs/offline-tooling.md trap 8).
    """
    host = os.environ.get("NS_WIN_HOST", "Windows_Jiaolong")
    remote = os.environ.get("NS_WORLD_JSONL", r"C:\temp\ns_world.jsonl")
    out = args.out or LOCAL_JSONL
    try:
        payload = _fetch_base64(host, remote)
    except (OSError, subprocess.SubprocessError) as exc:
        _emit("NO_GAME", {"reason": f"pull failed: {exc}"}, ())
        return exit_code_for("refused")
    directory = os.path.dirname(os.path.abspath(out))
    try:
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(payload)
    except OSError as exc:
        raise RuntimeError(f"{out}: cannot write the pulled log ({exc})") from exc
    _emit("NO_GAME", {"reason": f"pulled {len(payload)} bytes into {out}"}, ())
    return exit_code_for("ok")


def _fetch_base64(host: str, remote: str, slice_bytes: int = 525) -> bytes:
    """Read a file off the Windows host, base64-encoded, in slices.

    ``slice_bytes`` is 525 on purpose: 525 raw bytes are 700 base64
    characters, which is the size this channel carries stably.
    """
    size = int(_ssh(host, f"powershell -NoProfile -Command "
                           f"(Get-Item '{remote}').Length").strip() or 0)
    if size <= 0:
        return b""
    chunks = []
    offset = 0
    while offset < size:
        length = min(slice_bytes, size - offset)
        command = (
            f"$b=[IO.File]::ReadAllBytes('{remote}');"
            f"[Convert]::ToBase64String($b[{offset}..{offset + length - 1}])")
        chunk = _ssh(host, f"powershell -NoProfile -Command \"{command}\"")
        chunks.append(chunk)
        offset += length
    import base64
    return base64.b64decode("".join(chunks))


def _ssh(host: str, command: str) -> str:
    """Run one command on the Windows host and return its stdout."""
    result = subprocess.run(["ssh", host, command], capture_output=True,
                            text=True, timeout=60)
    if result.returncode != 0:
        raise OSError(f"ssh {host} failed ({result.returncode}): "
                      f"{(result.stderr or '').strip()}")
    return (result.stdout or "").strip()


# ---------------------------------------------------------------------------
# The argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-path", default=None,
                        help="the state file (default: the Windows-side path)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("probe", help="take one reading")
    p.add_argument("--out", default=None, help="write the evidence file here")
    p.add_argument("--action", default=None,
                   help="which action's block nonce the evidence file carries")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("status", help="report the state and the legal actions")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("assert-ready", help="the gate")
    p.add_argument("--action", required=True)
    p.add_argument("--guard", default=None)
    p.set_defaults(func=cmd_assert_ready)

    p = sub.add_parser("lease", help="issue a lease")
    p.add_argument("--action", required=True)
    p.add_argument("--guard", default=None)
    p.set_defaults(func=cmd_lease)

    p = sub.add_parser("consume", help="use a lease up")
    p.add_argument("--lease", required=True)
    p.set_defaults(func=cmd_consume)

    p = sub.add_parser("arm", help="record an installed guard")
    p.add_argument("--guard", required=True)
    p.add_argument("--lease", required=True)
    p.add_argument("--pid", type=int, default=0)
    p.add_argument("--start-time", default=None)
    p.set_defaults(func=cmd_arm)

    p = sub.add_parser("unarm", help="record a removed guard")
    p.add_argument("--guard", required=True)
    p.set_defaults(func=cmd_unarm)

    p = sub.add_parser("unblock", help="clear a block with evidence")
    p.add_argument("--evidence", required=True)
    p.add_argument("--reason", default="")
    p.add_argument("--nonce", default=None)
    p.add_argument("--action", default=None)
    p.set_defaults(func=cmd_unblock)

    p = sub.add_parser("quit", help="exit the game")
    p.set_defaults(func=cmd_quit)

    p = sub.add_parser("abort", help="stop retrying an action")
    p.add_argument("--action", required=True)
    p.add_argument("--reason", default="")
    p.add_argument("--pid", type=int, default=None)
    p.set_defaults(func=cmd_abort)

    p = sub.add_parser("pull", help="fetch the transition log off the host")
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_pull)
    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    _install_provider()
    try:
        return args.func(args)
    except TimeoutError as exc:
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")
    except RuntimeError as exc:
        # The machine itself is broken (the state module is not there, the
        # log cannot be written).  That is not a refusal and not a block: it
        # is the machinery refusing to answer, and the agent must not read it
        # as "go ahead".
        _emit("BLOCKED_WITH_EVIDENCE", {"reason": str(exc)}, ())
        return exit_code_for("wedged")


if __name__ == "__main__":
    raise SystemExit(main())
