#!/usr/bin/env python3
"""C4 forensics: read-only execution-frame sampler for base Execute 0x1D08520.

One bounded shot in one game process. The DLL detour records a 1/512 sample of
every base-Execute call: the keyword instance identity at [self], [self+8] and
its vtable shim slot, plus the first eight qwords of the execution frame (ctx).
The chain X=[ctx+0x30] -> S=[X+8] -> id=[S+8] / object=[S+0x20] is followed
HERE with ReadProcessMemory, never inside the game: a stale pointer can only
make one read return None.

Usage: python3 scripts/c2_scope_probe.py [dll] [--poll-s 120] [--settle-s 2]
       [--out C:/temp/c4_scope_probe.tsv] [--census ...] [--id-names ...]

This is a LIVE shot and requires an explicit naming from the user for the
session (docs/roadmap.md authorization table). Cleanup runs in a finally:
uninstall -> verify -> settle -> assert_game_alive. Never FreeLibrary the DLL,
whatever the rc.

Verdicts: captured is the only evidence result. no_calls / no_samples /
lexer_only are ENVIRONMENT results — load a running campaign, unpause, and
rerun in a NEW game process (this sampler refuses a process that already has a
detour on 0x1D08520).
"""

import argparse
import os
import struct
import sys
import time

from c2_harness import (
    resolve_pid, resolve_base_address, inject_dll,
    list_exports, call_remote, call_remote_with_arg,
    remote_alloc, read_memory, assert_game_alive,
)

DEFAULT_DLL = r"C:\temp\sqjs_c4.dll"
DEFAULT_OUT = r"C:/temp/c4_scope_probe.tsv"
DEFAULT_CENSUS = os.path.join(
    "evidence", "xrefs", "exec_frame_callers_4_4_4.tsv",
)
DEFAULT_ID_NAMES = os.path.join(
    "evidence", "xrefs", "descriptor_oracle_4_4_4.tsv",
)

POLL_INTERVAL_S = 1.0
POLL_TIMEOUT_S = 120.0
SETTLE_S = 2.0

ENTRY_SIZE = 104
STATS_SIZE = 512
LAYOUT_WORDS = 5
RING_LEN = 256
MAX_FOLLOW = 32
CTX_X_OFFSET = 0x30

VERDICT_DIAGNOSIS = {
    "no_calls": (
        "the detour saw no base-Execute call within the poll window. That is an "
        "ENVIRONMENT result, not a code verdict: load a running campaign and "
        "unpause the game, then rerun with a fresh game process."
    ),
    "no_samples": (
        "base Execute ran but the 1/512 gate never fired. A longer --poll-s on a "
        "busy campaign is the only lever; nothing was captured."
    ),
    "all_invalid": (
        "every sample had an implausible self or ctx pointer, so no frame was "
        "recorded. This is an environment/call-shape result; try a fresh process."
    ),
    "lexer_only": (
        "every valid sample carried the lexer sentinel [ctx+0x38]==0xb. These "
        "calls are lexer-path executions, not normal effect fires (section 52); "
        "they cannot answer which object a real execution frame is."
    ),
    "chain_unreadable": (
        "samples are valid but no ctx chain could be read: [ctx+0x30], [X+8], "
        "[S], [S+8] or [S+0x20] failed in every sample. Keep the entries; the "
        "failure itself is the observation."
    ),
}

_INT32_MAX = 0x7FFFFFFF
_UINT32_SPAN = 1 << 32

_dispatched = set()


# ---------------------------------------------------------------------------
# Pure decode / judgement layer (imported by test_c2_scope_probe.py)
# ---------------------------------------------------------------------------

def decode_layout(words):
    """Validate the DLL's five layout words; any drift is a ValueError."""
    words = list(words)
    if len(words) != LAYOUT_WORDS:
        raise ValueError(f"layout has {len(words)} words, expected {LAYOUT_WORDS}")
    out = {
        "entry": words[0],
        "stats": words[1],
        "ring": words[2],
        "mask": words[3],
        "version": words[4],
    }
    if out["entry"] != 104:
        raise ValueError(f"Entry size drifted: {out['entry']} != 104")
    if out["stats"] != 56:
        raise ValueError(f"Stats size drifted: {out['stats']} != 56")
    if out["ring"] != RING_LEN:
        raise ValueError(f"ring length drifted: {out['ring']} != {RING_LEN}")
    if out["mask"] != 511:
        raise ValueError(f"sample mask drifted: {out['mask']} != 511")
    if out["version"] != 1:
        raise ValueError(f"unknown layout version {out['version']} != 1")
    return out


def decode_entry(raw):
    """Decode one 104-byte Entry; a short buffer is a ValueError."""
    if len(raw) < ENTRY_SIZE:
        raise ValueError(f"Entry needs {ENTRY_SIZE} bytes, got {len(raw)}")
    (valid, lexer, _pad0, self_vtable_rva, shim_rva, token_id, caller_rva,
     self_ptr, ctx_ptr, *ctx_words) = struct.unpack(
        "<BBHIIII4xQQ8Q", raw[:ENTRY_SIZE]
    )
    return {
        "valid": valid,
        "lexer": lexer,
        "self_vtable_rva": self_vtable_rva,
        "shim_rva": shim_rva,
        "token_id": token_id,
        "caller_rva": caller_rva,
        "self_ptr": self_ptr,
        "ctx_ptr": ctx_ptr,
        "ctx_words": list(ctx_words),
    }


def decode_stats(text):
    """Parse whitespace-separated ``key=int`` tokens; duplicate keys raise."""
    out = {}
    for tok in text.split():
        if "=" not in tok:
            continue
        key, _, val = tok.partition("=")
        if key in out:
            raise ValueError(f"duplicate key {key!r} in stats text")
        out[key] = int(val)
    return out


def caller_site(return_rva):
    """The static call site: the engine's ``call rel32`` is 5 bytes."""
    if return_rva < 5:
        raise ValueError(f"return RVA 0x{return_rva:x} cannot precede a call")
    return return_rva - 5


def load_call_census(path):
    """Task 1 site table -> {site: {"func": int|None, "origin": str}}."""
    out = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 6:
                continue
            try:
                site = int(cols[4], 16)
                func = int(cols[0], 16)
            except ValueError:
                continue
            out[site] = {"func": func, "origin": cols[5]}
    return out


def load_id_names(path):
    """descriptor_oracle TSV -> {id: name}; ids there are decimal."""
    out = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 2:
                continue
            try:
                out[int(cols[0], 10)] = cols[1]
            except ValueError:
                continue
    return out


def _read_u64(reader, addr):
    raw = reader(addr, 8)
    if raw is None or len(raw) < 8:
        return None
    return struct.unpack("<Q", raw[:8])[0]


def _read_u32(reader, addr):
    raw = reader(addr, 4)
    if raw is None or len(raw) < 4:
        return None
    return struct.unpack("<I", raw[:4])[0]


def follow_chain(reader, ctx_ptr):
    """Follow X=[ctx+0x30] -> S=[X+8] -> id/object with a fallible reader.

    Every step is independent: any unreadable step leaves its fields None and
    ``ok`` False. The caller passes ReadProcessMemory; nothing here trusts an
    address it did not just read.
    """
    out = {
        "x": None, "s": None, "s_vptr": None, "id": None, "object": None,
        "ok": False,
    }
    x = _read_u64(reader, ctx_ptr + CTX_X_OFFSET)
    if x is None:
        return out
    out["x"] = x

    s = _read_u64(reader, x + 8)
    if s is None:
        return out
    out["s"] = s

    out["s_vptr"] = _read_u64(reader, s)
    out["id"] = _read_u32(reader, s + 8)
    out["object"] = _read_u64(reader, s + 0x20)
    out["ok"] = all(
        out[k] is not None for k in ("x", "s", "s_vptr", "id", "object")
    )
    return out


def summarize(entries, stats, chains, census, id_names):
    """Aggregate sampled entries, followed chains and the Task 1 census.

    ``census`` maps a call site to its function/origin; ``id_names`` maps the
    chain's token id to a keyword name. The id is a keyword token id, never a
    system id: an unknown id stays ``-`` instead of being guessed.
    """
    by_caller = {}
    vtables = set()
    valid = 0
    lexer = 0
    for e in entries:
        site = caller_site(e["caller_rva"]) if e["caller_rva"] >= 5 else None
        by_caller[site] = by_caller.get(site, 0) + 1
        if e["valid"]:
            valid += 1
            vtables.add(e["self_vtable_rva"])
            if e["lexer"]:
                lexer += 1

    chain_rows = []
    id_counts = {}
    chain_ok = 0
    for ctx, chain in sorted(chains.items()):
        if chain.get("ok"):
            chain_ok += 1
            if chain.get("id") is not None:
                id_counts[chain["id"]] = id_counts.get(chain["id"], 0) + 1
            name = id_names.get(chain.get("id"), "-")
        else:
            name = "-"
        chain_rows.append({
            "ctx": ctx,
            "ok": bool(chain.get("ok")),
            "x": chain.get("x"),
            "s": chain.get("s"),
            "s_vptr": chain.get("s_vptr"),
            "id": chain.get("id"),
            "object": chain.get("object"),
            "name": name,
        })

    callers = []
    for site, count in sorted(
        by_caller.items(),
        key=lambda kv: (-kv[1], -1 if kv[0] is None else kv[0]),
    ):
        meta = census.get(site, {}) if site is not None else {}
        callers.append({
            "site": site,
            "count": count,
            "func": meta.get("func"),
            "origin": meta.get("origin", "-"),
        })

    ids = sorted(
        ((cid, id_names.get(cid, "-"), n) for cid, n in id_counts.items()),
        key=lambda row: (-row[2], row[0]),
    )

    return {
        "calls": stats.get("calls", 0),
        "samples": stats.get("samples", 0),
        "valid": valid,
        "lexer": lexer,
        "chain_ok": chain_ok,
        "by_caller": by_caller,
        "distinct_vtables": len(vtables),
        "callers": callers,
        "chains": chain_rows,
        "ids": ids,
    }


def classify(summary):
    """Fixed order: no_calls -> no_samples -> all_invalid -> lexer_only ->
    chain_unreadable -> captured."""
    if summary.get("calls", 0) == 0:
        return "no_calls"
    if summary.get("samples", 0) == 0:
        return "no_samples"
    if summary.get("valid", 0) == 0:
        return "all_invalid"
    if summary.get("lexer", 0) > 0 and summary.get("lexer", 0) == summary.get("valid", 0):
        return "lexer_only"
    if summary.get("chain_ok", 0) == 0:
        return "chain_unreadable"
    return "captured"


def _hex_or_dash(value):
    return "-" if value is None else f"0x{value:x}"


def write_tsv(path, summary):
    """Long-form evidence dump; returns the number of data rows written."""
    rows = 0
    with open(path, "w", encoding="utf-8") as f:
        f.write("# kind\tkey\tvalue\tdetail\n")
        for row in summary.get("callers", []):
            site = "-" if row["site"] is None else f"0x{row['site']:x}"
            func = "-" if row["func"] is None else f"0x{row['func']:x}"
            f.write(
                f"caller\t{site}\t{row['count']}\t"
                f"func={func} origin={row['origin']}\n"
            )
            rows += 1
        for cid, name, count in summary.get("ids", []):
            f.write(f"id\t{cid}\t{count}\tname={name}\n")
            rows += 1
        for chain in summary.get("chains", []):
            f.write(
                f"chain\t0x{chain['ctx']:x}\t{1 if chain['ok'] else 0}\t"
                f"x={_hex_or_dash(chain['x'])} s={_hex_or_dash(chain['s'])} "
                f"vptr={_hex_or_dash(chain['s_vptr'])} "
                f"id={'-' if chain['id'] is None else chain['id']} "
                f"name={chain['name']} "
                f"object={_hex_or_dash(chain['object'])}\n"
            )
            rows += 1
    return rows


# ---------------------------------------------------------------------------
# Live driver (Windows + game process only)
# ---------------------------------------------------------------------------

def _signed32(raw):
    """Re-bias a thread exit code (unsigned 32-bit) to its C int value."""
    return raw - _UINT32_SPAN if raw > _INT32_MAX else raw


def dispatch_once(pid, base, rva, name, arg=None):
    """Dispatch a remote export at most once per session; return its C int rc."""
    if name in _dispatched:
        raise RuntimeError(
            f"{name} was already dispatched in this session; this probe is "
            "single-shot by design (a second install on the same process would "
            "hit an already-hooked target)"
        )
    _dispatched.add(name)
    if arg is None:
        return _signed32(call_remote(pid, base, rva))
    return _signed32(call_remote_with_arg(pid, base, rva, arg))


def gate_module(pid, dll_path, needed):
    """Inject this copy and clear every gate that must precede a dispatch."""
    dll_name = os.path.basename(dll_path)
    print(f"[scope] pid={pid}  dll={dll_path}")

    inject_dll(pid, dll_path)
    assert_game_alive(pid)
    base = resolve_base_address(pid, dll_name)
    print(f"[scope] {dll_name} base (64-bit): 0x{base:x}")

    head = read_memory(pid, base, 2)
    assert head == b"MZ", f"Bad header at 0x{base:x}: {head!r}"
    print("[scope] MZ header at base OK")

    exports = list_exports(dll_path)
    for name in needed:
        assert name in exports, f"{name} is not an export of {dll_path}"

    sanity = _signed32(call_remote(pid, base, exports["C2Sanity"]))
    assert sanity == 42, (
        f"C2Sanity returned {sanity}, expected 42 — refusing to dispatch "
        f"against this module copy"
    )
    assert_game_alive(pid)
    print("[scope] C2Sanity == 42, game alive — dispatch authorized")
    return base, exports


def read_layout(pid, base, exports):
    """C2ScopeProbeLayout -> validated dict. Raises ValueError on drift."""
    buf = remote_alloc(pid, 32)
    call_remote_with_arg(pid, base, exports["C2ScopeProbeLayout"], buf)
    words = struct.unpack("<5I", read_memory(pid, buf, LAYOUT_WORDS * 4))
    return decode_layout(words)


def reset_probe(pid, base, exports):
    """C2ScopeProbeReset must run before install (clears stats and image window)."""
    call_remote(pid, base, exports["C2ScopeProbeReset"])
    assert_game_alive(pid)


def install_probe(pid, base, exports):
    """The one install of this process; -2 means another detour already owns it."""
    rc = dispatch_once(pid, base, exports["C2ScopeProbeInstall"], "C2ScopeProbeInstall")
    assert_game_alive(pid)
    return rc


def read_stats(pid, base, exports, buf):
    """Dispatch C2ScopeProbeStatsInto and decode the NUL-terminated text."""
    call_remote_with_arg(pid, base, exports["C2ScopeProbeStatsInto"], buf)
    raw = read_memory(pid, buf, STATS_SIZE)
    text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return decode_stats(text), text


def drain_entries(pid, base, exports, buf):
    """C2ScopeProbeDrainInto -> oldest-first decoded Entry list."""
    count = call_remote_with_arg(
        pid, base, exports["C2ScopeProbeDrainInto"], buf
    ) & 0xFFFF_FFFF
    count = min(count, RING_LEN)
    if count == 0:
        return []
    blob = read_memory(pid, buf, count * ENTRY_SIZE)
    return [
        decode_entry(blob[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE])
        for i in range(count)
    ]


def follow_contexts(pid, entries):
    """Follow the chain for each distinct usable ctx, at most MAX_FOLLOW.

    Reads happen in this process via ReadProcessMemory; any exception becomes
    None for that step, so a stale pointer cannot take the game down.
    """
    def reader(addr, size):
        try:
            return read_memory(pid, addr, size)
        except Exception:  # noqa: BLE001 - an unreadable address is the datum
            return None

    chains = {}
    for entry in entries:
        if entry["valid"] != 1 or entry["ctx_words"][6] == 0:
            continue
        ctx = entry["ctx_ptr"]
        if ctx in chains:
            continue
        if len(chains) >= MAX_FOLLOW:
            break
        chains[ctx] = follow_chain(reader, ctx)
    return chains


def _cleanup(pid, base, exports, installed_ok, settle_s):
    """uninstall -> verify -> settle -> host alive. Returns False if not restored."""
    uninstall_rc = None
    try:
        uninstall_rc = _signed32(call_remote(pid, base, exports["C2ScopeProbeUninstall"]))
    except Exception as exc:  # noqa: BLE001 - cleanup must report, not raise
        print(f"[scope] C2ScopeProbeUninstall raised: {exc}")
    if uninstall_rc not in (0, None):
        print(
            f"[scope] WARNING: C2ScopeProbeUninstall rc={uninstall_rc} — the "
            "engine bytes may still be patched; NEVER FreeLibrary this DLL"
        )
    else:
        print(f"[scope] C2ScopeProbeUninstall rc={uninstall_rc}")

    verify_rc = None
    try:
        verify_rc = _signed32(call_remote(pid, base, exports["C2ScopeProbeVerify"]))
    except Exception as exc:  # noqa: BLE001
        print(f"[scope] C2ScopeProbeVerify raised: {exc}")

    if installed_ok:
        if verify_rc == 0:
            print("[scope] C2ScopeProbeVerify rc=0 (engine bytes intact)")
            restore_ok = True
        else:
            print(
                f"[scope] RESTORE_INCOMPLETE DO_NOT_FREELIBRARY verify={verify_rc}"
            )
            restore_ok = False
    else:
        print(f"[scope] verify={verify_rc} (not installed this run)")
        restore_ok = True

    time.sleep(settle_s)
    try:
        assert_game_alive(pid)
        print("[scope] host alive")
    except Exception as exc:  # noqa: BLE001
        print(f"[scope] HOST DEAD: {exc}")
        return False
    return restore_ok


def run(pid, dll_path, poll_s, settle_s, out_path, census, id_names):
    needed = (
        "C2Sanity", "C2ScopeProbeInstall", "C2ScopeProbeUninstall",
        "C2ScopeProbeVerify", "C2ScopeProbeLayout", "C2ScopeProbeStatsInto",
        "C2ScopeProbeDrainInto", "C2ScopeProbeReset",
    )
    base, exports = gate_module(pid, dll_path, needed)

    installed_ok = False
    rc = 1
    try:
        try:
            layout = read_layout(pid, base, exports)
        except ValueError as exc:
            print(f"LAYOUT_DRIFT: {exc}")
            layout = None
        if layout is not None:
            print(
                f"[scope] LAYOUT entry={layout['entry']} stats={layout['stats']} "
                f"ring={layout['ring']} mask={layout['mask']} "
                f"version={layout['version']}"
            )
            reset_probe(pid, base, exports)

            rc_install = install_probe(pid, base, exports)
            installed_ok = rc_install == 0
            print(f"[scope] C2ScopeProbeInstall rc={rc_install}")
            if not installed_ok:
                print(f"VERDICT: detour_unavailable rc={rc_install}")
            else:
                stats_buf = remote_alloc(pid, STATS_SIZE)
                deadline = time.monotonic() + poll_s
                last_progress = time.monotonic()
                while True:
                    stats, stats_text = read_stats(pid, base, exports, stats_buf)
                    if stats.get("samples", 0) > 0 or time.monotonic() >= deadline:
                        break
                    if time.monotonic() - last_progress >= 10.0:
                        print(
                            f"[scope] waiting: calls={stats.get('calls', 0)} "
                            f"samples={stats.get('samples', 0)} "
                            f"invalid_self={stats.get('invalid_self', 0)} "
                            f"invalid_ctx={stats.get('invalid_ctx', 0)}"
                        )
                        last_progress = time.monotonic()
                    time.sleep(POLL_INTERVAL_S)

                entries_buf = remote_alloc(pid, RING_LEN * ENTRY_SIZE)
                entries = drain_entries(pid, base, exports, entries_buf)
                chains = follow_contexts(pid, entries)
                summary = summarize(entries, stats, chains, census, id_names)
                verdict = classify(summary)

                print(f"STATS: {stats_text.strip()}")
                print("CALLERS:")
                for row in summary["callers"]:
                    site = "-" if row["site"] is None else f"0x{row['site']:x}"
                    func = "-" if row["func"] is None else f"0x{row['func']:x}"
                    print(
                        f"  site={site} count={row['count']} "
                        f"func={func} origin={row['origin']}"
                    )
                print("CHAIN:")
                for chain in summary["chains"]:
                    print(
                        f"  ctx=0x{chain['ctx']:x} ok={1 if chain['ok'] else 0} "
                        f"x={_hex_or_dash(chain['x'])} "
                        f"s={_hex_or_dash(chain['s'])} "
                        f"vptr={_hex_or_dash(chain['s_vptr'])} "
                        f"id={'-' if chain['id'] is None else chain['id']} "
                        f"name={chain['name']} "
                        f"object={_hex_or_dash(chain['object'])}"
                    )
                print(
                    f"[scope] entries={len(entries)} "
                    f"valid={summary['valid']} lexer={summary['lexer']} "
                    f"chain_ok={summary['chain_ok']} "
                    f"distinct_vtables={summary['distinct_vtables']} "
                    f"ids={summary['ids']}"
                )
                rows = write_tsv(out_path, summary)
                print(f"[scope] wrote {rows} rows to {out_path}")

                print(f"VERDICT: {verdict}")
                if verdict in VERDICT_DIAGNOSIS:
                    print(VERDICT_DIAGNOSIS[verdict])
                rc = 0 if verdict == "captured" else 1
    finally:
        restore_ok = _cleanup(pid, base, exports, installed_ok, settle_s)
    if not restore_ok:
        return 1
    return rc


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only base-Execute execution-frame sampler (C4 forensics)"
    )
    parser.add_argument("dll", nargs="?", default=DEFAULT_DLL)
    parser.add_argument("--poll-s", type=float, default=POLL_TIMEOUT_S)
    parser.add_argument("--settle-s", type=float, default=SETTLE_S)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--census", default=DEFAULT_CENSUS)
    parser.add_argument("--id-names", dest="id_names", default=DEFAULT_ID_NAMES)
    args = parser.parse_args(argv)

    if not os.path.isfile(args.dll):
        raise SystemExit(
            f"{args.dll} not found — upload the freshly built DLL first (this "
            "script injects THIS file, so it must be the bytes under test)"
        )

    census = {}
    if os.path.isfile(args.census):
        census = load_call_census(args.census)
    else:
        print(
            f"[scope] census missing at {args.census}; CALLERS origin/function "
            "will be '-' (join offline with Task 1's site table)"
        )

    id_names = {}
    if os.path.isfile(args.id_names):
        id_names = load_id_names(args.id_names)
    else:
        print(
            f"[scope] id-name table missing at {args.id_names}; chain names "
            "will be '-' (join offline with descriptor_oracle_4_4_4.tsv)"
        )

    pid = resolve_pid("stellaris")
    return run(
        pid, args.dll, args.poll_s, args.settle_s, args.out, census, id_names,
    )


if __name__ == "__main__":
    sys.exit(main())
