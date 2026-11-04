# fixtures/ — Windows-side inputs kept in the repo

| File | What it is |
|---|---|
| `neo_ps_probe_events.txt` | Deployed copy of `Documents/Paradox Interactive/Stellaris/mod/neo_ps_probe/events/neo_ps_probe_events.txt` on the game box. The mod is what makes the engine run `every_system` once a month; this copy is here so a change to the receipt lines is reviewable in the repo instead of only on one machine. |
| `tests/fixtures/windows/` | *(under `tests/`)* Labelled screen fixtures with the readings `read_window` produced — see that directory's JSON files. |

## `neo_ps_probe_events.txt`

Two things are load-bearing and both are comments in the file itself:

* 4.4.4 `on_action` bodies only accept `events` / `random_events`; a bare
  `effect`/`on_actions` body is rejected at parse time, so the effect lives in
  a hidden event (`neo_ps.1`) that `on_monthly_pulse` fires.
* `every_system` from a no-scope event iterates once, so the event enters a
  system scope with `random_system` first.

The `NEO_T0/T1/T2` lines are the **engine-side half** of the §7.7 reconcile
(`evidence/analysis/runtime_444_graph_runtime.md` §7.7): one line per system per
month, naming the tier the engine just wrote. They are receipts — nothing
branches on them. The host side computes its own tiers from the edge snapshots
and the two sets are compared by name; they must never read each other's
intermediate results.

Deploy: copy this file over the path above (LF endings, ASCII, tabs), then
launch the game. Without the DLL injected before the script parser runs,
`neo_action` is an unknown effect and `error.log` says so — that line is
expected in a run without the injection, and it is *not* a syntax error in the
receipt block.
