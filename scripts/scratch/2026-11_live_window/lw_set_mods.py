"""lw_set_mods.py — set dlc_load.json enabled_mods to an explicit list (scratch).

Why: the 2026-11-10 window starts with leftovers from earlier shots enabled
(neo_events, neo_flag_probe). Only the driver for this window should run; a
second monthly driver doubles the per-system dispatch and a flag probe writes
state R1 never asked for.

Usage (Windows): python C:/temp/lw_set_mods.py neo_ps_probe.mod
"""
import json
import pathlib
import sys

DOCS = pathlib.Path.home() / "Documents" / "Paradox Interactive" / "Stellaris"
PATH = DOCS / "dlc_load.json"


def main(argv):
    wanted = []
    for name in argv:
        name = name if name.startswith("mod/") else "mod/" + name
        if not name.endswith(".mod"):
            name += ".mod"
        wanted.append(name)
    data = json.loads(PATH.read_text(encoding="utf-8"))
    data["enabled_mods"] = wanted
    PATH.write_text(json.dumps(data, indent="\t") + "\n", encoding="utf-8")
    print("MODS=" + ",".join(data["enabled_mods"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
