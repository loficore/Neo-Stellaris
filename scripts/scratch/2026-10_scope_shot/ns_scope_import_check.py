"""Deployment smoke check for the C4 scope shot: import the driver, print its contract.

Read-only: touches no process, injects nothing. Run on the Windows host only.
"""

import os

import c2_scope_probe as m

print("ENTRY_SIZE", m.ENTRY_SIZE)
print("LAYOUT_WORDS", m.LAYOUT_WORDS)
print("DEFAULT_VTABLES", m.DEFAULT_VTABLES)
print("EXE_MODULE", m.EXE_MODULE)
print("verdicts", sorted(m.VERDICT_DIAGNOSIS))
print("default_vtables_exists", os.path.isfile(m.DEFAULT_VTABLES))
host_map = "C:/temp/ceffect_vtable_map_4_4_4.txt"
print("host_map_exists", os.path.isfile(host_map))
table = m.load_vtable_map(host_map)
print("vtable_entries", len(table))
print("sample_0247ADD0", table.get(0x0247ADD0))
