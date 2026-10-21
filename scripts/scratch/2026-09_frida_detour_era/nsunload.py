"""FreeLibrary our mod DLL inside stellaris.exe so the file can be overwritten.

Only safe when no detour from it is installed — execspy.py uninstalls before it exits.
"""
import sys, frida
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
dev = frida.get_local_device()
pid = next(p.pid for p in dev.enumerate_processes() if p.name.lower() == 'stellaris.exe')
s = dev.attach(pid)
sc = s.create_script(open(r'C:\ns\execspy.js', encoding='utf-8').read()); sc.load()
print('loaded before:', sc.exports_sync.loaded())
print('unload ->', sc.exports_sync.unload())
print('loaded after:', sc.exports_sync.loaded())
s.detach()
