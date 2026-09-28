"""Drives the log-only base-Execute detour in a live stellaris.exe.

usage: python execspy.py [observe_seconds] [--uninstall-only]

Runs on the Windows host. Loads C:\\ns\\stellaris_quickjs.dll into the game (replacing any
already-mapped copy so a rebuilt DLL takes effect), installs the recorder, waits until the
simulation is really running, observes for `observe_seconds` of activity, then prints
stats, the shim histogram and sample records, and uninstalls.

`--uninstall-only` skips the install/observe path and just detaches a currently installed
detour — run it after pausing the game when the main flow refused to restore hot bytes.

Install and uninstall both rewrite the same 16 bytes of the engine's hottest function, so
each one waits for a window where base Execute is silent (game paused).
"""
import json
import subprocess
import sys
import time

import frida

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DLL = r'C:\ns\stellaris_quickjs.dll'
JS = r'C:\ns\execspy.js'
INJECTOR = r'C:\ns\inject.exe'

args = [a for a in sys.argv[1:] if not a.startswith('--')]
flags = [a for a in sys.argv[1:] if a.startswith('--')]
seconds = int(args[0]) if args else 45
uninstall_only = '--uninstall-only' in flags

dev = frida.get_local_device()
procs = [p for p in dev.enumerate_processes() if p.name.lower() == 'stellaris.exe']
if not procs:
    sys.exit('stellaris.exe is not running')
pid = procs[0].pid
print(f'pid={pid}  observe={seconds}s')

sess = dev.attach(pid)
script = sess.create_script(open(JS, encoding='utf-8').read())
script.on('message', lambda m, d: print('MSG:', json.dumps(m)[:400]))
script.load()
api = script.exports_sync


def module_loaded():
    return json.loads(api.loaded())['loaded']


def wait_loaded(secs=10.0):
    deadline = time.time() + secs
    while time.time() < deadline:
        if module_loaded():
            return True
        time.sleep(0.5)
    return False


if module_loaded():
    # The game keeps one copy mapped, so a rebuilt DLL only takes effect after
    # FreeLibrary + LoadLibrary. Safe: the detour is uninstalled and nothing else in
    # the process references our module.
    print('FreeLibrary:', api.unload())
if not module_loaded():
    print('LoadLibraryW ->', api.load(DLL))
if not wait_loaded():
    print('frida load did not take, using inject.exe')
    run = subprocess.run([INJECTOR, str(pid), DLL], capture_output=True, text=True, timeout=60)
    print(run.stdout.strip() or run.stderr.strip())
    if not wait_loaded():
        sys.exit('DLL never loaded into the game process')
print('module:', json.loads(api.loaded()))
layout = json.loads(api.layout())
print('layout:', layout)
if layout['entry'] != 88 or layout['stats'] != 48:
    sys.exit('driver/Zig record sizes disagree: ' + json.dumps(layout))


def calls():
    return int(json.loads(api.stats())['calls'])


def wait_idle(label, timeout=60.0):
    """Install and uninstall both rewrite the same 16 bytes of a function game threads are
    executing, so each waits for a measured-silent window. The DLL's own counter is the
    quiescence proof once the detour is in."""
    print(f'Waiting for base Execute to go silent before "{label}" ({timeout:.0f}s max)...')
    deadline = time.time() + timeout
    prev = calls()
    while time.time() < deadline:
        time.sleep(0.5)
        now = calls()
        if now == prev:
            print(f'  idle at calls={now}')
            return True
        prev = now
    print(f'  still active after {timeout:.0f}s ({now} calls)')
    return False


RVA_BASE_EXECUTE = 0x1D08520


def spy(ms=1500):
    """Calls seen at base Execute from an independent Frida Interceptor. Used before the
    first install, where the DLL's own counter does not exist yet."""
    return int(json.loads(api.spy(RVA_BASE_EXECUTE, ms))['calls'])


def post_uninstall_check():
    n = spy()
    verdict = 'engine path restored and hot' if n > 0 else 'engine silent — resume to confirm'
    print(f'post-uninstall probe: {n} calls at base Execute in 1.5s ({verdict})')


def do_uninstall():
    """Pause-gated detach + the byte check that makes the success claim meaningful."""
    if not wait_idle('uninstall', timeout=300):
        sys.exit('base Execute still active -> detour LEFT INSTALLED (it forwards every '
                 'call). Pause the game and re-run with --uninstall-only.')
    print('ExecHookUninstall ->', api.uninstall())
    rc = api.verify()
    code = {'0': 'engine bytes intact at the target', '-1': 'MISMATCH — patch still there',
            '-2': 'non-windows build', '-3': 'target never resolved',
            '-6': 'RESTORE FAILED — do not FreeLibrary'}
    print(f'ExecHookVerify -> {rc} ({code.get(rc, rc)})')
    return rc


if uninstall_only:
    print(f'uninstall-only: stats before detach {json.loads(api.stats())}')
    rc = do_uninstall()
    post_uninstall_check()
    sess.detach()
    sys.exit(0 if rc == '0' else 1)


rc_code = {'-2': 'non-windows build', '-3': 'already hooked',
           '-4': 'prologue fingerprint mismatch (wrong game build or a leftover patch)',
           '-5': 'decoded patch wider than the saved snapshot', '-1': 'os failure',
           '-6': 'RESTORE FAILED — engine bytes may still be patched'}


n = spy()
print(f'probe: Frida Interceptor saw {n} calls at base+0x{RVA_BASE_EXECUTE:x} in 1.5s')
if n > 0:
    print('  game is RUNNING. Pause it — polling for silence up to 180s...')
    deadline = time.time() + 180
    while time.time() < deadline:
        time.sleep(2)
        n = spy()
        if n == 0:
            break
        print(f'  still active: {n} calls/1.5s', flush=True)
    else:
        sys.exit('game stayed active for 180s; refusing to patch a running hot function')
print('  quiescent -> installing')

rc = api.install()
print('ExecHookInstall ->', rc)
if rc != '0':
    live = json.loads(api.peek(RVA_BASE_EXECUTE, 32))
    print('  live head bytes: ' + ' '.join(live['hex'].split()))
    sys.exit('install failed: ' + rc_code.get(rc, rc))
# While installed the head is our JMP patch, so verify must report a mismatch; stats must
# report patch_size 16. Either one wrong means the recorder is not sitting where we think.
print('while installed -> verify:', api.verify(), '(expect -1), stats:', json.loads(api.stats()))

print(f'RESUME THE GAME NOW — waiting for the counter to actually move (300s max)...')
start = time.time()
seen = calls()
live = False
while time.time() - start < 300:
    time.sleep(2)
    now = calls()
    if now > seen:
        print(f'  live: calls {seen} -> {now}, observing {seconds}s')
        live = True
        break
    seen = now
    if int(time.time() - start) % 10 < 3:
        print(f'  calls={now} (still paused?)', flush=True)

time.sleep(seconds)
total = calls()

# Reading the recorder is safe at any time; only the patch/unpatch needs a quiet window, so
# dump first and gate just the uninstall.
print('stats:', json.loads(api.stats()))
if int(json.loads(api.stats())['hist_overflow']) > 0:
    print('  NOTE: hist_overflow > 0 -> the histogram table filled; its counts are complete '
          'only for the shims that got a slot. Raise HIST_LEN in exec_hook.zig.')
hist = json.loads(api.hist(int(layout['hist_len'])))
print(f"histogram: {hist['n']} distinct shims, counted over every call")
# Print every row: with hist_overflow == 0 this is the complete census, and the static
# CEffect map (scripts/rttibatch.py --effects) can be joined against it offline.
for r in hist['rows']:
    print(f"  shim {r['shim_rva']:>10}  vtable {r['vtable_rva']:>10}  x{r['count']}")

d = json.loads(api.drain(64))
print(f"drained {d['n']} records (entry {d['entry_size']} bytes)")
for r in d['records'][-20:]:
    print('  ', json.dumps(r))

rc = do_uninstall()
post_uninstall_check()
if not live and total == 0:
    print('VERDICT: hook installed cleanly but never fired -> the simulation was not '
          'running during the window, or 0x1D08520 is not the path the game executes.')
sess.detach()
