"""One-off: run a PowerShell snippet on Windows_Jiaolong *inside the user's
interactive desktop session*, which a plain ssh logon is not.

Why: `panel_pixel_map.py` needs EnumWindows + a real screen DC. Over ssh the
logon session has no desktop, so find_game() prints `no_game` even while the
long-lived supervisor daemon sees the window. The repo already crosses this
boundary with schtasks /ru <user> /rl highest (launch_stellaris.py's BRIDGE);
this is the same trick stripped down to "run one python command, capture its
stdout into a file, echo a short line back".

stdout over ssh must stay small (~700 B holds; docs/offline-tooling.md), so the
task's own stdout+stderr goes to C:/temp/pc_out.txt and only the last 400 chars
come back. Read the whole file with `python run_ps.py --cat pc_out.txt`.

Throwaway, needs the game. Usage:
    python3 run_ps.py '<powershell body with {{CMD}} for the python argv>' --cmd "snap closed"
"""

import base64
import subprocess
import sys

HOST = "Windows_Jiaolong"
TEMPLATE = r'''
$u = (whoami)
$st = (Get-Date).AddMinutes(2).ToString('HH:mm')
$cmd = 'python C:\temp\panel_pixel_map.py {{CMD}} 1> C:\temp\pc_out.txt 2>&1'
schtasks /create /tn nspcal /tr "cmd /c $cmd" /sc once /st $st /ru $u /rl highest /f | Out-Null
schtasks /run /tn nspcal | Out-Null
Start-Sleep -Seconds {{WAIT}}
schtasks /end /tn nspcal | Out-Null
schtasks /delete /tn nspcal /f | Out-Null
$t = Get-Content C:\temp\pc_out.txt -Raw
if ($null -eq $t) { $t = 'NO_OUTPUT_FILE' }
$n = $t.Length
if ($n -gt 600) { $t = $t.Substring($n - 600) }
Write-Output ("LEN=" + (Get-Content C:\temp\pc_out.txt -Raw).Length + " TAIL=" + $t)
'''

CAT = r'''
$t = Get-Content C:\temp\{{FILE}} -Raw
if ($null -eq $t) { Write-Output 'NO_FILE'; exit }
$s = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($t.Substring({{OFF}}, [Math]::Min({{N}}, $t.Length - {{OFF}}))))
Write-Output $s
'''

MAX_OUT = 700


def run_ps(body):
    b64 = base64.b64encode(body.encode("utf-16-le")).decode("ascii")
    p = subprocess.run(["ssh", HOST, "powershell", "-NoProfile", "-EncodedCommand", b64],
                       capture_output=True, timeout=180)
    out = p.stdout.decode("utf-8", "replace") if p.stdout else ""
    lines = [ln for ln in out.splitlines()
             if not ln.startswith("<Objs") and "#< CLIXML" not in ln]
    text = "\n".join(lines).encode("utf-8", "replace")[:MAX_OUT]
    return p.returncode, text.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")[:300]


def cat(path, off, n=450):
    rc, out, err = run_ps(CAT.replace("{{FILE}}", path).replace("{{OFF}}", str(off)).replace("{{N}}", str(n)))
    body = out.strip().split()[-1] if out.strip() else ""
    try:
        return rc, base64.b64decode(body + "===").decode("utf-8", "replace"), err
    except Exception as exc:  # noqa: BLE001 - a torn chunk is a read failure, not a crash
        return rc, "DECODE_FAIL %s raw=%s" % (exc, out[:80]), err


GREP = r'''
$r = Select-String -Path C:\temp\{{FILE}} -Pattern '{{PAT}}' | Select-Object -First 12
if ($null -eq $r) { Write-Output 'NO_MATCH'; exit }
($r | ForEach-Object { $_.Line }) -join "`n"
'''


def grep(path, pat):
    return run_ps(GREP.replace("{{FILE}}", path).replace("{{PAT}}", pat))


LINES = r'''
$t = @(Get-Content C:\temp\{{FILE}})
Write-Output ("LINES=" + $t.Count)
($t | Select-Object -Skip {{SKIP}} -First {{N}}) -join "`n"
'''


def lines(path, skip, n=10):
    return run_ps(LINES.replace("{{FILE}}", path).replace("{{SKIP}}", str(skip))
                  .replace("{{N}}", str(n)))


def main(argv):
    if argv and argv[0] == "--cat":
        rc, out, err = cat(argv[1], int(argv[2]) if len(argv) > 3 else 0)
    elif argv and argv[0] == "--grep":
        rc, out, err = grep(argv[1], argv[2])
    elif argv and argv[0] == "--lines":
        rc, out, err = lines(argv[1], int(argv[2]), int(argv[3]) if len(argv) > 3 else 10)
    else:
        wait = "8"
        cmd = " ".join(argv)
        if cmd.startswith("--wait "):
            wait, cmd = cmd.split(" ", 2)[1], cmd.split(" ", 2)[2]
        rc, out, err = run_ps(TEMPLATE.replace("{{CMD}}", cmd).replace("{{WAIT}}", wait))
    print(out)
    if err.strip():
        print("ERR:", err.strip()[:200])
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
