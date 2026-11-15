# pin_save.ps1 - one-shot probe: copy one autosave to a fixed name and refresh its mtime
# (--continuelastsave picks the newest mtime).
#
# Why a file and not an inline command: the path contains a space ("Paradox Interactive")
# and the three quoting layers (just -> ssh -> remote shell) eat single quotes, so an
# inline command always comes out mangled.
#
# ASCII ONLY on purpose: this box reads BOM-less .ps1 as ANSI (cp936), and a Chinese
# comment is enough to swallow the following line (measured 2026-11-14: the
# `LastWriteTime = ...` assignment silently stopped happening).
#
# Usage:
#   just win "powershell -NoProfile -ExecutionPolicy Bypass -File C:/temp/r10_pin_save.ps1"

$ErrorActionPreference = "Stop"
$dir = "C:\Users\13229\Documents\Paradox Interactive\Stellaris\save games\_1474567734"
$src = Join-Path $dir "autosave_2331.01.01.sav"
$dst = Join-Path $dir "r10_base.sav"

Copy-Item -LiteralPath $src -Destination $dst -Force
$now = Get-Date
[System.IO.File]::SetLastWriteTime($dst, $now)

Write-Output ("NOW=" + $now.ToString("o"))
Write-Output ("ATTRS=" + (Get-Item -LiteralPath $dst).Attributes)
Write-Output ("MTIME=" + (Get-Item -LiteralPath $dst).LastWriteTime.ToString("o"))
Write-Output ("SHA256=" + (Get-FileHash -LiteralPath $dst -Algorithm SHA256).Hash.ToLower())
Get-ChildItem -LiteralPath $dir -Filter *.sav |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 3 Name, Length, LastWriteTime |
    Format-Table -AutoSize | Out-String -Width 200
