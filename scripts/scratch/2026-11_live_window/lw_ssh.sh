#!/usr/bin/env bash
# lw_ssh.sh — run one command on Windows_Jiaolong over a transport whose TCP MSS
# fits the actual wg0 path MTU.
#
# Why: wg0 is configured MTU 1280, but the path between the WireGuard endpoints
# blackholes packets above ~1200 bytes (2026-11-10 probe: `ping -M do -s 1100`
# passes, `-s 1200` fails). Anything larger than ~1 KB (game.log tails, artifacts,
# saves) stalls for ~20 s and is then reset by the peer. Forcing MSS 900 on the
# underlying TCP fixes it without root and without touching ~/.ssh/config
# (which is outside this worktree).
#
# Usage:  scripts/scratch/2026-11_live_window/lw_ssh.sh '<remote command>'
#         ... | scripts/scratch/2026-11_live_window/lw_ssh.sh 'cmd /c type C:\path'
set -eu
exec ssh -o ConnectTimeout=10 \
         -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes \
         -o ProxyCommand='socat - TCP:10.66.0.7:22,mss=900' \
         Windows_Jiaolong "$@"
