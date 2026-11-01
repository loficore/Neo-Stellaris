#!/usr/bin/env python3
"""mod_registry.py — 「测试 mod 到底有没有被加载」的文件层判据(计划 Task 3 的生产者,§84.1)。

只读:不启游戏、不写任何 mod 文件、不改 `dlc_load.json`。它把下面三类文件放到同一张表上,
让「加载」变成可复核的**文件层事实**而不是推断:

```
dlc_load.json        游戏侧的用户清单:{"enabled_mods": [...], "disabled_dlcs": [...]}
mods_registry.json   官方启动器自己的注册库:{"mods": [{"path": ..., "name": ..., ...}]}
mod/*.mod            每个 mod 的描述符:name= / path= / supported_version=
```

## 两条载入通道,判据不同(§84.1 的表就是从这里生成的)

- **channel_launcher**:经官方启动器。启动器按**它自己的注册库**重写 `dlc_load.json`,
  所以判据是「注册库里有这一条 **且** 它 enabled」;手改的 `dlc_load.json` 会被覆盖。
- **channel_direct**:直接起 `stellaris.exe`(不经启动器)。判据是「手写的 `dlc_load.json`
  原样保留」**且**「游戏启动后清点到了这个 mod(游戏侧读点见 §84.1)」。

## 反例清单(这些**不能**当判据,程序会把它们单独打印出来)

`文件存在` / `error.log 没提` / `debug.log 没提` / `PS_HIT 计数为 0` / `进程起来了`。

用法:

```
python3 mod_registry.py --root <dir>          # 本地一份同样布局的目录(离线自测/事后拷贝)
python3 mod_registry.py --host <NS_WIN_HOST>  # 让主机上的 python 把三份文件打成 JSON 回传
```

旧名/来历:本脚本由计划 `2026-10-31-plus70-dispatcher-and-channels` 的 Task 3 建立。
"""
from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys

WIN_GAME_DIR = r"%USERPROFILE%\Documents\Paradox Interactive\Stellaris"
WIN_LAUNCHER_GLOBS = [
    r"%LOCALAPPDATA%\Paradox Interactive\launcher-v2\*.json",
    r"%APPDATA%\Paradox Interactive\launcher-v2\*.json",
    r"%USERPROFILE%\Documents\Paradox Interactive\Stellaris\mods_registry.json",
]
REMOTE_SNIPPET = r"""
import glob, json, os, sys
g = os.path.expandvars(r'%USERPROFILE%\Documents\Paradox Interactive\Stellaris')
out = {'dlc_load': None, 'registry': None, 'registry_path': None, 'mods': {}}
p = os.path.join(g, 'dlc_load.json')
if os.path.exists(p):
    out['dlc_load'] = open(p, 'r', encoding='utf-8-sig').read()
cands = glob.glob(os.path.join(g, 'mods_registry.json'))
cands += glob.glob(os.path.expandvars(r'%LOCALAPPDATA%\Paradox Interactive\launcher-v2\mods_registry.json'))
cands += glob.glob(os.path.expandvars(r'%APPDATA%\Paradox Interactive\launcher-v2\mods_registry.json'))
for c in cands:
    try:
        out['registry'] = open(c, 'r', encoding='utf-8-sig').read()
        out['registry_path'] = c
        break
    except OSError:
        pass
md = os.path.join(g, 'mod')
if os.path.isdir(md):
    for f in sorted(os.listdir(md)):
        if f.lower().endswith('.mod'):
            try:
                out['mods'][f] = open(os.path.join(md, f), 'r', encoding='utf-8-sig').read()
            except OSError:
                pass
print(json.dumps(out))
"""


def parse_paradox(text):
    """Clausewitz `key=value` text → dict; repeated keys become lists.

    Deliberately shallow: `.mod` descriptors and the launcher database are flat
    `key="value"` / `key={ ... }` files, and this probe only needs `path=`/`name=`.
    """
    out = {}
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"')
        if k in out:
            out[k] = out[k] if isinstance(out[k], list) else [out[k]]
            out[k].append(v)
        else:
            out[k] = v
    return out


def load_local(root):
    root = pathlib.Path(root)
    out = {"dlc_load": None, "registry": None, "registry_path": None, "mods": {}}
    p = root / "dlc_load.json"
    if p.exists():
        out["dlc_load"] = p.read_text(encoding="utf-8-sig")
    for c in (root / "mods_registry.json", root / "launcher" / "mods_registry.json"):
        if c.exists():
            out["registry"] = c.read_text(encoding="utf-8-sig")
            out["registry_path"] = str(c)
            break
    md = root / "mod"
    if md.is_dir():
        for f in sorted(md.iterdir()):
            if f.suffix.lower() == ".mod":
                out["mods"][f.name] = f.read_text(encoding="utf-8-sig")
    return out


def load_host(host):
    # The snippet has newlines; passing it through `json.dumps` inside a remote
    # `python -c "..."` leaves literal `\n` and dies with SyntaxError (review
    # I-1). Base64 keeps the wire one ASCII line, so the shell cannot rewrite it.
    payload = base64.b64encode(REMOTE_SNIPPET.encode()).decode()
    remote = "python -c \"import base64;exec(base64.b64decode('%s').decode())\"" % payload
    proc = subprocess.run(["ssh", host, remote],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise SystemExit(f"remote python failed rc={proc.returncode}: {proc.stderr.strip()[:400]}")
    return json.loads(proc.stdout)


def analyse(files):
    """(judgements, differences, descriptors) — pure, no I/O."""
    dlc = {}
    if files.get("dlc_load"):
        try:
            dlc = json.loads(files["dlc_load"])
        except json.JSONDecodeError:
            dlc = parse_paradox(files["dlc_load"])
    enabled = dlc.get("enabled_mods") or []
    if isinstance(enabled, str):
        enabled = [enabled]

    reg_paths, reg_names, reg_enabled = [], [], []
    if files.get("registry"):
        try:
            reg = json.loads(files["registry"])
        except json.JSONDecodeError:
            reg = parse_paradox(files["registry"])
        entries = reg.get("mods", [])
        # The launcher writes `mods` as a list of objects; a flattened
        # `key = { 0 = {...} }` shape shows up in hand-copied registries.
        if isinstance(entries, dict):
            entries = list(entries.values())
        for m in entries if isinstance(entries, list) else []:
            if isinstance(m, dict):
                reg_paths.append(m.get("path") or m.get("mod_file") or "")
                reg_names.append(m.get("name") or "")
                # An entry with no `enabled` key is the launcher's "listed"
                # state; it counts as enabled because the launcher only writes
                # the flag when it is false (§84.1's criterion is "present AND
                # enabled", and the two must not be conflated -- review I-4).
                reg_enabled.append(m.get("enabled", True) not in (False, "false", 0))

    descs = {name: parse_paradox(text) for name, text in (files.get("mods") or {}).items()}

    diff = {
        "registry_not_in_dlc_load": [p for p, en in zip(reg_paths, reg_enabled)
                                     if p and en and p not in enabled],
        "registry_disabled": [p for p, en in zip(reg_paths, reg_enabled) if p and not en],
        "dlc_load_not_in_registry": [p for p in enabled if p and p not in reg_paths],
    }
    judgements = [
        ("dlc_load.json", "enabled_mods", enabled,
         "游戏侧清单:这里是「游戏将要加载」的**唯一**输入之一(另一个是内建内容)"),
        ("mods_registry.json", "mods[].path/name/enabled",
         list(zip(reg_paths, reg_names, reg_enabled)),
         "启动器注册库:channel_launcher 的判据是「有这一条 且 enabled」"),
        ("mod/*.mod", "path=/name=", {k: {kk: v.get(kk) for kk in ("name", "path", "supported_version")}
                                      for k, v in descs.items()},
         "描述符:path= 指到 mod 目录;name= 是启动器显示名"),
    ]
    return judgements, diff, descs


COUNTER_EXAMPLES = [
    ("mod 目录 / .mod 文件存在", "文件放好 ≠ 被清点:enabled_mods 里没有它就一定不加载"),
    ("error.log 里没有提到它", "沉默不是加载:没有条目时游戏根本不解析这个 mod,自然不报错"),
    ("debug.log 里没有提到它", "同上"),
    ("artifact 里 PS_HIT = 0", "只说明「那条 effect 没跑」,分不开「mod 没加载」与「不走 +0x70」(§81.5)"),
    ("stellaris.exe 进程起来了", "进程与 mod 集无关:launcher 与直接起 exe 都能起进程"),
]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    host = root = None
    while argv:
        a = argv.pop(0)
        if a == "--host":
            host = argv.pop(0)
        elif a == "--root":
            root = argv.pop(0)
        else:
            raise SystemExit(f"unknown argument {a!r}")
    if not host and not root:
        raise SystemExit("need --root <dir> or --host <ssh-host>")
    files = load_host(host) if host else load_local(root)

    judgements, diff, descs = analyse(files)
    print(f"## source = {'host ' + host if host else 'dir ' + str(root)}")
    print(f"## registry file = {files.get('registry_path') or '(not found)'}")
    print()
    print("## 判据表")
    print("| 文件 | 字段 | 值 | 意味着什么 |")
    print("|---|---|---|---|")
    for f, field, value, why in judgements:
        print(f"| {f} | {field} | `{value}` | {why} |")
    print()
    print("## 两条通道的差异")
    print(f"channel_launcher: 注册库里 enabled、但 dlc_load.json 没有的:"
          f" {len(diff['registry_not_in_dlc_load'])} 条")
    for p in diff["registry_not_in_dlc_load"]:
        print(f"    - {p}   ← 启动器没把它写进 dlc_load.json")
    print(f"channel_launcher: 注册库里 disabled 的: {len(diff['registry_disabled'])} 条(不算差异,单独列)")
    for p in diff["registry_disabled"]:
        print(f"    - {p}   ← 启动器会把它从 dlc_load.json 里去掉")
    print(f"channel_direct: dlc_load.json 有 {len(diff['dlc_load_not_in_registry'])} 条不在注册库里")
    for p in diff["dlc_load_not_in_registry"]:
        print(f"    - {p}   ← 手写的 / 启动器不知道的;下一次 launcher 启动会被丢掉")
    print()
    print("## .mod 描述符")
    for name, d in descs.items():
        print(f"    {name}: name={d.get('name')!r} path={d.get('path')!r}"
              f" supported_version={d.get('supported_version')!r}")
    print()
    print("## 反例清单(不能当判据)")
    for what, why in COUNTER_EXAMPLES:
        print(f"    ✗ {what} —— {why}")
    print()
    print("PASS")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
