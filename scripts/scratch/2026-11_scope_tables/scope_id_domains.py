#!/usr/bin/env python3
"""一次性的存档侧 id 值域探针(只证伪,不验证)。

usage: scope_id_domains.py <save.sav> [more.sav ...]

对每个存档报 **id 键的值域**。Clausewitz 把 id 放在**块键**上,不在字段里:

    planets      顶层 `planets={ planet={ <id>={...} } }` 的键 —— 星球 id
    pop          顶层 `pop={ <id>={...} }` 的键 —— pop id(多数存档是空块)
    pop_groups   顶层 `pop_groups={ <id>={...} }` 的键 —— pop 组 id(带高位标志)
    ships        顶层 `ships={ <id>={...} }` 的键 —— 舰船 id
    fleet        顶层 `fleet={ <id>={...} }` 的键 —— 舰队 id
    colony       顶层 `colony={ <id>={...} }` 的键 —— 殖民地 id

每行:`count / min / max / max&0xffffff / fits24 / hi8[bit24..31 的分布]`。`fits24=False` 表示最大键的高 8 位非零,
即 id 是 `<tag 在 bit24..31> | <低 24 位索引>` 的编码 —— 这正是引擎里每一处
`and eax,0xffffff` 的掩码口径(`runtime_444_transitability_4_4_4.md` §5.2 第 2 条)。

**这不是对偏移的验证**:值域相符是最弱的证据(同卷 §5.4 第 1 条)。本探针只回答
「某张表的槽号 = `id & 0xffffff` 这条口径,与该块的值域**矛不矛盾**」。

`.sav` 是 ZIP,`gamestate` 是文本 Clausewitz。解析只做缩进感知的括号扫描,不猜、不修、不写回。
标准库 only;只读;退出码 0 = 全部解析成功,2 = 有存档打不开或没有 `gamestate`。
"""
from __future__ import annotations

import sys
import zipfile


def blocks(text: str):
    """Yield (name, body) for every `name=\\n{ ... }` block whose name starts a line.

    Indentation is ignored on purpose: the caller picks the depth it wants by
    walking the body it got.
    """
    i = 0
    n = len(text)
    while True:
        m = text.find("=\n", i)
        if m < 0:
            return
        start = text.rfind("\n", 0, m)
        name = text[start + 1:m].strip("\t \r")
        k = m + 2
        while k < n and text[k] in "\t \r\n":
            k += 1
        if k < n and text[k] == "{":
            depth = 0
            end = k
            while end < n:
                c = text[end]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                end += 1
            yield name, text[k + 1:end]
            i = end + 1
            continue
        i = m + 2


def top_blocks(text: str) -> dict[str, str]:
    """Column-0 blocks only (`name=` at the very start of a line, no indent)."""
    out: dict[str, str] = {}
    for name, body in blocks(text):
        if not name:
            continue
        out.setdefault(name, body)
    return out


def keys_of(body: str, tabs: int = 1) -> list[int]:
    """Id keys directly inside a block body.

    Clausewitz puts the brace on its own line, so a key line is ``\\t<digits>=``
    (one tab). Two tabs is a nested key; a non-numeric head is a field name.
    """
    out = []
    for raw in body.split("\n"):
        s = raw.rstrip("\r")
        if not s.startswith("\t" * tabs) or s.startswith("\t" * (tabs + 1)):
            continue
        head = s.strip("\t ").rstrip()
        if not head.endswith("="):
            continue
        head = head[:-1].strip()
        if head.isdigit():
            out.append(int(head))
    return out


def report(path: str) -> int:
    try:
        z = zipfile.ZipFile(path)
    except Exception as exc:  # noqa: BLE001 - one line, then exit 2
        print(f"{path}: not a zip ({exc})", file=sys.stderr)
        return 2
    try:
        text = z.read("gamestate").decode("utf-8", "replace")
    except KeyError:
        print(f"{path}: no gamestate entry", file=sys.stderr)
        return 2

    top = top_blocks(text)
    rows: dict[str, list[int]] = {}

    planets = top.get("planets")
    if planets is not None:
        for name, body in blocks(planets):
            if name == "planet":
                rows["planets"] = keys_of(body, tabs=2)
                break

    for name in ("pop", "pop_groups", "ships", "fleet", "colony"):
        body = top.get(name)
        if body is not None:
            rows[name] = keys_of(body)

    print(f"save={path}")
    for name in ("planets", "pop", "pop_groups", "ships", "fleet", "colony"):
        ids = rows.get(name, [])
        if not ids:
            print(f"  {name:11s} count=0 (本存档无此块或无 id 键)")
            continue
        mx = max(ids)
        tags: dict[int, int] = {}
        for v in ids:
            tags[v >> 24] = tags.get(v >> 24, 0) + 1
        top = " ".join(
            f"0x{t:02x}x{c}" for t, c in sorted(tags.items(), key=lambda kv: -kv[1])[:6]
        )
        print(
            f"  {name:11s} count={len(ids)} min={min(ids)} max={mx} "
            f"max&0xffffff={mx & 0xFFFFFF} fits24={mx & 0xFFFFFF == mx} hi8[{top}]"
        )
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    rc = 0
    for p in argv:
        rc = max(rc, report(p))
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
