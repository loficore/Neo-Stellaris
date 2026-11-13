#!/usr/bin/env python3
"""一次性探针:量「一个 bytes: 节点能不能改成形状配方」,给 locator 台账复算用。

本文件是 `evidence/xrefs/locator_upgrade_4_4_4.tsv` 的复算器,不是维护中的接口
(没有文档节、不进 justfile)。只读 exe 拷贝:不开进程、不注入、不需要 license。

用法:

    # ① 普查:manifest 里每个 bytes: address 节点,函数体内引用了哪些可打印 C 串,
    #    每个串被几个函数引用(1 = 串本身就是唯一锚点;N = 需要收敛条件)
    python3 scripts/scratch/2026-11_locator_upgrade/locator_strength.py

    # ② 复核一条具体配方:打印它解析出的候选函数 RVA(1 个 = 收敛)
    python3 scripts/scratch/2026-11_locator_upgrade/locator_strength.py \
        --locator 'strref:Supported Scopes:@reads=0x88@calls=0x1d12cd0'

判读口径(与 chain_drift.py 的 Resolver 同源,不另发明):

* 「串被几个函数引用」= `find_cstring`(后缀命中回溯到 C 串起点) → `lea/mov` 站点 →
  站点所在的 `.pdata` 函数起点去重。`chain_drift.Resolver._strref` 就是这条链,
  所以这里的计数和工具的候选数一致。
* 函数体内 0 个可打印 C 串 ⇒ 这个节点**没有** strref 路线可走,不是「没找到」。
* 函数不在 `.pdata` 里 ⇒ 连「所在函数」都定义不出来,strref/reads/calls 三种
  谓词都无从下手(`graph/system_resolver` 就是这种叶子函数)。
"""
import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
import chain_drift  # noqa: E402
import rttibatch  # noqa: E402

MIN_STRING = 8          # 比这短的串(如 "bool")到处都是,当锚点没有意义
PRINTABLE = 0x20, 0x7E


def rip_ref_map(img):
    """`{target_rva: [site_rva, ...]}` —— `.text` 里所有 `lea/mov reg,[rip+disp]`。"""
    out = collections.defaultdict(list)
    for i, (va, vs, praw) in enumerate(img.secs):
        if rttibatch.section_name(img, i) != ".text":
            continue
        code = img.blob[praw:praw + vs]
        for off in range(len(code) - 6):
            if code[off] not in (0x48, 0x4C) or code[off + 1] not in (0x8D, 0x8B):
                continue
            if code[off + 2] & 0xC7 != 0x05:
                continue
            disp = int.from_bytes(code[off + 3:off + 7], "little", signed=True)
            out[va + off + 7 + disp].append(va + off)
    return out


def string_at(img, rva):
    """`rva` 处的 C 串(`rva` 必须是串首),不可打印或太短则 None。"""
    try:
        back = img.read(max(rva - 256, 0), min(256, rva))
    except KeyError:
        return None
    for k in range(len(back) - 1, -1, -1):
        if back[k] == 0:
            if rva - len(back) + k + 1 != rva:
                return None          # lea 指进串中间:不是串首,不当锚点
            break
    try:
        raw = img.read(rva, 256)
    except KeyError:
        return None
    end = raw.find(b"\x00")
    if end < MIN_STRING:
        return None
    text = raw[:end]
    if sum(1 for b in text if PRINTABLE[0] <= b <= PRINTABLE[1]) / len(text) < 0.9:
        return None
    return text.decode("latin1")


def census(img, pdata, refmap, node):
    """一个节点一行:`(node, pdata?, strings, best_refs, best_string)`。"""
    rva = int(node.expect, 16)
    span = pdata.func_of(rva)
    if not span:
        return node, "no", 0, "-", "not a .pdata function"
    begin, end = span
    code = img.read(begin, end - begin)
    rows = []
    seen = set()
    for off in range(len(code) - 6):
        if code[off] not in (0x48, 0x4C) or code[off + 1] not in (0x8D, 0x8B):
            continue
        if code[off + 2] & 0xC7 != 0x05:
            continue
        disp = int.from_bytes(code[off + 3:off + 7], "little", signed=True)
        target = begin + off + 7 + disp
        if target in seen:
            continue
        seen.add(target)
        text = string_at(img, target)
        if text is None:
            continue
        funcs = {pdata.func_of(site)[0] for site in refmap.get(target, ())
                 if pdata.func_of(site)}
        rows.append((len(funcs), text))
    if not rows:
        return node, "yes", 0, "-", "(no printable C string)"
    rows.sort(key=lambda row: (row[0], -len(row[1])))
    best = rows[0]
    return node, "yes", len(rows), best[0], best[1]


def main(argv=None):
    parser = argparse.ArgumentParser(prog="locator_strength.py", description=__doc__.splitlines()[0])
    parser.add_argument("--exe", help="stellaris.exe copy (default: NS_STELLARIS_EXE, then the usual chain)")
    parser.add_argument("--manifest", default=chain_drift.DEFAULT_MANIFEST)
    parser.add_argument("--locator", help="resolve this recipe and print its candidate RVAs")
    args = parser.parse_args(argv)

    exe = args.exe or chain_drift.find_exe_or_none()
    if not exe or not os.path.exists(exe):
        print("locator_strength: exe not found", file=sys.stderr)
        return 3
    img = chain_drift.load_image(exe)
    pdata = chain_drift.pdata_index(img)
    if args.locator:
        for rva in chain_drift.Resolver(img, pdata).resolve(
                chain_drift.parse_locator(args.locator), {}):
            print(hex(rva))
        return 0

    with open(args.manifest, encoding="utf-8") as fh:
        nodes = chain_drift.parse_manifest(fh.read())
    refmap = rip_ref_map(img)
    print("node\tlocator_kind\tpdata\tstrings\tbest_refs\tbest_string")
    for node in nodes:
        if node.cls != "address":
            continue
        name, has_pdata, count, refs, text = census(img, pdata, refmap, node)
        kind = node.locator.split(":", 1)[0] if node.locator else "-"
        print(f"{node.chain}/{node.node}\t{kind}\t{has_pdata}\t{count}\t{refs}\t{text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
