#!/usr/bin/env python3
"""queue_dispatchers —— §60.7-1「谁经队列派发」的三条离线口径(零 shot)。

口径(读数逐字对齐 §60.5/§60.6,不可自行重推):
  A 对齐 qword 扫描 —— exe 各 CNT_INITIALIZED_DATA(chars & 0x40)段里找
    值 == BASE+0x1c42fe0 的 8 字节对齐 LE-qword;自校验 = 恰好 1 个命中 @0x26d4df8
    (§60.5 one-shot 的同一条判据,节表字段偏移照 find_refs.py)。
  B 引用者集合 —— vtable 0x26d4dd0 的 RIP 引用(riprefs --verify 同口径)+
    ctor 0x1c42d30 的直接 E8 rel32 调用点(§60.5 用 fastcalls 拿到的两个站点)。
  C 派发站点 —— 全 .text 里 `call qword ptr [reg+0x28]` 形态,func_of 归到承载函数,
    再筛「同一函数体内也引用 A/B 集合里的对象」。

失败语义:A/B 自校验不过 ⇒ 检测器坏了,退出码 1,不写 artifact,更不写负结论。
读 exe 走 disrva.resolve_exe()/CANDIDATES,不写死绝对路径。
"""
import os
import re
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
if os.path.join(_REPO, "scripts") not in sys.path:
    sys.path.insert(0, os.path.join(_REPO, "scripts"))

from capstone import Cs, CS_ARCH_X86, CS_MODE_64   # noqa: E402
from capstone.x86 import X86_OP_MEM, X86_REG_RIP   # noqa: E402

from disrva import BASE, resolve_exe, _image  # noqa: E402
from riprefs import refs_for                  # noqa: E402  (与 §60.5 `riprefs.py --verify` 同一实现)
from pdata import func_of                     # noqa: E402

CARRIER_RVA = 0x1C42FE0
CARRIER_END = 0x1C43884
VTABLE_RVA = 0x26D4DD0
CTOR_RVA = 0x1C42D30
DTOR_RVA = 0x1C42DE0
NEW_RVA = 0x2185218
OBJ_SIZE = 0x128
CTOR_EXPECT_CALLERS = {0x1BA708E, 0x1BA7685}          # §60.5 fastcalls 两桶的站点
CTOR_EXPECT_SITES = {0x1BA7076, 0x1BA766E}            # `mov ecx,0x128` 的真字节位置
# (§60.5 里写的 0x1ba7070/0x1ba7660 是 disrva 命令的窗口参数,不是这对字节的首地址 ——
#  本节按 §60.5 自己的命令重跑,首地址落在 0x1ba7076/0x1ba766e,datum 以字节为准)


def _md():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def _section_secs(secs, name):
    return next(s for s in secs if s[0] == name)


def _blob(image, secs, name):
    nm, va, vs, rawsz, praw, ch = _section_secs(secs, name)
    return va, image[praw:praw + min(vs, rawsz)]


def read_image():
    st = _image()
    if st is None:
        raise SystemExit(f"[queue_dispatchers] 没有可读的 stellaris.exe 拷贝(设 NS_STELLARIS_EXE):"
                         f"候选链 {resolve_exe()}")
    return st  # (exe_path, image_bytes, secs)


def channel_a(image, secs):
    """口径 A:对齐 qword == BASE+CARRIER 在 CNT_INITIALIZED_DATA 段里的命中 RVA 列表。"""
    key = struct.pack("<Q", BASE + CARRIER_RVA)
    hits = []
    for nm, va, vs, rawsz, praw, ch in secs:
        if not (ch & 0x40):            # §60.5:只看 CNT_INITIALIZED_DATA
            continue
        data = image[praw:praw + min(vs, rawsz)]
        for off in range(0, len(data) - 7):
            if (va + off) % 8:         # 命中必须 8 字节对齐(相对 RVA)
                continue
            if data[off:off + 8] == key:
                hits.append((nm, va + off))
    return hits


def channel_b(image, secs):
    """口径 B:vtable 0x26d4dd0 的 RIP 引用(§60.5 的 riprefs --verify 同实现)
    + ctor 0x1c42d30 的直接 `E8 rel32` 调用点(riprefs 只管 rip 形态,§60.5 的
    两个构造站点是 fastcalls 拿的 —— 这里用同口径的候选算术 + 对齐复核复现)。"""
    vtable_refs = sorted(site for site, _enc in
                         refs_for({VTABLE_RVA}, ".text", True).get(VTABLE_RVA, []))

    va, blob = _blob(image, secs, ".text")
    md = _md()
    ctor_callers = []
    for m in re.finditer(b"\xe8", blob):
        i = m.start()
        if i + 5 > len(blob):
            continue
        disp = struct.unpack_from("<i", blob, i + 1)[0]
        site = va + i
        if site + 5 + disp != CTOR_RVA:
            continue
        fb = func_of(site)                 # 对齐复核:从函数首解码,site 处须真是那条 call
        if fb is None:
            continue
        insn = None
        for ins in md.disasm(blob[fb[0] - va:fb[1] - va + 16], BASE + fb[0]):
            if ins.address - BASE == site:
                insn = ins
                break
        if insn is None or insn.mnemonic != "call":
            continue
        ctor_callers.append(site)
    ctor_callers = sorted(ctor_callers)

    # 构造点 = ctor 调用点之前窗口里的 `mov ecx,0x128; call new` 对
    # (与 ctor 调用点之间隔着 new 返回值的落槽指令,不是紧邻;窗口取 0x40)
    build_sites = []
    for site in ctor_callers:
        lo = site - va - 0x40
        window = blob[max(lo, 0):site - va]
        pat = b"\xb9" + struct.pack("<I", OBJ_SIZE) + b"\xe8"
        for mt in re.finditer(re.escape(pat), window):
            off = (site - va) - len(window) + mt.start()   # blob 内偏移
            disp = struct.unpack_from("<i", blob, off + 6)[0]
            rva = off + va
            if rva + 10 + disp == NEW_RVA:
                build_sites.append(rva)
    size = OBJ_SIZE if build_sites and len(build_sites) == len(ctor_callers) else None
    return {"vtable_refs": vtable_refs, "ctor_callers": ctor_callers,
            "build_sites": build_sites, "size": size}


def _call_mem_disp_sites(image, secs, disp):
    """全 .text 里 `call qword ptr [reg+disp]`(含 SIB 变体)的真站点。

    候选 = 字节形态(mod=01 disp8 / mod=10 disp32;rm=100 走 SIB),
    复核 = 从 .pdata 函数首对齐解码到 site(capstone 判定 call + mem + 非 rip + 同 disp)。
    与 riprefs --verify 同一「候选算术 + 对齐复核」口径,只是操作数形态不同。
    disp 只有 disp8/disp32 两种可编码形态(disp8 上限 0x7f,0x28/0x60 都在内)⇒ 无形态漏。"""
    va, blob = _blob(image, secs, ".text")
    d8 = disp & 0xFF
    pats = [(re.compile(rb"\xff[\x50-\x53\x55-\x57]\x%02x" % d8), 3, "disp8"),
            (re.compile(rb"\xff\x54[\x00-\xff]\x%02x" % d8), 4, "sib8"),
            (re.compile(rb"\xff[\x90-\x93\x95-\x97]\x%02x\x00\x00\x00" % d8), 6, "disp32"),
            (re.compile(rb"\xff\x94[\x00-\xff]\x%02x\x00\x00\x00" % d8), 7, "sib32")]
    cands = []
    for pat, size, form in pats:
        for m in pat.finditer(blob):
            cands.append((va + m.start(), va + m.start() + size, form))
    by_func = {}
    for s, e, form in cands:
        fb = func_of(s)
        if fb:
            by_func.setdefault(fb, []).append((s, form))
    md = _md()
    out = []
    for (fstart, fend, _uw), items in by_func.items():
        pos = fstart - va
        code = blob[pos:fend - va + 16]
        want = {s: f for s, f in items}
        for ins in md.disasm(code, BASE + fstart):
            r = ins.address - BASE
            if r not in want:
                continue
            form = want.pop(r)
            if ins.mnemonic != "call" or not ins.operands:
                continue
            op = ins.operands[0]
            if op.type != X86_OP_MEM or op.mem.base == X86_REG_RIP or op.mem.disp != disp:
                continue
            out.append({"site": r, "func": (fstart, fend), "form": form})
    return out


def _object_ref_functions(image, secs):
    """函数首址 -> 它引用的 A/B 对象(vtable 0x26d4dd0 / ctor 0x1c42d30;
    rip 引用走 riprefs refs_for --verify 同实现,直接 `call ctor` 走 B 的 E8 口径)。"""
    refs = refs_for({VTABLE_RVA, CTOR_RVA}, ".text", True)
    fn_objs = {}
    for target, hits in refs.items():
        for site, _enc in hits:
            fb = func_of(site)
            if fb:
                fn_objs.setdefault(fb[0], set()).add(target)
    for site in (0x1BA708E, 0x1BA7685):      # B 的两条 `call ctor`(在其调用函数内即引用 ctor)
        fb = func_of(site)
        if fb:
            fn_objs.setdefault(fb[0], set()).add(CTOR_RVA)
    return fn_objs


def channel_c(image, secs):
    """口径 C:`call [reg+0x28]` 站点集合 + 每个站点所在函数是否引用 A/B 对象。

    检测器先行(§62 同一族坑 / Review Focus 1):先用完全相同的机器找
    `call [rax+0x60]` —— §60.5 记量的排空循环 0x1c42ee0..0x1c42fdc 里有一条,
    校准不过就拒绝出数,0x28 的结果不写。"""
    cal = [s for s in _call_mem_disp_sites(image, secs, 0x60)
           if s["func"] == (0x1C42EE0, 0x1C42FDC)]
    sites = _call_mem_disp_sites(image, secs, 0x28)
    fn_objs = _object_ref_functions(image, secs)
    for s in sites:
        s["object_ref"] = fn_objs.get(s["func"][0])
    return sites, {"cal_0x60_in_drain": len(cal), "cal_sites": cal}


def _verdict(sites, matched):
    """三档(brief 逐字):found = 站点函数引用 A/B 对象;partial = 集合非空但无一配上;
    no_dispatcher_static = 集合归约后为空(只有 A/B 都绿时才有资格到这档 —— main 的结构保证了这点)。"""
    if matched:
        return "dispatchers_found"
    if sites:
        return "dispatchers_partial"
    return "no_dispatcher_static"


def _artifact_rows(hits_a, b, sites):
    """列:channel, site_rva, func_rva(被调/被指向函数,'-'),
    func_begin(站点所在函数入口,'-'), form, slot, object_ref, note。"""
    rows = []
    for nm, rva in hits_a:
        fb = func_of(CARRIER_RVA)
        rows.append(("A", _hx(rva), _hx(CARRIER_RVA), _hx(fb[0]), "aligned-qword",
                     "0x28", _hx(VTABLE_RVA), f"{nm} 槽 = vtable+0x28;载体 0x1c42fe0..0x1c43884"))
    for s in b["vtable_refs"]:
        fb = func_of(s)
        rows.append(("B", _hx(s), "-", _hx(fb[0]), "rip-ref(verified)",
                     "-", _hx(VTABLE_RVA), f"func {fb[0]:x}..{fb[1]:x}"))
    for s in b["ctor_callers"]:
        fb = func_of(s)
        rows.append(("B", _hx(s), _hx(CTOR_RVA), _hx(fb[0]), "e8-rel32(call ctor)",
                     "-", _hx(CTOR_RVA), f"func {fb[0]:x}..{fb[1]:x};§60.5 fastcalls 两桶"))
    for s in b["build_sites"]:
        fb = func_of(s)
        rows.append(("B", _hx(s), _hx(NEW_RVA), _hx(fb[0]), "mov-ecx+call-new",
                     "-", _hx(CTOR_RVA), f"构造点 mov ecx,0x{OBJ_SIZE:x};call 0x{NEW_RVA:x}"))
    for st in sites:
        objs = st.get("object_ref")
        rows.append(("C", _hx(st["site"]),
                     _hx(CARRIER_RVA) if objs else "-", _hx(st["func"][0]),
                     "call[" + st["form"] + "+0x28]", "0x28",
                     "|".join(_hx(o) for o in sorted(objs)) if objs else "-",
                     f"func {st['func'][0]:x}..{st['func'][1]:x}"))
    return rows


def write_artifact(exe, hits_a, b, sites, matched, verdict):
    path = os.path.join(_REPO, "evidence", "xrefs", "queue_dispatchers_4_4_4.tsv")
    rows = _artifact_rows(hits_a, b, sites)
    with open(path, "w", encoding="utf-8") as f:
        f.write("channel\tsite_rva\tfunc_rva\tfunc_begin\tform\tslot\tobject_ref\tnote\n")
        f.write(f"#verdict\t{verdict}\tcall[reg+0x28]_sites={len(sites)}\t"
                f"with_ab_object_ref={len(matched)}\t"
                f"A/B 自校验 + C 校准(0x60 形态同机器)全绿才写本文件;"
                f"exe={os.path.basename(exe)}\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")
    return path


def _hx(v):
    return "-" if v is None else f"0x{v:x}"


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="queue_dispatchers.py")
    ap.add_argument("--only", choices="ABC", help="只跑一条口径(A/B 带自校验)")
    args = ap.parse_args(argv)

    exe, image, secs = read_image()
    hits_a = b = sites = matched = None
    if args.only in (None, "A"):
        hits_a = channel_a(image, secs)
        if len(hits_a) == 1 and hits_a[0][1] == 0x26D4DF8:
            print(f"channel A: aligned_hits=1 self_check=ok @ 0x{hits_a[0][1]:x}")
        else:
            print(f"channel A: aligned_hits={len(hits_a)} self_check=FAIL "
                  f"@ {['%s:0x%x' % (nm, rva) for nm, rva in hits_a]} —— 检测器坏了,停")
            return 1
        if args.only == "A":
            return 0
    if args.only in (None, "B"):
        b = channel_b(image, secs)
        for s in b["vtable_refs"]:
            print(f"channel B vtable-ref  0x{s:x}  func {func_of(s)[0]:x}..{func_of(s)[1]:x}")
        for s in b["ctor_callers"]:
            print(f"channel B ctor-call   0x{s:x}")
        for s in b["build_sites"]:
            print(f"channel B build-site  0x{s:x}  mov ecx,0x{b['size'] or OBJ_SIZE:x}; call new 0x{NEW_RVA:x}")
        fns = {func_of(s)[0] for s in b["vtable_refs"]}
        ok = (fns == {CTOR_RVA, DTOR_RVA} and len(b["vtable_refs"]) == 2   # §60.5:恰好 2 处
              and set(b["ctor_callers"]) == CTOR_EXPECT_CALLERS
              and set(b["build_sites"]) == CTOR_EXPECT_SITES and b["size"] == OBJ_SIZE)
        if ok:
            print(f"channel B: self_check=ok vtable_refs={len(b['vtable_refs'])} "
                  f"ctor_callers={len(b['ctor_callers'])} build_sites="
                  f"{['0x%x' % s for s in b['build_sites']]} size=0x{b['size']:x}")
        else:
            print(f"channel B: self_check=FAIL vtable_fns={fns} "
                  f"ctor_callers={['0x%x' % s for s in b['ctor_callers']]} "
                  f"build_sites={['0x%x' % s for s in b['build_sites']]} size={b['size']} "
                  f"—— 检测器坏了,停")
            return 1
        if args.only == "B":
            return 0
    if args.only in (None, "C"):
        sites, cal = channel_c(image, secs)
        if cal["cal_0x60_in_drain"] < 1:
            print("channel C: self_check=FAIL 同机器在校准位移 0x60 上找不到 §60.5 "
                  "排空循环里的 `call [rax+0x60]` —— 检测器坏了,停(0x28 结果不出)")
            return 1
        cal_s = ["0x%x" % s["site"] for s in cal["cal_sites"]]
        matched = [s for s in sites if s["object_ref"]]
        print(f"channel C: calib call[reg+0x60] @0x1c42ee0..0x1c42fdc -> {cal_s} "
              f"self_check=ok; call[reg+0x28] sites={len(sites)} "
              f"with_ab_object_ref={len(matched)} "
              f"{[('0x%x' % s['site'], sorted(hex(o) for o in s['object_ref'])) for s in matched]}")
        if args.only == "C":
            return 0
    verdict = _verdict(sites, matched)
    path = write_artifact(exe, hits_a, b, sites, matched, verdict)
    print(f"verdict={verdict} -> {os.path.relpath(path, _REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
