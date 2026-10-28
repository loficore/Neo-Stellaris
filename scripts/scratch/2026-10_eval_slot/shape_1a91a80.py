#!/usr/bin/env python3
"""shape_1a91a80.py — 触发求值槽共用基体 `0x1A91A80` 的静态形状(§77,零 shot)。

一次性的离线探针:读本地 exe 拷贝,打印四件事实 ——
  1. 目标前 32 B 的十六进制(guard 的指纹,Task 2 的 `EXPECTED_CODE` 逐字复制它);
  2. `+0x1C` 处 `E8 rel32` 的调用目标;
  3. `0x1A918E0` 的前 8 条指令(它读 `[rdx+0x158]`,是 ctx 的类型门);
  4. 镜像里等于该 RVA 的 qword 个数(分 `.rdata` 与全镜像两口径)。

用法:
    python3 scripts/scratch/2026-10_eval_slot/shape_1a91a80.py

不碰游戏、不联网、不写引擎内存;exe 路径走 `disrva.resolve_exe()` 的候选链
(`NS_STELLARIS_EXE` 优先),不内联受保护的路径。
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import disrva  # noqa: E402

TARGET_RVA = 0x1A91A80
CALLEE_RVA = 0x1A918E0
FINGERPRINT_LEN = 32
CALL_AT = 0x1C  # the `E8 rel32` inside the 32-byte window


def _sections():
    """(name, va, vsize, raw_size, raw_ptr, data, image_base) for every section."""
    exe = pathlib.Path(disrva.resolve_exe())
    data = exe.read_bytes()
    import struct

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    # PE32+ optional header: ImageBase is the first 8-byte field (offset 24).
    image_base = struct.unpack_from("<Q", data, pe_off + 24 + 24)[0]
    table = pe_off + 24 + opt_size
    out = []
    for i in range(nsec):
        o = table + i * 40
        name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
        vsz, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        out.append((name, va, vsz, rawsz, rawptr, data, image_base))
    return out


def main() -> int:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    print(f"exe = {disrva.resolve_exe()}")
    raw, _name = disrva.rd(TARGET_RVA, FINGERPRINT_LEN)
    if len(raw) != FINGERPRINT_LEN:
        print(f"FAIL: could not read {FINGERPRINT_LEN} bytes at {TARGET_RVA:#x}")
        return 1

    print(f"\n== 1. fingerprint: {FINGERPRINT_LEN} bytes at {TARGET_RVA:#x} ==")
    print(" ".join(f"{b:02X}" for b in raw))

    print(f"\n== 2. the `E8 rel32` at +{CALL_AT:#x} ==")
    rel = int.from_bytes(raw[CALL_AT + 1:CALL_AT + 5], "little", signed=True)
    call_site = TARGET_RVA + CALL_AT
    print(f"call site  = {call_site:#x}")
    print(f"call target = {call_site + 5 + rel:#x}")

    print(f"\n== 3. first 8 instructions at {CALLEE_RVA:#x} ==")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    body, _ = disrva.rd(CALLEE_RVA, 96)
    for i, ins in enumerate(md.disasm(body, CALLEE_RVA)):
        print(f"{ins.address:08x}  {ins.mnemonic:<7} {ins.op_str}")
        if i >= 7:
            break

    print("\n== 4. qwords equal to the target ==")
    import struct

    whole = 0
    rdata = 0
    image_base = 0
    for name, va, vsz, rawsz, rawptr, data, image_base in _sections():
        blob = data[rawptr:rawptr + rawsz]
        # `.rdata` holds **absolute addresses**, not RVAs: a vtable slot is
        # `ImageBase + RVA`.  Counting the bare RVA finds nothing (measured: 0).
        wanted = image_base + TARGET_RVA
        count = sum(
            1
            for off in range(0, len(blob) - 7, 8)
            if struct.unpack_from("<Q", blob, off)[0] == wanted
        )
        whole += count
        if ".rdata" in name:
            rdata += count
            print(f"  {name:<10} qwords == {wanted:#x}: {count}")
    print(f"  image base  : {image_base:#x}")
    print(f"  .rdata total : {rdata}")
    print(f"  whole image  : {whole}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
