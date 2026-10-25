"""Contract tests for ``scripts/exec_frame_sites.py`` —— 真实站点反解,不是 -5 估值。

合成字节不碰 exe;只有带 ``read_real_exe`` fixture 的那两条需要本机有 exe 拷贝
(``resolve_exe()`` 为 None 时整条 skip,这台机器上它是可选的 —— 但本机确实有)。

歧义那条的候选是**实跑打印后钉死**的(本工具的判读卡明令不许靠注释猜):REX 重叠
``48 FF 50 08`` 与 ``FF 50 08`` 都恰好结束于返回点,这是真实的反汇编边界歧义。
"""
import pathlib
import sys

import pytest
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import exec_frame_sites  # noqa: E402
from exec_frame_sites import (  # noqa: E402
    DEFAULT_CENSUS,
    DEFAULT_OUT,
    SITE_WINDOW,
    candidate_call_sites,
    frame_rows,
    main,
    parse_probe_caller_rows,
    resolve_call_site,
)

MD = Cs(CS_ARCH_X86, CS_MODE_64)          # 测试模块里建一次,和工具同配置


@pytest.fixture(scope="session")
def read_real_exe():
    """真实 exe 拷贝的 RVA 读取器;没有拷贝就整条 skip(工具在别的机器上照样可测)。"""
    exe = exec_frame_sites.resolve_exe()
    if exe is None:
        pytest.skip("这台机器没有可读的 stellaris.exe 拷贝(resolve_exe() is None)")
    return exec_frame_sites.make_reader(exe)


def _page_read(data, base):
    """一段合成镜像:[base, base+len(data)) 内可完整读,越界返回 None(拒绝口径)。"""
    def read(rva, n):
        if rva < base or rva + n > base + len(data):
            return None
        return data[rva - base:rva - base + n]
    return read


# ---------------------------------------------------------------------------
# candidate_call_sites:逐偏移解码,只收「恰好结束于返回点」的 call/jmp
# ---------------------------------------------------------------------------

def test_rel32_site_is_return_minus_five():
    win = bytes([0x90, 0x90, 0xE8, 0xFB, 0xFF, 0xFF, 0xFF])
    assert candidate_call_sites(win, 7, MD) == [(2, "call")]


def test_mem_form_call_qword_ptr_rax_plus_8():
    win = bytes([0x48, 0x8B, 0x07, 0xFF, 0x50, 0x08])   # mov rax,[rdi]; call qword ptr [rax+8]
    assert candidate_call_sites(win, 6, MD) == [(3, "call")]


def test_all_nop_window_has_no_boundary():
    win = bytes([0x90] * 24)
    assert candidate_call_sites(win, 16, MD) == []


# ---------------------------------------------------------------------------
# resolve_call_site:form 词汇表 {rel32, mem, thunk, ambiguous, none}
# ---------------------------------------------------------------------------

def test_two_candidate_boundaries_refuse_the_site():
    # REX 重叠:48 FF 50 08 与 FF 50 08 都恰好结束于返回点 —— 候选边界是真歧义,
    # 不选最短也不选最长。候选表是实跑打印后钉死的,不是注释里的猜测。
    # body 放在 base+0x10:回看窗 [ret-16, ret) 必须整个落在页内。
    base = 0x1000
    body = bytes([0x48, 0xFF, 0x50, 0x08])
    page = bytes(0x1010) + body + bytes([0x90] * 64)
    read = _page_read(page, base)
    ret = 0x1010 + base + len(body)
    win = read(ret - SITE_WINDOW, SITE_WINDOW + 64)
    assert candidate_call_sites(win, SITE_WINDOW, MD) == [(12, "call"), (13, "call")]
    got = resolve_call_site(ret, read)            # 同一段字节走公开接口
    assert got["form"] == "ambiguous" and got["site"] is None


def test_rel32_resolves_with_site_and_insn(read_real_exe):
    # §59.7 第一行:ret=0x1bcd192(v4 的 est 0x1bcd18d + 5),真站点就是估值本身 ——
    # 因为它确实是 5 B 的 E8 rel32,而且 callee 首字节是 48(真函数,不是跳板)。
    got = resolve_call_site(0x1BCD192, read_real_exe)
    assert got["site"] == 0x1BCD18D and got["form"] == "rel32"
    assert got["insn"].startswith("call")


def test_reader_bounds_on_real_image(read_real_exe):
    # 段表 va/vs 读反的回归钉:回看窗必须能读;.text 之前的头区与镜像之外必须拒绝。
    assert read_real_exe(0x1BCD182, 16) is not None
    assert read_real_exe(0, 4) is None                       # 段表之前的 PE 头区
    assert read_real_exe(0x7FFFFFFF, 4) is None


def test_v4_row_0x1c4369e_resolves_to_the_mem_site_at_0x1c4369b(read_real_exe):
    got = resolve_call_site(0x1C4369E, read_real_exe)
    assert got["site"] == 0x1C4369B and got["form"] == "mem"


def test_thunk_form_when_rel32_target_is_a_jump_stub():
    base = 0x1000
    page = bytearray([0x90] * 0x100)
    site = base + 0x14                       # 回看窗 [site+5-16, site+5) 整个落在页内
    target = base + 0x60                     # 跳板:E9 jmp rel32
    disp = (target - (site + 5)) & 0xFFFFFFFF
    page[site - base:site - base + 5] = bytes([0xE8]) + disp.to_bytes(4, "little")
    page[target - base] = 0xE9
    read = _page_read(bytes(page), base)
    got = resolve_call_site(site + 5, read)
    assert got["site"] == site and got["form"] == "thunk"
    # 对照:同一 call 若目标不是 EB/E9 开头,form 保持 rel32
    page[target - base] = 0x48
    got = resolve_call_site(site + 5, _page_read(bytes(page), base))
    assert got["site"] == site and got["form"] == "rel32"


def test_resolve_call_site_clean_window_is_form_none_dict():
    # candidate_call_sites 层的 [] 由 test_all_nop_window_has_no_boundary 钉;
    # 这里钉 resolve_call_site 层的公开契约:整窗 nop(无任何恰好结束边界)时
    # 必须返回 {"site": None, "form": "none", "insn": None} 这个 dict 本身。
    # body 放在 base+0x1010 起:回看窗 [ret-16, ret) 必须整个落在页内。
    base = 0x1000
    body = bytes([0x90] * 16)
    page = bytes(0x1010) + body + bytes([0x90] * 64)
    read = _page_read(page, base)
    ret = base + 0x1010 + len(body)
    win = read(ret - SITE_WINDOW, SITE_WINDOW + 64)
    assert candidate_call_sites(win, SITE_WINDOW, MD) == []   # 实跑钉死,再走公开接口
    assert resolve_call_site(ret, read) == {"site": None, "form": "none", "insn": None}


def test_unique_jmp_boundary_resolves_as_thunk():
    # resolve_call_site 的终点分支(唯一边界是 jmp):`nop*14; EB 90` 让唯一
    # 「恰好结束于返回点」的 call/jmp 边界是偏移 14 的 jmp rel8 —— 候选表实跑打印后钉死。
    # call 不会把返回点画在 jmp 之后,能记录到这种返回 RVA 的只能是被重打的跳板 ⇒ thunk。
    base = 0x1000
    body = bytes([0x90] * 14 + [0xEB, 0x90])
    page = bytes(0x1010) + body + bytes([0x90] * 64)
    read = _page_read(page, base)
    ret = base + 0x1010 + len(body)
    win = read(ret - SITE_WINDOW, SITE_WINDOW + 64)
    assert candidate_call_sites(win, SITE_WINDOW, MD) == [(14, "jmp")]
    got = resolve_call_site(ret, read)
    assert got["site"] == ret - 2 and got["form"] == "thunk"
    assert got["insn"].startswith("jmp")


def test_unreadable_window_is_a_refusal_not_a_none_form():
    from exec_frame_sites import SiteDecodeError
    with pytest.raises(SiteDecodeError):
        resolve_call_site(0x1000, lambda rva, n: None)      # 读不出来 ≠ 窗口里没有边界
    with pytest.raises(SiteDecodeError):
        resolve_call_site(0x0, lambda rva, n: None)         # 回看窗为负,同样拒绝


# ---------------------------------------------------------------------------
# parse_probe_caller_rows:v4 键是估值(assumed),Task 2 起键是返回 RVA
# ---------------------------------------------------------------------------

def test_probe_rows_v4_assumed_and_task2_explicit(tmp_path):
    p = tmp_path / "probe.tsv"
    p.write_text(
        "# kind\tkey\tvalue\tdetail\n"
        "meta\tcalls\t3061\t-\n"
        "caller\t0x1bcd18d\t3\tfunc=0x1bcd120 origin=incoming_arg\n"
        "caller\t0x1c43699\t2\tfunc=- origin=-\n"
        "caller\t0x1bcd192\t3\tret=0x1bcd192 est_site=0x1bcd18d func=0x1bcd120 "
        "origin=incoming_arg\n",
        encoding="utf-8")
    rows = parse_probe_caller_rows(str(p))
    assert rows == [
        {"ret": 0x1BCD192, "count": 3, "assumed": True},    # v4:key+5
        {"ret": 0x1C4369E, "count": 2, "assumed": True},    # v4:key+5
        {"ret": 0x1BCD192, "count": 3, "assumed": False},   # Task 2:用 ret=
    ]


def test_probe_row_malformed_key_is_refused(tmp_path):
    p = tmp_path / "probe.tsv"
    p.write_text("caller\tnot-hex\t3\t-\n", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_probe_caller_rows(str(p))


# ---------------------------------------------------------------------------
# frame_rows:join .pdata 与 census
# ---------------------------------------------------------------------------

def test_frame_rows_joins_site_not_estimate():
    rows = [{"ret": 0x100, "count": 1, "assumed": False}]

    def resolve(ret):
        return {"site": 0xFC, "form": "mem", "insn": "call qword ptr [rax + 8]"}

    def func_of(rva):
        assert rva == 0xFC                     # join 用真站点,不是 ret/est
        return (0xF0, 0x120, 0x60)

    census = {0xFC: {"func": 0xF0, "origin": "incoming_arg"}}
    got = frame_rows(rows, resolve, func_of, census)[0]
    assert got == {"ret": 0x100, "count": 1, "site": 0xFC, "form": "mem",
                   "insn": "call qword ptr [rax + 8]", "func_start": 0xF0,
                   "func_end": 0x120, "census_origin": "incoming_arg",
                   "site_in_census": 1}


def test_frame_rows_ambiguous_falls_back_to_ret_for_func():
    rows = [{"ret": 0x100, "count": 2, "assumed": True}]

    def resolve(ret):
        return {"site": None, "form": "ambiguous", "insn": "0xfb call; 0xfc call"}

    def func_of(rva):
        assert rva == 0x100                    # 站点不可判时仍能给调用方函数
        return (0xF0, 0x120, 0x60)

    got = frame_rows(rows, resolve, func_of, {0xFB: {"func": 0xF0, "origin": "x"}})[0]
    assert got["site"] is None and got["func_start"] == 0xF0
    assert got["census_origin"] == "-" and got["site_in_census"] == 0


# ---------------------------------------------------------------------------
# census 解析:共享 loader(c2_scope_probe.load_call_census)与本地回退的漂移钉
# ---------------------------------------------------------------------------

# 与 test_main_end_to_end_on_real_bytes 的 census 同款头(7 列 + `#` 头行),
# 外加两份解析器都必须跳过的行:空行、注释行、<6 列短行、坏 hex 行。
_CENSUS_FIXTURE = (
    "# func_start\tfunc_end\tcaller_count\tsrc_files\tsite\trdx_origin\tevidence\n"
    "\n"
    "0x1bcd120\t0x1bcd227\t1\t-\t0x1bcd18d\tincoming_arg\t-\n"
    "0x1c42fe0\t0x1c43884\t1\t-\t0x1c4369b\t-\t-\n"
    "# comment mid-table\n"
    "short\trow\n"
    "0xzz\t0x1\t2\t3\t0x4\t5\n"
    "0x10\t0x20\t1\t-\t0x30\torigin_x\t-\textra_col\n"
)


def test_local_census_fallback_matches_shared_loader(tmp_path):
    # `_load_call_census_local` 是刻意保留的逐字重复:共享 loader 的 import 链可能因
    # 缺 `c2_harness` 而炸,本地回退必须不依赖它。两份一旦漂移,缺 c2_harness 的机器会静默
    # 拿到不同的 census join —— 这条用同一 fixture 钉两边输出**完全相等**。
    p = tmp_path / "census.tsv"
    p.write_text(_CENSUS_FIXTURE, encoding="utf-8")
    local = exec_frame_sites._load_call_census_local(str(p))
    assert local == {  # 非空且逐条钉语义,防「两边都返回 {} 也算相等」
        0x1BCD18D: {"func": 0x1BCD120, "origin": "incoming_arg"},
        0x1C4369B: {"func": 0x1C42FE0, "origin": "-"},
        0x30: {"func": 0x10, "origin": "origin_x"},
    }
    try:
        from c2_scope_probe import load_call_census
    except Exception as exc:
        pytest.skip(f"本机 import 不了共享 loader(c2_harness 侧依赖):{exc};"
                    "漂移钉要两边都能跑才成立;本地回退的语义已由上面的断言钉住")
    assert load_call_census(str(p)) == local


def test_load_census_routes_to_local_fallback_when_shared_import_fails(tmp_path, monkeypatch):
    # 钉 `_load_census` 的 fallback 分支本身:sys.modules 塞 None 使
    # `from c2_scope_probe import ...` 抛 ImportError,join 必须原样落到本地解析。
    p = tmp_path / "census.tsv"
    p.write_text(_CENSUS_FIXTURE, encoding="utf-8")
    monkeypatch.setitem(sys.modules, "c2_scope_probe", None)
    assert exec_frame_sites._load_census(str(p)) == \
        exec_frame_sites._load_call_census_local(str(p))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_defaults_are_pinned_paths():
    assert DEFAULT_CENSUS == "evidence/xrefs/exec_frame_callers_4_4_4.tsv"
    assert DEFAULT_OUT == "evidence/xrefs/exec_frame_sites_4_4_4.tsv"


def test_missing_exe_copy_is_one_message_not_a_traceback(monkeypatch, capsys):
    monkeypatch.setattr(exec_frame_sites, "resolve_exe", lambda: None)
    assert main(["--probe", "whatever.tsv"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("[exec_frame_sites] ") and "Traceback" not in err


def test_main_end_to_end_on_real_bytes(tmp_path):
    if exec_frame_sites.resolve_exe() is None:
        pytest.skip("no local exe copy")
    try:
        import pdata  # noqa: F401  —— main 内部延迟 import 它;这里只为把环境缺 exe 变成 skip
    except Exception as exc:
        pytest.skip(f"pdata import fails without an exe copy at its own path: {exc}")
    probe = tmp_path / "probe.tsv"
    probe.write_text(
        "# kind\tkey\tvalue\tdetail\n"
        "caller\t0x1bcd18d\t3\tfunc=0x1bcd120 origin=incoming_arg\n",
        encoding="utf-8")
    census = tmp_path / "census.tsv"
    census.write_text(
        "# func_start\tfunc_end\tcaller_count\tsrc_files\tsite\trdx_origin\tevidence\n"
        "0x1bcd120\t0x1bcd227\t1\t-\t0x1bcd18d\tincoming_arg\t-\n",
        encoding="utf-8")
    out = tmp_path / "sites.tsv"
    assert main(["--probe", str(probe), "--census", str(census), "--out", str(out)]) == 0
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == ("# ret_rva\tcount\tsite_rva\tform\tinsn\tfunc_start\tfunc_end"
                        "\tcensus_origin\tsite_in_census")
    row = lines[1].split("\t")
    assert row[0] == "0x1bcd192" and row[2] == "0x1bcd18d" and row[3] == "rel32"
    assert row[5] == "0x1bcd120" and row[8] == "1"          # .pdata 与 census join 都命中
    assert "meta\tresolved\t1" in out.read_text(encoding="utf-8")
