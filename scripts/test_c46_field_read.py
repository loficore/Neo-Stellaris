"""c46_field_read 的判据围栏(纯函数,一行真内存都不碰)。

判词逐字来自 `evidence/analysis/runtime_444_transitability_4_4_4.md` §6.2:
`owner_named` / `owner_constant` / `owner_out_of_domain` / `owner_lock_shape_mismatch`;
通道层的四档是 `field_read_ok` / `protocol_desync` / `instrument_broken` / `environment`。

口径:**判据住在 Python**(DLL 只返回 0/-1..-5)。所以这一份测试就是「N1 那一发怎么读、
读到什么算证明」的可执行版本 —— 没有游戏、没有 Windows API、没有进程。
"""

import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import c46_field_read as mod


REPO = pathlib.Path(__file__).resolve().parent.parent
ZIG = REPO / "src" / "dll" / "api" / "field_read.zig"

GOOD_LAYOUT = [1, 296, 40, 256, 3, 0x1370, 0x1374, 0x00FF_FFFF]

#: 国家 id 集合(N1 的 A/B/C 三条 owner 都落在里面;U 是无主哨兵)。
#: 20 = `0x06000014 & 0xffffff` —— 掩码口径那一格(§5.2)。
DOMAIN = [0, 7, 20]


def sent(kind=mod.KIND_SYSTEM, subject=7, off=mod.OWNER_OFF, length=4):
    """这一发写进缓冲的请求四格(驱动用它判回显是否一致)。"""
    return {"kind": kind, "subject": subject, "off": off, "len": length}


def reply_blob(*, kind=mod.KIND_SYSTEM, subject=7, off=mod.OWNER_OFF, length=4,
               status=0, got=4, resolved=0x1_4000_0200, data=b"\x07\x00\x00\x00"):
    """一块 296 B 回复(头 40 B 用 `<QQIIiIQ`,数据从 OFF_DATA 起)。"""
    blob = bytearray(mod.BUF_SIZE)
    struct.pack_into("<QQIIiIQ", blob, 0, kind, subject, off, length, status, got, resolved)
    blob[mod.OFF_DATA:mod.OFF_DATA + len(data)] = data
    return bytes(blob)


def reading(system, owner, *, lock=0, flag_a=0, flag_b=1, lock_len=mod.LOCK_READ_LEN):
    return mod.OwnerReading(system=system, owner=owner, lock=lock,
                            flag_a=flag_a, flag_b=flag_b, lock_len=lock_len)


# --- 通道层:三档 ------------------------------------------------------------------


def test_layout_mismatch_reports_instrument_broken():
    # 字 5 = owner 偏移。换成 0x136c 就是「读邻居那一格」—— 这种漂移必须在校验处停住,
    # 而不是把邻居的值当 owner 写成证据。
    drifted = list(GOOD_LAYOUT)
    drifted[5] = 0x136C
    verdict, detail = mod.classify(rc=0, reply=mod.decode_reply(reply_blob()),
                                   sent=sent(), layout_words=drifted)
    assert verdict == "instrument_broken"
    assert "layout" in detail and "word[5]" in detail


def test_header_status_and_rc_disagree_is_protocol_desync():
    # rc 说 -4、头里却写着 0:这是半途读数(缓冲里躺着上一次的值),不是「读到了」。
    reply = mod.decode_reply(reply_blob(status=0, got=0, data=b""))
    verdict, detail = mod.classify(rc=mod.STATUS_UNREADABLE, reply=reply, sent=sent())
    assert verdict == "protocol_desync"
    assert "status" in detail

    # 回显对不上同样是协议层:说明这块缓冲不是这一发写的。
    reply = mod.decode_reply(reply_blob(subject=8))
    verdict, detail = mod.classify(rc=0, reply=reply, sent=sent())
    assert verdict == "protocol_desync"
    assert "subject" in detail

    # 成功却 got != len(截断),以及失败却 got != 0(部分数据),都不是合法回复。
    assert mod.classify(rc=0, reply=mod.decode_reply(reply_blob(got=2, data=b"\x07\x00")),
                        sent=sent())[0] == "protocol_desync"
    assert mod.classify(rc=mod.STATUS_UNRESOLVED,
                        reply=mod.decode_reply(reply_blob(status=-2, got=4)),
                        sent=sent())[0] == "protocol_desync"


def test_missing_exports_and_unknown_rc_are_instrument_broken():
    verdict, detail = mod.classify(rc=None, reply=None, sent=sent(),
                                   exports_ok=False, missing=("C3FieldReadInto",))
    assert verdict == "instrument_broken" and "C3FieldReadInto" in detail
    assert mod.classify(rc=7, reply=None, sent=sent())[0] == "instrument_broken"
    # -1 不是「这次读失败」,而是「我们不在游戏进程里」:仪器档。
    assert mod.classify(rc=mod.STATUS_NO_BASE, reply=None, sent=sent())[0] == "instrument_broken"


def test_no_game_and_refused_window_are_environment():
    assert mod.classify(rc=None, reply=None, sent=sent(), no_game=True)[0] == "environment"
    assert mod.classify(rc=None, reply=None, sent=sent(), gate="refused")[0] == "environment"
    assert mod.classify(rc=0, reply=mod.decode_reply(reply_blob()), sent=sent(),
                        alive=False)[0] == "environment"


def test_consistent_reply_is_field_read_ok():
    verdict, detail = mod.classify(rc=0, reply=mod.decode_reply(reply_blob()), sent=sent())
    assert verdict == "field_read_ok", detail
    # 通道「说清了这次读不到」也是 field_read_ok:判词是通道的健康,不是值的内容。
    assert mod.classify(rc=mod.STATUS_UNRESOLVED,
                        reply=mod.decode_reply(reply_blob(status=-2, got=0, data=b"")),
                        sent=sent())[0] == "field_read_ok"


# --- 值域:国家 id 集合(§5.2 的掩码口径)-------------------------------------------


def test_country_domain_reports_the_masked_index_problem():
    domain, problems = mod.country_domain(41, [0, 7, 0x06000014])
    assert domain == [0, 7, 0x06000014]
    assert problems == []          # 0x06000014 & 0xffffff = 20 < 41:合法

    # bound=0 是主菜单期的表:值域未知,不许当成「表是空的 ⇒ 没有国家」。
    domain, problems = mod.country_domain(0, [])
    assert domain == [] and any("bound=0" in p for p in problems)

    # 掩码后的索引越界 ⇒ 头部不像索引对象(不是「多了一个国家」)。
    domain, problems = mod.country_domain(8, [0, 0x06000014])
    assert domain == [0, 0x06000014]
    assert any("超出 bound" in p for p in problems), problems


# --- N1 判词(§6.2 逐字)------------------------------------------------------------


def test_n1_three_distinct_values_in_domain_is_owner_named():
    owned = [reading(11, 0), reading(12, 7), reading(13, 0x06000014)]
    unowned = reading(99, mod.NO_OWNER)
    verdict, detail = mod.judge_n1(owned=owned, unowned=unowned, domain=[*DOMAIN, 0x06000014])
    assert verdict == "owner_named", detail
    assert "0xffffffff" in detail or "0xFFFFFFFF" in detail


def test_n1_equal_values_is_owner_constant():
    owned = [reading(11, 7), reading(12, 7), reading(13, 0)]
    verdict, detail = mod.judge_n1(owned=owned, unowned=reading(99, mod.NO_OWNER),
                                   domain=DOMAIN)
    assert verdict == "owner_constant"
    assert "7" in detail


def test_n1_value_outside_masked_domain_is_owner_out_of_domain():
    # 11 不在 {0,7,20} 里(掩码后也一样)⇒ 值域判负,不是「三个值互不相同就成立」。
    owned = [reading(11, 11), reading(12, 7), reading(13, 0)]
    verdict, detail = mod.judge_n1(owned=owned, unowned=reading(99, mod.NO_OWNER),
                                   domain=DOMAIN)
    assert verdict == "owner_out_of_domain"
    assert "11" in detail

    # 空值域(表没走通)不能当「都在集合内」:那是仪器档。
    verdict, detail = mod.judge_n1(owned=owned, domain=[])
    assert verdict == "instrument_broken"

    # 无主那一行读到的是某个国家 ⇒ 与哨兵矛盾;值域这一档负责说出来。
    verdict, detail = mod.judge_n1(owned=[reading(11, 0), reading(12, 7), reading(13, 20)],
                                   unowned=reading(99, 7), domain=DOMAIN)
    assert verdict == "owner_out_of_domain"
    assert "unowned" in detail.lower() or "U" in detail


def test_n1_lock_shape_mismatch():
    owned = [reading(11, 0), reading(12, 7), reading(13, 20)]
    # (a) 锁/两旗标不是同一次 6 B 读回来的 ⇒ 那 4 格不是一个「带锁的单值格」。
    torn = [reading(11, 0), reading(12, 7, lock_len=4), reading(13, 20)]
    verdict, detail = mod.judge_n1(owned=torn, unowned=reading(99, mod.NO_OWNER),
                                   domain=DOMAIN)
    assert verdict == "owner_lock_shape_mismatch"
    assert "6" in detail

    # (b) 旗标字节不是 0/1:形状不符(不是判 owner 的值域)。
    weird = [reading(11, 0), reading(12, 7, flag_a=3), reading(13, 20)]
    verdict, detail = mod.judge_n1(owned=weird, unowned=reading(99, mod.NO_OWNER),
                                   domain=DOMAIN)
    assert verdict == "owner_lock_shape_mismatch"
    assert "flag" in detail.lower() or "旗标" in detail

    # 三条都干净 ⇒ 没有形状问题(防止 (a)/(b) 的判据恒真)。
    assert mod.judge_n1(owned=owned, unowned=reading(99, mod.NO_OWNER),
                        domain=DOMAIN)[0] == "owner_named"


def test_n1_needs_three_owned_rows():
    verdict, detail = mod.judge_n1(owned=[reading(11, 0), reading(12, 7)], domain=DOMAIN)
    assert verdict == "instrument_broken"
    assert "3" in detail


# --- 零进程:--plan n1 -------------------------------------------------------------


def test_plan_n1_is_pure_and_lists_every_offset(monkeypatch):
    for name in ("c2_harness", "world_probe", "session_bridge"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    assert mod.main(["--plan", "n1"]) == 0
    # 「不碰进程」的可执行定义:这条路径连 harness 都没 import。
    for name in ("c2_harness", "world_probe"):
        assert name not in sys.modules

    text = mod.plan_n1()
    for off in ("0x1370", "0x1374", "0x1378", "0x1379"):
        assert off in text, off
    for verdict in ("owner_constant", "owner_out_of_domain", "owner_lock_shape_mismatch"):
        assert verdict in text, verdict
    assert "0xffffff" in text.lower() or "0x00ff_ffff" in text.lower()


# --- 协议三方一致(DLL 源码 / 驱动 / 文档)-------------------------------------------


def test_protocol_constants_match_the_zig_source():
    zig = ZIG.read_text(encoding="utf-8")
    for fragment in ("pub const LAYOUT_VERSION: u32 = 1;",
                     "pub const BUF_SIZE: usize = 296;",
                     "pub const OFF_DATA: usize = 40;",
                     "pub const MAX_LEN: u32 = 256;",
                     "pub const MAX_KIND: u32 = 3;"):
        assert fragment in zig, fragment
    # 八个词的**顺序**是契约:LAYOUT 字面量里必须是这八个符号,顺序不变。
    huge = zig[zig.index("pub const LAYOUT: [8]u32"):]
    literal = huge[:huge.index("};")]
    order = ["LAYOUT_VERSION", "BUF_SIZE", "OFF_DATA", "MAX_LEN", "MAX_KIND",
             "OWNER_OFF", "OWNER_LOCK_OFF", "ID_MASK"]
    positions = [literal.index(name) for name in order]
    assert positions == sorted(positions), positions
    assert len(literal.split(",")) >= 8


def test_request_and_reply_encoders_round_trip():
    request = mod.encode_request(mod.KIND_COUNTRY, 41, 0x1E88, 4)
    # 请求只占头的前 24 B:`status`/`got`/`resolved` 由调用前的整块清零保持在 0。
    assert len(request) == mod.OFF_STATUS
    reply = mod.decode_reply(reply_blob(kind=mod.KIND_COUNTRY, subject=41, off=0x1E88,
                                        got=4, data=b"\x01\x00\x00\x00"))
    assert reply["kind"] == mod.KIND_COUNTRY and reply["subject"] == 41
    assert reply["off"] == 0x1E88 and reply["status"] == 0
    assert reply["got"] == 4 and reply["data"] == b"\x01\x00\x00\x00"
    assert reply["resolved"] == 0x1_4000_0200
    # 短缓冲是拒读(不是「后面补零」)。
    try:
        mod.decode_reply(b"\x00" * (mod.BUF_SIZE - 1))
    except ValueError as exc:
        assert str(exc)
    else:                                    # pragma: no cover - 故意失败的那一半
        raise AssertionError("a short reply must raise, not be zero-padded")


def test_systems_and_probe_argument_parsing():
    assert mod.parse_systems("7,42,99") == [7, 42, 99]
    assert mod.parse_probe("7:0x1370:4") == (7, 0x1370, 4)
    for bad in ("", "7,", "7,x", "-1"):
        try:
            mod.parse_systems(bad)
        except ValueError:
            continue
        raise AssertionError(f"parse_systems accepted {bad!r}")
    for bad in ("7", "7:0x1370", "7:0x1370:0", "7:0x1370:257"):
        try:
            mod.parse_probe(bad)
        except ValueError:
            continue
        raise AssertionError(f"parse_probe accepted {bad!r}")


# --- 文档三方一致(README + offline-tooling)-----------------------------------------

DOC = REPO / "docs" / "offline-tooling.md"
README = REPO / "scripts" / "README.md"


def test_doc_section_quotes_the_same_layout_row():
    doc = DOC.read_text(encoding="utf-8")
    assert "### `scripts/c46_field_read.py" in doc
    # 三方一致的第三处:文档里的 layout 行必须**逐字**等于驱动自己的 EXPECTED_LAYOUT。
    assert mod.format_layout(mod.EXPECTED_LAYOUT) in doc
    for token in ("296", "protocol_desync", "owner_named", "session_bridge.py",
                  "--plan n1", "header.status == rc", "0x1370", "0x1374",
                  "0x1378", "0x1379", "0xffffff"):
        assert token in doc, token
    # N1 照单与 N2–N5 的输入缺口表是这一节的交付物,不是附注。
    for token in ("N1", "N2", "N3", "N4", "N5"):
        assert token in doc, token


def test_readme_lists_the_tool_and_its_fence():
    readme = README.read_text(encoding="utf-8")
    assert "c46_field_read.py" in readme
    assert "test_c46_field_read.py" in readme
    assert "17 passed" in readme
