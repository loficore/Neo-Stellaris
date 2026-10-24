"""Pure-function tests for scope_reclassify.py — no game, no process, no exe read.

The fixture is the LEGACY object-row grammar from evidence/logs/
scope_probe_v2_4_4_4.tsv (§56.3): the pre-fix driver never wrote an absolute
`vptr=`, and a candidate whose qword failed to resolve to an image RVA is a dash,
not a missing row.
"""

from scope_reclassify import load_candidate_map, parse_object_rows, reclassify


LEGACY = (
    "# kind\tkey\tvalue\tdetail\n"
    "object\t0x17ec8f580\t0\tsource=self off=0x0 ptr=0x7ff6a67369e8 vptr_rva=0x33c8d0 slot2_rva=-\n"
    "object\t0x17ec8f580\t0\tsource=self off=0x18 ptr=0x54454e414c50 vptr_rva=- slot2_rva=-\n"
)


def test_parse_object_rows_keeps_a_row_whose_rva_is_a_dash():
    rows = parse_object_rows(LEGACY)
    assert len(rows) == 2
    assert rows[1]["vptr_rva"] is None and rows[1]["has_vptr_abs"] is False


def test_reclassify_splits_four_buckets_and_never_loses_a_row():
    rows = parse_object_rows(LEGACY)
    floor = {0x33c8d0}                 # 旧判据:命中
    allv = {0x33c8d0: (5, 0x10, 0x33c8d0, 0x20)}   # 新集:同一行,再加别的
    out = reclassify(rows, floor, allv)
    assert out["total"] == 2
    assert out["floor_hits"] == 1
    assert out["undecidable_no_rva"] == 1          # 那行 `-` 进「无法判定」,不进「不是对象」
    assert out["still_no"] == 0


def test_reclassify_reports_a_hit_that_only_the_unfiltered_set_sees():
    rows = parse_object_rows(
        "object\t0x1\t0\tsource=helper off=0x0 ptr=0x2 vptr_rva=0x26dc2d0 slot2_rva=-\n")
    out = reclassify(rows, floor=set(), allv={0x26dc2d0: (6, 0x9ec250, 0x26dc2d0, 0)})
    assert out["new_only_hits"] == 1
    assert [r["vptr_rva"] for r in out["new_rows"]] == [0x26dc2d0]


def test_reclassify_total_is_the_sum_of_its_buckets():
    # 分桶必须互斥且穷尽 —— 否则「重问一遍」悄悄丢了行
    out = reclassify(parse_object_rows(LEGACY), {0x33c8d0}, {})
    assert out["total"] == (out["floor_hits"] + out["new_only_hits"]
                            + out["undecidable_no_rva"] + out["still_no"])


def test_load_candidate_map_reads_the_row_grammar_task_3_writes(tmp_path):
    # `slot0 0x…`,两个空格分隔的列 —— 写错这一格语法,新集就是空集,而每个桶都仍然「有数」
    path = tmp_path / "cands.txt"
    path.write_text(
        "# 172296 vtable-shaped runs in .rdata, run>=3, NOT filtered by slot[1]\n"
        "vtable 0x026dc2d0  run=8  slot0 0x009ec250  slot1 0x01ca5ae0  slot2 0x01ca5c90\n"
        "vtable 0x026dc2d8  run=8  slot0 0x01ca5ae0  slot1 0x01ca5c90\n",
        encoding="utf-8")
    assert load_candidate_map(str(path)) == {0x26dc2d0: (8, 0x9ec250, 0x1ca5ae0, 0x1ca5c90)}
