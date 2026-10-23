import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from chokepoints_emit import ChokepointDataError, main, parse_scores, render_zig
TSV = ROOT / "evidence/xrefs/chokepoint_scores_4_4_4.tsv"
SAVE_SHA = "6f271294bcfe3620a5e7da367a7f3fb0891c77315baffa28601ca48ec5d8d94e"
HEADER = "system_id\tdegree\tbetweenness\tbetweenness_norm\tscore\tis_articulation\tis_bridge_endpoint"

def test_parse_scores_reads_the_shipped_table():
    scores = parse_scores(TSV.read_text(encoding="utf-8"))
    assert len(scores) == 787
    assert (scores[0], scores[1], scores[7], scores[239], scores[578]) == (2, 1, 118, 200, 286)
    assert sum(1 for s in scores if s == 0) == 205
    assert (sum(1 for s in scores if s >= 100 and s < 200),
            sum(1 for s in scores if s >= 200),
            sum(1 for s in scores if s < 100)) == (55, 15, 717)

@pytest.mark.parametrize("text", [
    HEADER.rsplit("\t", 1)[0] + "\n0\t1\t0\t0\t1\t0\n",                       # 6 列头
    HEADER + "\n0\t1\t0\t0\t1\t0\t0\n2\t1\t0\t0\t1\t0\t0\n",                  # id 缺号
    HEADER + "\n0\t1\t0\t0\t65536\t0\t0\n",                                   # score 越界
    HEADER + "\n0\t1\t0\t0\t1\t0\n",                                          # 行只有 6 字段
])
def test_parse_scores_rejects_bad_header_gaps_and_wide_scores(text):
    with pytest.raises(ChokepointDataError):
        parse_scores(text)

def test_parse_scores_accepts_crlf_and_lf():
    rows = ["0\t1\t0\t0\t2\t0\t0", "1\t1\t0\t0\t1\t0\t0"]
    assert parse_scores("\r\n".join([HEADER, *rows]) + "\r\n") == [2, 1]
    assert parse_scores("\n".join([HEADER, *rows]) + "\n") == [2, 1]

def test_render_zig_round_trips_small_tables():
    src = render_zig([0, 99, 100, 199, 200, 286], "a" * 64)
    assert "SCORE_COUNT: usize = 6" in src
    assert "TIER1_MIN: u16 = 100" in src
    assert "TIER2_MIN: u16 = 200" in src
    assert "0, 99, 100, 199, 200, 286" in src
    with pytest.raises(ChokepointDataError):
        render_zig([65536], "a" * 64)
    with pytest.raises(ChokepointDataError):
        render_zig([1], "abc")

def test_generated_file_matches_the_emitter():
    assert (ROOT / "src/dll/c2/chokepoint_table.zig").read_text() == \
        render_zig(parse_scores(TSV.read_text(encoding="utf-8")), SAVE_SHA)

def test_main_check_and_write(tmp_path):
    small = tmp_path / "s.tsv"
    small.write_text(HEADER + "\n0\t1\t0\t0\t2\t0\t0\n1\t1\t0\t0\t150\t0\t0\n", encoding="utf-8")
    out = tmp_path / "t.zig"
    argv = ["--tsv", str(small), "--out", str(out), "--save-sha", SAVE_SHA]
    assert main(argv) == 0
    assert main(argv + ["--check"]) == 0
    out.write_text(out.read_text() + " ", encoding="utf-8")
    assert main(argv + ["--check"]) == 2
    out.unlink()
    assert main(argv + ["--check"]) == 2
