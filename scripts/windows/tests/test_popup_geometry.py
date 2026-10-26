"""Host-side tests for the popup panel-geometry pure core.

Five fixtures pin the gate constants of the bright-panel bbox: row gate
max(60, 8%), column gate max(40, 8%), count floor 100/100, size gate
300/250. No Windows API, no PIL, no numpy.
"""

import inspect

import game_supervisor as gs
import popup_geometry as pg


def test_two_bright_faces_yield_one_envelope_not_two_slices():
    rows = [0] * 100 + [640] * 400 + [0] * 100          # h=600
    cols = [400] * 340 + [0] * 360 + [400] * 300        # w=1000，中间 340..699 是暗缝
    assert pg.panel_bbox(rows, cols) == [0, 100, 999, 499]


def test_bbox_top_is_first_row_clearing_the_density_gate():
    rows = [0] * 20 + [40] * 21 + [0] * 59 + [1000] * 400 + [0] * 100   # h=600
    cols = [400] * 1000                                                  # w=1000
    assert pg.panel_bbox(rows, cols) == [0, 100, 999, 499]


def test_single_face_bbox_is_its_own_extent():
    rows = [0] * 100 + [600] * 400 + [0] * 100
    cols = [400] * 600 + [0] * 400
    assert pg.panel_bbox(rows, cols) == [0, 100, 599, 499]


def test_below_the_count_floor_is_none():
    assert pg.panel_bbox([0] * 100 + [900] * 99 + [0] * 401, [500] * 1000) is None   # 99 行过门
    assert pg.panel_bbox([0] * 100 + [900] * 400 + [0] * 100, [500] * 99 + [0] * 901) is None  # 99 列过门


def test_below_the_size_gate_is_none():
    rows = [0] * 100 + [299] * 400 + [0] * 100
    assert pg.panel_bbox(rows, [400] * 299 + [0] * 701) is None      # 宽 298 < 300
    assert pg.panel_bbox([0] * 100 + [1000] * 249 + [0] * 251, [400] * 1000) is None  # 高 248 < 250


def test_numpy_side_keeps_only_the_luma_threshold():
    src = inspect.getsource(gs._panel_bbox)
    assert "luma > 120" in src
    for gate_literal in ("0.08", "300", "250"):
        assert gate_literal not in src


def test_pure_core_never_imports_numpy():
    assert "import numpy" not in inspect.getsource(pg)


def test_close_point_in_crop_batch2_contract():
    bbox = [879, 555, 1939, 1105]        # 批次 2 那扇「对话框 + 舰队列表」并集切片的信封
    assert pg.close_point_in_crop(bbox) == (964, 51)


def test_close_point_in_crop_tracks_close_point():
    bbox = [879, 555, 1939, 1105]
    x, y, method = gs.close_point(bbox)
    assert (x, y) == (1843, 606) and method == "fixed_inset"
    assert pg.close_point_in_crop(bbox) == (x - bbox[0], y - bbox[1])


def test_close_point_in_crop_negative_when_inset_exceeds_width():
    assert pg.close_point_in_crop([0, 500, 90, 900]) == (-6, 51)   # 裁片里没有 ✖：x 为负


def test_window_enum_record_keeps_every_candidate():
    cands = [(0x1001, (0, 0, 100, 100)), (0x1002, (879, 555, 1939, 1105))]
    rec = pg.window_enum_record(pid=4242, candidates=cands, chosen=0x1002)
    assert rec["event"] == "window_candidates" and rec["candidates_n"] == 2
    assert [r["hwnd"] for r in rec["rects"]] == [0x1001, 0x1002]
    assert rec["rects"][1]["rect"] == [879, 555, 1939, 1105]
