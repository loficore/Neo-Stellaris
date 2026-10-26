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
