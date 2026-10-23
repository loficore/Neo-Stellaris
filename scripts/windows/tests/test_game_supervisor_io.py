"""Host-side tests for the supervisor's file-channel and shim helpers.

The live half is Windows-only; these functions are plain filesystem code and
must stay covered on the Linux host.
"""

import json
import os

import game_supervisor as gs


def test_atomic_write_json_replaces_without_leaving_a_tmp(tmp_path):
    path = tmp_path / "status.json"
    gs.atomic_write_json(path, {"state": "playing"})
    gs.atomic_write_json(path, {"state": "paused"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"state": "paused"}
    assert not (tmp_path / "status.json.tmp").exists()


def test_rotate_log_moves_the_old_bytes_and_is_missing_file_safe(tmp_path):
    path = tmp_path / "log.jsonl"
    gs.rotate_log(path, 50)
    assert not path.exists()
    path.write_text("x" * 100, encoding="utf-8")
    gs.rotate_log(path, 50)
    assert not path.exists()
    assert (tmp_path / "log.jsonl.1").read_text(encoding="utf-8") == "x" * 100
    path.write_text("y" * 10, encoding="utf-8")
    gs.rotate_log(path, 50)
    assert path.read_text(encoding="utf-8") == "y" * 10


def test_read_command_consumes_once_and_replays_only_on_a_new_mtime(tmp_path):
    cmd = tmp_path / "cmd.txt"
    seen = tmp_path / "cmd.seen"
    cmd.write_text("pause\n", encoding="utf-8")
    assert gs.read_command(cmd, seen) == "pause"
    assert gs.read_command(cmd, seen) is None
    st = cmd.stat()
    os.utime(cmd, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    assert gs.read_command(cmd, seen) == "pause"


def test_read_command_ignores_blank_and_absent(tmp_path):
    cmd = tmp_path / "cmd.txt"
    seen = tmp_path / "cmd.seen"
    cmd.write_text("   \n", encoding="utf-8")
    assert gs.read_command(cmd, seen) is None
    assert gs.read_command(tmp_path / "absent.txt", seen) is None


def test_task_shim_is_ascii_and_runs_serve():
    text = gs.task_shim_text(r"C:\Python\pythonw.exe", r"C:\temp\game_supervisor.py")
    text.encode("ascii")
    assert "serve" in text
    assert "game_supervisor.py" in text
    assert text.count("\n") >= 1


def test_norm_geometry_maps_any_window_to_the_spike_reference():
    rows = [{"y0": 430, "y1": 434, "x0": 630, "x1": 800}]
    bbox = [200, 140, 880, 540]
    nrows, nbbox, ngold = gs._norm_geometry(rows, bbox, 4000, (0, 0, 1080, 720))
    assert nrows == [{"y0": 860, "y1": 868, "x0": 1260, "x1": 1600}]
    assert nbbox == [400, 280, 1760, 1080]
    assert ngold == 16000
