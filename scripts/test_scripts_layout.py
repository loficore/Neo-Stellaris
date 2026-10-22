"""Executable fence for the scripts/ naming-and-directory convention.

The rule text lives in ``AGENTS.md`` section「scripts/ 命名与目录约定」; the
inventory this fence must agree with is ``scripts/README.md``.  Every rule is a
pure function that takes a directory/file list and returns violation strings
shaped ``"<basename>: <reason>"``.  Each rule is tested twice: once against a
synthetic violating tree (proves the fence bites) and once against the real
repo (proves today's tree is clean).

Pure Python, host-only: nothing here imports a live-channel module or touches
``ctypes.WinDLL`` at import (ruling P3).  ``evidence/`` is never scanned.

Exemptions are added by naming the file in the rule function's docstring,
never by ``xfail`` — xfail hides the drift that motivated the fence.
"""

import os, re, sys, pathlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parent

def _read(path):
    return path.read_text(encoding="utf-8", errors="replace")

def top_level_scripts(root):
    """``scripts/*.py`` + ``scripts/*.js``, excluding ``scratch/`` and ``windows/``.

    The maintained top-level inventory per ``scripts/README.md``.
    """
    return sorted(p for p in list(root.glob("*.py")) + list(root.glob("*.js")))

_EXE_READER_RE = re.compile(r"(open|read_bytes|Path)\(.*stellaris\.exe")

def offline_exe_readers(files):
    """Files that read the game exe *from disk*: an exe-opening call or a
    ``SteamLibrary`` literal, and not a live-channel script (no
    ``CreateRemoteThread``) — the rule keys on what a script does, not its family.
    """
    out = []
    for f in files:
        src = _read(f)
        if (_EXE_READER_RE.search(src) or "SteamLibrary" in src) \
                and "CreateRemoteThread" not in src:
            out.append(f)
    return out

def violates_env_var(files):
    """R-env: an offline exe reader must carry a ``NS_STELLARIS_EXE`` candidate;
    a hard-coded ``D:\\SteamLibrary\\...`` fallback next to one is compliant.
    """
    return [f"{f.name}: reads stellaris.exe from disk with no NS_STELLARIS_EXE candidate"
            for f in offline_exe_readers(files)
            if "NS_STELLARIS_EXE" not in _read(f)]

GAME_VERSION_TOKENS = {"444"}
_BANNED_STEMS = {"final", "new", "misc", "old", "tmp"}

def violates_version_suffix(files):
    """R-suffix: no ``2``/``final``/``new``/``misc``-style version suffix on
    maintained script names — version belongs in git, not in filenames.  A
    trailing digit run is only allowed when it is a game-version token
    (``444`` in ``scan444.py`` / ``anchor444.js``).
    """
    out = []
    for f in files:
        digits = re.search(r"\d+$", f.stem)
        if f.stem in _BANNED_STEMS:
            out.append(f"{f.name}: banned placeholder-style stem (version belongs in git)")
        elif digits and digits.group() not in GAME_VERSION_TOKENS:
            out.append(f"{f.name}: trailing digit run '{digits.group()}' is a tool "
                       "version suffix, not a game version token")
    return out

def violates_pairing(scripts_dir):
    """R-pair: every ``.js`` directly in the given directory must have its stem
    appear in the text of some ``.py`` in that same directory.

    Substring-of-text is deliberate: ``dis.js`` is carried by ``fridadis.py``
    and ``anchor444.js`` by ``scan444.py:15``, cross-named on purpose because
    ``C:\\ns\\...`` is a wire path.  Only the directory it is given is scanned —
    called with ``SCRIPTS``, never with ``scratch/`` (frozen history such as
    ``2026-09_frida_hot_site_spies/body.js`` is explained by its own README).
    """
    out = []
    # A guard that discusses its subjects must not vouch for them: test_* files
    # are excluded from the driver set, else this fence's own docstring would
    # pair an orphaned .js after its real driver is renamed or moved.
    drivers = [_read(p) for p in sorted(scripts_dir.glob("*.py"))
               if not p.name.startswith("test_")]
    for js in sorted(scripts_dir.glob("*.js")):
        if not any(js.stem in src for src in drivers):
            out.append(f"{js.name}: no .py in this directory references it "
                       "(.py driver and .js script are a pair)")
    return out

FAMILY_PREFIXES = ("c1_", "c2_")

def violates_family_depth(root):
    """R-depth: a ``c1_*``/``c2_*``/``test_c2_harness.py`` ``.py`` must sit
    exactly at ``scripts/<name>`` — bare-name imports and the ``C:/temp`` scp
    contract (ruling P5) locate it by that path.  ``windows/`` is out of scope:
    the launcher family is a separate package with its own ``PYTHONPATH=.``.
    """
    out = []
    for p in sorted(root.rglob("*.py")):
        if p.parent == root:
            continue
        if "windows" in p.relative_to(root).parts:
            continue
        if p.name == "test_c2_harness.py" or p.name.startswith(FAMILY_PREFIXES):
            out.append(f"{p.name}: must sit directly under scripts/ "
                       "(bare-name imports + C:/temp wire contract)")
    return out

_SCRIPT_REF_RE = re.compile(r"(?:^|[\s`(])scripts/([A-Za-z0-9_./-]+\.(?:py|js|sh|bat))",
                            re.MULTILINE)

# The living docs named by the convention (``AGENTS.md`` 「scripts/ 命名与目录约定」,
# R-refs).  Single source of truth: both the R-refs scan and
# test_named_living_docs_exist read this, so when a later task retires PLAN.md it
# is removed *here* once and the existence assertion follows — a test that pinned
# ``REPO / "PLAN.md"`` in its body would block that deletion.
LIVING_DOCS_NAMED = [REPO / "AGENTS.md", REPO / "PLAN.md"]

def dangling_script_refs(doc_paths):
    """R-refs: every ``scripts/<path>`` token written in a living doc must
    resolve — literally under ``REPO`` first, else as the basename of a file
    anywhere under ``scripts/`` (scratch basenames are cited by evidence-style
    history and may be referenced shallowly).  Violation strings name the
    *doc* basename, so ``docs/superpowers/`` (private) must be filtered out by
    the caller.  ``evidence/`` is immutable and never scanned.
    """
    basenames = {p.name for p in SCRIPTS.rglob("*") if p.is_file()}
    out = []
    for doc in doc_paths:
        for m in _SCRIPT_REF_RE.finditer(_read(doc)):
            ref = m.group(1)
            if (REPO / ref).exists() or pathlib.PurePosixPath(ref).name in basenames:
                continue
            out.append(f"{doc.name}: dangling reference scripts/{ref}")
    return out

ROADMAP_MAX_LINES = 140
_ROADMAP_COLUMNS = ("阶段", "状态", "证据", "计划", "第一前置")
_ROADMAP_STATUSES = {"done", "blocked", "in-progress", "planned"}
_ROADMAP_PLAN_RE = re.compile(r"\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md")
_ROADMAP_VOLUME_RE = re.compile(r"(structures|pipeline|c1_validation)")
_ROADMAP_SECTION_RE = re.compile(r"§\d")
_ROADMAP_SEP_RE = re.compile(r"^:?-+:?$")

def _roadmap_cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]

def violates_roadmap_shape(roadmap_path):
    """R-roadmap: ``docs/roadmap.md`` must stay a slim index, not re-inflate into
    a PLAN.md.  Total line count is capped; the 阶段状态表 (the one table whose
    header carries all five column names — located *by header name, not position*,
    so a differently-shaped sibling table above it is not policed) must use a
    status from the vocabulary and fill its evidence/plan cell per status; no
    ``docs/superpowers/`` path may appear.  Violation strings are
    ``"<label>: <reason>"`` — the file basename for doc-level hits, the row's
    阶段 value for per-row hits — matching the neighboring-rule shape.
    """
    name = roadmap_path.name
    text = _read(roadmap_path)
    lines = text.splitlines()
    out = []
    if len(lines) > ROADMAP_MAX_LINES:
        out.append(f"{name}: lines > {ROADMAP_MAX_LINES} ({len(lines)} lines)")
    if "docs/superpowers/" in text:
        out.append(f"{name}: references private plan path docs/superpowers/")

    header_index = None
    col = {}
    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = _roadmap_cells(line)
        if all(c in cells for c in _ROADMAP_COLUMNS):
            header_index = i
            col = {c: cells.index(c) for c in _ROADMAP_COLUMNS}
            break
    if header_index is None:
        return out

    def evidence_ok(value):
        return bool(_ROADMAP_VOLUME_RE.search(value) and _ROADMAP_SECTION_RE.search(value))

    for line in lines[header_index + 1:]:
        if not line.strip().startswith("|"):
            break
        cells = _roadmap_cells(line)
        if cells and all(_ROADMAP_SEP_RE.match(c) for c in cells):
            continue
        if len(cells) <= max(col.values()):
            continue
        label = cells[col["阶段"]]
        status = cells[col["状态"]]
        evidence = cells[col["证据"]]
        plan = cells[col["计划"]]
        if status not in _ROADMAP_STATUSES:
            out.append(f"{label}: unknown status '{status}' "
                       f"(allowed: {sorted(_ROADMAP_STATUSES)})")
            continue
        if status in ("blocked", "in-progress") and not evidence_ok(evidence):
            out.append(f"{label}: {status} row needs evidence — a volume alias "
                       "(structures|pipeline|c1_validation) plus §<number>")
        if status == "planned" and not _ROADMAP_PLAN_RE.search(plan):
            out.append(f"{label}: planned row needs a plan filename matching "
                       "YYYY-MM-DD-<topic>.md")
        if status == "done" and not (evidence_ok(evidence) or _ROADMAP_PLAN_RE.search(plan)):
            out.append(f"{label}: done row needs evidence (§ + volume alias) "
                       "or a plan filename")
    return out

def violates_hardcoded_rvas(files):
    """R-rva: no hard-coded module-level ``RVAS`` dict literal in a maintained
    script — every RVA must be re-parsed from the injected copy via
    ``list_exports`` (ruling P10).
    """
    # armed by test_no_hardcoded_rva_dict_anywhere_in_the_maintained_tree
    # (Task 2); the pattern lives only in this compiled regex, so the guard
    # file itself stays clean and the real-tree test names only genuine
    # violators — P10 has no exemption, not even for the fence.
    rvas_re = re.compile(r"\bRVAS\s*=\s*\{")
    return [f"{f.name}: hard-coded RVAS dict (ruling P10 — re-parse with list_exports)"
            for f in files if rvas_re.search(_read(f))]

def test_env_var_rule_names_a_disk_reader_without_the_var(tmp_path):
    bad = tmp_path / "peek.py"
    bad.write_text('EXE = r"D:\\SteamLibrary\\steamapps\\common\\Stellaris\\stellaris.exe"\n'
                   "f = open(EXE, 'rb').read()\n")
    good = tmp_path / "ok.py"
    good.write_text("_cands = [os.environ.get('NS_STELLARIS_EXE'),\n"
                    "  r'D:\\SteamLibrary\\steamapps\\common\\Stellaris\\stellaris.exe']\n"
                    "f = open(next(c for c in _cands if os.path.exists(c)), 'rb')\n")
    # regex branch: the exe-opening call itself matches, no SteamLibrary literal
    regex_bad = tmp_path / "regex_peek.py"
    regex_bad.write_text("f = open('/opt/game/stellaris.exe', 'rb')\n")
    # exclusion branch: a live-channel script (CreateRemoteThread) is out of scope
    live_ok = tmp_path / "live.py"
    live_ok.write_text("f = open('/opt/game/stellaris.exe', 'rb')\n"
                       "kernel32.CreateRemoteThread(pid, None, 0, addr, None, 0, None)\n")
    assert violates_env_var([bad, good, regex_bad, live_ok]) == [
        "peek.py: reads stellaris.exe from disk with no NS_STELLARIS_EXE candidate",
        "regex_peek.py: reads stellaris.exe from disk with no NS_STELLARIS_EXE candidate"]

def test_real_tree_has_no_env_var_violation():
    assert violates_env_var(top_level_scripts(SCRIPTS)) == []

def test_live_scripts_are_out_of_scope_for_the_env_var_rule():
    offenders = {v.split(":")[0] for v in violates_env_var(top_level_scripts(SCRIPTS))}
    for live in ("c1_remote.py", "c1_verify_bst.py", "c1_verify_reverse.py",
                 "c2_control_sleep.py", "c2_harness.py", "execspy.py", "fridadis.py",
                 "frida-test.py", "test_c2_harness.py"):
        assert live not in offenders

def test_version_suffix_rule_accepts_game_version_tokens_only(tmp_path):
    for name, dirty in (("body2.py", True), ("fs3.py", True), ("spy7.js", True),
                        ("misc.py", True), ("scan444.py", False),
                        ("anchor444.js", False), ("thunkarrays.py", False)):
        (tmp_path / name).write_text("")
    hits = {v.split(":")[0] for v in violates_version_suffix(sorted(tmp_path.glob("*.*")))}
    assert hits == {"body2.py", "fs3.py", "spy7.js", "misc.py"}

def test_real_top_level_tree_is_suffix_clean():
    assert violates_version_suffix(top_level_scripts(SCRIPTS)) == []

def test_pairing_rule_flags_an_orphan_js_at_top_level(tmp_path):
    (tmp_path / "driver.py").write_text('JS = r"C:\\ns\\partner.js"\n')
    (tmp_path / "partner.js").write_text("")
    (tmp_path / "orphan.js").write_text("")
    (tmp_path / "scratch").mkdir()
    (tmp_path / "scratch" / "frozen.js").write_text("")   # out of scope
    assert [v.split(":")[0] for v in violates_pairing(tmp_path)] == ["orphan.js"]

def test_real_top_level_js_files_all_have_a_driver():
    assert violates_pairing(SCRIPTS) == []

def test_family_depth_rule_flags_a_nested_c2_script(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "c2_harness.py").write_text("")
    (tmp_path / "c2_task5_init.py").write_text("")
    (tmp_path / "windows").mkdir()
    (tmp_path / "windows" / "launch_stellaris.py").write_text("")
    # Family-named file under windows/: pins the exclusion itself — without
    # it, deleting the windows skip in violates_family_depth changes nothing
    # anyone can observe (a mutation-surviving branch).
    (tmp_path / "windows" / "c2_helper.py").write_text("")
    assert violates_family_depth(tmp_path) == ["c2_harness.py: must sit directly "
                                               "under scripts/ (bare-name imports + "
                                               "C:/temp wire contract)"]

def test_real_family_is_at_depth_one():
    assert violates_family_depth(SCRIPTS) == []

def test_living_docs_script_references_resolve():
    docs = LIVING_DOCS_NAMED + list((REPO / "docs").rglob("*.md"))
    docs = [d for d in docs if "superpowers" not in str(d)]
    assert dangling_script_refs(docs) == []

def test_dangling_rule_fires_on_a_moved_script(tmp_path):
    (tmp_path / "docs").mkdir(); (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "gone.py").touch()
    (tmp_path / "docs" / "a.md").write_text("run `python3 scripts/nowhere.py`\n")
    hits = dangling_script_refs([tmp_path / "docs" / "a.md"])
    assert len(hits) == 1 and hits[0].startswith("a.md:")

def test_hardcoded_rva_rule_flags_a_rvas_dict(tmp_path):
    bad = tmp_path / "some_tool.py"
    # The offending dict text is assembled at runtime so this guard file never
    # contains the literal pattern the rule scans for; the armed real-tree test
    # must name exactly the genuine violators, and P10 has no exemption for
    # the fence's own fixture strings.
    bad.write_text("RVAS " + "= " + "{\n    'C2Sanity': 0x1234,\n}\n")
    good = tmp_path / "clean.py"
    good.write_text("exports = list_exports(dll_path)\n")
    assert violates_hardcoded_rvas([bad, good]) == [
        "some_tool.py: hard-coded RVAS dict (ruling P10 — re-parse with list_exports)"]

def test_no_hardcoded_rva_dict_anywhere_in_the_maintained_tree():
    assert violates_hardcoded_rvas(top_level_scripts(SCRIPTS)) == []

import importlib

def test_c2_test_sanity_resolves_rvas_from_the_reparsed_table():
    m = importlib.import_module("c2_test_sanity")
    exports = {"C2Sanity": 0x1234, "C2Init": 0x5678}
    assert m.resolve_targets(exports, ("C2Sanity", "C2Init")) == exports
    try:
        m.resolve_targets(exports, ("C2Sanity", "C2Gone"))
        assert False, "a stale export name must raise, not dispatch a guessed address"
    except KeyError as exc:
        assert "C2Gone" in str(exc)

def test_c2_test_sanity_refuses_dispatch_when_sanity_is_not_42():
    m = importlib.import_module("c2_test_sanity")
    assert m.sanity_gate(42) is True
    for rc in (0, 3, 259, 41):
        assert m.sanity_gate(rc) is False

WORKTREE_ONLY = {"dispatch_watching_buffer", "_gle", "kernel32_call_address", "_prime_buffer"}

def test_c2_test_sanity_keeps_its_cli_shape():
    src = (SCRIPTS / "c2_test_sanity.py").read_text()
    assert "argv[1]" in src and "argv[2]" in src

def test_c2_test_sanity_does_not_reach_into_the_other_plan():
    import ast
    tree = ast.parse((SCRIPTS / "c2_test_sanity.py").read_text())
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not (names | attrs) & WORKTREE_ONLY, \
        "these symbols exist only in the uncommitted worktree copy of c2_harness.py"

# --- living-docs input existence + roadmap shape fence (plan-decomposition Task 1) ---

def test_named_living_docs_exist():
    missing = [str(p) for p in LIVING_DOCS_NAMED if not p.exists()]
    assert missing == []

def test_roadmap_rule_flags_bloat_and_missing_pointers(tmp_path):
    bad = tmp_path / "roadmap.md"
    bad.write_text(
        "## 3. 阶段状态表\n"
        "| 阶段 | 状态 | 证据 | 计划 | 第一前置 |\n"
        "|---|---|---|---|---|\n"
        "| C2 | blocked | 无 | x.md | 重开游戏 |\n"
        "| B3 | planned |  |  | 上传 dis.js |\n"
        "| A | done | pipeline §17 |  |  |\n")
    hits = violates_roadmap_shape(bad)
    assert any("C2" in h and "evidence" in h for h in hits)
    assert any("B3" in h and "plan filename" in h for h in hits)
    assert not any("A:" in h for h in hits)          # done 行有 § 就够,不逼它再交计划名

def test_roadmap_rule_flags_an_oversized_doc(tmp_path):
    big = tmp_path / "roadmap.md"
    big.write_text("\n".join(["| 阶段 | 状态 | 证据 | 计划 | 第一前置 |"] +
                             ["| Cx | done | pipeline §17 |  |  |"] * (ROADMAP_MAX_LINES + 1)))
    assert any("lines > 140" in h for h in violates_roadmap_shape(big))

def test_roadmap_rule_flags_a_private_plan_path_and_unknown_status(tmp_path):
    p = tmp_path / "roadmap.md"
    p.write_text("see docs/superpowers/plans/2026-10-22-x.md\n"
                 "| 阶段 | 状态 | 证据 | 计划 | 第一前置 |\n|---|---|---|---|---|\n"
                 "| Q | open | pipeline §17 |  |  |\n")
    hits = violates_roadmap_shape(p)
    assert any("private plan path" in h for h in hits)
    assert any("Q" in h and "status" in h for h in hits)
