"""站点围栏：双语页面 1:1、nav 可达、页面不引用内部目录。
纯文本/JSON 检查，无网络、无 npm——它要和 `pytest scripts -q` 一起跑。"""
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
SITE = REPO / "site"
NAV = SITE / ".vitepress" / "nav.json"


# 站点内容只有手写的 md：`.vitepress/` 是配置与构建产物，`node_modules/` 是依赖树，
# 两者里的 `.md` 都不是页面（不排除 `node_modules` 会让门在 `npm ci` 之后自己变红）。
_SKIP_DIRS = {".vitepress", "node_modules"}


def _md_files(root):
    return {p.relative_to(root).as_posix() for p in root.rglob("*.md")
            if not _SKIP_DIRS.intersection(p.parts)}


def page_sets_match():
    en = {p for p in _md_files(SITE) if not p.startswith("zh/")}
    # `_md_files(SITE / "zh")` already yields paths relative to `zh/`, so they are
    # directly comparable with the English set. (Stripping a second "zh/" here
    # would chop three characters off every name and compare apples to oranges.)
    zh = _md_files(SITE / "zh")
    return en == zh


def nav_targets_exist():
    nav = json.loads(NAV.read_text(encoding="utf-8"))
    missing = []
    for lang, prefix in (("en", ""), ("zh", "zh/")):
        for section in nav[lang]:
            for item in section["items"]:
                rel = item["link"].strip("/")
                # The zh links carry the locale prefix ("/zh/guide/install");
                # it names the locale, not the file, so drop it before joining.
                if prefix and rel.startswith(prefix):
                    rel = rel[len(prefix):]
                rel = "index.md" if not rel else f"{rel}.md"
                if not (SITE / prefix / rel).is_file():
                    missing.append(f"{lang}:{item['link']}")
    return missing


_LINK = re.compile(r"\]\(([^)]+)\)")


def no_internal_links():
    bad = []
    for path in SITE.rglob("*.md"):
        if _SKIP_DIRS.intersection(path.parts):
            continue
        for target in _LINK.findall(path.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "#", "/")):
                continue
            if "evidence/" in target or "docs/" in target:
                bad.append(f"{path.relative_to(SITE)} -> {target}")
    return bad


def test_page_sets_match():
    assert page_sets_match()


def test_nav_targets_exist():
    assert nav_targets_exist() == []


def test_no_internal_links():
    assert no_internal_links() == []
