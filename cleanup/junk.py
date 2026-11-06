"""불필요 파일 후보: 캐시/임시/백업/로그, 재설치 가능한 폴더, AI가 남긴 문서, 오래 안 쓴 큰 파일."""
from __future__ import annotations

import fnmatch
import os
import re

from .core import age_days, dir_size, finding, walk

CACHE_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".ipynb_checkpoints",
              ".tox", ".hypothesis", ".cache"}
REBUILD_DIRS = {"node_modules": "npm install 로 다시 만들 수 있음",
                ".venv": "가상환경, 다시 만들 수 있음", "venv": "가상환경, 다시 만들 수 있음",
                ".next": "빌드 캐시", ".nuxt": "빌드 캐시", ".parcel-cache": "빌드 캐시",
                ".turbo": "빌드 캐시"}
TEMP_FILES = [".DS_Store", "*.tmp", "*.crdownload", "*.swp", "~$*",
              "*.pyc", "*.part", "._*"]
BACKUP_FILES = ["*.bak", "*.orig", "*.old", "*~"]
# AI 도구가 흔히 남기는 문서의 이름 특징. 설정 파일(CLAUDE.md 등)과 일반 문서는 제외.
KEEP_MD = {"README", "LICENSE", "CONTRIBUTING", "CHANGELOG", "CLAUDE", "AGENTS", "GEMINI",
           "CODE_OF_CONDUCT", "SECURITY", "NOTICE", "AUTHORS", "TODO", "MEMORY", "SKILL"}
_CAPS_SNAKE = re.compile(r"^[A-Z0-9]+(?:[_-][A-Z0-9]+)+$")
_KEYWORDS = re.compile(r"(summary|report|plan|analysis|notes|status|complete|implementation|"
                       r"walkthrough|scratch|handoff|session|debug|fixes?)", re.I)
SKIP_DIRS = {".git", "site-packages", "Library", ".Trash", "Photos Library.photoslibrary"}


def _match(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def ai_doc_reason(name: str) -> str | None:
    stem, ext = os.path.splitext(name)
    if ext.lower() != ".md" or stem.upper() in KEEP_MD:
        return None
    if _CAPS_SNAKE.match(stem):
        return "AI가 자주 만드는 대문자_이름.md 형태"
    m = _KEYWORDS.search(stem)
    if m and (stem.isupper() or "_" in stem or "-" in stem):
        return f"파일명에 '{m.group(1).lower()}' 포함 — AI 작업 메모/보고서일 가능성"
    return None


def scan_junk(roots, stale_days=180, min_stale_mb=5, ai_doc_days=14, log_days=30,
              include_stale=True, progress=None, max_stale=300):
    results, fid = [], 0
    stale = []
    min_stale = min_stale_mb * 1024 * 1024

    def prune(name, full):
        if name in SKIP_DIRS:
            return False  # 방출 안 하고 내부로도 안 들어가려면 아래서 처리
        return name in CACHE_DIRS or name in REBUILD_DIRS

    for root in roots:
        if not os.path.isdir(root):
            continue

        def _prune(name, full):
            if name in SKIP_DIRS:
                return False
            return prune(name, full)

        for item in walk(root, prune=_prune, progress=progress):
            if item[0] == "dir":
                path = item[1]
                name = os.path.basename(path)
                size, newest = dir_size(path)
                fid += 1
                if name in CACHE_DIRS:
                    results.append(finding(fid, path, size, "cache", "자동으로 다시 생기는 캐시 폴더",
                                           "safe", newest, True))
                else:
                    reason = REBUILD_DIRS[name]
                    results.append(finding(fid, path, size, "rebuildable", reason, "review", newest, True))
                continue
            _, path, st = item
            name = os.path.basename(path)
            if _match(name, TEMP_FILES):
                fid += 1
                results.append(finding(fid, path, st.st_size, "temp", "임시/시스템 부산물", "safe", st.st_mtime, False))
            elif _match(name, BACKUP_FILES):
                fid += 1
                results.append(finding(fid, path, st.st_size, "backup", "백업/잔여 파일 (.bak 등)", "review", st.st_mtime, False))
            elif name.lower().endswith(".log") and age_days(st.st_mtime) >= log_days:
                fid += 1
                results.append(finding(fid, path, st.st_size, "log", f"{age_days(st.st_mtime)}일 지난 로그", "review", st.st_mtime, False))
            else:
                why = ai_doc_reason(name)
                if why and age_days(st.st_mtime) >= ai_doc_days:
                    fid += 1
                    results.append(finding(fid, path, st.st_size, "ai_doc", why + " (내용 확인 후 삭제)", "review", st.st_mtime, False))
                elif include_stale and st.st_size >= min_stale and age_days(max(st.st_mtime, st.st_atime)) >= stale_days:
                    stale.append((st.st_size, path, st))
    stale.sort(reverse=True)
    for size, path, st in stale[:max_stale]:
        fid += 1
        d = age_days(max(st.st_mtime, st.st_atime))
        results.append(finding(fid, path, size, "stale", f"{d}일 동안 수정·열람 기록 없음 (접근시각은 OS 설정에 따라 부정확할 수 있음)",
                               "review", st.st_mtime, False))
    results.sort(key=lambda r: r["size"], reverse=True)
    return {"items": results, "notes": [f"오래된 파일은 크기 상위 {max_stale}개만 표시" ] if len(stale) > max_stale else []}
