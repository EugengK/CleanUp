"""AI 도구가 여기저기 남긴 흔적 찾기: 전역 설정/캐시 폴더 + 프로젝트 안의 AI 설정 파일."""
from __future__ import annotations

import os
import sys

from .core import dir_size, finding, home, walk, age_days

# (홈 기준 상대경로, 설명)
GLOBAL = [
    (".claude", "Claude Code 설정·대화기록·플러그인 (사용 중이면 유지)"),
    (".claude.json", "Claude Code 계정/설정"),
    (".cursor", "Cursor 설정·확장"), (".codex", "Codex CLI 설정·기록"),
    (".gemini", "Gemini CLI 설정·기록"), (".continue", "Continue 확장 설정"),
    (".windsurf", "Windsurf 설정"), (".codeium", "Codeium 캐시"),
    (".aider", "Aider 데이터"), (".ollama", "Ollama 모델 (용량 큼)"),
    (".lmstudio", "LM Studio 모델 (용량 큼)"),
    (".cache/huggingface", "HuggingFace 모델 캐시 (용량 큼)"), (".cache/torch", "PyTorch 모델 캐시"),
    (".cache/pip", "pip 다운로드 캐시"), (".cache/uv", "uv 캐시"), (".npm/_cacache", "npm 캐시"),
    (".npm/_npx", "npx 임시 설치"), (".bun/install/cache", "bun 캐시"),
    ("Library/Caches/pip", "pip 캐시"), ("Library/Caches/Homebrew", "Homebrew 다운로드 캐시 (brew cleanup 으로도 정리 가능)"),
    ("Library/Developer/Xcode/DerivedData", "Xcode 빌드 캐시 (지워도 다시 생성됨)"),
    ("Library/Developer/Xcode/iOS DeviceSupport", "Xcode 기기 지원 파일 (용량 큼)"),
    ("Library/Developer/CoreSimulator", "iOS 시뮬레이터 데이터 (용량 큼)"),
    ("Library/Application Support/Claude", "Claude 데스크톱 앱 데이터 (사용 중이면 유지)"),
    ("Library/Application Support/Cursor", "Cursor 앱 데이터"),
    ("Library/Application Support/Code/CachedExtensionVSIXs", "VS Code 확장 설치 캐시"),
    ("Library/Application Support/Windsurf", "Windsurf 앱 데이터"),
]
# 프로젝트 안에서 찾을 AI 흔적 (이름 → 설명)
PROJECT_MARKERS = {".claude": "프로젝트별 Claude Code 설정", "CLAUDE.md": "Claude 지침 파일",
                   "AGENTS.md": "에이전트 지침 파일", "GEMINI.md": "Gemini 지침 파일",
                   ".cursor": "프로젝트별 Cursor 설정", ".cursorrules": "Cursor 규칙",
                   ".windsurf": "Windsurf 설정", ".continue": "Continue 설정",
                   ".aider.chat.history.md": "Aider 대화기록", ".aider.input.history": "Aider 입력기록"}
PROJECT_FILES = {"package.json", "pyproject.toml", "requirements.txt", "Cargo.toml", "go.mod", "pom.xml"}
SKIP = {"node_modules", ".venv", "venv", "site-packages", "__pycache__", "Library", ".Trash"}


def scan_footprints(roots, stale_days=180, max_depth=6, progress=None):
    results, fid = [], 0
    for rel, desc in GLOBAL:
        p = str(home() / rel)
        if not os.path.exists(p):
            continue
        if os.path.isdir(p):
            size, newest = dir_size(p)
        else:
            st = os.lstat(p)
            size, newest = st.st_size, st.st_mtime
        fid += 1
        results.append(finding(fid, p, size, "global", desc, "review", newest))
    projects = {}
    for root in roots:
        if not os.path.isdir(root):
            continue
        base_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.count(os.sep) - base_depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in SKIP and not os.path.islink(os.path.join(dirpath, d))]
            if progress is not None:
                progress["dir"] = dirpath
            names = set(dirnames) | set(filenames)
            found = {n: d for n, d in PROJECT_MARKERS.items() if n in names}
            if not found:
                continue
            for n, desc in found.items():
                p = os.path.join(dirpath, n)
                if os.path.isdir(p):
                    size, newest = dir_size(p)
                else:
                    st = os.lstat(p)
                    size, newest = st.st_size, st.st_mtime
                fid += 1
                results.append(finding(fid, p, size, "marker", desc, "review", newest))
            if names & PROJECT_FILES or ".git" in names:
                projects[dirpath] = sorted(found)
    for pdir, markers in projects.items():
        size, newest = dir_size(pdir)
        stale = age_days(newest) >= stale_days
        fid += 1
        results.append(finding(
            fid, pdir, size, "project",
            f"AI 도구를 쓴 프로젝트 폴더 ({', '.join(markers)})" + (f" — {age_days(newest)}일째 변경 없음" if stale else ""),
            "review" if stale else "info", newest, True))
    results.sort(key=lambda r: (r["kind"] != "project", -r["size"]))
    note = ["'info' 표시는 최근 변경된 프로젝트라 정리 대상이 아닐 가능성이 큽니다."]
    return {"items": results, "notes": note}
