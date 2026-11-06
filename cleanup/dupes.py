"""중복 파일: 크기 → 앞부분 해시 → 전체 SHA-256 순으로 좁혀 정확히 같은 내용만 묶는다."""
from __future__ import annotations

import hashlib
import os
import re
from collections import defaultdict

from .core import finding, walk

SKIP = {".git", "node_modules", "__pycache__", "site-packages", ".venv", "venv", "$RECYCLE.BIN", ".Trash"}
_COPY = re.compile(r"(\(\d+\)|\bcopy\b|복사|사본|_\d+$| - copy)", re.I)


def _hash(path, limit=None):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            if limit:
                h.update(f.read(limit))
            else:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def keep_score(path: str, mtime: float):
    """낮을수록 '원본'일 가능성이 높다: 복사본 이름 아님 → 경로 짧음 → 오래됨."""
    name = os.path.basename(path)
    return (1 if _COPY.search(os.path.splitext(name)[0]) else 0, path.count(os.sep), mtime)


def scan_dupes(roots, min_kb=10, progress=None):
    by_size = defaultdict(list)
    seen_inodes = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        for item in walk(root, prune=lambda n, p: n in SKIP, progress=progress):
            if item[0] != "file":
                continue
            _, path, st = item
            if st.st_size < min_kb * 1024:
                continue
            key = (st.st_dev, st.st_ino)
            if st.st_ino and key in seen_inodes:
                continue  # 하드링크는 같은 데이터이므로 중복 아님
            seen_inodes.add(key)
            by_size[st.st_size].append((path, st))
    groups, fid, gid = [], 0, 0
    for size, files in by_size.items():
        if len(files) < 2:
            continue
        by_head = defaultdict(list)
        for path, st in files:
            hd = _hash(path, 65536)
            if hd:
                by_head[hd].append((path, st))
        for cand in by_head.values():
            if len(cand) < 2:
                continue
            if progress is not None:
                progress["dir"] = f"해시 확인: {os.path.basename(cand[0][0])}"
            by_full = defaultdict(list)
            for path, st in cand:
                hf = _hash(path)
                if hf:
                    by_full[hf].append((path, st))
            for same in by_full.values():
                if len(same) < 2:
                    continue
                same.sort(key=lambda x: keep_score(x[0], x[1].st_mtime))
                gid += 1
                members = []
                for i, (path, st) in enumerate(same):
                    fid += 1
                    f = finding(fid, path, size, "duplicate", "같은 내용의 파일이 더 있음" if i else "보관 추천 (원본으로 보임)",
                                "info" if i == 0 else "review", st.st_mtime, False, {"group": gid, "keep": i == 0})
                    members.append(f)
                groups.append({"group": gid, "size": size, "wasted": size * (len(same) - 1), "items": members})
    groups.sort(key=lambda g: g["wasted"], reverse=True)
    flat = [m for g in groups for m in g["items"]]
    return {"items": flat, "groups": [{"group": g["group"], "size": g["size"], "wasted": g["wasted"],
                                       "ids": [m["id"] for m in g["items"]]} for g in groups],
            "wasted_total": sum(g["wasted"] for g in groups), "notes": []}
